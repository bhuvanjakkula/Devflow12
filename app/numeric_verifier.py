"""Bounded numeric AST interpreter. No eval, imports, subprocesses or Python compilation."""
import ast
import hashlib
import math
import operator

BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
       ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod}
CMP = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
       ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge}
ALLOWED = (ast.Return, ast.Assign, ast.If, ast.Pass, ast.Expr, ast.Constant, ast.Name,
           ast.Load, ast.Store, ast.BinOp, ast.UnaryOp, ast.UAdd, ast.USub, ast.Not,
           ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.IfExp, *BIN, *CMP)


class Unsupported(ValueError):
    pass


def bounded(value):
    if type(value) not in (int, float, bool) or abs(value) > 1e12 or not math.isfinite(value):
        raise Unsupported('Only finite numeric/boolean values within +/- 1e12 are supported')
    return value


class Interpreter:
    def __init__(self):
        self.steps = 0

    def tick(self):
        self.steps += 1
        if self.steps > 2000:
            raise Unsupported('Interpreter step limit exceeded')

    def expression(self, node, env):
        self.tick()
        if isinstance(node, ast.Constant):
            return bounded(node.value)
        if isinstance(node, ast.Name):
            if node.id not in env:
                raise Unsupported('Undefined or external variable: ' + node.id)
            return env[node.id]
        if isinstance(node, ast.BinOp):
            return bounded(BIN[type(node.op)](self.expression(node.left, env), self.expression(node.right, env)))
        if isinstance(node, ast.UnaryOp):
            value = self.expression(node.operand, env)
            return bounded(-value if isinstance(node.op, ast.USub) else +value if isinstance(node.op, ast.UAdd) else not value)
        if isinstance(node, ast.IfExp):
            return self.expression(node.body if self.expression(node.test, env) else node.orelse, env)
        if isinstance(node, ast.BoolOp):
            value = self.expression(node.values[0], env)
            for item in node.values[1:]:
                if isinstance(node.op, ast.And) and not value or isinstance(node.op, ast.Or) and value:
                    return value
                value = self.expression(item, env)
            return value
        if isinstance(node, ast.Compare):
            left = self.expression(node.left, env)
            for op, right in zip(node.ops, node.comparators):
                right = self.expression(right, env)
                if not CMP[type(op)](left, right):
                    return False
                left = right
            return True
        raise Unsupported('Unsupported expression: ' + type(node).__name__)

    def block(self, statements, env):
        for node in statements:
            self.tick()
            if isinstance(node, ast.Return):
                return True, self.expression(node.value, env)
            if isinstance(node, ast.Assign):
                value = self.expression(node.value, env)
                for target in node.targets:
                    env[target.id] = value
            elif isinstance(node, ast.If):
                returned, value = self.block(node.body if self.expression(node.test, env) else node.orelse, env)
                if returned:
                    return True, value
            elif isinstance(node, ast.Expr):
                if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                    self.expression(node.value, env)
        return False, None


def verify_numeric(source, function, cases):
    report = {'source_sha256': hashlib.sha256(source.encode()).hexdigest(), 'function': function,
              'method': 'bounded numeric AST interpretation', 'cases': [],
              'scope': 'User-supplied finite examples only; not full Python execution or a proof over all inputs.'}
    try:
        if not cases:
            raise Unsupported('At least one independently specified example is required')
        tree = ast.parse(source)
        if sum(1 for _ in ast.walk(tree)) > 3000:
            raise Unsupported('Maximum 3000 AST nodes')
        if any(not isinstance(n, ast.FunctionDef) and not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)) for n in tree.body):
            raise Unsupported('Module may contain only function definitions and docstrings')
        for definition in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
            signature = definition.args
            if (definition.decorator_list or signature.defaults or signature.kw_defaults or
                    definition.returns is not None or getattr(definition, 'type_params', []) or
                    any(a.annotation is not None for a in signature.posonlyargs + signature.args + signature.kwonlyargs) or
                    signature.vararg and signature.vararg.annotation or signature.kwarg and signature.kwarg.annotation):
                raise Unsupported('Definition-time decorators, annotations, defaults and type parameters are unsupported')
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function]
        if len(functions) != 1:
            raise Unsupported('Exactly one named function definition is required')
        fn = functions[0]
        if fn.args.posonlyargs or fn.args.vararg or fn.args.kwarg or fn.args.kwonlyargs:
            raise Unsupported('Only ordinary positional-or-keyword parameters are supported')
        names = [arg.arg for arg in fn.args.posonlyargs + fn.args.args]
        if len(names) != len(set(names)):
            raise Unsupported('Duplicate parameter names are invalid')
        for statement in fn.body:
            for node in ast.walk(statement):
                if not isinstance(node, ALLOWED):
                    raise Unsupported('Unsupported syntax: ' + type(node).__name__)
                if isinstance(node, ast.Assign) and any(not isinstance(t, ast.Name) for t in node.targets):
                    raise Unsupported('Only local variable assignments are supported')
                if isinstance(node, ast.Constant) and not isinstance(node.value, str):
                    bounded(node.value)
        for index, case in enumerate(cases, 1):
            if set(case['inputs']) != set(names):
                raise Unsupported('Example input names must match all function parameters')
            interpreter = Interpreter()
            row = {'case': index, 'inputs': case['inputs'], 'expected': case['expected']}
            try:
                returned, value = interpreter.block(fn.body, {k: bounded(v) for k, v in case['inputs'].items()})
                if not returned:
                    raise Unsupported('Function reached its end without a numeric return')
                # Preserve boolean vs numeric distinctions; numeric int/float equality is accepted.
                matches = value == case['expected'] and (type(value) is bool) == (type(case['expected']) is bool)
                row.update(actual=value, status='passed' if matches else 'counterexample', steps=interpreter.steps)
            except (ZeroDivisionError, OverflowError) as error:
                row.update(status='counterexample', error=type(error).__name__, steps=interpreter.steps)
            except Unsupported as error:
                row.update(status='unsupported', reason=str(error), steps=interpreter.steps)
            report['cases'].append(row)
        statuses = {row['status'] for row in report['cases']}
        report['status'] = 'counterexample_found' if 'counterexample' in statuses else 'incomplete' if 'unsupported' in statuses else 'examples_passed'
    except (SyntaxError, Unsupported, RecursionError, ValueError) as error:
        report.update(status='unsupported', reason=str(error))
    return report
