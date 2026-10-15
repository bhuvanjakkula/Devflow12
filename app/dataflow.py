"""Conservative bounded Python input-to-sink analysis with helper-call summaries."""
import ast

from app.intelligence import qualified

SINKS = {'eval': ('CWE-95', 'Dynamic evaluation'), 'exec': ('CWE-95', 'Dynamic execution'),
         'builtins.eval': ('CWE-95', 'Dynamic evaluation'), 'builtins.exec': ('CWE-95', 'Dynamic execution'),
         'os.system': ('CWE-78', 'Shell command'), 'pickle.loads': ('CWE-502', 'Unsafe deserialization'),
         'pickle.load': ('CWE-502', 'Unsafe deserialization')}


def scan_dataflow(files):
    units = []
    diagnostics = []
    for path, source in sorted(files.items()):
        if not path.endswith('.py'):
            continue
        try:
            tree = ast.parse(source)
            if sum(1 for _ in ast.walk(tree)) > 3000:
                diagnostics.append({'path': path, 'reason': 'AST node limit exceeded'})
                continue
        except (SyntaxError, RecursionError, ValueError):
            diagnostics.append({'path': path, 'reason': 'Source could not be parsed'})
            continue
        module = path[:-3].replace('/', '.').removesuffix('.__init__')
        aliases = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            if isinstance(node, ast.ImportFrom):
                package = module.split('.') if path.endswith('/__init__.py') else module.split('.')[:-1]
                prefix = '.'.join(package[:max(0, len(package) - node.level + 1)] + ([node.module] if node.module else [])) if node.level else node.module or ''
                for item in node.names:
                    aliases[item.asname or item.name] = '.'.join(filter(None, [prefix, item.name]))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                units.append((path, module, node, aliases))
        # Also analyze module-level input -> sink flows; definitions/imports are skipped.
        units.append((path, module, tree, aliases))
    if len(units) > 300:
        return {'findings': [], 'status': 'incomplete', 'diagnostics': [{'reason': 'Maximum 300 analysis units'}]}
    summaries = {}
    findings = {}
    converged = False
    for iteration in range(8):
        next_summaries = {}
        for path, module, fn, aliases in units:
            name = module + '.' + fn.name if hasattr(fn, 'name') else module + '.<module>'
            args = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs if hasattr(fn, 'args') else []
            env = {a.arg: {('parameter:' + a.arg, fn.lineno)} for a in args}
            params = {a.arg: index for index, a in enumerate(args)}
            dangerous = set()

            def expression(node, state):
                if node is None or isinstance(node, ast.Constant):
                    return set()
                if isinstance(node, ast.Name):
                    return set(state.get(node.id, set()))
                if isinstance(node, ast.Call):
                    target = qualified(node.func, aliases)
                    taints = [expression(a, state) for a in node.args]
                    keyword_taints = {k.arg: expression(k.value, state) for k in node.keywords}
                    sources = {'input', 'builtins.input', 'request.args.get', 'request.form.get', 'request.json.get', 'request.get_json', 'request.get_data'}
                    combined = set().union(*taints, *keyword_taints.values())
                    if target in sources or target.removeprefix('flask.') in sources:
                        combined.add(('external:' + target, node.lineno))
                    sink = SINKS.get(target)
                    if target.startswith('subprocess.'):
                        if any(k.arg == 'shell' and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                            sink = ('CWE-78', 'Shell command')
                    if target.endswith(('.execute', '.executemany')):
                        # Parameterized value arguments do not taint the query string.
                        sink = ('CWE-89', 'Potential SQL injection')
                    summary = summaries.get(target) or summaries.get(module + '.' + target)
                    if summary:
                        risky = set()
                        for index in summary['dangerous_parameters']:
                            if index < len(taints):
                                risky |= taints[index]
                            param_name = summary['parameters'][index]
                            risky |= keyword_taints.get(param_name, set())
                        if risky:
                            sink = ('HELPER_FLOW', 'Input reaches risky helper: ' + target)
                            sink_taint = risky
                        else:
                            sink_taint = set()
                    else:
                        sink_taint = taints[0] if taints else keyword_taints.get('command', keyword_taints.get('args', keyword_taints.get('source', keyword_taints.get('sql', set()))))
                    if sink and sink_taint:
                        origins = sorted(sink_taint)
                        findings[(path, node.lineno, sink[0], name)] = {
                            'path': path, 'line': node.lineno, 'function': name, 'severity': 'high',
                            'rule': sink[0], 'title': sink[1], 'sink': target,
                            'sources': [{'kind': kind, 'line': line} for kind, line in origins],
                            'confidence': 'potential flow; caller trust and exploitability require review',
                            'recommendation': 'Validate trust boundaries; remove dynamic execution or parameterize the operation.'}
                        dangerous.update(params[kind.split(':', 1)[1]] for kind, _ in origins if kind.startswith('parameter:') and kind.split(':', 1)[1] in params)
                    # Unknown calls conservatively preserve taint; no guessed sanitizer can clear it.
                    return combined
                taint = set()
                for child in ast.iter_child_nodes(node):
                    taint |= expression(child, state)
                if isinstance(node, (ast.Attribute, ast.Subscript)):
                    target = qualified(node.value if isinstance(node, ast.Subscript) else node, aliases)
                    if target.removeprefix('flask.').startswith(('request.args', 'request.form', 'request.json', 'request.data', 'sys.argv')):
                        taint.add(('external:' + target, node.lineno))
                return taint

            def block(statements, state):
                for node in statements:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                        continue
                    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        taint = expression(node.value, state)
                        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                        for target in targets:
                            if isinstance(target, ast.Name):
                                state[target.id] = taint | (state.get(target.id, set()) if isinstance(node, ast.AugAssign) else set())
                    elif isinstance(node, ast.If):
                        expression(node.test, state)
                        left, right = {k: set(v) for k, v in state.items()}, {k: set(v) for k, v in state.items()}
                        block(node.body, left)
                        block(node.orelse, right)
                        state.update({k: left.get(k, set()) | right.get(k, set()) for k in left.keys() | right.keys()})
                    else:
                        expression(node, state)
                return state

            block(fn.body, env)
            next_summaries[name] = {'dangerous_parameters': sorted(dangerous), 'parameters': [a.arg for a in args]}
        if summaries == next_summaries:
            converged = True
            break
        summaries = next_summaries
    return {'findings': sorted(findings.values(), key=lambda f: (f['path'], f['line'], f['rule'])),
            'status': 'analysis_complete_within_supported_scope' if converged and not diagnostics else 'incomplete',
            'iterations': iteration + 1, 'diagnostics': diagnostics,
            'limitations': ['Conservative potential flows, not confirmed vulnerabilities.',
                            'Function parameters are treated as potentially untrusted; unknown calls preserve taint.',
                            'Top-level functions and static helper imports only. Object fields, loops, exception flow and dynamic dispatch are not fully modeled.']}
