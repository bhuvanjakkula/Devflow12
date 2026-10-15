"""Deterministic, local-only analyzers. No untrusted code is executed."""
from __future__ import annotations

import ast
import re
from typing import Any

UNCLEAR_TERMS = {
    "fast": "Specify a measurable response-time target.",
    "quickly": "Specify a time limit or performance objective.",
    "easy": "Describe an observable usability outcome.",
    "user-friendly": "Specify user tasks and measurable usability criteria.",
    "secure": "Specify roles, authorization rules, and concrete security controls.",
    "scalable": "Specify expected throughput, concurrent users, and growth.",
    "etc": "List the remaining items explicitly.",
    "appropriate": "Define the exact selection criteria.",
    "efficient": "Set a measurable resource or performance budget.",
    "as needed": "Define when the behavior must occur.",
    "soon": "Specify an actual deadline or time window.",
}


def analyze_requirements(text: str) -> dict[str, Any]:
    normalized = re.sub(r"\s+", " ", text.strip())
    raw_sentences = re.split(r"(?<=[.!?])\s+|\s*\n+\s*|\s*;\s*", text.strip())
    items = [re.sub(r"^[\s\d.)\-•]+", "", s).strip() for s in raw_sentences]
    items = [s for s in items if len(s) > 2][:30]
    if not items and normalized:
        items = [normalized]
    warnings: list[dict[str, str]] = []
    for term, message in UNCLEAR_TERMS.items():
        if re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", normalized, re.I):
            warnings.append({"term": term, "recommendation": message})
    questions: list[str] = []
    low = normalized.lower()
    if not re.search(r"\b(users?|customers?|admins?|managers?|developers?|staff|visitors?|clients?|operators?)\b", low):
        questions.append("Which user roles or actors will use this feature?")
    if not re.search(r"\b(must|shall|should|when|if|after|before|can|will)\b", low):
        questions.append("What specific trigger and expected system behavior must be implemented?")
    if not re.search(r"\b(error|fail|invalid|empty|missing|denied|unavailable|timeout)\b", low):
        questions.append("How should the system handle invalid inputs, failures, and edge cases?")
    if not re.search(r"\b(only|permission|role|authenticate|authorize|private|access|login)\b", low):
        questions.append("Are any permissions, privacy, or authentication rules required?")
    if not re.search(r"\b(\d+\s*(?:ms|seconds?|minutes?|hours?|days?|users?|requests?|%)|under \d+|at least \d+)\b", low):
        questions.append("Which measurable performance, reliability, or volume target matters?")
    for w in warnings[:3]:
        questions.append(f"For '{w['term']}': {w['recommendation']}")
    criteria = []
    for index, item in enumerate(items[:12], start=1):
        criteria.append({
            "id": f"AC-{index:02d}",
            "requirement": item,
            "draft_acceptance_test": (
                f"Given the relevant preconditions, when the user performs the action described in "
                f"'{item[:110]}', then the agreed observable result occurs."
            ),
        })
    quality = max(0, 100 - 10 * len(warnings) - 7 * len(questions))
    return {
        "summary": normalized[:300],
        "requirements": items,
        "ambiguities": warnings,
        "open_questions": questions,
        "acceptance_criteria_drafts": criteria,
        "clarity_indicator": quality,
        "notice": "Heuristic drafting only; a human must confirm requirements and acceptance tests.",
    }


def _make_finding(line: int, severity: str, title: str, details: str, recommendation: str) -> dict[str, Any]:
    return {"line": line, "severity": severity, "title": title, "details": details, "recommendation": recommendation}


def analyze_python_code(code: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(code)
    except SyntaxError as error:
        findings.append(_make_finding(
            error.lineno or 1, "high", "Syntax error", error.msg,
            "Correct the syntax and re-run the analyzer.",
        ))
        return {
            "language": "python", "findings": findings,
            "metrics": {"lines": len(code.splitlines()), "functions": 0, "classes": 0},
            "test_suggestions": [], "notice": "Static heuristics only; code was not executed.",
        }
    functions: list[str] = []
    classes: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.name)
            if not ast.get_docstring(node) and not node.name.startswith("_"):
                findings.append(_make_finding(node.lineno, "low", "Missing function documentation", node.name, "Document inputs, outputs, and failure cases."))
        if isinstance(node, ast.ClassDef):
            classes.append(node.name)
        if isinstance(node, ast.ExceptHandler) and (node.type is None or isinstance(node.type, ast.Name) and node.type.id == "Exception"):
            findings.append(_make_finding(node.lineno, "medium", "Overly broad exception handling", "May hide unexpected errors.", "Catch specific exceptions and log unexpected failures."))
        if isinstance(node, ast.Call):
            fn = node.func
            bare_name = fn.id if isinstance(fn, ast.Name) else None
            attr_name = fn.attr if isinstance(fn, ast.Attribute) else None
            target_name = fn.value.id if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name) else None
            if bare_name in {"eval", "exec"}:
                findings.append(_make_finding(node.lineno, "high", f"Use of {bare_name}()", "Dynamic code execution can be dangerous with untrusted data.", "Replace with explicit parsing or a constrained evaluator."))
            if target_name == "os" and attr_name == "system":
                findings.append(_make_finding(node.lineno, "high", "Shell command execution", "os.system invokes a shell.", "Use fixed commands with subprocess and a vetted argument list where possible."))
            if target_name == "subprocess" and attr_name in {"Popen", "run", "call", "check_output", "check_call"}:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(_make_finding(node.lineno, "high", "subprocess shell=True", "Shell interpolation can create command injection risks.", "Avoid shell=True and pass arguments as a list."))
            if target_name == "pickle" and attr_name in {"loads", "load"}:
                findings.append(_make_finding(node.lineno, "high", "Pickle deserialization", "Loading untrusted pickle content can execute code.", "Use a safer data format such as JSON for untrusted input."))
            if target_name == "yaml" and attr_name == "load":
                if not any(kw.arg == "Loader" for kw in node.keywords):
                    findings.append(_make_finding(node.lineno, "medium", "YAML load without explicit loader", "Loader security depends on configuration.", "Use yaml.safe_load for untrusted data."))
            if target_name == "requests" and attr_name in {"get", "post", "put", "delete", "patch", "request"}:
                if not any(kw.arg == "timeout" for kw in node.keywords):
                    findings.append(_make_finding(node.lineno, "medium", "HTTP call without timeout", "A request may block unexpectedly.", "Set an explicit connect/read timeout."))
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                if isinstance(target, ast.Name) and re.search(r"(password|secret|api_key|private_key|access_token)$", target.id, re.I):
                    if isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) > 3 and not re.search(r"(example|placeholder|dummy|change.?me|test)", value.value, re.I):
                        findings.append(_make_finding(node.lineno, "high", "Possible embedded credential", f"Literal assigned to {target.id}.", "Use environment-based secret management and rotate any exposed credential."))
    test_suggestions = [f"Unit-test {fn} with normal inputs, invalid inputs, boundary values and failure cases." for fn in functions[:8]]
    if not functions:
        test_suggestions.append("Add tests for the module's observable behavior and error paths.")
    findings.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["severity"]], f["line"]))
    return {
        "language": "python", "findings": findings[:100],
        "metrics": {"lines": len(code.splitlines()), "functions": len(functions), "classes": len(classes)},
        "test_suggestions": test_suggestions,
        "notice": "Non-executing static heuristics. No scanner can establish that code is secure or correct.",
    }


def build_plan(requirement_analysis: dict[str, Any]) -> dict[str, Any]:
    requirements = requirement_analysis.get("requirements", [])
    open_questions = requirement_analysis.get("open_questions", [])
    return {
        "testing": [
            "Unit tests: validate each rule with expected and invalid inputs.",
            "Integration tests: verify APIs, databases, and external dependencies.",
            "Negative tests: invalid credentials, missing data, forbidden actions, and failures.",
            "Regression tests: replay previously reported bugs after changes.",
            "Performance tests: measure against agreed load and latency targets.",
            "Security tests: verify authorization boundaries and sensitive-data handling.",
        ],
        "documentation_draft": {
            "overview": requirement_analysis.get("summary", ""),
            "functional_requirements": requirements[:15],
            "questions_to_resolve": open_questions[:10],
            "sections_to_write": ["User roles", "Business rules", "Data model", "API contracts", "Deployment procedure", "Troubleshooting", "Change log"],
        },
        "notice": "These are starting-point checklists, not executed tests or verified documentation.",
    }
