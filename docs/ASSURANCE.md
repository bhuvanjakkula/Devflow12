# DevFlow 12 v0.5 — requirements, verification and security

This release addresses the three priorities in the supplied research summary with executable tooling. It does not claim to reproduce research results, implement a neuro-symbolic system, or solve general program verification. No third-party research text is bundled.

## Run

```powershell
python -m pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:8000/engineering. Create a project and use the three new tools: **Structured specifications**, **Independent numeric verification**, and **Security data-flow analysis**. Create acceptance criteria through the Traceability page; select one in the workbench to bind specification and verification reports to it. Refresh the page after creating criteria elsewhere.

## Structured requirements and executable examples

The structured specification separates actor, trigger, behavior, failure handling, constraints and expected input/output examples. Missing fields and vague terms produce clarification questions. Identical numeric/boolean inputs with contradictory outputs are rejected as inconsistent examples. The system never invents an expected output from the implementation under test.

Example target: `app/rules.py`, function `clamp`.

```json
{
  "actor": "Customer",
  "trigger": "Submit an amount",
  "behavior": "Return zero for negative amounts and preserve nonnegative amounts.",
  "failure_behavior": "Reject nonnumeric amounts.",
  "source_file": "app/rules.py",
  "function": "clamp",
  "examples": [
    {"inputs": {"x": -1}, "expected": 0},
    {"inputs": {"x": 0}, "expected": 0},
    {"inputs": {"x": 5}, "expected": 5}
  ]
}
```

Download the generated pytest file and run it **in a trusted development environment** where the target module exists. These tests execute the target when you run them externally; the DevFlow endpoint only generates their source. They test explicit numeric examples, not every requirement or the textual nonnumeric-error behavior. `ready_for_stakeholder_review` is not approval. No submitted specification automatically edits the existing acceptance criterion.

## Independent numeric checking

The verifier parses Python into an AST and interprets a small numeric language with a hard whitelist. It does not import modules, compile submitted Python, use `eval`, spawn processes, or invoke supplied functions in the host interpreter.

Supported: finite integer/float/boolean inputs; arithmetic `+ - * / // %`; numeric comparisons; local assignments; `if`/`else`; conditional expressions; short-circuit `and`/`or`; unary signs and `not`; explicit numeric/boolean returns. Function docstrings are ignored. Ordinary positional-or-keyword parameter names are bound directly by the model.

Unsupported: imports, calls (including function calls), loops, attributes, indexing, comprehensions, exception statements, exponentiation, strings as values, defaults, decorators, annotations, type parameters, positional-only/variadic/keyword-only arguments and external state. Definition-time expressions are checked across all functions; every branch of the selected function is validated before interpreting examples. Other function definitions are never evaluated or called.

Limits: 60,000 source characters, 3,000 AST nodes, 50 examples, 20 input parameters, +/- 1e9 input/expected values, +/- 1e12 intermediate values, and 2,000 interpretation steps per case. Integer/float comparisons use exact numeric equality; booleans are distinguished from numbers. Floating-point tolerance and expected-exception assertions are not implemented.

For a faulty clamp that returns `1` for negative values, input `x=-1` with expected `0` produces `counterexample_found`, including the actual result. A supported function satisfying the supplied examples reports `examples_passed`. Unsupported syntax reports `unsupported`; a resource/value limit encountered during a case reports `incomplete`. These are finite-example model results, not formal proofs or full Python runtime tests.

Verification reports contain the criterion ID/revision and exact source SHA-256. The lifecycle view compares them against the current criterion revision, explicit code links and latest repository-file hash. A new requirement revision or a changed source snapshot marks previous numeric verification stale. A current counterexample or unsupported result adds an advisory blocker. Model results never manufacture an accepted test-evidence record or stakeholder approval.

## Security data-flow checking

The analyzer tracks potential input sources through local assignments and conservative branch merges. Function parameters are potentially untrusted. Recognized external sources include `input`, selected Flask request accessors and `sys.argv`. It detects flows into dynamic evaluation/execution, shell commands, pickle deserialization and SQL query strings.

Static helper summaries propagate risk through imported top-level functions, including supported relative imports. Reports identify source kinds/lines, sink lines, file paths and helper names without returning literal source contents. Parameterized SQL values do not contaminate a constant query string. Unknown calls preserve taint; the tool does not assume an unrecognized validator makes input safe.

Repository analysis runs these flow checks automatically and merges the findings into the existing lifecycle assessment. The standalone **Security data-flow analysis** tool saves a separate report; use repository analysis to attach its findings to the source snapshot used by the lifecycle gate.

Limits: at most 300 analysis units, 3,000 AST nodes per parsed file and eight summary passes. Unparseable/oversized files or nonconvergence produce `incomplete`. Dynamic dispatch, object-field mutation, complex loop/exception flow, runtime import behavior, sanitizers and arbitrary framework sources are not fully modeled. Reports are potential flows, not confirmed exploitable vulnerabilities. Parameters treated as untrusted and unknown-call propagation can produce false positives.

## API and storage

New POST endpoints under `/api/projects/{id}/engineering`: `specifications`, `verify-numeric`, `security-flow`. New GET endpoint: `assurance-reports`. Interactive schemas are at `/api/docs`. The original repository, lifecycle and workflow APIs remain available.

New reports are stored in SQLite with project scope. Numeric reports retain example values and results, source identity and criterion revision; they do not retain the submitted source. Specification reports retain the structured text and examples. Avoid secret or sensitive example values. This remains a local application with no production identity/access system.

## Validation

41 tests passed across the original workflow and new tools, including seeded counterexamples, supported numeric semantics, boolean distinctions, short-circuit evaluation, zero division, rejected host and definition-time operations, huge constants, cross-file helper flows, parameterized-SQL controls, branch merges, generated test syntax, contradictory examples and revision/source binding.

The next meaningful extensions are property/solver-backed checking for carefully defined languages, trusted CI adapters for runtime evidence, broader security analyzers, measured benchmarks on independently labeled examples, and authenticated multi-user review. Current reports do not claim those capabilities.
