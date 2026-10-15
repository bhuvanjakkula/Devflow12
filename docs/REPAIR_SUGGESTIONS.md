# DevFlow 12 v0.8 — rechecked repairs and smaller counterexamples

Start with `python run.py`, then open `/engineering`. Create an acceptance criterion and structured specification, resolve supported clarification issues, and approve the current criterion. Retain the specification report ID.

Choose **Rechecked repair suggestions** and supply the specification ID and faulty source. The saved function name, source path and examples remain fixed. The API is POST `/api/projects/{id}/engineering/specifications/{specification_id}/mutation-check` with `mode: "repair"` plus source and optional existing search limits.

The baseline must be supported and exhibit a counterexample against the saved examples. DevFlow searches the existing bounded, one-site numeric-literal, arithmetic and comparison edits. Only candidates that pass all saved examples appear in `repair_proposals`, with source, SHA-256, patch diff and independent interpreter recheck results. Candidate ordering is by source hash for reproducibility, not a learned quality ranking. If the examples already pass, the report states `no_repair_needed_for_examples`; it does not infer absence of other bugs.

The tool does not apply patches, weaken examples, update acceptance status, generate accepted runtime-test evidence or resolve lifecycle blockers. Repair reports are retained in experiment history and do not supersede normal test-strength audits in lifecycle assessment. Review the patch, add independently confirmed boundary/error cases, apply it in your development environment and run the real regression suite. Reanalyze changed source before relying on later reports.

Mutation audits now greedily shrink distinguishing numeric inputs toward lower magnitude, checking the original/reference behavior and the mutant after every accepted reduction. This search is capped at 32 attempts per witness. Reports preserve a validated difference and state that global minimality is unproven. The original implementation remains the oracle for test-gap suggestions, so stakeholder confirmation is still needed.

Limits and source retention are unchanged from the saved-specification and audit guides. Repair works only in the restricted numeric model and limited operator space. It is not a general AI repair system, SMT proof, runtime sandbox or production deployment feature.

55 tests pass, including seeded bug repair proposals, rechecking all proposed examples, shrinking while preserving differences, unsafe-operation rejection and suppressing unnecessary proposals when baseline examples pass.
