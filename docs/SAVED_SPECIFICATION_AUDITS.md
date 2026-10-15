# DevFlow 12 v0.7 — audits against saved specifications

The new endpoint separates fixed expected behavior from candidate code. It loads examples, function name and source path from a saved specification report; the request cannot supply replacements for these fields.

## Workflow

1. Create acceptance criteria in Traceability and write a structured specification linked to the criterion. Resolve all clarification questions. Keep the returned `assurance_report_id`.
2. Approve the criterion at its current revision. Review the specification examples with the stakeholder; criterion approval alone does not independently attest their correctness.
3. Open `/api/docs` and POST `/api/projects/{id}/engineering/specifications/{specification_id}/mutation-check`, supplying candidate `source` and optionally `seed`, `max_mutants`, `probe_count`.
4. Inspect killed/surviving variants and suggested distinguishing inputs. Expected results derived from the original candidate remain suggestions requiring confirmation.
5. Link the source path to the criterion and run repository analysis on the exact source. The integrated lifecycle report now includes `specification_audits`, source/revision freshness and advisory test-gap blockers.

Specifications must belong to the project, have no unresolved supported clarification issue, and be linked to a current approved criterion. Changed criterion revisions require a new specification record. Audit requests reject extra fields such as replacement examples. Saved records are immutable through the current API; local database access is not protected by authenticated authorization.

A new specification can be created with different examples, but it receives a separate record ID and hash. Each audit retains its original specification ID and contract fingerprint. Candidate changes do not edit or approve that specification, code or test evidence.

The workflow does not prove the specification is correct, execute host Python, integrate an SMT solver, or establish general correctness. The numeric model and mutation limits described in `ASSURANCE.md` and `AUDIT_AND_REPLAY.md` remain in force. Hashes are content fingerprints, not authenticity signatures. Existing free-form mutation audits remain available and are separate from saved-specification audits.

52 tests pass, including approved/current criterion enforcement, extra-field rejection, project isolation, source linkage and audit staleness after requirement changes.
