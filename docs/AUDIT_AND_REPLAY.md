# DevFlow 12 v0.6 — mutation audits and reproducible evidence

This release applies two practical ideas from the supplied material: constrain generated variants to a supported grammar, and retain a canonical record that can be checked and replayed. It does not implement an LLM, ADT solver, SMT solver, quantified synthesis or general termination proofs. Research benchmark percentages are not claimed as DevFlow results.

## Start

```powershell
python -m pip install -r requirements.txt
python run.py
```

Open http://127.0.0.1:8000/engineering. The existing requirements, security-flow, numeric verifier and lifecycle tools remain available.

## Mutation test-strength audit

Select a project and acceptance criterion. Choose **Mutation test-strength audit**, paste a supported numeric function and its independently authored examples, and run the analysis.

The original function must pass those examples before mutations are attempted. Supported edits are numeric-literal replacements preserving integer/float literal type, `+`/`-` swaps, and comparison-operator swaps preserving Boolean output. Each variant is parsed and checked through the restricted numeric interpreter. AST fingerprints remove duplicate variants. Only one mutation site is changed in each variant.

- **Killed:** an example exposes a behavioral difference or numeric error in the mutant.
- **Survived examples:** the supplied examples did not expose a difference. This does not establish semantic equivalence.
- **Unsupported:** the model or its resource/value limits could not evaluate the variant. It is excluded from the score denominator.

The mutation score is killed / supported variants. It is a limited measure of these examples against these operators, not a defect-detection probability or correctness proof. No score is reported when there are no supported variants.

For survivors, bounded probes use zero, signs, numeric literal boundaries, and seeded integer samples. Each input preserves the example's primitive input type. The original implementation provides reference outputs for these probes; any distinguishing input is a **test-gap suggestion requiring stakeholder confirmation**, not an approved requirement oracle. Oracle errors or unsupported reference results are skipped. Passing baseline examples does not establish that the original implementation is correct.

The persisted seed and full probe schedule support exact reinspection. Limits: 12,000 source characters, 20 mutants and 30 probes, in addition to numeric-model limits described in [ASSURANCE.md](ASSURANCE.md). Candidate generation is deterministic for the same inputs, seed, implementation version and Python environment. This is bounded input probing, not coverage-guided native fuzzing.

API: `POST /api/projects/{id}/engineering/mutation-audit`, using the numeric-verification fields plus `seed`, `max_mutants`, and `probe_count`. Reports are persisted with criterion revision, original source hash, candidate source variants, example outcomes and proposed test gaps. **Mutation reports therefore retain source variants**; use trusted local source and avoid embedded secrets. No source is imported, run as host Python, or automatically overwritten.

## Verification replay

Run **Independent numeric verification** first. New reports include a replay record with:

- schema and interpreter model versions;
- Python version;
- exact source SHA-256;
- frozen function name and input/expected-output examples;
- canonical contract and result hashes.

Choose **Replay verification**, enter the `assurance_report_id` returned by verification and paste the exact original source. DevFlow loads that project's saved record, checks its hashes, and repeats the frozen examples. It returns `reproduced`, `source_mismatch`, `record_integrity_mismatch`, `incompatible_model`, or `result_divergence`. Whitespace changes affect the exact source hash; run a new verification for changed source. Legacy v0.5 reports lacking a replay record require a new verification.

API: `POST /api/projects/{id}/engineering/verification/{report_id}/replay`, body `{"source": "..."}`. Cross-project report IDs are rejected. Replay also reports whether the original criterion revision is still current. A successfully reproduced historical result is not fresh evidence for a revised requirement. Replay never approves criteria, creates accepted runtime-test evidence or authorizes deployment.

Hashes detect content changes but are not signatures or proof of authenticity. The app still has no authenticated multi-user identity system. Cross-platform floating-point identity is not guaranteed, and this replay mechanism does not claim deterministic behavior for external SMT solvers.

Mutation and replay history is available through **Load report history** or `GET /api/projects/{id}/engineering/experiments`.

## Validation and next steps

47 tests pass, including identical seeded audits, improved mutant detection with stronger examples, unique AST variants, one-site operator changes, rejection of host operations, baseline failure, replay source/model/integrity checks, recomputed-hash result divergence, stale requirement replay, API limits and project isolation. Existing generated-pytest, security and lifecycle tests remain green.

Future additions should be separate adapters: constrained LLM proposals, solver-backed checks over explicitly supported theories, and isolated native test/fuzz workers. Record tool versions, seeds, resource bounds and concrete witness validation for each adapter. Keep expectations separate from candidate generation and preserve `unknown`/unsupported outcomes instead of treating them as passes.
