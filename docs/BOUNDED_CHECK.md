# Finite-domain comparison — v0.6.1

Start with `python run.py` and open `/api/docs`. Use POST `/api/projects/{id}/engineering/bounded-check` after creating a project and an acceptance criterion in the traceability workflow.

```json
{
  "criterion_id": 1,
  "source_file": "app/rules.py",
  "function": "clamp",
  "source": "def clamp(x):\n    return x if x >= 0 else 1",
  "reference_source": "def clamp(x):\n    return x if x >= 0 else 0",
  "domains": {"x": [-1, 0, 1]}
}
```

Replace the criterion ID with one belonging to your project. The example finds a counterexample at -1 and checks all three inputs. A separately authored reference supplies expected results; its correctness is assumed, not established by the checker.

Parameters are enumerated in sorted-name order across the full Cartesian product. Results include concrete counterexamples, incomplete inputs, checked-combination count and domain/source/reference hashes. Unsupported reference behavior is incomplete, never a match. Candidate numeric errors against a supported reference are counterexamples.

Limits: four parameters, sixteen values per parameter, 256 combinations, 12,000 characters per source, plus the restricted numeric interpreter limits. No supplied source is imported or run as host Python. `matches_declared_domain` means agreement only on these inputs in that model; it says nothing about inputs outside the domain, correctness of the reference, or actual runtime behavior.

This endpoint returns a downloadable JSON response through API documentation; it does not persist reports or alter lifecycle release status. Existing mutation/replay tools retain their separate storage and semantics. This addition is finite enumeration, not an SMT solver, quantifier-instantiation engine, or cross-solver proof.

The full suite passes 51 tests, including counterexample extraction, Cartesian ordering, incomplete references and domain limits.
