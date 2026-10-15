# DevFlow 12 — Intelligent Software Development Assistant v0.4

This implementation follows the proposed modular platform architecture. The shared analysis engine currently consists of deterministic rules, Python AST analysis, SQLite project history and reviewed, self-reported test evidence. AI services, GitHub integration and automatic test execution are future extensions.

## Four product groups

| Group | Modules | Current shared outputs |
|---|---|---|
| Planning | Requirements, estimation, collaboration | Criteria and revisions; complexity scenarios; decisions |
| Development | Debugging, code quality, legacy understanding | Traceback hypotheses; source locations; import graph |
| Quality | Testing, security, documentation | Suggested regression targets; static findings; revision-bound reference |
| Operations | Integration, deployment, maintenance | Contract/environment differences; advisory release blockers; change impact |

The engineering dashboard shows these groups together. Its default **Integrated lifecycle** view reads `GET /api/projects/{id}/engineering/lifecycle`, presenting one report with all criterion impacts, the latest repository snapshot, decision history and evidence gaps.

## Connected requirement-change workflow

1. Create a project at `/`, enter a customer requirement, edit its drafted criteria and approve them.
2. Link implementation references to a criterion. Enter repository-relative paths such as `app/rules.py` using forward slashes. Blank or unmatched paths remain explicitly unmapped.
3. At `/engineering`, run a repository analysis with those files and importing modules/tests. It stores the current criterion revisions alongside source fingerprints and appends their statements to the generated documentation.
4. Record and review test evidence in the original workflow.
5. Edit the criterion. Its revision increments, approval returns to draft, and prior-revision evidence no longer counts as current. In the same database transaction, DevFlow records an `impact_assessed` workflow event with the linked files, transitive importers, test targets, findings, stale evidence IDs and documentation-refresh status.
6. Load the integrated report to review affected modules and unresolved evidence. Reapprove the criterion, modify source as needed, rescan for fresh documentation, run your tests externally and submit new reviewed evidence.

For an individual criterion, use `GET /api/projects/{id}/workflow/criteria/{criterion_id}/impact`. Recorded events preserve the analysis available at change time; the live impact endpoint uses the newest repository report. Editing a criterion to the same statement creates neither a revision nor a new impact event.

## What the release assessment means

`needs_attention` lists missing criteria, missing repository analysis, criteria without a current reviewed pass, unmapped implementation paths, stale requirement-documentation snapshots and high-severity static findings. `ready_for_human_review` means these supported checks found no blocker. `deployment_authorized` is always false: DevFlow neither deploys software nor authenticates CI evidence.

Documentation matching means the repository report captured the current criterion revision. It does not prove the submitted source implements that requirement or that no newer source exists outside DevFlow. Import mapping uses explicit code links; the system does not guess semantic requirement-to-code relationships. Test target mapping is incomplete and does not replace a full regression run.

Repository rescan never upgrades old test evidence. Requirement approval and evidence review remain separate actions. Self-reported names and results are retained with their limitations.

## Development roadmap

- Foundation available: requirement drafting/approval, rule-based code checks, test recommendations, generated references and traceability.
- Further development: verified debugging and broader security/legacy tooling, building on current static prototypes.
- Operations development: real schema validation, environment probes and trusted deployment evidence, building on comparison prototypes.
- Commercial development: authenticated users and tenant authorization, trusted CI/GitHub adapters, isolated execution workers, historical estimate calibration, and optional AI adapters with controlled data access.

The narrow commercial workflow is requirement revision → linked implementation → fresh regression evidence → human release review. Each future integration should attach its evidence to a specific criterion revision and source identity.

## Validation

22 tests pass, including requirement revisions propagating across files/tests/docs/evidence, impact event persistence, missing snapshots, cross-project access rejection, unmapped paths and high-risk findings. The prior engineering and traceability tests remain in the suite.
