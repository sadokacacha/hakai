# AGENTS.md — Hakai Autonomous Engineering

## 1. Purpose

This document governs engineering workflow, task sequencing, verification, audit tracking, and autonomous execution for Hakai.

CLAUDE.md defines the architecture, conventions, and application requirements.

The goal is to deliver a reliable, maintainable application without requiring the user to micromanage each engineering task.

---

## 2. Source of truth

Determine project state from actual evidence:

1. Current source code.
2. Git history.
3. Current branch and working tree.
4. Tests.
5. audit.md.
6. Existing roadmap documents.
7. CLAUDE.md.
8. This file.

Do not trust stale phase summaries blindly.

When sources disagree, investigate and document the discrepancy. Do not overwrite historical records simply to make the roadmap look consistent.

---

## 3. Authorization and safety boundaries

All active network testing must be authorized and performed within appropriate controlled environments.

- Do not automatically execute privileged network operations.
- Do not modify host networking during automated tests.
- Mock system-level commands where possible.
- Require explicit operator approval for live networking tests.
- Restrict sensitive active testing to isolated lab networks.
- Preserve authorization checks.
- Preserve operator-visible status.
- Preserve restoration mechanisms.
- Do not add stealth, evasion, covert interception, credential harvesting, or arbitrary-target functionality.

Ordinary engineering maintenance, tests, defensive diagnostics, reliability fixes, UI improvements, documentation, and dependency maintenance remain in scope.

---

## 4. Autonomy

The user delegates routine engineering tasks.

Do not ask the user what to do next when an established roadmap determines the next task.

You are expected to:

- Inspect.
- Plan internally.
- Make reasonable engineering decisions.
- Implement.
- Test.
- Review.
- Document.
- Commit.
- Continue.

Do not stop after writing a plan.

Do not stop after producing an audit.

Do not stop after completing one task if more approved tasks remain.

Avoid unnecessary user interruptions.

---

## 5. Decision policy

Make routine reversible decisions autonomously.

Examples of decisions you do not need to ask about:

- Internal refactoring.
- Bug fixes.
- Regression tests.
- Type improvements.
- Logging improvements.
- Error handling.
- Documentation.
- Non-breaking dependency updates.
- Test cleanup.
- Small UI fixes.
- Dead-code removal supported by evidence.

Ask the user before:

- Destructive actions.
- Deleting user data.
- Changing significant product behavior.
- Changing major architecture.
- Live network testing.
- Privileged host networking operations.
- Adding external services requiring credentials.
- Purchasing anything.
- Merging.
- Pushing.
- Releasing.

If blocked, document the blocker and continue with independent tasks.

---

## 6. Task lifecycle

Every task follows this workflow.

### Step 1 — Inspect

- Check branch.
- Check git status.
- Review recent commits.
- Inspect relevant files.
- Review existing tests.
- Read relevant instructions.
- Confirm the task is still incomplete.

### Step 2 — Establish baseline

Run relevant tests or checks before modifying code when appropriate.

Record existing failures separately from new failures.

### Step 3 — Implement

- Make the smallest correct change.
- Preserve working behavior.
- Avoid unnecessary dependencies.
- Avoid unrelated changes.
- Keep architecture consistent.

### Step 4 — Test

- Add regression coverage.
- Run focused tests.
- Run related tests.
- Test failure paths.
- Mock privileged operations.

### Step 5 — Verify

Run applicable quality checks.

Fix regressions caused by your changes.

### Step 6 — Review

Inspect:

- Diff.
- Accidental changes.
- Resource lifecycle.
- Error handling.
- Logging.
- Test coverage.
- Security boundaries.
- Compatibility.

### Step 7 — Document

Update audit.md.

Record:

- Task ID.
- Status.
- Implementation.
- Files changed.
- Test evidence.
- Remaining limitations.

### Step 8 — Commit

Create a focused commit after successful verification.

Never amend existing commits.

### Step 9 — Continue

Move to the next eligible task automatically.

Do not ask the user to select the next task when the roadmap determines it.

---

## 7. Task status definitions

Use these statuses consistently:

- TODO — Not started.
- IN PROGRESS — Actively being worked on.
- BLOCKED — Cannot proceed without a dependency or decision.
- DONE — Implementation and verification completed.
- DEFERRED — Intentionally postponed with a reason.

A task cannot be marked DONE based solely on inspection.

A task cannot be marked DONE if verification has not been completed.

For tasks requiring real hardware, privileged system behavior, or live network verification, distinguish implementation completion from manual verification.

---

## 8. Phase roadmap

The phase numbers below are historical project identifiers, not a guarantee that every task is still outstanding.

Verify the actual status from audit.md, commits, and source code.

### P0–P3

Previously completed.

Do not repeat without evidence of regressions.

### P4 — Reliability cleanup

Previously completed, with documented residuals.

Review only outstanding residuals or evidence of regressions.

Known historical residuals:

- Protection-panel threading residual PP-1.
- P4-5(2) Windows behavior decision.

Confirm their actual status before proceeding.

### P5 — Naming cleanup

Review the established P5 roadmap.

Complete remaining naming cleanup sequentially.

Do not rename public interfaces unnecessarily.

Preserve compatibility and avoid cosmetic changes without clear value.

### P6 — UI and dependency cleanup

Review the established P6 roadmap.

Historical themes included:

- UI cleanup.
- Pillow/Pillow dependency review.
- Tk/CustomTkinter compatibility.
- Dependency removal candidates.

Determine which tasks are actually unfinished.

### P7 — Feature review

Previously reviewed.

Historical report states:

- Kill-switch issue fixed.
- Write-only state persistence removed.
- DNS spoof and device monitoring were deferred to `/wire`.

Verify the current state rather than repeating the completed review.

### P8 — Verification

Verification phase.

Run consolidated verification against the actual current HEAD.

Required checks as applicable:

- pytest.
- Ruff lint.
- Ruff formatting.
- Mypy.
- Dependency consistency.
- Import/startup checks.
- Regression checks.

Do not count mocked testing as live verification.

Do not fabricate evidence.

### P9 — Release engineering

A previous cold review was completed and committed.

Revisit only if:

- New code changes introduce new release risks.
- A deferred blocker needs resolution.
- Dependencies become outdated.
- New evidence invalidates the prior review.

P9 includes:

- Dependency/toolchain modernization.
- Security and dependency audit.
- Architecture review.
- Reliability.
- Error paths.
- Resource lifecycle.
- Restoration.
- Test coverage.
- Release readiness.

### /wire — Deferred networking feature integration

This is a separately tracked, sensitive networking workstream.

Do not automatically resume it as part of general reliability work.

Keep active traffic interception and DNS-redirection development limited to authorized isolated-lab functionality. Do not expand covert or arbitrary-target capabilities.

Do not let deferred tasks block unrelated engineering improvements.

---

## 9. Verification standards

Use the repository's existing tools.

Typical checks:

```bash
pytest -v
ruff check .
ruff format --check .
mypy .
```

Run focused tests when appropriate.

Run consolidated verification at phase completion.

For each check, record:

- Command.
- Whether it actually ran.
- Actual result.
- Existing failures.
- New failures.
- Limitations.

Do not suppress failures simply to make a gate appear green.

Formatting debt may be deferred only when it is clearly pre-existing and documented.

---

## 10. Dependency management

Do not blindly upgrade all dependencies.

For dependency tasks:

- Inspect Python compatibility.
- Inspect package constraints.
- Check stable versions.
- Review changelogs for significant upgrades.
- Identify breaking changes.
- Remove unused dependencies only with evidence.
- Test the application after changes.
- Keep installation reproducible.
- Avoid unnecessary dependency replacements.

Document dependency changes in audit.md.

---

## 11. Git rules

Allowed autonomous Git actions:

- Read status.
- Read history.
- Create branches when the existing workflow requires them.
- Add focused changes.
- Commit completed tasks.

Forbidden without explicit user approval:

- Force-push.
- Amend.
- Reset.
- Destructive cleanup.
- Merge.
- Push.
- Release tagging.

Never discard unrelated user changes.

Do not commit secrets, credentials, environment files, generated scratch scripts, or unintended artifacts.

---

## 12. Blocker policy

If a task is blocked:

1. Mark it BLOCKED or DEFERRED.
2. Explain why.
3. Record the impact.
4. Identify the safest reasonable default.
5. Continue with unrelated eligible tasks.
6. Batch decisions into the final report.

Interrupt the user only when continued execution would be unsafe, destructive, or impossible without an important decision.

---

## 13. Progress reporting

Do not flood the user with progress updates.

Work autonomously and provide a consolidated report at meaningful checkpoints.

Checkpoint reports should be brief and contain:

- Completed tasks.
- Commit identifiers.
- Verification results.
- Remaining tasks.
- Blockers.

Avoid asking questions at the end of every task.

---

## 14. Completion criteria

A phase is closed only when:

- All phase tasks are accounted for.
- Completed work has evidence.
- Required tests pass.
- Known failures are documented.
- Deferred work has a reason.
- audit.md is updated.

The overall delegated mission is complete when:

- All approved roadmap tasks are completed.
- All automated gates pass or remaining failures are explicitly justified.
- Remaining manual verification is documented.
- Deferred items are documented.
- A cold review is completed.
- A release recommendation is provided.

---

## 15. Final report

At the end, provide a consolidated report:

- Starting state.
- Roadmap reconciliation.
- Phases completed.
- Tasks completed.
- Files changed.
- Commits.
- Dependency changes.
- Tests executed and results.
- Remaining defects.
- Deferred work.
- Manual verification checklist.
- Release blockers.
- GO / NO-GO recommendation.

Do not merge, push, or release automatically.

The user should not have to manually coordinate the roadmap.