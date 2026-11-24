# AGENTS.md — Lanwarden Engineering Workflow

## 1. Authority

This file defines project engineering standards, authorization requirements, phase sequencing, verification and review procedures.

CLAUDE.md defines the project overview and general conventions.

When instructions conflict, follow the applicable safety requirements and the more specific engineering requirements.

## 2. Authorization and network scope

- Development and testing must respect authorization boundaries.
- Active network testing is restricted to explicitly authorized environments.
- Use isolated lab networks and allowlisted test devices.
- Require operator confirmation before active network operations.
- Do not silently target arbitrary LAN devices.
- Do not add stealth, evasion or credential-harvesting functionality.
- Preserve operator-visible status and reliable rollback.

Mocked tests are acceptable for code that cannot be verified without an actual lab environment.

## 3. Phase management

The project uses sequential development phases.

Rules:
- Follow the established phase order.
- Do not skip unfinished tasks.
- Do not repeat completed tasks without evidence of a regression.
- Every task must have implementation evidence.
- Every task must have test evidence.
- Update audit.md after each completed task.
- Commit only after relevant verification.
- Stop at phase boundaries and report progress.

## 4. Current reliability roadmap

### P0–P3
Previously completed. Do not repeat without a demonstrated regression.

### P4 — Reliability cleanup

P4-1 — IP validation / netutil consolidation — COMPLETED (core/netutil).
P4-2 — OUI lookup deduplication — COMPLETED (OUI DB in core/oui, lookup in network/oui_lookup).
P4-3 — Dead-code removal — COMPLETED.
P4-4 — Unused configuration keys — COMPLETED.
P4-5 — Platform shim — COMPLETED (core/osutil); a Windows-behaviour product
       decision for the evasion modules (masquerade/chameleon) remains open.
P4-6 — UI threading — COMPLETED (ui/workers off-Qt-thread submit).

> The P4–P7 phase items were superseded by the STEP 1–6 product pass (rename to
> Lanwarden, nft FORWARD chain, sqlite/WAL storage, raw AF_PACKET send path,
> PySide6 UI rebuild, cold review) and the subsequent reliability fixes.
> **audit.md is the authoritative, current record** — treat it as the source of
> truth when it disagrees with the phase labels above.

### P5
Follow the existing project roadmap and audit.md.

### P6
Follow the existing project roadmap and audit.md.

### P7
Follow the existing project roadmap and audit.md.

### P8 — Verification workflow

P8 is the verification workflow for completed changes.

For each applicable task:
- Run focused tests.
- Run the relevant full test suite.
- Run lint.
- Run formatting checks.
- Run type checking.
- Inspect changed files.
- Check for regressions.
- Record actual results.

Do not fabricate test results.

### P9 — Release engineering review

Perform a cold review of the complete branch before merge.

Review:
- Architecture.
- Reliability.
- Resource lifecycle.
- Error handling.
- Persistence.
- State restoration.
- Security boundaries.
- Dependencies.
- Test coverage.
- Documentation.
- Git history.
- Outstanding issues.

Do not automatically modify unrelated code during the review.

## 5. Verification requirements

Every completed task must include:

1. Files inspected.
2. Files changed.
3. Reason for changes.
4. Tests added or modified.
5. Commands executed.
6. Actual results.
7. Remaining limitations.
8. Manual verification requirements.

## 6. Git discipline

- Work on the designated feature branch.
- Never discard unrelated user changes.
- Never force-push.
- Never amend previous commits without explicit permission.
- Keep commits focused.
- Use descriptive commit messages.
- Verify the working tree before committing.

## 7. Failure handling

If a task fails:
- Identify the actual failure.
- Do not hide or suppress it.
- Fix it when within scope.
- Add regression coverage.
- Rerun the relevant verification.

If blocked:
- Explain the exact blocker.
- Identify what is completed.
- Identify what remains.
- Do not falsely mark the phase complete.

## 8. Completion standard

A task is not complete merely because its code compiles.

It must be integrated, tested, reviewed and documented.

The goal is a reliable, maintainable and releasable application.