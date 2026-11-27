# Hakai

Hakai is a Python desktop LAN administration and network diagnostics application.

**Stack:** Python 3, Scapy networking engine, CustomTkinter desktop UI.

The application includes device discovery, network monitoring, traffic management, protection controls, persistence, system networking integrations, and defensive diagnostics.

---

## Mission

Maintain, improve, and complete Hakai as a reliable, maintainable desktop application.

Priorities:

1. Correctness.
2. Reliability.
3. Resource lifecycle.
4. System-state restoration.
5. Responsive UI.
6. Maintainable architecture.
7. Test coverage.
8. Dependency hygiene.
9. Documentation.
10. Release readiness.

Do not unnecessarily rewrite working modules.

Do not repeat completed tasks without evidence of a regression.

Do not confuse routine maintenance with entirely new functionality.

---

## Technology

- Python 3
- Scapy
- CustomTkinter
- Tkinter
- pytest
- Ruff
- mypy

Use existing technologies unless a documented reason justifies changing them.

Avoid unnecessary dependencies.

---

## Commands

### Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run

```bash
python main.py
```

### Tests

```bash
pytest -v
```

### Quality checks

```bash
ruff check .
ruff format --check .
mypy .
```

Run the appropriate focused tests and quality gates after each task. Run consolidated verification before declaring a phase complete.

---

## Project layout

```text
main.py

core/
    controller
    device
    persistence
    protector
    shutdown
    netutil

network/
    arp
    traffic
    dns_spoof
    recon_engine
    mdns_sniff
    scanner
    ipv6
    deauth
    xdp_engine
    oui_lookup

system/
    iptables_manager
    stealth
    netinfo
    tc_manager
    masquerade
    network_manager

ui/
    dashboard
    info_dialog
    protection_panel
    limit_dialog

tests/

audit.md
AGENTS.md
CLAUDE.md
```

This layout is illustrative. Inspect the actual repository before assuming every file or module exists.

---

## Engineering conventions

- Type hints on every function signature.
- Avoid bare `except`.
- Catch specific exceptions.
- Log errors meaningfully.
- No `print()` in library code.
- Validate addresses with `ipaddress`.
- Use subprocess argument lists, never shell command strings.
- Never use `shell=True` unless an exceptional, justified, reviewed case exists.
- Keep side effects isolated from pure logic.
- Close resources.
- Make cleanup idempotent.
- Preserve existing public interfaces when possible.
- Avoid unnecessary abstractions.
- Avoid duplicate utilities.
- Avoid unnecessary dependencies.
- Never silently no-op on unsupported platforms.
- Document platform limitations clearly.

---

## Architecture rules

- Preserve the existing architecture unless a concrete problem requires change.
- Keep UI, controller, networking, and system operations separated.
- Do not perform blocking work on the Tk main thread.
- Use established threading and async utilities.
- UI updates must be performed safely on the Tk thread.
- Ensure worker tasks can be cancelled or terminated safely.
- Avoid unbounded thread or process creation.
- Use bounded timeouts for external processes and network operations.
- Keep state transitions explicit.
- Keep error handling consistent.
- Avoid circular imports.
- Avoid global state when existing architecture offers a better alternative.

---

## Networking reliability

Hakai interacts with Linux networking subsystems and may require elevated privileges.

Network-related work must account for:

- iptables
- nftables
- sysctl
- interfaces
- traffic control
- MTU
- routing
- masquerading
- IPv4
- IPv6
- XDP, where supported

Reliability requirements:

- Preserve original system state before modifying it.
- Restore changed state during normal shutdown.
- Restore changed state during error handling.
- Make restoration idempotent.
- Do not assume a command succeeded.
- Verify return codes.
- Use bounded command execution.
- Log restoration failures.
- Avoid leaving stale rules behind.
- Handle partial initialization.
- Handle partial teardown.
- Make failure paths testable.
- Do not report an operation as successful if it failed.

iptables FORWARD is first-match-wins. Rule ordering must be reviewed carefully; DROP rules must not be bypassed by preceding ACCEPT rules.

Do not assume interfaces have a default MTU. Capture original values before making changes.

---

## Platform support

The networking engine is Linux-specific.

- Detect unsupported platforms explicitly.
- Avoid silent-success stubs.
- Explain unavailable functionality to the user.
- Keep platform-specific behavior isolated.
- Do not crash the UI because an optional subsystem is unavailable.
- Do not make platform behavior appear equivalent when it is not.

Windows behavior must follow an explicit documented product decision: supported, partially supported, or unsupported.

---

## Security and authorization

Hakai is intended for authorized network administration and controlled testing.

- Active networking operations require explicit operator intent.
- Restrict active testing to authorized environments.
- Use allowlisted lab devices when testing sensitive networking behavior.
- Do not silently target arbitrary LAN devices.
- Keep operator-visible status.
- Preserve safeguards and restoration mechanisms.
- Do not add stealth, evasion, credential theft, or covert interception functionality.
- Do not perform live network experiments automatically.
- Do not perform privileged system changes without explicit approval.

Mock system operations in automated tests where live system changes are unnecessary.

---

## Persistence

- Persist only data the application needs.
- Avoid storing unnecessary sensitive data.
- Validate persisted data before using it.
- Handle missing, corrupted, and outdated state.
- Keep configuration and runtime state clearly separated.
- Use safe serialization formats.
- Do not use pickle, eval, or unsafe deserialization.
- Maintain backwards compatibility where reasonable.
- Document schema changes.

---

## UI and user experience

- Keep the UI responsive.
- Never block the Tk event loop with long-running operations.
- Use the existing async/thread helper when appropriate.
- Update widgets only on the UI thread.
- Provide accurate feedback for success, failure, and progress.
- Prevent duplicate operations.
- Handle cancellation and application shutdown.
- Keep dialogs and widgets consistent with the existing design.
- Avoid unnecessary visual redesign.

---

## Testing

Use pytest.

Tests should cover:

- Pure logic.
- Validation.
- State transitions.
- Controller behavior.
- Failure paths.
- Restoration.
- Persistence.
- Lifecycle.
- UI integration where practical.
- Platform-specific behavior.
- Regression cases.

Mock privileged system operations.

Do not make automated tests modify the host's networking configuration.

Never fabricate test output.

Distinguish:

- Automated tests.
- Mocked verification.
- Static inspection.
- Manual verification.
- Live lab verification.

---

## Git workflow

- Work on the designated branch.
- Inspect git status before changing anything.
- Preserve unrelated user changes.
- Use focused commits.
- Use descriptive commit messages.
- Never force-push.
- Never amend commits.
- Never reset the branch.
- Never discard unrelated work.
- Never merge without explicit approval.
- Never push without explicit approval.
- Never create release tags without explicit approval.

---

## Documentation

Maintain `audit.md` as the project's current progress and engineering record.

Update it when:

- Tasks are completed.
- Tasks are deferred.
- Findings are discovered.
- Tests change.
- Dependencies change.
- Release blockers change.
- Manual verification is required.

Do not let the roadmap become stale.

Use actual repository evidence instead of assumptions.

---

## Autonomous Engineering Mode

The user delegates routine engineering work.

Do not repeatedly ask the user which task to do next when the roadmap already defines it.

Autonomously:

- Inspect the repository.
- Determine current progress.
- Identify the next eligible task.
- Implement routine fixes.
- Add tests.
- Run verification.
- Fix regressions caused by your work.
- Review your diff.
- Update documentation.
- Commit focused tasks.
- Continue to the next task.

Do not stop after:

- An audit.
- A plan.
- A list of findings.
- One task.
- One phase.

Continue until all approved work is completed or genuine blockers remain.

Make reasonable, reversible engineering decisions independently.

Ask the user only when necessary for:

- Significant product behavior changes.
- Destructive or irreversible actions.
- Live network operations.
- Privileged networking changes.
- External credentials.
- Purchases or external services.
- Major architecture changes.
- Unresolvable decisions that materially affect the product.

When blocked, document the issue and continue with independent work.

---

## Definition of done

A task is complete only when:

1. The implementation is complete.
2. Relevant tests are added or updated.
3. Tests have actually been executed.
4. Regressions are addressed.
5. Relevant quality checks are complete.
6. The diff has been reviewed.
7. Documentation is updated.
8. The task status is accurately recorded.
9. A focused commit exists, if the task is commit-ready.

Do not mark work complete based only on code inspection.

---

## Final reporting

When delegated work is complete, provide a consolidated report:

- Initial repository state.
- Tasks completed.
- Phases closed.
- Files changed.
- Commits created.
- Tests and actual results.
- Tool and dependency updates.
- Outstanding defects.
- Deferred items.
- Manual verification required.
- Release blockers.
- GO / NO-GO recommendation.

Do not merge, push, or release automatically.