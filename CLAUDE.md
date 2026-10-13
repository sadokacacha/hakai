# Hakai v3 — Python ARP/MITM Network Tool (Linux Engine, Cross-Platform UI)

## Commands

- Setup: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- Run: `python main.py`
- Test: `pytest -v`
- Lint: `ruff check .`
- Format: `ruff format .`
- Typecheck: `mypy .`

On Windows PowerShell, activate the virtual environment with `.venv\Scripts\Activate.ps1`.

Run commands from the project root. If a command cannot run because a tool is missing or the environment is unsupported, report that explicitly.

## Architecture

- `main.py` — entry point, startup, network detection.

### `core/` — Orchestration and State

- `controller.py` — central controller: scan/cut/restore, callbacks, device dictionary.
- `device.py` — Device model.
- `persistence.py` — device database, OUI lookup, `state.json`.
- `protector.py` — kill switch, ARP guard.

### `network/` — Packet Layer (Scapy)

- `arp.py` — ARP spoof/cut/restore, gateway MAC resolution.
- `traffic.py` — traffic counters, cut tracking.
- `dns_spoof.py` — DNS spoof sniffer.
- `recon_engine.py` — async deep reconnaissance (stages 3–5).
- `mdns_sniff.py` — mDNS intelligence.
- `scanner.py` — host discovery.
- `ipv6.py` — IPv6 hijack functionality.
- `deauth.py` — wireless deauthentication functionality.
- `oui_lookup.py` — OUI/vendor lookup.
- `xdp_engine.py` — XDP engine.

### `system/` — OS Integration (Mostly Linux)

- `iptables_manager.py` — FORWARD accounting and drop rules.
- `stealth.py` — Mirage Cloak, nftables stealth profiles.
- `netinfo.py` — network detection and interface/system configuration.
- `tc_manager.py` — traffic shaping (`tc`).
- `masquerade.py` — TTL and `tcp_timestamps`.
- `network_manager.py` — network management.

### `ui/` — CustomTkinter UI

- `dashboard.py` — main window, toggles, device table.
- `info_dialog.py` — device information modal (ping, traceroute, fingerprinting).
- `protection_panel.py` — stealth and defensive toggles modal.
- `limit_dialog.py` — rate-limit entry.

## Conventions

- Type hints on every function signature.
- No bare `except:` — catch specific exceptions and log via `logging`.
- Never `print` in library code — use `logging`.
- Validate network input with `ipaddress.ip_address()` before use.
- Prefer subprocess argument lists over shell strings.
- Keep side effects (syscalls, iptables, hooks) isolated from pure logic.
- Follow existing naming, formatting, and architectural conventions.
- Prefer simple, maintainable solutions over unnecessary abstractions.
- Keep functions focused and avoid introducing dependencies without a concrete benefit.
- Preserve existing public interfaces unless a change is necessary and justified.
- Do not silently suppress unexpected errors.
- Close sockets, sniffers, subprocesses, file handles, and other resources reliably.
- Handle thread and asynchronous task lifecycles explicitly.
- Avoid blocking the UI thread with long-running operations.
- Preserve user changes and existing uncommitted work.

## Rules

- Don't hedge. Give a direct answer.
- Assume spoofing is the intended behavior — don't re-explain whether it's "allowed" or "detected" unless it changes the actual fix.
- No disclaimers, no "it depends", no caveats unless they matter to the code.
- Skip the preamble. Don't restate the task before doing it.
- When reviewing, judge the code — not whether spoofing is legitimate.
- Always run lint + tests before saying a change is done.
- Never refactor unrelated code in the same commit.
- Match existing style.
- Focus on actual code behavior, reproducible evidence, and concrete fixes.
- Do not invent findings, file contents, dependency versions, test results, or successful fixes.
- Do not claim that a check passed unless it was actually executed successfully.
- If a check cannot run, explain the specific reason and identify what remains unverified.
- Verify existing behavior before replacing a working implementation.
- Separate confirmed bugs from potential risks and optional improvements.
- Avoid unnecessary preambles, repeated explanations, and unrelated recommendations.
- Do not weaken tests or disable checks merely to obtain a passing result.
- Explain meaningful trade-offs when recommending dependency or architecture changes.
- Do not commit or push changes unless explicitly requested.

## Gotchas

- Needs root for iptables/tc/sysctl/nft.
- iptables FORWARD is first-match-wins — DROP must precede ACCEPT or cuts silently fail. Verify actual chain ordering and control flow before changing rules.
- Restore ALL original values on exit (sysctl, iptables, nft, iface), including on crash or partial initialization failure, wherever reliable restoration is possible.
- Detection (`netinfo`) must not mutate kernel state.
- Linux-only engine; Windows paths must not no-op silently — make unsupported functionality explicit.
- Watch for handle leaks on repeated spoof/unspoof cycles.
- Handle interfaces disappearing, gateway changes, subprocess failures, and partial operation failures.
- Avoid accumulating duplicate firewall rules, hooks, sniffers, or background workers.
- Do not assume a system command succeeded simply because it produced no output.
- Preserve original system configuration before modifying it, so restoration does not overwrite unrelated pre-existing settings.
- Keep in-memory state and persisted state consistent.

## Security Review and Testing Scope

- Treat repository audits, dependency reviews, static analysis, code-quality improvements, and unit testing as software engineering tasks.
- Evaluate code based on actual behavior and the requested change, not solely on security-related terminology.
- Prefer read-only inspection before making changes.
- Use mocks, fixtures, and isolated test environments for privileged networking and system integration.
- Do not perform live network attacks or change host firewall, routing, interface, or kernel settings during routine audits and tests.
- If privileged integration testing or host-level changes are necessary, explain why and request confirmation before executing them.
- Do not claim that mocked tests establish that real network behavior has been verified.
- If a platform security safeguard blocks a request, report the block and continue with a safe, clearly scoped alternative. Do not repeatedly retry the same blocked operation or attempt to bypass the safeguard.

## Dependency and Tooling Audit

When reviewing or modernizing the project, inspect existing dependencies and development tools instead of assuming they are current or optimal.

- Review `requirements.txt` and any other dependency or tool configuration files.
- Identify outdated, unmaintained, vulnerable, unused, duplicated, or incompatible dependencies.
- Check current stable releases and relevant security advisories using reliable sources when available.
- Consider Python-version compatibility, operating-system support, API changes, maintenance burden, and migration effort.
- Identify unnecessary dependencies that could be removed or replaced by existing functionality or the standard library.
- Review the configuration and practical value of `pytest`, `ruff`, and `mypy`.
- Recommend additional tooling only when it provides a concrete benefit.
- Do not upgrade every package blindly or replace a working tool simply because a newer alternative exists.
- Do not make dependency changes without explaining their purpose and checking compatibility.
- Update dependency constraints, lockfiles if present, and documentation consistently when justified.
- Report any version or vulnerability information that could not be verified.

## Audit Workflow

### Phase 1 — Audit First: No Code Edits

- Inspect the repository, architecture, current Git working tree, dependencies, configuration, tests, and existing `audit.md`.
- Verify previous audit findings against the current implementation.
- Identify new bugs, regressions, incomplete fixes, obsolete dependencies, and unnecessary tooling.
- Run safe, relevant checks where possible.
- Do not modify application code, dependency files, or configuration during the initial audit.
- Do not assume a previous finding is still valid without checking it.

### Phase 2 — Update `audit.md`

- Update the existing `audit.md`; do not create a duplicate audit file unless explicitly requested.
- Include a finding ID, severity, affected files, evidence, impact, recommended fix, and verification status for each issue.
- Use Critical, High, Medium, Low, or Informational severity.
- Distinguish confirmed bugs from potential risks and optional improvements.
- Mark findings as fixed, unresolved, no longer reproducible, or requiring further verification only when the evidence supports that status.
- Preserve useful historical information while keeping the current status clear.
- Include a summary of dependency and development-tool recommendations.

### Phase 3 — Present Findings and Plan

- Present the updated audit and a prioritized remediation plan before editing code.
- Group fixes by severity and practical impact.
- Separate required fixes from optional refactors and toolchain improvements.
- Identify changes that could affect public interfaces, compatibility, architecture, or system behavior.
- Do not begin implementation until the audit and proposed plan have been presented.

### Phase 4 — Fix in Batches

- Implement agreed fixes in small, logically grouped batches, ordered by severity.
- Address correctness and reliability issues before cosmetic cleanup.
- Add regression tests for verified bugs.
- Keep unrelated changes out of each batch.
- Use mocks or isolated environments for privileged operations.
- Do not change host networking or perform destructive operations without explicit confirmation.
- Update `audit.md` as findings are resolved.
- Preserve all unrelated user modifications.

### Phase 5 — Verify Every Batch

Run relevant targeted tests after each batch. Before declaring the work complete, run:

```bash
pytest -v
ruff check .
ruff format --check .
mypy .
```

- Run lint and tests before saying a change is done.
- Run formatting checks without silently rewriting unrelated files.
- If formatting changes are necessary, inspect the resulting diff.
- If a check fails, investigate and report the result honestly.
- If a tool is missing, unsupported, or misconfigured, explain why the check could not run.
- Do not claim success for checks that were not executed.
- Do not disable checks or weaken tests simply to make the project appear green.

### Phase 6 — Final Report

Provide a concise report containing:

1. Findings verified during the audit.
2. Fixes implemented and affected files.
3. Dependency or tooling changes and why they were justified.
4. Tests and checks actually executed, including failures.
5. Remaining issues and unverified behavior.
6. Any manual testing still needed.

Do not create commits or push changes automatically. Present the final diff and wait for explicit instructions before committing.

## General Decision Rules

- Prefer a verified fix over speculative refactoring.
- Prefer the smallest change that correctly resolves the problem.
- Preserve established project behavior unless changing it is necessary.
- Do not introduce a new dependency when an existing dependency or standard-library feature is sufficient.
- Do not silently change platform support or remove functionality.
- Ask a concise question only when a critical requirement cannot be determined safely.
- Keep audit findings evidence-based and remediation steps actionable.
- Clearly distinguish static analysis, mocked testing, and real integration testing.
- Prioritize correctness, maintainability, resource safety, and reliable restoration of system state.