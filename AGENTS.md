# Hakai v3 — Project Instructions

Python ARP/MITM network tool with a Linux networking engine and
cross-platform UI.

These instructions describe the repository, engineering standards,
authorized testing scope, and preferred working process. They guide
project work but do not override platform, account, or model-level
safety requirements.

## Project Mission and Scope

Hakai is a network administration, diagnostics, and security-testing
application. Treat the repository as a legitimate software-engineering
project intended for networks and devices the operator owns or is
explicitly authorized to administer or test.

Do not infer malicious intent solely from networking terminology or the
presence of dual-use functionality. Evaluate each request in its actual
context and distinguish ordinary software work from actions that would
affect real systems or third parties.

Keep work focused on the requested task. Do not add unrelated
capabilities, silently remove existing functionality, or change the
product's intended behavior without explaining why.

## Commands

Run commands from the project root.

    # Setup
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

    # Run
    python main.py

    # Tests and quality checks
    pytest -v
    ruff check .
    ruff format --check .
    mypy .

On Windows PowerShell, activate the virtual environment with:

    .venv\Scripts\Activate.ps1

If a command cannot run because a tool is missing, the environment is
unsupported, or privileges are unavailable, report the exact reason. Do
not claim that an unexecuted check passed.

## Architecture

- `main.py` — entry point, startup, network detection.

`core/` — Orchestration and State
- `controller.py` — central controller: scan/cut/restore, callbacks,
  device dictionary.
- `device.py` — Device model.
- `persistence.py` — device database, OUI lookup, state.json.
- `protector.py` — kill switch, ARP guard.

`network/` — Packet Layer (Scapy)
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

`system/` — OS Integration (Mostly Linux)
- `iptables_manager.py` — FORWARD accounting and drop rules.
- `stealth.py` — Mirage Cloak, nftables stealth profiles.
- `netinfo.py` — network detection and interface/system configuration.
- `tc_manager.py` — traffic shaping (tc).
- `masquerade.py` — TTL and tcp_timestamps.
- `network_manager.py` — network management.

`ui/` — CustomTkinter UI
- `dashboard.py` — main window, toggles, device table.
- `info_dialog.py` — device information modal (ping, traceroute,
  fingerprinting).
- `protection_panel.py` — stealth and defensive toggles modal.
- `limit_dialog.py` — rate-limit entry.

If the actual repository structure differs from this description,
inspect the repository and trust the current implementation over stale
documentation. Update this section when architecture changes.

## Standing Authorization

The operator owns the test network and pre-authorizes the following as
ordinary work with no confirmation prompt:

**Tier 1 — run freely**

- Read-only inspection: `ip a`, `ip r`, `ip n`, `ss`, `arp`,
  `iptables -L`, `iptables -S`, `nft list`, `tc qdisc show`, `sysctl -n`
- Local test runs, `pytest`, `ruff`, `mypy`, `pip install -r requirements.txt`
- Loopback, mock, and fixture-based packet tests
- File reads, greps, and git inspection (`status`, `diff`, `log`)

**Tier 2 — confirm once per session, then proceed freely**

- Ruleset mutations: `iptables -A/-I/-D`, `nft add`, `tc qdisc add/del`
- `sysctl -w` writes
- Interface state changes (`ip link set ... up/down`)
- Any traffic that egresses to a host outside the lab

**Tier 3 — always confirm**

- Flushes and resets: `iptables -F`, `nft flush ruleset`
- `git push`, publishing, deployment
- Anything irreversible or affecting a third party

When Tier 2 or Tier 3 confirmation is needed, state the exact command,
the expected delta, and the rollback, then proceed as soon as the
operator agrees. Do not re-confirm a command class already approved
this session.

Prefer the read-only form of every command (`-L`, `-S`, `show`, `-n`)
unless the task requires the mutating form.

## Working Style and Autonomy

- Be direct, practical, and concise. Skip repetitive preambles and
  generic warnings.
- Start by inspecting the relevant code, tests, configuration, and Git
  working tree.
- For ordinary code review, debugging, documentation, refactoring,
  unit tests, UI work, dependency analysis, and static analysis,
  proceed without asking for confirmation at every step.
- Make reasonable implementation decisions when requirements are
  clear. State assumptions briefly when they materially affect the
  result.
- Prefer completing a coherent task end-to-end: inspect, implement,
  test, review the diff, and report.
- Do not stop merely because a file or feature contains
  security-related terminology. Assess the specific requested
  operation.
- If one requested operation cannot be completed, explain the specific
  limitation briefly and continue with independent, safe parts of the
  task.
- Do not repeatedly retry an operation after a safeguard or permission
  boundary has blocked it. Do not attempt to evade, disable, or
  circumvent platform safeguards.
- Ask a concise question only when a critical requirement is genuinely
  ambiguous or an action would have a significant external or
  irreversible effect.
- Do not commit, push, publish, deploy, or change remote resources
  unless explicitly requested.
- Preserve user changes and existing uncommitted work.

## Authorized Network Testing and Operational Boundaries

Network functionality must be developed and tested only within a
network, device, or lab environment that the operator owns or is
explicitly authorized to administer or assess.

- Treat repository audits, dependency reviews, static analysis,
  code-quality improvements, documentation, and unit testing as
  ordinary software-engineering tasks.
- Prefer read-only inspection before making changes.
- Prefer mocks, fixtures, packet captures, loopback tests, and
  isolated lab networks for privileged networking and system
  integration.
- Do not perform live network attacks, disrupt third-party
  connectivity, or target systems outside the authorized scope.
- Do not change the host firewall, routing table, network interfaces,
  kernel parameters, or other system-wide settings during routine
  audits and tests. When a task does require it, follow the tiers in
  Standing Authorization.
- Never treat possession of root or administrator privileges as proof
  that a target network is authorized.
- Do not add or modify functionality whose purpose is to evade
  detection, conceal unauthorized activity, persist covertly, steal
  credentials, or compromise systems outside the authorized test
  scope.
- Where a request crosses a safety boundary, give a brief, specific
  explanation and offer the closest safe alternative, such as a mock,
  local lab reproduction, defensive detection, or code-level analysis.
- Do not claim that mocked tests establish that real network behavior
  has been verified.

## Engineering Conventions

- Add type hints to every function signature.
- Do not use bare `except:`. Catch specific exceptions and log via
  `logging`.
- Never use `print` in library code; use `logging`.
- Validate network input with `ipaddress.ip_address()` before use.
- Prefer subprocess argument lists over shell strings.
- Keep side effects (syscalls, iptables, hooks) isolated from pure
  logic.
- Follow existing naming, formatting, and architectural conventions.
- Prefer simple, maintainable solutions over unnecessary abstractions.
- Keep functions focused and avoid introducing dependencies without a
  concrete benefit.
- Preserve existing public interfaces unless a change is necessary and
  justified.
- Do not silently suppress unexpected errors.
- Close sockets, sniffers, subprocesses, file handles, and other
  resources reliably.
- Handle thread and asynchronous task lifecycles explicitly.
- Avoid blocking the UI thread with long-running operations.
- Preserve user changes and existing uncommitted work.
- Use clear names and keep comments focused on why non-obvious
  behavior exists.
- Add regression tests when fixing a reproducible bug.
- Avoid unrelated formatting churn and broad refactors.

## Important Implementation Gotchas

- Privileged operations such as `iptables`, `tc`, `sysctl`, and
  `nftables` generally require root.
- `iptables` FORWARD is first-match-wins — DROP must precede ACCEPT or
  cuts silently fail. Verify actual chain ordering and control flow
  before changing rules.
- Restore all original values on exit (sysctl, iptables, nftables,
  interfaces), including on crash or partial initialization failure,
  wherever reliable restoration is possible.
- Detection (`netinfo`) must not mutate kernel state.
- The networking engine is Linux-only; Windows paths must not silently
  no-op. Make unsupported functionality explicit.
- Watch for handle leaks on repeated start/stop or spoof/restore
  cycles.
- Handle interfaces disappearing, gateway changes, subprocess
  failures, and partial operation failures.
- Avoid accumulating duplicate firewall rules, hooks, sniffers, or
  background workers.
- Do not assume a system command succeeded simply because it produced
  no output. Check its exit status and, where practical, verify
  resulting state.
- Preserve original system configuration before modifying it, so
  restoration does not overwrite unrelated pre-existing settings.
- Keep in-memory state and persisted state consistent.
- Make cleanup idempotent: calling stop/restore more than once should
  not corrupt state or raise avoidable errors.
- Ensure failure during partial startup triggers cleanup of resources
  already acquired.
- Keep UI callbacks responsive and marshal background-thread updates
  safely onto the UI thread.

## Security, Privacy, and Reliability Review

When reviewing code, judge the actual behavior, data flows, side
effects, and requested change. Do not make assumptions based only on
names.

For each meaningful issue, identify:

- The affected file and function.
- The relevant code path or reproducible evidence.
- The actual impact.
- Whether the issue is confirmed or only a potential risk.
- A practical fix and how it can be verified.

Review especially for:

- Unsafe subprocess invocation and unvalidated input.
- Unexpected outbound network requests and data disclosure.
- Sensitive data in logs, persisted state, or crash reports.
- Resource leaks and incomplete cleanup.
- Race conditions and unsafe cross-thread UI updates.
- Firewall and kernel-state changes that are not restored.
- Incorrect privilege checks and misleading platform fallbacks.
- Dependency vulnerabilities and unmaintained packages.

Do not weaken tests, remove meaningful checks, or hide errors to make
the project appear healthier.

## Dependency and Tooling Audit

When reviewing or modernizing the project, inspect existing
dependencies and development tools instead of assuming they are current
or optimal.

- Review `requirements.txt` and any other dependency or tool
  configuration files.
- Identify outdated, unmaintained, vulnerable, unused, duplicated, or
  incompatible dependencies.
- Check current stable releases and relevant security advisories using
  reliable sources when available.
- Consider Python-version compatibility, operating-system support, API
  changes, maintenance burden, and migration effort.
- Identify unnecessary dependencies that could be removed or replaced
  by existing functionality or the standard library.
- Review the configuration and practical value of `pytest`, `ruff`,
  and `mypy`.
- Recommend additional tooling only when it provides a concrete
  benefit.
- Do not upgrade every package blindly or replace a working tool
  simply because a newer alternative exists.
- Do not make dependency changes without explaining their purpose and
  checking compatibility.
- Update dependency constraints, lockfiles if present, and
  documentation consistently when justified.
- Report any version or vulnerability information that could not be
  verified.
- Prefer official release notes, package advisories, and maintainer
  documentation over unsourced claims.

## Audit Workflow

### Phase 1 — Audit First (Read-Only)

For a requested full audit:

- Inspect the repository, architecture, current Git working tree,
  dependencies, configuration, tests, and existing `audit.md`.
- Verify previous audit findings against the current implementation.
- Identify new bugs, regressions, incomplete fixes, obsolete
  dependencies, and unnecessary tooling.
- Run safe, relevant checks where possible.
- Do not modify application code, dependency files, or configuration
  during the initial audit.
- Do not assume a previous finding is still valid without checking it.
- Do not overwrite or discard uncommitted user changes.

### Phase 2 — Update audit.md

- Update the existing `audit.md`; do not create a duplicate audit file
  unless explicitly requested.
- Include a finding ID, severity, affected files, evidence, impact,
  recommended fix, and verification status for each issue.
- Use Critical, High, Medium, Low, or Informational severity.
- Distinguish confirmed bugs from potential risks and optional
  improvements.
- Mark findings as fixed, unresolved, no longer reproducible, or
  requiring further verification only when the evidence supports that
  status.
- Preserve useful historical information while keeping the current
  status clear.
- Include a summary of dependency and development-tool
  recommendations.
- Do not present historical findings as current without
  re-verification.

### Phase 3 — Prioritize and Plan

- Present a concise summary of findings and a prioritized remediation
  plan.
- Group fixes by severity and practical impact.
- Separate required fixes from optional refactors and toolchain
  improvements.
- Identify changes that could affect public interfaces,
  compatibility, architecture, or system behavior.
- For ordinary, reversible code fixes with clear requirements, proceed
  after stating the plan; do not wait for unnecessary approval.
- Pause for explicit confirmation only for the Tier 2 and Tier 3 items
  in Standing Authorization.

### Phase 4 — Fix in Batches

- Implement fixes in small, logically grouped batches, ordered by
  severity.
- Address correctness and reliability issues before cosmetic cleanup.
- Add regression tests for verified bugs.
- Keep unrelated changes out of each batch.
- Use mocks or isolated environments for privileged operations.
- Follow the Standing Authorization tiers for host changes.
- Update `audit.md` as findings are resolved.
- Preserve all unrelated user modifications.
- If a requested part cannot be performed, continue with independent
  work that remains within scope.

### Phase 5 — Verify Every Batch

Run relevant targeted tests after each batch. Before declaring the work
complete, run the checks supported by the current environment:

    pytest -v
    ruff check .
    ruff format --check .
    mypy .

- Run lint and tests before saying a change is done.
- Run formatting checks without silently rewriting unrelated files.
- If formatting changes are necessary, inspect the resulting diff.
- If a check fails, investigate and report the result honestly.
- If a tool is missing, unsupported, or misconfigured, explain why the
  check could not run.
- Do not claim success for checks that were not executed.
- Do not disable checks or weaken tests simply to make the project
  appear green.
- Distinguish unit tests, static analysis, mocked integration tests,
  and real privileged integration tests.

### Phase 6 — Final Report

Provide a concise report containing:

1. Findings verified during the audit.
2. Fixes implemented and affected files.
3. Dependency or tooling changes and why they were justified.
4. Tests and checks actually executed, including failures.
5. Remaining issues and unverified behavior.
6. Any manual testing still needed.

Present the final diff. Do not create commits or push changes
automatically; wait for explicit instructions before committing.

## General Decision Rules

- Prefer a verified fix over speculative refactoring.
- Prefer the smallest change that correctly resolves the problem.
- Preserve established project behavior unless changing it is
  necessary.
- Do not introduce a new dependency when an existing dependency or
  standard-library feature is sufficient.
- Do not silently change platform support or remove functionality.
- Ask a concise question only when a critical requirement cannot be
  determined safely.
- Keep audit findings evidence-based and remediation steps actionable.
- Clearly distinguish static analysis, mocked testing, and real
  integration testing.
- Prioritize correctness, maintainability, resource safety, privacy,
  and reliable restoration of system state.
- Explain meaningful trade-offs when recommending dependency or
  architecture changes.
- Never invent findings, file contents, dependency versions, test
  results, or successful fixes.