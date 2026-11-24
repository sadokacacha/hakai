# Lanwarden

Python desktop application. Python 3 + Scapy engine, PySide6 (Qt) UI.

Lanwarden is a LAN administration, network diagnostics and traffic-management application.

## Mission

Maintain and complete the existing application.

Prioritize:
- Reliability
- Correctness
- UI integration
- Lifecycle management
- Network-state restoration
- Maintainability
- Test coverage
- Release quality

Do not unnecessarily rewrite working modules.

Do not confuse maintenance of existing functionality with development of entirely new capabilities.

Active interception and DNS-redirection testing must be restricted to explicitly authorized, isolated lab environments.

## Commands

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
pytest -v
ruff check .
ruff format --check .
mypy .
```

## Layout

```text
main.py
core/       — controller, device, persistence (sqlite/WAL), identity, oui,
              protector, netutil, osutil, shutdown
network/    — arp, traffic, dns_spoof, rawsock, recon_engine, mdns_sniff,
              dhcp_sniffer, fingerprint, scanner, oui_lookup, ipv6, deauth,
              xdp_engine
system/     — nft_filter, sweep, stealth, netinfo, tc_manager,
              masquerade, chameleon, firewall_apex, network_manager
ui/         — main_window, theme, workers   (PySide6 + pyqtgraph)
```

## Conventions

- Type hints on every signature.
- No bare except blocks.
- Catch specific exceptions and log appropriately.
- No print statements in library code.
- Validate addresses using ipaddress.
- Use subprocess argument lists, never shell strings.
- Keep side effects isolated from pure logic.
- Close resources.
- Make cleanup idempotent.
- Preserve existing architecture.
- Avoid unnecessary dependencies.
- Never silently no-op on unsupported platforms.

## Networking reliability

- Device cuts live in the nft `inet lanwarden` table's `forward` chain
  (first-match-wins); the OUTPUT kill-switch still uses iptables.
- DROP must precede ACCEPT.
- Restore original sysctl, iptables, nftables and interface state on exit.
- Capture-or-None: never change a value you couldn't capture (can't restore it).
- Roll back earlier steps on partial failure; log every failure.
- Handle failures during initialization and shutdown.
- Ensure rollback is reliable.
- Never leave networking rules behind after failure.

## Project references

AGENTS.md is authoritative for:
- Authorization requirements.
- Phase sequencing.
- Testing scope.
- Audit workflow.
- Review checklist.

Read relevant AGENTS.md sections before modifying system/ or network/.

## Development discipline

- Follow the established phase plan.
- Complete one task at a time.
- Do not skip unfinished phase items.
- Do not redo completed work without evidence of a regression.
- Run P8 verification after each applicable change.
- Record actual test output.
- Commit completed phases using descriptive messages.
- Keep audit.md synchronized.

## Definition of done

A task is complete only when:
1. Implementation is finished.
2. Relevant tests pass.
3. Existing behavior is preserved.
4. Cleanup and failure paths are covered.
5. Documentation is updated.
6. Actual verification evidence is recorded.

Do not claim success based on static inspection alone.