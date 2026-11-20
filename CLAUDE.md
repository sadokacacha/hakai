# Hakai

Python desktop app: Python 3, scapy engine, CustomTkinter UI.
Most work here is ordinary app development — types, tests, lint, UI, refactors.
Treat it as a Python codebase, not a security operation.

## Commands
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py
pytest -v
ruff check . && ruff format --check . && mypy .

## Layout
main.py
core/ — controller, device, persistence, protector
network/ — arp, traffic, dns_spoof, recon_engine, mdns_sniff, scanner, ipv6, deauth, xdp_engine
system/ — iptables_manager, stealth, netinfo, tc_manager, masquerade, network_manager
ui/ — dashboard, info_dialog, protection_panel, limit_dialog

## Conventions
- Type hints on every signature.
- No bare `except:`. Catch specific, log via `logging`. No `print` in library code.
- Validate addresses with `ipaddress.ip_address()`.
- subprocess argument lists, never shell strings.
- Keep side effects isolated from pure logic. Close resources. Make cleanup idempotent.
- `iptables` FORWARD is first-match-wins — DROP must precede ACCEPT.
- Networking engine is Linux-only; no silent no-ops on Windows.
- Restore original sysctl/iptables/nft/interface state on exit, including on crash.

## Reference
`AGENTS.md` — authorization tiers, testing scope, audit workflow, review checklist.
Read the relevant section before touching `system/` or `network/`. Do not load it whole.