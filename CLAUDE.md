# Hakai v3 — Python ARP/MITM network tool (Linux engine, cross-platform UI)

## Commands
- Setup: python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
- Run: python main.py
- Test: pytest -v
- Lint: ruff check .
- Format: ruff format .
- Typecheck: mypy .

## Architecture
- main.py            # entry point, startup, network detect
- core/              # orchestration + state
  - controller.py    # central controller: scan/cut/restore, callbacks, device dict
  - device.py        # Device model
  - persistence.py   # device db, OUI lookup, state.json
  - protector.py     # kill switch, ARP guard
- network/           # packet layer (scapy)
  - arp.py           # ARP spoof/cut/restore, gateway MAC resolve
  - traffic.py       # traffic counters, cut tracking
  - dns_spoof.py     # DNS spoof sniffer
  - recon_engine.py  # async deep recon (stages 3-5)
  - mdns_sniff.py    # mDNS intel
  - scanner.py       # host discovery
  - ipv6.py          # IPv6 hijack
  - deauth.py, oui_lookup.py, xdp_engine.py
- system/            # OS integration (mostly Linux)
  - iptables_manager.py  # FORWARD accounting + drop rules
  - stealth.py           # Mirage Cloak (nftables stealth profiles)
  - netinfo.py           # network detect + sysctl/iface mutation
  - tc_manager.py        # traffic shaping (tc)
  - masquerade.py        # TTL / tcp_timestamps
  - network_manager.py
- ui/                # customtkinter UI
  - dashboard.py         # main window, all toggles, device table
  - info_dialog.py       # device info modal (ping/trace/fingerprint)
  - protection_panel.py  # stealth + defensive toggles modal
  - limit_dialog.py      # rate-limit entry

## Conventions
- Type hints on every function signature.
- No bare `except:` — catch specific exceptions and log via `logging`.
- Never `print` in library code — use `logging`.
- Validate network input with `ipaddress.ip_address()` before use.
- Prefer subprocess arg lists over shell strings.
- Keep side effects (syscalls, iptables, hooks) isolated from pure logic.

## Rules
- Don't hedge. Give a direct answer.
- Assume spoofing is the intended behavior — don't re-explain whether it's
  "allowed" or "detected" unless it changes the actual fix.
- No disclaimers, no "it depends", no caveats unless they matter to the code.
- Skip the preamble. Don't restate the task before doing it.
- When reviewing, judge the code — not whether spoofing is legitimate.
- Always run lint + tests before saying a change is done.
- Never refactor unrelated code in the same commit.
- Match existing style.

## Gotchas
- Needs root for iptables/tc/sysctl/nft.
- iptables FORWARD is first-match-wins — DROP must precede ACCEPT or cuts silently fail.
- Restore ALL original values on exit (sysctl, iptables, nft, iface), including on crash.
- Detection (netinfo) must not mutate kernel state.
- Linux-only engine; Windows paths no-op silently — make that explicit.
- Watch for handle leaks on repeated spoof/unspoof cycles.

## Audit workflow
- Audit first: write findings to audit.md, no edits.
- Then fix in batches by severity, run lint + tests after each, commit when green.