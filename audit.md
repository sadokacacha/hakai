# Hakai v3 — Code Audit

Read-only audit of the full application source (`main.py`, `core/`, `network/`,
`system/`, `ui/`), plus dependencies and tooling. `venv/` is excluded.

Severity scale:

- **Critical** — crashes a reachable code path, corrupts state, or defeats the feature's core guarantee.
- **High** — wrong results, silent failure of a major feature, or a security/privacy exposure.
- **Medium** — concurrency hazard, cross-platform break, or fragile logic that fails on common inputs.
- **Low** — hygiene, dead code, cosmetic, convention violations.

---

## Baseline — 2026-11-19 (Phase 0)

Read-only baseline captured before any Phase-1+ changes. No edits to code,
no installs, no upgrades. Measured on this host, not the committed 2026-10-13
figures.

**Environment:** Linux (Arch, kernel 7.2.9-arch1-1), Python **3.14.8**,
project `.venv`. Installed: scapy 2.8.0, customtkinter 6.0.0, Pillow 12.3.0,
pytest 9.1.1, ruff 0.17.0, mypy 2.4.0. (Prior committed baseline was Windows
11 / Python 3.13.15 — environment changed, so figures are re-measured.)

**Scope decision (this session):** reliability & quality only. Restoration,
resource/lifecycle cleanup, idempotency, defensive `protector`, tests,
subprocess/input hardening, dependency hygiene, and UI shell are in scope.
Crashes/leaks in the offensive/evasion modules are in scope to *fix*, but
improving their real-world effectiveness is out of scope. No live disruptive
network tests — mocks/fixtures only.

### Commands run and actual results

| Command | Result |
|---|---|
| `git status --short` | 34 files modified (working tree), `run.bat` staged-deleted, `AGENTS.md` + `run.sh` untracked |
| `git stash list` | empty |
| `git log -5 --oneline` | `4f6b9bc` updating claude · `b935828` Add tooling config… · `8186592` Rewrite audit.md… · `95636c1` Tidy requirements… · `c6bfe88` Validate bandwidth-limit input |
| `pytest -v` | **22 passed** in 0.33s |
| `ruff check .` | **All checks passed!** |
| `ruff format --check .` | **35 files would be reformatted**, 8 already formatted |
| `mypy .` | **Success: no issues found in 39 source files** (14 `annotation-unchecked` notes only) |
| `pip list --outdated` | minor bumps available: mypy 2.4.0→2.4.1, pillow 12.3.0→13.0.0, pytest 9.1.1→9.2.0, ruff 0.17.0→0.17.5, pluggy, mypy_extensions, pip |

### Existing failures / gaps

- **No test failures.** Suite is green (22 tests).
- **Formatting drift:** the uncommitted working tree (5737 insertions /
  5901 deletions across 37 files) is not `ruff format`-clean (35 files). This
  is the one actionable static signal; everything else passes.
- **Working tree is a large uncommitted rewrite** — preserved as-is, not
  stashed or reset.
- **`ruff format --check` is not part of the committed baseline table** in
  §0 but is part of the mission's required checks; recording it here.

### Not run / not verifiable here

- **No live GUI launch** (no attempt to drive the Tk mainloop headless).
- **Privileged network engine not exercised** — Linux engine needs root +
  real interfaces/packets; out of scope per the reliability-only decision and
  the no-live-disruption rule. Restoration correctness will be verified by
  unit tests with mocked subprocess/syscall layers, which does **not** prove
  real-OS restoration.
- No dependency installs or upgrades performed.

---

## System Map — 2026-11-19 (Phase 1)

Read-only trace of the full application. No code edited. Purpose: understand
every module and the 12 runtime paths before changing anything. Issues noted
here as **Limits** are candidates for the Phase-2 bug hunt, not fixes.

### Module inventory (every module classified)

| Module | Role | Appears in path(s) |
|---|---|---|
| `main.py` | entry point, root/dep checks, wiring, mainloop | Startup, Shutdown |
| `core/controller.py` | central orchestrator, device dict, all ops | all |
| `core/device.py` | Device model + serialization | Device state |
| `core/persistence.py` | config/state/nick JSON, OUI dict, `classify_device`, fmt helpers | Startup, Device state, Discovery |
| `core/protector.py` | ARP guard, kill-switch, sentry, ARP monitor | Protection |
| `network/arp.py` | 5-layer cut/spoof/restore, MAC resolve, watchdog | Gateway resolution, Cut, Restore |
| `network/traffic.py` | 3-layer per-IP byte/speed counter | Traffic accounting |
| `network/scanner.py` | nmap/ARP/arp-table scan + passive discovery + hostname pool | Discovery |
| `network/fingerprint.py` | nmap -O -sV background fingerprint | Discovery |
| `network/recon_engine.py` | async SSL/UPnP/NetBIOS/PTR/IPv6 recon | Discovery |
| `network/mdns_sniff.py` | mDNS name/class extractor | Discovery |
| `network/dhcp_sniffer.py` | DHCP opt 55/12/60 OS+hostname extractor | Discovery |
| `network/oui_lookup.py` | second OUI vendor lookup (`get_vendor`) | Discovery (**dup**, see Limits) |
| `network/dns_spoof.py` | DNS REDIRECT + spoofed replies | *(independent — unreached, see Limits)* |
| `network/ipv6.py` | IPv6 RA + rogue DHCPv6 | Feature (Aegis toggle) |
| `network/deauth.py` | 802.11 PMF-bypass deauth | Cut (L5, WiFi only) |
| `network/xdp_engine.py` | eBPF XDP drop (needs BCC) | Cut, Shutdown |
| `system/netinfo.py` | detect net, `engage_mitm`, `restore_network` | Interface/Gateway detect, Startup, Restore, Shutdown |
| `system/iptables_manager.py` | FORWARD ACCEPT accounting + DROP | Traffic accounting (DROP half is **dead**, see Limits) |
| `system/tc_manager.py` | HTB per-IP bandwidth shaping | Limit |
| `system/stealth.py` | Mirage cloak (MAC/hostname/nft) | Feature (evasion) |
| `system/masquerade.py` | TTL/timestamp sysctl spoof | Feature (evasion) |
| `system/chameleon.py` | MTU/MSS clamp | Feature (evasion) |
| `system/firewall_apex.py` | `GhostFirewall` nft stealth-drop | Feature (evasion) |
| `system/network_manager.py` | nmcli static IP / DHCP | Feature (Protection panel) |
| `ui/dashboard.py` | main window, device table, all user commands | UI marshalling, all user ops |
| `ui/info_dialog.py` | per-device modal (ping/traceroute/fp/reset) | Feature |
| `ui/protection_panel.py` | defense/stealth/static-IP modal | Feature |
| `ui/limit_dialog.py` | bandwidth entry modal | Limit |
| `ui/theme.py` | color/font tokens | Independent infrastructure |

**Independent infrastructure (not in a runtime path):** `ui/theme.py` (tokens),
`scratch/verify_fix.py` (throwaway), `tests/` (4 files), `conftest.py`.

### The 12 execution paths

**1. Startup** — `main.main()` → `_check_root` (exits if non-root on Linux),
`_check_deps` (warns on missing nmap/arpspoof/tc/iw), `detect_network`, optional
`DeauthManager`, `Controller(net)` (constructs all subsystems, `xdp.load()`
attaches eBPF immediately), `ctrl.start()` → `engage_mitm` (sysctl + promisc +
ethtool offloads), `traffic.start`, `scanner.start_passive_discovery`,
`protector.start`, `save_state`, `tc.init`, gateway MAC resolve thread,
`_start_intel_sniffer`. Then vendor-DB sync thread, `Dashboard(ctrl)`, mainloop.
*External:* sysctl, ip link, ethtool, iptables (later). *Cleanup:* via Shutdown.
*Tests:* none (import-level only). **Limits:** `xdp.load()` and `engage_mitm`
mutate host state at startup before any user action; a crash before `stop()`
leaves promisc/offloads/XDP applied (Restore path only runs on clean exit).

**2. Interface detection** — `netinfo.detect_network` → `_detect_network_linux`
parses `ip route` (default line) for gateway+iface, `ip -4 addr` for IP/subnet,
`ioctl(SIOCGIFHWADDR)` for MAC, `iw dev` for wifi. Captures originals
(ip_forward, rp_filter, send/accept_redirects, promisc) read-only. *External:*
ip, iw, cat. *Failure:* no default route → empty iface → `detect` returns mostly
empty NetInfo; callers guard on `net.iface`. **Limits:** the `_run("cat", ...)`
reads for original sysctls are read via subprocess rather than file read; the
per-iface `rp_filter` original is **not** captured (only `all`).

**3. Gateway resolution** — `arp._resolve_macs("", gateway, iface)` (ping to
force ARP entry → scapy `srp` ×2 → `arp -n` table parse). Called at startup in a
thread and by `protector.enable_arp_guard`. *Failure:* returns `""` MACs; cut/
guard degrade. **Limits:** best-effort, no retry ceiling surfaced to UI.

**4. Discovery** — two sub-paths. *Active:* `controller.scan` →
`scanner.scan` (nmap -sn → nbstat/mdns script → scapy ARP sweep → arp table,
all merged) → merge into `devices` under lock → `ipt.add_accounting` per IP →
`classify_device` → async `resolve_hostname`, `fingerprint`, `run_deep_recon`.
*Passive:* `scanner._passive_sniff` (mDNS/SSDP/NBNS/LLMNR/DHCP) + controller
`_start_intel_sniffer` (DHCP opt55/12 + mDNS + DNS correlation + TTL/window).
All feed `classify_device`'s confidence scoring. *External:* nmap, arp, dig.
*Tests:* `test_network_helpers` (infer_os, vendor), `test_persistence`
(sanitizers, classify). **Limits:** `recon_engine.get_ssl_cert_cn` does ad-hoc
DER byte-scanning (fragile); two OUI tables feed two different lookups.

**5. Device state** — `Controller.devices: dict[ip,Device]` guarded by
`self._lock`; all sniffer callbacks mutate under lock; iteration uses
`snapshot_devices()`. `Device.to_state()` → `persistence.save_state`. Nickname is
a property persisted by MAC. *Tests:* `test_persistence` (classify paths).
**Limits:** `save_state` only called at startup and on explicit `save_state()`;
no periodic persistence; loaded `state.json` is never re-hydrated into `devices`
(write-only).

**6. Traffic accounting** — `TrafficCounter.start` spawns `_proc_loop`
(/proc/net/dev), `_ipt_loop` (parse `iptables -L FORWARD -v -x`), `_scapy_loop`
(per-packet). `get`/`get_usage`/`get_mode` read merged counters. ACCEPT rules
added by `ipt.add_accounting` during scan. *External:* iptables, /proc.
*Tests:* `test_traffic_spd_window`, `test_tc_burst`. **Limits:** counters are
process-lifetime only; `_ipt_loop` reconciles by string-matching the chain.

**7. Cut** — `controller.cut_device` sets `dev.cut/status`, `traffic.mark_cut`,
then worker thread: `arp.cut` (`_apply_drop` iptables DROP at FORWARD pos 1 →
`spoof`: resolve MACs → scapy flood + ICMP redirect + gratuitous ARP →
`arpspoof` fallback → watchdog) → `xdp.add_drop` → optional WiFi
`deauth.start_pmf_bypass`. `cut_all` loops. *External:* iptables, sysctl,
arpspoof, scapy. *Tests:* `test_iptables_manager` (bookkeeping only, mocked).
**Limits:** `IPTManager.add_drop/remove_drop/is_dropped` are **dead code** — the
real DROP is done inside `arp.py` directly; the manager only does accounting.
UI marks a device CUT before the worker confirms MAC resolution.

**8. Restore** — `controller.restore_device` → `arp.restore` (stop flood, kill
arpspoof pgroup, `_remove_drop` ×3, send 5× real ARP replies) → `dns.stop_spoof`
→ `xdp.remove_drop` → `tc.unlimit` if limited → reset `dev` flags →
`traffic.unmark_cut`. `restore_all` loops over cut/limited. *Tests:*
`test_iptables_manager::test_cleanup_clears_all`. **Limits:** restore success is
not verified against the real ARP table; `restore_device` does not remove the
FORWARD ACCEPT accounting rule (left until `stop`).

**9. Protection** — `Protector.start` spawns `_monitor_loop` (scapy ARP sniff →
reputation/spoof/gateway-conflict detection → optional self-heal / kill-switch)
and `_self_healing_sentry` (poll /proc/net/arp every 0.5 s, re-pin gateway
NUD_PERMANENT). `enable_arp_guard` sets `ip neigh ... nud permanent`;
`toggle_kill_switch` inserts a marked OUTPUT DROP on trigger. *External:* ip
neigh, iptables, scapy. *Tests:* none directly. **Limits:** `_self_healing_sentry`
indexes `parts[2]`/`parts[0]` of /proc/net/arp lines without a length guard
(broad `except` swallows it); `on_protection_alert` is invoked from sniffer
threads straight into the Tk log (see path 12).

**10. Shutdown** — `Dashboard.on_close` → `controller.stop`: `_running=False`,
`arp.restore_all`, `arp.stop_watchdog`, `dns.stop_all`, `xdp.unload`,
`traffic.stop`, `protector.stop`, `tc.teardown`, `ipt.cleanup`, `ipv6.stop`,
`scanner.stop_passive_discovery`, `restore_network`, `disengage_stealth` if
active → `self.destroy()`. *External:* iptables, tc, sysctl, ip link, nft.
**Limits:** `restore_network` reverts ip_forward/rp_filter(all)/redirects/
promisc/ethtool but **not** `proxy_arp=1` nor per-iface `rp_filter` set by
`engage_mitm` — partial restoration. Sniffer threads have `timeout=10–30 s`, so
they linger (daemon, so process exit is fine). No cleanup on crash/KeyboardInt.

**11. Error propagation** — pervasive broad `try/except … pass` (netinfo,
engage/restore, arp layers, sniff loops, dns, ipv6, stealth). Subprocess calls
use `capture_output=True` and mostly ignore `returncode`. User-visible errors go
through the `log=` callback where present. **Limits:** AGENTS.md "do not assume a
command succeeded" is widely violated; failures are silent. This is the single
biggest reliability theme and the core of the Phase-2 hunt.

**12. UI thread marshalling** — `Dashboard._refresh_loop` runs on the Tk thread
via `after(1200,…)` and is the safe path. **But** `_start_scan` runs
`controller.scan` in a worker thread that calls `self.log_tactical(...)` (→
`status_box.insert`) directly, and `on_protection_alert`
(= `log_tactical`) is called from the protector's sniffer threads. Tkinter is
not thread-safe; these are cross-thread widget writes. **Limits:** no
marshalling (`after`/queue) between background threads and the Tk log — a
confirmed concurrency hazard flagged by AGENTS.md.

### Dead ends / reachability notes

- `network/dns_spoof.py`: `controller.toggle_dns_spoof` exists but **no caller**
  wires a "start DNS spoof" control; only `restore_device`/`stop_all` call
  `stop_spoof`. Feature is effectively unreachable (Phase-6 verdict pending).
- `system/iptables_manager.py` DROP half: unreferenced; `arp.py` owns cuts.
- `network/oui_lookup.py` vs `persistence._OUI_DB`: two parallel OUI stores.
- `Dashboard._on_ttl_change` / `limit_dialog` sparkline history: defined, lightly
  used; to be reviewed in Phase 6/7.

---

## Bug Hunt — 2026-11-19 (Phase 2)

One file per invocation. Each confirmed bug has a mocked regression test that
failed on the old code and passes on the fix. Mocked evidence proves the logic
issues the right commands; it does **not** prove real-kernel restoration (needs
root + a live NIC — see Limits).

### `system/netinfo.py` — RESOLVED (3 bugs fixed, 1 clean note)

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| NET-1 | High | `engage_mitm` / `restore_network` | **Fixed** |
| NET-2 | Medium | `restore_network` (ethtool) | **Fixed** |
| NET-3 | Medium | `engage_mitm` / `restore_network` | **Fixed** |

**NET-1 — Incomplete state restoration (app-vs-OS drift).**
`engage_mitm` set `net.ipv4.conf.all.proxy_arp=1` and
`net.ipv4.conf.<iface>.rp_filter=0`, but the old `restore_network` reverted
neither (it only handled `all.rp_filter`, forwarding, redirects, promisc). After
a clean shutdown the host was left with proxy-ARP **enabled** and reverse-path
filtering **disabled** on the interface — a security-relevant, silent drift.
*Evidence:* old `restore_network` had no `proxy_arp` or per-iface `rp_filter`
write; `NetInfo` had no field to capture them.
*Fix:* capture `_orig_proxy_arp` and `_orig_iface_rp_filter` read-only during
detection; revert both in `restore_network`.
*Regression:* `test_restore_reverts_every_engaged_sysctl` — asserts every sysctl
`engage_mitm` writes is reverted to its captured original.

**NET-2 — Offloads force-restored to "on" instead of original.**
Old `restore_network` ran `ethtool -K … gro on lro on tso on gso on`, enabling
offloads that may have been **off** before Hakai started (originals never
captured). *Fix:* capture `_orig_offloads` via `ethtool -k` during detection;
restore each feature to its captured state, and skip entirely if nothing was
captured. *Regression:* `test_restore_offloads_to_captured_state_not_blindly_on`.

**NET-3 — Silent subprocess failures / no success signal.**
Both functions wrapped everything in one `except Exception: pass` and ignored
every `returncode`, so a failed restore was invisible (violates AGENTS.md "do
not assume a command succeeded" and "never report restoration successful without
verification"). *Fix:* `_write_sysctl`/`_set_promisc`/ethtool helpers check
`returncode`, log via `logging` on failure, and `restore_network`/`engage_mitm`
now **return bool**; a partial restore logs a warning and returns False.
*Regression:* `test_restore_reports_failure`, `test_restore_reports_success`.

Also hardened in the same pass (no behaviour change): replaced the broad
`except Exception` around detection with specific `OSError`/`SubprocessError`;
swapped the `cat /proc/...` reads for `sysctl -n` with a safe default so a
failed read can't masquerade as a real captured original.

**Clean note (not changed):** Windows detection path is detection-only and does
not pretend privileged ops succeed, so the "Windows no-op" check passes here.
IPv6 gateway is not detected by `netinfo` — that is a scope gap, not a bug.

**Limits (netinfo):** restoration correctness is proven only against a mocked
`subprocess`. Real-host verification (that the kernel actually returns to the
captured values) still requires a root Linux session and is unverified here.
`restore_network` now returns a success bool, but `controller.stop()` does not
yet consume it — surfacing that to the UI is a later-phase item.

Verification (netinfo batch):
`pytest -q` → **26 passed** (22 + 4 new) · `ruff check` / `ruff format` on
changed files → clean · `mypy .` → no issues (40 files).

### `network/arp.py` — RESOLVED (2 fixed) + 3 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| ARP-1 | High | `_start_flood` / `_start_arpspoof` / `_watchdog` | **Fixed** |
| ARP-2 | Medium | `cut` / `spoof` | **Fixed** |
| ARP-3 | Medium | `cut` return value | Documented (cross-file) |
| ARP-4 | Low | `_apply_drop` TOCTOU | Documented |
| ARP-5 | Medium | Windows unguarded iptables/sysctl | Documented (scope) |

**ARP-1 — Restore/watchdog race leaks poisoning threads & processes (defeats
restore).** `restore(ip)` pops the IP from `_cut_ips` but does **not** stop the
watchdog. The watchdog (`_watchdog`) snapshots `_cut_ips`, then — without
re-checking — calls `_start_flood` / `_start_arpspoof` for each entry. If
`restore()` pops the IP after the snapshot, the watchdog restarts the Scapy
flood and the `arpspoof` binary for an IP no longer being cut. Worse,
`_start_arpspoof` only recorded its spawned procs *if* `ip in _cut_ips` — so on
this race the processes were spawned but never tracked and never killed: they
**keep ARP-poisoning after the device was "restored".** *Evidence:* old
`_start_arpspoof` checked membership only after `Popen`; `_start_flood` had no
membership check; `_watchdog` had no stale-entry guard.
*Fix:* membership guard at the start of `_start_flood` and `_start_arpspoof`
(under `_lock`); `_start_arpspoof` now kills any procs spawned if the IP was
removed mid-spawn; `_watchdog` re-checks `ip in _cut_ips` under the lock before
re-arming. *Regression:* `test_start_arpspoof_no_leak_when_not_cut`,
`test_start_flood_no_leak_when_not_cut`.

**ARP-2 — No IP validation before root commands.** `cut`/`spoof` passed `ip`
and `gateway` straight into `iptables -I FORWARD`, `arpspoof`, `ping`, `arp -n`
(all as root) with no `ipaddress` check — against the AGENTS.md/CLAUDE.md
convention. (Argument lists mean no shell injection, but the convention exists
and an unvalidated value is a silent-failure/hardening gap.) *Fix:* module-level
`_valid_ip()`; `cut`/`spoof` return False before issuing any command on invalid
input. *Regression:* `test_cut_rejects_invalid_ip` / `_gateway` /
`test_spoof_rejects_invalid_ip`.

**ARP-3 (documented, cross-file) — Misleading cut result.** `cut()` returns the
`spoof()` result, which is False when the target MAC can't be resolved — but the
L1 iptables DROP was already applied, so the device **is** cut while the UI logs
"ARP resolution failed (target not reachable)". The honest fix spans
`controller.cut_device` (distinguish "dropped at L1 but not poisoning" from
"failed"); deferred to the controller's Phase-2 pass to keep this batch single-file.

**ARP-4 (documented) — `_apply_drop` check-then-insert TOCTOU.** `-C` then `-I`
is not atomic and runs outside `_lock`; concurrent `cut`+watchdog on the *same*
IP could duplicate the DROP rule. Low likelihood (watchdog sleeps first; per-IP
rules rarely collide) and `-C` mitigates most cases; `_remove_drop` clears up to
3 duplicates. Noted, not fixed.

**ARP-5 (documented, scope) — Windows.** `_apply_drop`/`_remove_drop`/`spoof`
call `iptables`/`sysctl` with no `_IS_WINDOWS` guard, so on Windows they raise
`FileNotFoundError` rather than failing explicitly. The engine is Linux-only;
making Windows *explicitly* unsupported (vs. `iptables_manager`'s silent fake-
success) is a cross-platform consistency decision for Phase 4/6, not a
reliability fix for the Linux target.

**Limits (arp):** the leak fix is verified by the deterministic entry-guard
invariant (mocked `Popen`/no real threads), which is what the watchdog relies
on. The *timing* race itself is narrowed to a microsecond window, not formally
proven absent under live concurrency. ARP-3/4/5 remain open as documented.

Verification (arp batch):
`pytest -q` → **31 passed** (+5 arp tests) · `ruff check` / `ruff format` on
changed files → clean · `mypy network/arp.py` → clean.

---

### `core/controller.py` — RESOLVED (1 fixed) + 4 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| CTL-1 | High | `stop()` | **Fixed** |
| CTL-2 | Medium | `start()` partial-failure cleanup | Documented |
| CTL-3 | Medium | `log=` / `on_protection_alert` cross-thread UI | Documented (cross-file → dashboard) |
| CTL-4 | Low | `cut_device` optimistic state vs `arp.cut` result | Documented |
| CTL-5 | Low | unbounded recon/fingerprint/cut threads | Documented |

**CTL-1 — Shutdown aborts remaining cleanup on any error → partial restoration.**
Old `stop()` was a flat sequence (`arp.restore_all` … `xdp.unload` … `tc.teardown`
… `restore_network` … `disengage_stealth`) with no per-step isolation and no
reentrancy guard. If any step raised — `xdp.unload()` can, via bcc `remove_xdp`
— every later step was skipped, so `restore_network` (promisc/rp_filter/
proxy_arp/redirects) and `disengage_stealth` never ran and the host was left
mutated. It also ignored `restore_network`'s new success bool, and a double
`stop()` re-ran the whole teardown. *Evidence:* `test_stop_*` failed on the old
code — `test_stop_is_idempotent` showed `restore` ran twice; the raising-step
test propagated the error and skipped restore.
*Fix:* `stop()` now guards reentrancy (`_stopped` under `_lock`), runs each
cleanup step in an isolated `try/except` that logs via `logging` and continues,
always attempts `netinfo.restore_network` last, and logs a warning when it
reports a partial restore. *Regression:*
`test_stop_runs_restore_even_if_a_step_raises`, `test_stop_is_idempotent`.

**CTL-2 (documented) — `start()` has no partial-startup cleanup.** `start()`
acquires engine resources (engage_mitm, traffic/scanner/protector threads, tc,
intel sniffer) with no rollback if one fails mid-way (AGENTS.md: "failure during
partial startup triggers cleanup"). Lower risk now that `engage_mitm` returns a
bool instead of raising and the `.start()` methods self-guard; a `try: … except:
self.stop()` wrapper is a clean follow-up but deferred to keep this batch tight.

**CTL-3 (documented, cross-file) — Cross-thread UI via callbacks.** `cut_device`'s
worker thread and the scan thread call the `log=` callback (`Dashboard.
log_tactical` → `status_box.insert`), and `on_protection_alert` is invoked from
the protector's sniffer threads. Tkinter is not thread-safe. The controller is
only invoking a supplied callback; the marshalling fix (`after()`/queue) belongs
in `ui/dashboard.py` and is tracked there for the Phase-2 UI pass.

**CTL-4 (documented) — Optimistic cut state vs `arp.cut` result.** `cut_device`
sets `dev.cut=True`/`status="cut"`/`traffic.mark_cut` before the worker runs; if
`arp.cut` returns False the device stays shown as CUT. The dangerous "shows CUT
but nothing happened" case is already prevented (an unknown IP fails the
`devices.get` guard first); the residual is a cosmetic log mismatch
("resolution failed" while the L1 DROP is actually in place). Ties into ARP-3;
an `arp.cut` result enum (FULL/DROP-ONLY/FAILED) is the clean cross-file fix.

**CTL-5 (documented) — Unbounded background threads.** Each scan spawns a recon
thread (`asyncio.run`, 5 s grace) and a fingerprint thread per device, plus a
thread per cut. They are daemon and self-terminating (no leak), but uncapped;
a shared executor is an architecture improvement for Phase 4/7.

Verification (controller batch):
`pytest -q` → **33 passed** (+2) · `ruff check` / `ruff format` on changed
files → clean · `mypy core/controller.py` → clean.

**Limits (controller):** CTL-1 is proven with mocked subsystems — it verifies
the control flow (restore always runs, exactly once). It does not prove the real
teardown sequence against a live kernel. CTL-2–5 remain open as documented.

---

### `system/iptables_manager.py` — RESOLVED (3 fixed, test hygiene) + 2 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| IPT-1 | Medium | `add_accounting` / `add_drop` | **Fixed** |
| IPT-2 | Medium | `add_accounting` / `add_drop` | **Fixed** |
| IPT-5 | Medium | `_ipt` (missing binary) | **Fixed** |
| IPT-4 | — | existing tests mutate real host | **Fixed** (test hygiene) |
| IPT-3 | Low | `remove_accounting` retry asymmetry | Documented |
| IPT-win | Medium | `_ipt` Windows fake success | Documented (systemic) |

**Usage note:** grep confirms only `add_accounting` (controller scan) and
`cleanup` (controller stop) are called by the app. `add_drop`/`remove_drop`/
`is_dropped` are **dead** — `network/arp.py` applies its own FORWARD DROP. The
DROP half was hardened for consistency but is a Phase-4/7 removal candidate (a
header note now says so). Rule ordering is **clean**: ACCEPT is `-A` (appended),
DROP is `-I FORWARD 1` (prepended), so DROP always precedes ACCEPT — correct for
first-match-wins.

**IPT-1 — Insert exit code ignored → stale state + silent failure.**
`add_accounting`/`add_drop` checked `-C` to decide whether to insert, but never
checked the `-A`/`-I` result; they recorded the IP in `_accounting`/`_dropped`
regardless, so a failed rule insert was invisible (AGENTS.md: "do not assume a
command succeeded"). *Fix:* both now check the insert result, log via `logging`
on failure, and return a success `bool`. The IP is still tracked for cleanup
even on partial failure (so a rule that *did* apply is still removed; `-D` is
harmless when absent). *Regression:* `test_add_accounting_reports_insert_failure`,
`test_add_accounting_success_when_rule_present`, `test_add_drop_reports_insert_failure`.

**IPT-2 — No IP validation before root commands.** IPs flowed straight into
`iptables` with no `ipaddress` check. *Fix:* `_valid_ip()` guard; `add_accounting`
/`add_drop` return False and issue no command on invalid input. *Regression:*
`test_add_accounting_rejects_invalid_ip`, `test_add_drop_rejects_invalid_ip`.

**IPT-5 — `_ipt` raised on a missing binary.** `_ipt` ran `subprocess.run(["iptables",…])`
with no guard, so a host without the iptables binary would raise
`FileNotFoundError` up through `controller.scan`. *Fix:* catch
`OSError`/`SubprocessError`, log, and return a `returncode=1` CompletedProcess so
callers degrade. *Regression:* `test_ipt_handles_missing_binary`.

**IPT-4 — Test hygiene (fixed).** The existing `test_iptables_manager.py` issued
**real** `iptables` commands on Linux (the "no-op off Linux" comment was wrong on
a Linux host) — deterministic only because non-root made them fail. Added an
autouse fixture stubbing `_ipt`, so they no longer touch host state and pass
regardless of privilege.

**IPT-3 (documented) — Asymmetric duplicate removal.** `remove_drop` retries 3×
to clear duplicate DROP rules; `remove_accounting` is single-pass. Duplicates
can only arise under a `-C`/`-A` race, and `add_accounting` is called serialized
under `controller._lock`, so the risk is low. Noted, not fixed.

**IPT-win (documented, systemic) — Windows fake success.** `_ipt` returns
`returncode=0` on Windows, so `add_*` "succeed" while applying nothing (silent
no-op that "pretends to work"). This is the cross-platform inconsistency also
seen in ARP-5 / `tc_manager`; making Windows *explicitly* unsupported is a
systemic decision for Phase 4/6, not a point fix here.

Verification (iptables batch):
`pytest -q` → **39 passed** (+6 new, 3 existing isolated) · `ruff check` /
`ruff format` on changed files → clean · `mypy system/iptables_manager.py` → clean.

**Limits (iptables):** proven with a stubbed `_ipt` — verifies the success/
failure signal, validation, and missing-binary degradation. Does not prove real
FORWARD rule insertion/ordering on a live kernel.

---

### `core/protector.py` — RESOLVED (2 fixed) + 4 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| PROT-1 | Medium | `_self_healing_sentry` | **Fixed** |
| PROT-4 | Medium | `enable_arp_guard` | **Fixed** |
| PROT-2 | Medium | alert callbacks from sniffer/sentry threads | Documented (cross-file → dashboard) |
| PROT-3 | Medium | kill-switch self-undo | Documented (design) |
| PROT-5 | Low | reputation dict unbounded / lockless | Documented |
| PROT-6 | Low | `start()` re-entry vs winding-down threads | Documented |

**PROT-1 — Sentry IndexError on malformed `/proc/net/arp` lines aborts the scan.**
`_self_healing_sentry` did `parts = line.split(); if parts[0] == gateway: if
parts[2] != "0x6"` with no length check. A blank/truncated line → `parts[0]`
IndexError, swallowed by the surrounding `except Exception: pass` — which breaks
out of the whole `for` loop, so any malformed line *before* the gateway row
means the gateway lock isn't checked that cycle. *Fix:* extracted the parse into
`_gateway_is_unlocked(arp_text)` that skips short lines (`len(parts) < 3:
continue`); the sentry reads the file (narrow `OSError`) and calls the helper.
*Regression:* `test_gateway_unlocked_handles_malformed_lines`,
`test_gateway_locked_returns_false`, `test_gateway_absent_returns_false`.

**PROT-4 — `enable_arp_guard` reports false success.** It ran `ip neigh replace`
inside a `try` and set `arp_guard_enabled = True` / returned True regardless of
the command's result, so a failed kernel lock still logged "ARP Guard ACTIVE".
It also didn't validate the gateway. *Fix:* validate gateway with `ipaddress`;
check `returncode`; only mark enabled / return True on `rc == 0`, else log and
return False. *Regression:* `test_enable_arp_guard_reports_command_failure`,
`test_enable_arp_guard_rejects_invalid_gateway`, `test_enable_arp_guard_success`.

**PROT-2 (documented, cross-file) — Cross-thread UI.** `_arp_cb` (sniffer thread)
and the sentry thread call `self.ctrl.on_protection_alert(...)`, which the
dashboard wires to `log_tactical` → `status_box.insert` (Tk). Same hazard family
as CTL-3; the marshalling fix belongs in `ui/dashboard.py`.

**PROT-3 (documented, design) — Kill-switch undoes itself.** `_trigger_kill_switch`
inserts an OUTPUT DROP ("emergency network shutdown") then calls `ctrl.stop()`,
whose `protector.stop()` → `disable_kill_switch()` immediately **removes** that
DROP. So the network is dropped then restored within one trigger — the kill
cutoff doesn't persist. Whether the network *should* stay cut (requiring manual
`iptables -D`) or be restored is a genuine design choice with user-safety
implications; not changed unilaterally. Flagged for a product decision (Phase 6/7).

**PROT-5 (documented) — `reputation` dict.** Grows one entry per observed `psrc`
(and a MAC set per entry) with no eviction; mutated only from the single sniffer
callback thread (so no race), but an unbounded slow memory growth on a busy LAN.

**PROT-6 (documented) — `start()` re-entry.** Guards `if self._running`, but
after `stop()` a fresh `start()` can spawn new monitor/sentry threads while the
previous `sniff()` loops are still winding down (up to their 30 s timeout).
Daemon threads, so no leak at exit; brief duplication only.

**Clean:** Windows handling here is explicit (sentry returns early;
`enable_arp_guard` returns False with an "not supported" log; kill-switch guards
`if not _IS_WINDOWS`) — no fake-success no-ops. Rule ordering N/A.

Verification (protector batch):
`pytest -q` → **45 passed** (+6) · `ruff check` / `ruff format` on changed
files → clean · `mypy core/protector.py` → clean.

**Limits (protector):** proven with mocked subprocess + synthetic `/proc/net/arp`
text — verifies the parse robustness and the success/failure signal, not live
kernel neighbour behaviour. Note: `_valid_ip` is now duplicated across `arp.py`,
`iptables_manager.py`, and `protector.py` — a small shared helper is a Phase-4
consolidation item.

---

### `network/traffic.py` — RESOLVED (3 fixed) + 3 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| TRAF-1 | Medium | `_read_proc` | **Fixed** |
| TRAF-2 | Low-Med | `_proc_loop` 32-bit wrap | **Fixed** |
| TRAF-4 | Low | `start()` sysctl except | **Fixed** |
| TRAF-3 | Low | `_ipt_loop` delta heuristic | Documented |
| TRAF-5 | Low | unbounded `_known_ips`/`_mac_to_ip` | Documented |
| TRAF-6 | Low | repeated start/stop thread overlap | Documented |

**TRAF-1 — Substring interface match reads the wrong counters.** `_read_proc`
did `if iface in line`, so `iface="eth0"` matched `/proc/net/dev` lines for
`veth0…`, `eth0.100` (VLAN), etc. — returning another interface's byte counters
and corrupting the interface-level speed/total. *Fix:* extracted
`_parse_iface_counters(text, iface)` that matches the name field before `:`
**exactly**; `_read_proc` reads the file (narrow `OSError`) and delegates.
*Regression:* `test_parse_iface_counters_exact_match` / `_vlan_is_distinct` /
`_absent_iface` / `_ignores_garbage`.

**TRAF-2 — 32-bit wrap assumption on 64-bit counters.** `_proc_loop` did
`if rx_d < 0: rx_d += 2**32`. `/proc/net/dev` counters are 64-bit on modern
kernels, so a genuine decrease (iface down/up reset) became a bogus ~4 GB delta
→ an absurd one-sample speed spike. *Fix:* `_counter_delta(cur, prev)` returns
`max(cur-prev, 0)` — a reset yields 0 (one sample skipped) instead of a 4 GB
spike. *Trade-off:* on a genuinely 32-bit-wrapping NIC (rare, old drivers) this
loses one ~4 GB delta per wrap, which is far better than a false 34 Gbps reading
on the common 64-bit path. *Regression:* `test_counter_delta_normal_increase`,
`test_counter_delta_reset_returns_zero_not_wrap`.

**TRAF-4 — Silent sysctl failure in `start()`.** Narrowed the broad
`except Exception: pass` around the `ip_forward` sysctl to
`OSError`/`SubprocessError` with a `logging` warning.

**TRAF-3 (documented) — `_ipt_loop` reset heuristic.** On a counter decrease it
uses `cur` as the delta (assumes it restarted from 0), a different heuristic from
`_proc_loop`. This does not produce a 2**32 spike and is arguably correct
(captures traffic since the reset), so it is left as-is; unifying the two is a
consistency nicety, not a bug.

**TRAF-5 (documented) — Unbounded maps.** `_known_ips`/`_mac_to_ip` and the
per-IP deques/totals grow with every device seen and are never evicted (no
`unregister_device`); a slow memory creep on long-lived sessions with device
churn.

**TRAF-6 (documented) — Repeated start/stop overlap.** `stop()` just flips
`_running`; a `_scapy_loop`'s `sniff(timeout=2)` can still be in flight when a
later `start()` spawns a new sniffer thread (`controller._restart_services` does
stop→start). Brief thread overlap, daemon, no leak at exit.

**Clean:** no address-before-subprocess concern here (IPs are internal dict keys;
the only subprocess, `iptables -L`/`sysctl`, takes no device IP). Windows paths
return 0/early (honest, not fake success). Deque access is consistently under
`self._lock`.

Verification (traffic batch):
`pytest -q` → **51 passed** (+6) · `ruff check` / `ruff format` on changed
files → clean · `mypy network/traffic.py` → clean.

**Limits (traffic):** parsing/delta fixes are proven with synthetic
`/proc/net/dev` text and pure-function unit tests; the live sniffer/iptables
polling loops are not exercised against real traffic.

---

### `core/persistence.py` — RESOLVED (4 fixed) + 2 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| PERS-1 | Medium | `_save` | **Fixed** |
| PERS-2 | Low-Med | `Persistence` singleton | **Fixed** |
| PERS-5 | Low | import-time `mkdir` | **Fixed** |
| PERS-6 | Low | `_load` swallows errors | **Fixed** |
| PERS-3 | Low | `save_state` iterates caller's live dict | Documented |
| PERS-4 | Low | `sync_vendor_db_bg` swallows network errors | Documented |

**PERS-1 — Non-atomic save → silent total state loss.** `_save` did
`path.write_text(json.dumps(data))`, which truncates then writes; an interrupted
or concurrent write leaves a truncated/corrupt JSON file, and `_load`'s broad
`except` then silently discards it and returns defaults — so a crash mid-save
loses all nicknames/config/state with no warning. *Fix:* serialize first, write
a `.tmp`, then `os.replace()` (atomic rename on the same filesystem); clean up
the temp and `return False`/log on failure. *Regression:* `test_save_load_roundtrip`,
`test_save_atomic_preserves_original_on_replace_failure` (original survives a
failed replace), `test_save_rejects_unserializable`.

**PERS-2 — Singleton not thread-safe.** `db` is read (`get_nickname` from the
sniffer and UI-refresh threads) and written (`set_nickname`/`save_config`) with
no lock; `json.dumps` over a dict being mutated concurrently can raise, and two
saves to one file could interleave. *Fix:* a `threading.Lock` guards the mutate+
save in `save_config`/`set_nickname`, and `_save` is handed a `dict(...)`
snapshot; the atomic `os.replace` makes concurrent saves last-writer-wins
cleanly. (The lock itself is robustness, not unit-race-tested.)

**PERS-5 — Import-time crash.** `CONFIG_DIR.mkdir(...)` ran unguarded at import,
so a read-only home crashed the whole app on `import core.persistence`. *Fix:*
wrapped in `try/except OSError` with a warning; `_save` reports failure later.

**PERS-6 — Silent corrupt-config reset.** `_load`'s `except Exception: pass`
reset a corrupt/unreadable file to defaults with no trace. *Fix:* narrowed to
`OSError`/`ValueError` and logs a warning naming the file. *Regression:*
`test_load_corrupt_returns_default`, `test_load_missing_returns_default`.

**PERS-3 (documented) — `save_state` now snapshots** the devices dict
(`list(devices.items())`) so a concurrent mutation can't raise mid-build; the
caller (`controller`) still owns the dict's locking.

**PERS-4 (documented) — `sync_vendor_db_bg`** swallows network/update errors in
a daemon thread; acceptable for an optional OUI refresh, noted for completeness.

**Clean:** no subprocess / iptables / address-to-command concerns here (pure
data + JSON). `_load` defaults are fresh objects per call (no shared-mutable-
default bug). MAC bit checks (`is_private_mac`/`is_stealth_mac`) are length-
guarded.

Verification (persistence batch):
`pytest -q` → **56 passed** (+5) · `ruff check` / `ruff format` on changed
files → clean · `mypy core/persistence.py` → clean.

**Limits (persistence):** atomicity is verified by forcing `os.replace` to fail
and asserting the original file survives — the true crash-mid-write case can't
be unit-tested without killing the process, but `os.replace` is atomic by
contract on POSIX. The thread-lock (PERS-2) is not race-tested.

---

### `network/dns_spoof.py` — RESOLVED (3 fixed) + 2 documented

*Offensive module — fixes are reliability/cleanup only, not spoof effectiveness
(per the session scope).*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| DNS-1 | Medium | `start_spoof` / `stop_spoof` | **Fixed** |
| DNS-2 | Medium | `start_spoof` (-I) / `stop_spoof` (-D) | **Fixed** |
| DNS-5 | Low | `_running` set outside lock | **Fixed** |
| DNS-4 | Low | sniff thread lingers after per-target stop | Documented |
| DNS-6 | Low | Windows silent no-op | Documented (systemic) |

**DNS-1 — No IP validation before root iptables.** `target_ip` flowed straight
into `iptables -t nat -I PREROUTING -s <ip>`. *Fix:* `_valid_ip()` guard;
`start_spoof` returns False and issues no command on invalid input. *Regression:*
`test_start_spoof_rejects_invalid_ip`.

**DNS-2 — Duplicate NAT REDIRECT rule leak.** `start_spoof` ran `-I` with no
`-C` check, so a repeated start stacked identical PREROUTING rules; `stop_spoof`
did a single `-D`, removing only one → the rest leaked past cleanup. *Fix:*
`-C` guard before `-I` (idempotent add); `stop_spoof` loops `-D` (up to 3×) to
clear duplicates; both check/ log the result and narrow the except. *Regression:*
`test_start_spoof_checks_before_insert`, `test_stop_spoof_clears_duplicate_rules`.

**DNS-5 — `_running` race.** It was set outside the lock, so two concurrent
`start_spoof` calls could each start a sniff thread. *Fix:* decide `start_thread`
and set `_running` under the lock; start the thread after releasing it.

**DNS-4 (documented) — Lingering sniffer.** `stop_spoof` for the last target
doesn't stop the single shared sniff thread (only `stop_all` does); it idles
harmlessly (the callback early-returns on an empty map) until shutdown.

**DNS-6 (documented, systemic) — Windows.** No `_IS_WINDOWS` guard; on Windows
the iptables calls now fail into the narrowed `except` (logged, no crash) — a
silent no-op, same cross-platform class as IPT-win / ARP-5.

**Reachability note:** `controller.toggle_dns_spoof` can *start* this, but no UI
control is wired to it (p1), so `start_spoof` is currently unreachable;
`stop_spoof`/`stop_all` *are* reached (restore paths). Fixed for correctness and
in case it is wired later. `_valid_ip` is now a 4th copy — Phase-4 dedupe item.

Verification (dns_spoof batch):
`pytest -q` → **59 passed** (+3) · `ruff check` / `ruff format` on changed
files → clean · `mypy network/dns_spoof.py` → clean.

**Limits (dns_spoof):** proven with mocked iptables + a stubbed sniff loop —
verifies validation, the -C/-I idempotency, and the -D duplicate retry, not real
NAT redirection or DNS interception on a live host.

---

### `network/recon_engine.py` — RESOLVED (4 fixed) + 2 documented

*Reliability only (recon is best-effort intel) — connection cleanup + input
validation, not recon accuracy.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| RECON-1 | Medium | `get_ssl_cert_cn` | **Fixed** |
| RECON-2 | Medium | `get_upnp_friendly_name` | **Fixed** |
| RECON-4 | Low-Med | `run_recon` | **Fixed** |
| RECON-10 | Low | `get_event_loop()` | **Fixed** |
| RECON-5 | Low | `get_ipv6_neighbor` uncorrelated result | Documented |
| RECON-7 | Low | fragile DER byte-scan | Documented |

**RECON-1 — SSL probe leaks the connection on error.** `get_ssl_cert_cn` called
`writer.close()` only after `getpeercert()` succeeded; any exception (e.g.
`ssl_obj` is None → AttributeError) hit `except: return ""` and left the opened
connection unclosed. Recon runs per device per scan, so this leaks a socket on
every failed probe. *Fix:* `try/finally` closes the writer on all paths (and
guards `ssl_obj` being None). *Regression:* `test_ssl_cert_cn_closes_writer_on_error`.

**RECON-2 — UPnP probe leaks a connection per failed port.** Same pattern,
inside a 3-port loop: a read/parse failure skipped `writer.close()` and
`continue`d to open the next port. *Fix:* per-iteration `writer = None` +
`finally` close. *Regression:* `test_upnp_closes_every_writer_on_error`.

**RECON-4 — No target validation in `run_recon`.** Only `get_ptr_record`
validated its inputs; ssl/upnp/netbios would try to connect to a garbage host
(triggering DNS lookups). *Fix:* `ipaddress.ip_address(ip)` guard at the top of
`run_recon`, returning the empty result dict on failure. *Regression:*
`test_run_recon_rejects_invalid_ip`.

**RECON-10 — Deprecated `get_event_loop()`.** Two `asyncio.get_event_loop()`
calls (inside running coroutines) replaced with `asyncio.get_running_loop()` —
`get_event_loop()` is deprecated and breaks on Python 3.14 (this host) when no
loop is current.

**RECON-5 (documented) — `get_ipv6_neighbor` returns the wrong neighbor.** It
returns the first `ip -6 neigh` line's address with no correlation to the target
(the comment admits "this logic would match MAC…" but doesn't). The resulting
`ipv6_ll` field is **not consumed by `classify_device`**, so the wrong value is
inert — documented, not fixed (a real correlation would be a recon-accuracy
change, out of scope).

**RECON-7 (documented) — Fragile DER scan.** `get_ssl_cert_cn` locates the CN by
ad-hoc byte offsets rather than parsing the certificate; accuracy issue, not
reliability.

**Clean:** `get_netbios_name` closes its transport in `finally` correctly;
subprocess probes (`dig`, `ip -6 neigh`) use arg lists and degrade on a missing
binary; the per-call semaphore is intentional (fresh loop per thread).

Verification (recon batch):
`pytest -q` → **62 passed** (+3) · `ruff check` / `ruff format` on changed
files → clean · `mypy network/recon_engine.py` → clean.

**Limits (recon):** leak fixes proven with a mocked `open_connection` whose
writer records `close()`; validation proven with a mocked transport. Real TLS/
UPnP/NetBIOS probing against live hosts is not exercised.

---

### `network/scanner.py` — RESOLVED (2 fixed) + 3 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| SCAN-3 | Medium (security) | `_fetch_upnp_friendly` | **Fixed** |
| SCAN-2 | Low-Med | `_merge_host` | **Fixed** |
| SCAN-1 | Low | `resolve_hostname` negative cache | Documented |
| SCAN-4 | Low | module thread pools never shut down | Documented |
| SCAN-5 | Low | IPv4-only discovery / nmap rc unchecked | Documented |

**SCAN-3 — Untrusted SSDP LOCATION fetched with any URL scheme (SSRF / local
file read).** `_passive_sniff` extracts the `LOCATION` header from an SSDP packet
— fully attacker-controlled by any device on the LAN — and `_fetch_upnp_friendly`
passed it straight to `urllib.request.urlopen`. `urllib` honours `file://`, so a
rogue `LOCATION: file:///etc/passwd` makes the **root** scanner read local files
(and any `http://internal-host/...` enables SSRF to internal services). *Fix:*
`urlparse(location_url).scheme not in ("http", "https")` → return before
fetching. *Regression:* `test_upnp_fetch_rejects_file_scheme`,
`test_upnp_fetch_allows_http_scheme`.

**SCAN-2 — Loose IP validation in `_merge_host`.** The `^\d+\.\d+\.\d+\.\d+$`
regex accepts out-of-range octets (`192.300.1.1`), so malformed `arp`/scapy rows
became bogus Device entries. *Fix:* validate with `ipaddress.ip_address`, require
IPv4 unicast, reject the unspecified address and first-octet ≥ 224 (preserving
the old multicast/broadcast cutoff). *Regression:* `test_merge_host_rejects_invalid_octets`
(+ IPv6/multicast/valid behaviour pinned).

**SCAN-1 (documented) — Sticky negative hostname cache.** `resolve_hostname`
caches a failed lookup as `""` permanently, so a device whose name becomes
resolvable later (late PTR/mDNS) is never retried. Not changed: dropping the
negative cache would re-hammer nmap/avahi each scan — a discovery-tuning
trade-off, not a reliability bug.

**SCAN-4 (documented) — Thread pools never shut down.** `_hn_pool`/`_guess_pool`
/`_upnp_pool` are module-level `ThreadPoolExecutor`s with no `shutdown()`; the
interpreter's atexit join handles process exit, so no hang, but they are not
owned by any lifecycle.

**SCAN-5 (documented) — Scope / best-effort.** Discovery is IPv4-only
(`_merge_host` rejects IPv6 by design); nmap/scapy/arp layers swallow errors and
don't check nmap's return code (a failed nmap silently yields no hosts, with the
scapy/arp layers as the safety net).

**Clean:** subprocess calls (nmap/avahi/arp) use arg lists with timeouts;
`guess_identity_from_ports` closes its probe sockets via `with`; `_hn_cache`
access is consistently under `_hn_lock`; Windows `arp -a` branch is explicit.

Verification (scanner batch):
`pytest -q` → **68 passed** (+6) · `ruff check` / `ruff format` on changed
files → clean · `mypy .` → no issues (49 files). (Repositioned a pre-existing
`# type: ignore[arg-type]` on the scapy `srp` call that `ruff format` had
detached from its line.)

**Limits (scanner):** the scheme guard and `_merge_host` validation are pure-
function/mocked-`urlopen` tests; live SSDP/nmap/ARP scanning is not exercised.

---

### `network/ipv6.py` — RESOLVED (1 fixed) + 3 documented

*Offensive module — the fix is restoration/collateral-reduction, not hijack
effectiveness (per session scope).*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| IPV6-1 | Medium | `stop()` | **Fixed** |
| IPV6-5 | Low | `_dhcp_sniff._cb` | Documented |
| IPV6-7 | Low | unguarded scapy import | Documented |
| IPV6-6 | Low | no Windows/iface awareness | Documented |

**IPV6-1 — No route withdrawal on stop (network-state drift).** `_ra_loop`
advertises the host as the default IPv6 router with `routerlifetime=1800` to
`ff02::1` (all nodes), but `stop()` only set `_running=False`. Targets therefore
keep the **bogus default route for up to 30 minutes** after the operator stops —
the IPv6 equivalent of the ARP restore gap (NET-1/ARP-1), and the codebase
already does the analogous cleanup in `arp._send_restore`. *Fix:* `stop()` now
calls `_withdraw_ra()` (only if it was running), sending a `routerlifetime=0` RA
with a zero-lifetime prefix so targets drop the route immediately. *Regression:*
`test_stop_sends_withdrawal_ra` (asserts `routerlifetime == 0`),
`test_stop_when_not_running_sends_nothing`.

**IPV6-5 (documented) — Sniffer teardown on a malformed packet.**
`_dhcp_sniff._cb` reads `pkt[Ether].src` / `pkt[IPv6].src` outside its try; a
Solicit without an Ether/IPv6 layer raises out of the callback, which the outer
loop catches and restarts (losing ≤10 s of sniffing). Self-healing, low impact.

**IPV6-7 (documented) — Unguarded scapy import.** Unlike `arp`/`traffic`,
`ipv6.py` imports scapy at module top with no `SCAPY_OK` fallback; a missing
scapy would fail the whole app's import. Acceptable since scapy is a required
dependency, noted for consistency.

**Clean:** no subprocess / iptables / address-to-command concerns (pure scapy,
static documentation prefix `2001:db8:1::` and `fe80::1`); `start()`/`stop()`
are idempotent; threads are daemon.

Verification (ipv6 batch):
`pytest -q` → **70 passed** (+2) · `ruff check` / `ruff format` on changed
files → clean · `mypy network/ipv6.py` → clean. (`ruff format` normalized the
whole file, which was in the pre-existing unformatted WIP.)

**Limits (ipv6):** the withdrawal RA is verified with a mocked `sendp` (asserts
the packet shape); it is **not** verified that a real target actually drops the
route — that needs a root Linux host + an IPv6 lab, unavailable here.

---

### `network/deauth.py` — RESOLVED (2 fixed) + 3 documented

*Offensive module — these are lifecycle/state-management fixes, not deauth
effectiveness.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| DEAUTH-1 | Medium | `_pmf_loop` / `start_pmf_bypass` | **Fixed** |
| DEAUTH-2 | Low-Med | `start_pmf_bypass` | **Fixed** |
| DEAUTH-3 | Low | `_enable_monitor` dead code | Documented |
| DEAUTH-5 | Low | `_stops` / `stop(ip)` vestigial | Documented |
| DEAUTH-6 | Low | `DEAUTH_INTERVAL`/`BURST_COUNT` unused | Documented |

**DEAUTH-1 — Worker dies after first drain and never restarts.** `_pmf_loop`
did `while self._running: … if not targets: break` but never set `_running =
False` on that break. After `stop_pmf_bypass` emptied `_targets`, the thread
exited with `_running` still True, so `start_pmf_bypass`'s `if not self._running`
guard never spawned a new worker — **deauth silently stopped working for the rest
of the session.** *Fix:* the loop now marks `_running = False` under the lock
when targets drain (and returns), `start_pmf_bypass` decides start/running
atomically under the lock, and `stop_all` sets `_running = False` to stop the
loop promptly. *Regression:* `test_pmf_loop_resets_running_when_no_targets`,
`test_start_pmf_bypass_restarts_after_drain`.

**DEAUTH-2 — `start_pmf_bypass` ignored `_active`.** It guarded on iface/bssid
but not `SCAPY_WIFI_OK`, so with scapy's `Dot11` layer unavailable it spawned a
worker that immediately crashed building `RadioTap()/Dot11()` (both `None`),
leaving `_running` stale-True. *Fix:* early `if not self._active: return`.
*Regression:* `test_start_pmf_bypass_noop_when_scapy_wifi_unavailable`.

**DEAUTH-3/5/6 (documented) — Dead/vestigial.** `_enable_monitor` is never
called (the loop assumes the iface is already in monitor mode); the `_stops`
dict is never populated so `stop(ip)` is a no-op (the real per-target stop is
`stop_pmf_bypass(target_mac)`, which `arp.restore` also calls); `DEAUTH_INTERVAL`
and `BURST_COUNT` are unused (the loop hardcodes `count=5` and `time.sleep(1)`).
Removal candidates for Phase 4/7; left in place (cross-file callers).

**Clean:** MAC/BSSID inputs go into scapy Dot11 frames, not subprocess (no
address-to-command concern); packet-send is wrapped in try/except; threads are
daemon; `_active`/`is_available` correctly reflects scapy+bssid+iface.

Verification (deauth batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **73 passed** (+3); `ruff check .` → clean; `ruff format --check .` → 22
pre-existing WIP would reformat, **my 2 files clean**; `mypy .` → no issues
(51 files). No newly-introduced error at commit time.

**Limits (deauth):** lifecycle fixes verified with a stubbed `threading.Thread`
and a synchronous `_pmf_loop` call — no real 802.11 frames sent, no monitor-mode
interface exercised (needs root + a monitor-capable NIC + a lab).

---

### `network/xdp_engine.py` — RESOLVED (3 fixed) + 1 documented

*Offensive drop layer — cleanup/validation only, not drop effectiveness.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| XDP-1 | Medium | `unload()` | **Fixed** |
| XDP-2 | Low | `add_drop` / `remove_drop` | **Fixed** |
| XDP-5 | Low | `load()` partial failure | **Fixed** |
| XDP-3 | Low | swallowed map errors | Fixed (now logged) |

**XDP-1 — `unload()` not crash-safe → XDP program left on the NIC.** It called
`self._bpf.remove_xdp(self.iface, 0)` unwrapped and set `_loaded=False`
*afterwards*. If `remove_xdp` raised (bcc error, iface gone), the exception
propagated and `_loaded` stayed True — the XDP program remained attached to the
interface and `unload()` was not idempotent (a second call would retry the
raising detach). *Fix:* wrap `remove_xdp` in `try/except` with a `finally` that
always sets `_loaded=False` and `_bpf=None`, logging the failure (noting the
program may remain attached). `controller.stop()`'s per-step isolation (CTL-1)
already contained the propagation; this makes the engine itself safe/idempotent.
*Regression:* `test_unload_is_safe_and_idempotent_when_remove_raises`,
`test_unload_clears_state_on_success`.

**XDP-2 — Lenient key parsing.** `add_drop`/`remove_drop` built the eBPF `__be32`
map key with `socket.inet_aton`, which accepts non-dotted-quad forms (`"1.2.3"`
→ `0x01020003`), producing a key that never matches real packet IPs (a silent
no-op drop). *Fix:* `_key()` uses `ipaddress.IPv4Address(ip).packed`, rejecting
anything that isn't a proper dotted-quad IPv4 and logging the rejection.
*Regression:* `test_add_drop_rejects_non_dotted_quad`,
`test_add_drop_valid_ipv4_uses_packed_key`.

**XDP-5 — Half-built BPF on load failure.** `load()` left `self._bpf` set if
`attach_xdp` failed after the program loaded. *Fix:* reset `_bpf=None`/
`_loaded=False` in the `except`.

**XDP-3 — Swallowed errors now logged.** `add_drop`'s map-set failure (e.g. the
256-entry map full) was silently swallowed; it now logs a warning (the real cut
is still backed by iptables + ARP).

**Clean:** Windows degrades honestly — `load()` returns False when bcc is absent,
and every op guards on `_loaded`, so nothing fakes success. `add_drop` ×257 is
the only functional limit (map `max_entries` 256), documented not fixed.

Verification (xdp batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **78 passed** (+5); `ruff check .` → clean; `ruff format --check` my 2 files →
clean (pre-existing WIP still dirty, not mine); `mypy .` → no issues (52 files).
No newly-introduced error at commit time.

**Limits (xdp):** verified with a **fake BPF object** (dict-backed map, a
`remove_xdp` that raises on demand) — no real eBPF program, kernel attach, or
packet drop is exercised (needs root + BCC/clang + kernel headers + a lab NIC).

---

### `network/mdns_sniff.py` — RESOLVED (1 fixed) + 2 documented

*Passive mDNS parser (no subprocess/threads/state). Empirically verified scapy
2.8 behaviour before asserting: `dns.qd` is a list, TXT `rdata` is a list.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| MDNS-4 | Low-Med | QD loop | **Fixed** |
| MDNS-1 | Low | `pkt[IP]` only | Documented |
| MDNS-5 | Low | TXT `rdata` detection dead | Documented |

**MDNS-4 — QD loop trusts the attacker-influenced `qdcount` header.** The loop
ran `for i in range(dns.qdcount)` and indexed `dns.qd[i]`. `dns.qd` is the
dissected record **list**, so: (a) an inflated `qdcount` (up to 65535) wastes
thousands of caught `IndexError`s per packet (~0.4 s measured for 65535) — a
minor LAN DoS on the sniffer thread; (b) a `qdcount` that **under-reports** the
carried records silently drops them. *Fix:* iterate the actual `dns.qd` list
(normalised to a list) instead of `range(qdcount)`. *Regression:*
`test_qd_iterates_actual_records_not_qdcount` (a packet with `qdcount=1` but two
questions — old code parsed only one), `test_inflated_qdcount_parses_without_error`.

**MDNS-1 (documented) — IPv4-only.** `ip = pkt[IP].src if haslayer(IP) else
None`, so mDNS over IPv6 (`ff02::fb`) is dropped. The sibling passive sniffer in
`scanner.py` reads both. Not expanded — reading the IPv6 source would broaden
recon attribution (an effectiveness change), left as a documented scope gap.

**MDNS-5 (documented) — Dead TXT model detection.** The `model=iphone/appletv/
macbook` TXT check is guarded by `isinstance(rdata, bytes)`, but scapy TXT
`rdata` is a **list**, so the branch never runs. Making it work is a recon-
accuracy improvement (out of scope); documented as latent dead code.

**Clean:** no subprocess/iptables/threads/address-to-command here; the answer-
record loop already walks the real record chain (bounded) and is exception-
guarded; callback exceptions are contained per record.

Verification (mdns batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** (scapy import uses a targeted
`# type: ignore[attr-defined]`, justified by scapy's dynamic `scapy.all`), then
full gates — `pytest -v` → **80 passed** (+2); `ruff check .` → clean;
`ruff format --check` my 2 files → clean; `mypy .` → no issues (53 files).

**Limits (mdns):** verified with hand-built scapy packets exercising the parse —
not against live multicast mDNS traffic.

---

### `system/stealth.py` — RESOLVED (2 fixed) + 3 documented

*Evasion module. The cloak (`engage_mirage_cloak`) is left functionally
unchanged (scope + AGENTS.md). Only `disengage_stealth` — which restores the
REAL identity, the un-cloak/safe direction — is fixed.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| STEALTH-1 | Medium | `disengage_stealth` | **Fixed** |
| STEALTH-2 | Medium | `disengage_stealth` | **Fixed** |
| STEALTH-5 | Low | disengage doesn't reconnect wifi | Documented |
| STEALTH-6 | Low | engage `sleep(1)` blocks caller | Documented (UI-layer) |
| STEALTH-7 | Low | Windows false success | Documented (systemic) |

**STEALTH-1 — Partial un-cloak on any failure.** `disengage_stealth` ran the
hostname restore, the MAC restore, and the nft-table removal in **one** `try`
with `check=True`. A failing `hostnamectl set-hostname` raised and skipped the
MAC restore and firewall removal — leaving the host with the **spoofed MAC and
the stealth-drop firewall still active** (which silently drops inbound traffic).
Same partial-restoration class as CTL-1/NET-1. *Fix:* each step runs in isolation
via a `_run()` helper that checks the return code and logs; one failure no longer
blocks the others. *Regression:*
`test_disengage_restores_mac_and_firewall_even_if_hostname_fails`.

**STEALTH-2 — False success.** It returned `"[IDENTITY RESTORED]"`
unconditionally (the except swallowed failures and fell through to the same
return), so the controller/UI logged a successful un-cloak even when the MAC was
still spoofed. *Fix:* return `"[IDENTITY RESTORED]"` only when the
identity-critical restores (hostname + MAC) all succeeded, else
`"[IDENTITY RESTORE INCOMPLETE]"`. The nft-table removal is best-effort (its
absence — cloak never fully engaged — is not a failure). *Regression:*
`test_disengage_reports_success_when_all_ok` (+ the INCOMPLETE assertion above).

**STEALTH-5 (documented) — No wifi reconnect on disengage.** `engage` reconnects
wifi after the MAC change (`nmcli dev wifi connect`), but `disengage` restores
the MAC without reconnecting, so un-cloaking can leave wifi disassociated.
Reconnecting needs the SSID (not captured at disengage) — a functional gap, not
fixed here.

**STEALTH-6 (documented, UI-layer) — Blocking caller.** `engage_mirage_cloak`'s
`time.sleep(1)` plus the ip/nmcli/nft subprocesses run on whatever thread calls
`toggle_stealth` — the protection panel calls it on the Tk thread, freezing the
UI. The marshalling fix belongs in the UI layer (same family as CTL-3/PROT-2).

**STEALTH-7 (documented, systemic) — Windows.** hostnamectl/ip/nmcli/nft are
Linux-only; on Windows they fail into the caught except and the functions return
their success strings regardless (false success) — the cross-platform class seen
in IPT-win/ARP-5/DNS-6.

**Not touched (scope):** `engage_mirage_cloak` — the MAC/hostname spoof + nft
stealth-drop setup. Its steps are already isolated in separate try blocks; its
"[CLOAKED AS …]" return is evasion feedback, deliberately left as-is.

Verification (stealth batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **82 passed** (+2); `ruff check .` → clean; `ruff format --check` my 2 files →
clean; `mypy .` → no issues (54 files).

**Limits (stealth):** un-cloak restoration verified against a mocked
`subprocess` (asserts each step is attempted and the status is truthful) — not
that a real NIC's MAC/hostname/nft table actually revert (root + Linux + manual).

---

### `system/tc_manager.py` — RESOLVED (3 fixed) + 2 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| TC-1 | Medium | `limit()` | **Fixed** |
| TC-2 | Low | `limit()` | **Fixed** |
| TC-6 | Low | `teardown()` | **Fixed** |
| TC-3 | Low | `init()` / `teardown()` original qdisc | Documented |
| TC-win | Low | Windows fake success | Documented (systemic) |

**TC-1 — `limit()` always reports success.** The class `add/change` return code
only controlled the `for` loop's `break`, the fq_codel/filter results were
ignored, and `return True` fired unconditionally. So a failed `tc class` (bad
rate, qdisc not initialised) or failed u32 filter still told the controller/UI
the limit was applied ("⚡ {ip} → {kb} KB/s"). *Fix:* track `class_ok` and return
False (setting `last_error`, logging) if the class didn't apply — popping the
phantom class id so a failed limit leaves no stale state; then check both filter
return codes and return False if either failed (keeping the class id so
unlimit/teardown removes it). *Regression:*
`test_limit_returns_false_when_class_add_fails`,
`test_limit_returns_false_when_filter_add_fails`, `test_limit_returns_true_when_all_ok`,
`test_failed_class_add_does_not_leave_phantom_class`.

**TC-2 — No IP validation.** `ip` flowed into the `tc filter … match ip dst/src`
commands unvalidated. *Fix:* `_valid_ip()` guard; `limit()` returns False and
issues no command on invalid input. *Regression:* `test_limit_rejects_invalid_ip`.

**TC-6 — `teardown()` raced `_classes`.** It reset `_active`/`_classes`/`_next_id`
without the lock while `limit`/`unlimit` mutate them. *Fix:* wrap the body in
`self._lock`.

**TC-3 (documented) — Original qdisc not captured.** `init()` runs
`tc qdisc del root` before installing HTB, destroying any pre-existing *custom*
root qdisc; `teardown()`'s `del root` reverts to the kernel default
(`net.core.default_qdisc`), not whatever custom qdisc was there before. Capturing
and re-applying an arbitrary qdisc config is complex and rarely needed (most
hosts use the kernel default); left as a documented limitation.

**TC-win (documented, systemic) — Windows.** `_tc` returns rc=0 on Windows and
`init()` sets `_active=True` without running `tc`, so `limit()` returns True
doing nothing (false success). Same cross-platform class as IPT-win/ARP-5.

**Clean:** the `_tc` command construction is correct (`tc <subcmd> <action> dev
<iface> <params>`); per-IP priorities (`cid*2`/`cid*2+1`) avoid filter collisions
(a prior fix); `unlimit` removes both filters and the class; `_burst` math is
unit-tested (`test_tc_burst`).

Verification (tc batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **87 passed** (+5); `ruff check .` → clean; `ruff format --check` my 2 files →
clean; `mypy .` → no issues (55 files).

**Limits (tc):** `limit()`'s success/failure signalling and validation are proven
against a mocked `_tc` — no real HTB class/filter is installed and no actual
bandwidth is shaped (root + Linux + lab + manual).

---

### `system/masquerade.py` — RESOLVED (2 fixed) + 2 documented

*Evasion module. The mimic apply (`_engage`) is kept functionally identical; only
the disable path (`_restore` — un-masquerade, the safe direction) is fixed.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| MASQ-2 | Medium | disable restore loop | **Fixed** |
| MASQ-3 | Low | disable status | **Fixed** |
| MASQ-1 | Low | capture rc not checked | Documented |
| MASQ-6 | Low | Windows | Documented (honest, not fake) |

**Good (pre-existing):** this module **already captures the originals before
mutating** (`_ORIG` filled from `sysctl -n` on first engage), so the capture-
before-mutate principle is satisfied here.

**MASQ-2 — Partial restore on failure.** Enable and disable shared one
`for key,value in settings.items(): sysctl -w … check=True` loop. On disable, a
single failing restore raised (check=True) and **aborted the remaining restores**,
leaving the host partially masqueraded (e.g. TTL back to original but timestamps
still `0`). Same class as STEALTH-1/NET-1. *Fix:* split into `_engage()`
(unchanged evasion apply) and `_restore()`, which writes each captured original
in its own isolated `try`, checks the return code, and logs. *Regression:*
`test_restore_isolates_failures_and_reports_truthfully`.

**MASQ-3 — Untruthful restore status.** Disable returned `[DNA: NATIVE]` (or a
raised `[ERROR …]`) regardless of partial success. *Fix:* `_restore()` returns
`[DNA: NATIVE]` only when every captured original restored, else
`[DNA: RESTORE INCOMPLETE]`; `[DNA: NATIVE]` when nothing was ever masqueraded.
*Regression:* `test_restore_reports_native_when_all_ok`,
`test_restore_noop_when_nothing_captured`, and the INCOMPLETE assertion above.

**MASQ-1 (documented) — Capture rc not checked.** `_engage` reads originals with
`sysctl -n` but doesn't check the return code; a failed read stores `""`, and
`_restore` skips empty values (so that key is never restored — left at the mimic
value). Rare on a normal host (all three keys exist); the engage path is evasion
and intentionally not hardened further.

**MASQ-6 (documented) — Windows.** No `_IS_WINDOWS` guard, but `sysctl` raising
`FileNotFoundError` is caught and returns `[ERROR: STACK_SPOOF_FAIL …]` — this
module **errors honestly** on Windows rather than fake-succeeding (unlike
IPT-win/TC-win).

**Not touched (scope):** `_engage` — the Windows-mimic apply — is byte-for-byte
the original enable branch (`test_engage_still_applies_mimic_values` pins it).

Verification (masquerade batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **91 passed** (+4); `ruff check .` → clean; `ruff format --check` my 2 files →
clean; `mypy .` → no issues (56 files).

**Limits (masquerade):** restore isolation/status proven against a mocked
`subprocess` — not that the real kernel sysctls actually revert (root + Linux +
manual).

---

### `system/network_manager.py` — RESOLVED (3 fixed) + 1 documented

*Legitimate admin feature (static IP/DNS via nmcli), reachable from the
Protection panel.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| NM-1 | Medium | `apply_static_config` | **Fixed** |
| NM-2 | Medium | `apply_static_config` | **Fixed** |
| NM-3 | Low | `set_dhcp` missing `which` guard | **Fixed** |
| NM-6 | Low | Windows | Documented (honest, not fake) |

**NM-1 — Unvalidated user input into privileged nmcli.** The protection panel
collects `ip`/`gateway`/`dns` via free-text `simpledialog.askstring` and passes
them straight to `nmcli connection modify … ipv4.*`. No validation. *Fix:*
validate before any nmcli call — `ip` as a host-with-prefix
(`ipaddress.ip_interface`, e.g. `192.168.1.50/24`), `gateway` as an IP, and each
comma-separated `dns` entry as an IP; return `(False, msg)` on invalid input.
*Regression:* `test_apply_rejects_invalid_ip` / `_gateway` / `_dns`.

**NM-2 — No rollback → half-configured connection can drop the network.** The
five `nmcli … modify … check=True` steps ran in sequence; a mid-sequence failure
(e.g. the gateway step) left the connection in `ipv4.method manual` with a
partial/invalid config and never brought it up — the host could **lose
connectivity**. *Fix:* on any `CalledProcessError`/`OSError` in the sequence, log
and **revert the connection to DHCP** (`ipv4.method auto` + `connection up`) to
restore a working state, reporting `"…; reverted to DHCP"` (and a second message
if even the revert fails). Also added `capture_output=True` so nmcli doesn't
print to the console (no stray output from library code). *Regression:*
`test_apply_reverts_to_dhcp_on_mid_sequence_failure`, `test_apply_accepts_valid_config`.

**NM-3 — `set_dhcp` hardening.** Added the `shutil.which("nmcli")` guard (matching
`apply_static_config`), a `conn_name` check, `capture_output`, and a narrowed
`except (CalledProcessError, OSError)`.

**NM-6 (documented) — Windows.** `apply_static_config` returns
`(False, "nmcli not found")` via `shutil.which`; `set_dhcp` now does too. The
module **errors honestly** on Windows rather than fake-succeeding.

**Clean:** argument lists (no shell injection); `apply_static_config` already
reported failure honestly (`check=True` → error) — the gap was the missing
rollback, not false success.

Verification (network_manager batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** — this caught an **RUF059** (unused
unpacked `msg`) in the new test *before commit* (the `tests/*` ignore covers F841
but not RUF059); fixed by using `_`. Then full gates — `pytest -v` → **96 passed**
(+5); `ruff check .` → clean; `ruff format --check` my 2 files → clean;
`mypy .` → no issues (57 files).

**Limits (network_manager):** validation + the DHCP-revert control flow are proven
against a mocked `subprocess` — no real nmcli reconfiguration is performed (root +
NetworkManager + lab + manual). The revert targets DHCP, not necessarily the exact
prior config (a documented best-effort recovery).

---

### `ui/dashboard.py` — RESOLVED (2 fixed) + 1 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| DASH-1 | Medium | `log_tactical` (cross-thread Tk) | **Fixed** |
| DASH-3 | Low-Med | `ctk.TclError` (invalid attr) | **Fixed** (pre-existing) |
| DASH-2 | Low | UI-blocking toggle handlers | Documented |

**DASH-1 — Cross-thread Tk writes (the sink for CTL-3 / PROT-2).** `log_tactical`
wrote directly to the `status_box` widget (`insert`/`see`), but it is invoked
from background threads: the scan worker (`_start_scan` → `ctrl.scan(log=…)`),
the cut `_do` worker threads (`ctrl.cut_device(log=…)`), and the protector's
sniffer thread (`on_protection_alert = lambda m: log_tactical(m, "danger")`).
Tkinter is not thread-safe — concurrent widget access can corrupt the Tk state or
crash. *Fix:* `log_tactical` now only `put()`s `(timestamp, msg)` on a
`queue.Queue` (thread-safe); a UI-thread loop `_drain_log_queue()` (started in
`__init__`, reschedules via `after(200,…)`) drains the queue and performs the
only widget writes. *Regression:*
`test_log_tactical_enqueues_and_does_not_touch_widget` (asserts no direct widget
write + the message is enqueued), `test_drain_log_queue_writes_on_ui_thread_and_reschedules`.

**DASH-3 — Invalid `ctk.TclError` (pre-existing latent bug).** Three
`except (ctk.TclError, …)` clauses referenced a non-existent attribute
(`customtkinter` does not re-export `TclError`), so if a real `TclError` were
raised (widget destroyed mid-refresh), evaluating the handler would itself raise
`AttributeError` and crash the refresh/log loop instead of swallowing it.
Found while adding DASH-1's handler. *Fix:* import `tkinter.TclError` and use it
in all three clauses (`_update_row` and the new `_drain_log_queue`).

**DASH-2 (documented) — UI-thread-blocking toggles.** `_toggle_nuclear`,
`_toggle_ghost`, `_toggle_arp`, `_toggle_chameleon`, `_toggle_ipv6` call their
controller methods synchronously on the Tk thread; those run subprocesses (and
`stealth`'s `time.sleep(1)` — STEALTH-6), freezing the UI for seconds.
`_start_scan` already offloads to a thread; the toggles should too. Deferred:
threading the handlers is a broader UI change, and each would then log via the
now-thread-safe `log_tactical`. Noted for a focused UI pass.

**Clean:** `_refresh_loop`, `_make_row`, `_update_row`, `_select`, and the
`_cmd_*` handlers all run on the UI thread (via `after` or button callbacks);
`_update_row` already guards widget access with `winfo_exists()` and the (now
valid) `TclError` catch; row iteration uses `ctrl.snapshot_devices()`.

Verification (dashboard batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **98 passed** (+2); `ruff check .` → clean; `ruff format --check` my 2 files →
clean; `mypy .` → no issues (58 files). The existing headless dashboard test
(`test_dashboard_wires_…`) still passes.

**Limits (dashboard):** the marshalling is verified by calling the methods
**unbound with a fake `self`** (no Tk display/CTk instance) — it proves
`log_tactical` enqueues instead of touching the widget and that `_drain_log_queue`
writes + reschedules. It does **not** exercise a live Tk event loop under real
concurrent logging (no display available; that is manual).

---

### `system/chameleon.py` — RESOLVED (4 fixed) + 1 documented

*Evasion module. The MTU/MSS values (1492/1420) are unchanged; only restore
correctness + cleanup hygiene are fixed.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| CHAM-1 | Medium | disable MTU restore | **Fixed** |
| CHAM-2 | Medium | disable step isolation | **Fixed** |
| CHAM-3 | Low | enable `-A` (duplicate rules) | **Fixed** |
| CHAM-4 | Low | empty-iface guard | **Fixed** |
| CHAM-6 | Low | Windows | Documented (honest, not fake) |

**CHAM-1 — Hardcoded MTU restore.** Disable did `mtu = "1500"` unconditionally,
but the **original MTU was never captured** — a VPN/PPPoE (1492/1480) or jumbo
(9000) interface was clobbered to 1500 on un-obfuscate (state drift). Same class
as NET-2's hardcoded ethtool restore. *Fix:* `_engage` captures the current MTU
(`ip -o link show`) into `_ORIG_MTU[iface]` before changing it; `_restore` writes
that captured value back (falling back to 1500 only if never captured).
*Regression:* `test_disable_restores_captured_original_mtu`.

**CHAM-2 — Partial restore.** Disable set MTU with `check=True` then removed the
clamp; a MTU failure raised and skipped the clamp removal. *Fix:* `_restore`
isolates the MTU write and the clamp removal (each its own `try`, rc checked,
logged) and returns `[EVASION: RESTORE INCOMPLETE]` on partial failure.

**CHAM-3 — Duplicate mangle rules.** Enable ran `iptables … -A … TCPMSS` with no
`-C`, so a repeated engage stacked identical POSTROUTING rules; disable removed
only one. *Fix:* `-C` before `-A` (idempotent add); `_restore` loops `-D` to
clear duplicates. *Regression:* `test_enable_checks_before_adding_mss_rule`.

**CHAM-4 — Empty-iface guard.** `toggle_chameleon("", …)` would run `ip link set
dev "" …`. *Fix:* return an error before any command when `iface` is empty.
*Regression:* `test_toggle_rejects_empty_iface`.

**CHAM-6 (documented) — Windows.** `ip`/`iptables` raising `FileNotFoundError`
is caught and returns `[ERROR: CHAMELEON_FAIL …]` — honest, not fake success.

**Not touched (scope):** the MTU 1492 / MSS 1420 evasion values are unchanged —
`_engage` applies exactly what it did before, plus capture + idempotency.

Verification (chameleon batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test**, then full gates — `pytest -v`
→ **101 passed** (+3); `ruff check .` → clean; `ruff format --check` my 2 files →
clean; `mypy .` → no issues (59 files).

**Limits (chameleon):** MTU capture/restore, step isolation, and rule idempotency
are proven against a mocked `subprocess` — no real MTU change or mangle rule is
applied (root + Linux + lab + manual).

---

### `system/firewall_apex.py` — RESOLVED (1 fixed) + 2 clean/documented

*GhostFirewall — nftables stealth-drop (defensive). Only the fail-safe behaviour
is changed; the rule set is unchanged.*

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| FW-1 | Medium | `toggle_stealth` enable build | **Fixed** |
| FW-2 | — | disable path | **Clean** |
| FW-6 | Low | Windows | Documented (honest) |

**FW-1 — Partial build locks the host out (fail-unsafe).** Enable creates the
input chain with `policy drop` first, then adds `ct state established,related
accept` and `iif lo accept` (each `check=True`). If a rule add failed mid-build,
the old `except` returned `[ERROR: FIREWALL_FAIL]` but **left a drop-policy chain
without the accept rules** — the host drops all inbound traffic (incl. its
established connections), i.e. **locks itself out of its own network** — while
`self.active` stayed False, so the UI wouldn't show it as on for the user to
disable (the next toggle's leading `nft delete table` would be the only way out).
*Fix:* wrap the build; on any `CalledProcessError`/`OSError`, **roll back** by
deleting the half-built `hakai_stealth` table, set `active=False`, and return
`[ERROR: FIREWALL_FAIL - build rolled back]`. Also set `active=False` on the
outer error path, and `capture_output=True` so nft doesn't print from library
code. *Regression:* `test_enable_rolls_back_half_built_table_on_failure`
(asserts ≥2 `nft delete table` — the clean-slate one **and** the rollback),
`test_enable_success_sets_active`, `test_disable_removes_table_and_clears_active`.

**FW-2 (clean) — Disable.** The unconditional leading `nft delete table inet
hakai_stealth` removes the table on disable (and before every enable), so the
`else` branch correctly just clears `active`. The delete is **scoped to the
hakai_stealth table** — it never flushes the host's other nftables rules.

**FW-6 (documented) — Windows.** `nft` raising `FileNotFoundError` is caught and
returns `[ERROR: …]` — honest, not fake success.

**Not touched (scope):** the stealth-drop rule set (drop policy + established/lo
accept) is unchanged — only the failure handling was made fail-safe.

Verification (firewall_apex batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** (the test's fake-match condition was
corrected during authoring — `"established,related"` is a substring of one rule
arg, not a list element), then full gates — `pytest -v` → **104 passed** (+3);
`ruff check .` → clean; `ruff format --check` my 2 files → clean; `mypy .` → no
issues (60 files).

**Limits (firewall_apex):** the rollback-on-failure control flow is proven
against a mocked `subprocess` — no real nft table/chain/rule is created or
removed (root + Linux + lab + manual).

---

### `ui/info_dialog.py` — RESOLVED (1 fixed, 1 hardened) + 2 documented

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| INFO-3 | Medium | `do_fingerprint` callback | **Fixed** |
| INFO-6 | Low | ping/traceroute label update vs destroyed dialog | **Fixed** |
| INFO-1 | Low | ip not validated before ping/traceroute | Documented |
| INFO-5 | Low | ping has no subprocess timeout | Documented |

**INFO-3 — Cross-thread Tk update of the dashboard row.** `do_fingerprint`'s
`_done` runs on the fingerprint worker thread (`controller.fingerprint` →
`fingerprint_device` spawns a thread). It marshalled its own dialog-label update
via `dlg.after(0, …)`, but called `fingerprint_done_cb(ip, dev)` — the dashboard's
`_update_row` — **directly**, updating a dashboard widget off the UI thread (the
same hazard class as DASH-1/CTL-3). *Fix:* extracted `_marshal(widget, func)`
(schedules via `widget.after(0,…)`, no-op if the widget was destroyed) and
`_make_fingerprint_done(dlg, parent, rl, cb)`, which marshals the label update on
the dialog **and** the row-refresh callback on the parent window (which outlives
the dialog). *Regression:* `test_fingerprint_done_marshals_callback_not_direct`
(asserts `cb` is scheduled on `parent.after`, not called directly),
`test_fingerprint_done_without_callback_is_safe`, `test_marshal_*`.

**INFO-6 — Destroyed-dialog safety.** The ping/traceroute worker threads did
`dlg.after(0, …)`; if the user closed the dialog mid-operation, that raised
`TclError` in the daemon thread. Now routed through `_marshal`, which swallows
`TclError`/`RuntimeError`.

**INFO-1 (documented) — IP validation.** `ip` flows into `ping`/`traceroute`
(arg lists, no injection). It is a device-dict key already validated by the
scanner (`_merge_host` uses `ipaddress`), so this is low; not adding another
validation site here (Phase-4 will centralise it).

**INFO-5 (documented) — ping timeout.** `ping -c 4 -W 1` self-limits (~4 s), so
the missing subprocess-level `timeout=` is low risk; `traceroute` already has
`timeout=25`.

**Clean:** the ping/traceroute/fingerprint workers already correctly marshalled
their *own* label updates via `after` (now via `_marshal`); `do_reset_usage` runs
on the UI thread and `reset_usage` is lock-guarded.

Verification (info_dialog batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** (importing `ui.info_dialog` loads only
tkinter + theme constants, no Tk root — the helpers are unit-testable with mocks),
then full gates — `pytest -v` → **108 passed** (+4); `ruff check .` → clean;
`ruff format --check` my 2 files → clean; `mypy .` → no issues (61 files).

**Limits (info_dialog):** the marshalling helpers are unit-tested with mock
widgets; the wiring into the (Tk-closure) `do_fingerprint`/`do_ping`/
`do_traceroute` handlers is by construction (they call `_marshal`/
`_make_fingerprint_done`) — not exercised against a live Tk dialog (no display;
manual).

---

### `network/fingerprint.py` — RESOLVED (2 fixed) — mostly clean

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| FP-1 | Low-Med | `fingerprint_device` | **Fixed** |
| FP-3 | Low | broad `except Exception` | **Fixed** (narrowed) |
| FP-2 | — | cross-thread callback | **Clean** (caller marshals) |

**This file is largely clean.** It correctly runs `nmap -O -sV` in a daemon
thread and calls back; the callback contract is "runs on a worker thread", and
the callers now marshal their UI updates (DASH-1 for the log, INFO-3 for the
fingerprint row refresh). Windows degrades honestly (empty result when `nmap`
is absent). The nmap-output parsing is correct.

**FP-1 — No IP validation + always spawned a thread.** `ip` went to `nmap` with
no `ipaddress` check (it is pre-validated by the scanner, but this is the one
convention gap). *Fix:* validate **synchronously** at the top of
`fingerprint_device`; on an invalid IP, call `callback([], "", {})` and return
without spawning the worker thread or running nmap. *Regression:*
`test_invalid_ip_skips_nmap_and_returns_empty`.

**FP-3 — Broad swallow narrowed; parse extracted.** The nmap result parsing is
now a pure `_parse_nmap(stdout)` helper (unit-testable without threads/nmap), and
the worker's `except Exception: pass` is narrowed to `(OSError,
subprocess.SubprocessError)` with a debug log (TimeoutExpired is a
SubprocessError subclass, so it is still covered). *Regression:*
`test_parse_nmap_extracts_ports_services_and_os`,
`test_parse_nmap_aggressive_guess_when_no_os_details`, `test_parse_nmap_empty_output`.

Verification (fingerprint batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** — this caught an **RUF059** (unused
unpacked `svcs`) in the new test *before commit* (the `tests/*` ignore covers
F841 not RUF059); fixed with `_`. Then full gates — `pytest -v` → **112 passed**
(+4); `ruff check .` → clean; `ruff format --check` my 2 files → clean;
`mypy .` → no issues (62 files).

**Limits (fingerprint):** `_parse_nmap` is tested against captured nmap text and
the validation path is synchronous/deterministic; no real nmap scan is run
(nmap + root for `-O` + lab + manual).

---

### `network/dhcp_sniffer.py` — RESOLVED (1 fixed) — mostly clean

| ID | Sev | Location | Status |
|----|-----|----------|--------|
| DHCP-1 | Low-Med | `sniff_dhcp_os` option loop | **Fixed** |
| DHCP-2 | Low | `best_ip` not validated | Documented |

**This file is mostly clean** — pure scapy DHCP option parsing (no subprocess,
state, restoration, or Windows concern); every layer access is `haslayer`-guarded;
the `os_cb`/`hostname_cb` callbacks run on the intel-sniffer thread and only
mutate device state under the controller lock (no Tk), so cross-thread UI is the
caller's concern, not this file's.

**DHCP-1 — Malformed option aborts the parse (untrusted-input robustness).** The
loop skipped non-tuples (`isinstance(opt, tuple)`) but not **short** tuples, so a
crafted/malformed option like `("hostname",)` made `opt[1]` raise `IndexError`.
DHCP is untrusted LAN broadcast input, and the exception propagated out of
`sniff_dhcp_os` into the controller's intel-sniffer loop, whose broad `except`
would restart the whole sniffer (losing a window of DHCP/mDNS/recon). *Fix:* also
skip options with `len(opt) < 2`. *Regression:*
`test_malformed_short_option_does_not_abort_parse` (valid options after the
malformed one are still parsed), `test_valid_hostname_and_os_parse`.

**DHCP-2 (documented) — `best_ip` not validated.** A crafted `requested_addr`
could put a garbage string in `best_ip`, which flows to the by-IP pending-name
map — but the hostname is also applied by MAC (the reliable path) and a garbage
IP key never matches a real device, so it is inert. Not fixed.

Verification (dhcp_sniffer batch, per updated p2.md):
per-file `ruff`/`mypy` on **src + test** (scapy import uses a targeted
`# type: ignore[attr-defined]`), then full gates — `pytest -v` → **114 passed**
(+2); `ruff check .` → clean; `ruff format --check` my 2 files → clean;
`mypy .` → no issues (63 files).

**Limits (dhcp_sniffer):** the parser is exercised with a fake packet carrying
the exact option structures; real wire DHCP dissection (where scapy normally
produces well-formed 2-tuples) is not exercised.

---

### Sweep: `oui_lookup.py`, `device.py`, `limit_dialog.py` — CLEAN; `protection_panel.py` — 1 documented

Four small files reviewed together. Three are clean; no code changed (nothing
confirmed-buggy with a clean test seam), so this entry records the review.

**`network/oui_lookup.py` — CLEAN.** `get_vendor`/`is_randomized` are pure and
length-guarded (empty/short MAC → `"Unknown Device"`, no crash); no subprocess,
state, restoration, or cross-thread concern. *Nit (not a bug):* `OuiLookup()` is
instantiated per call, but only when the optional `ouilookup` package is
installed (it isn't in this env, so the branch is skipped). Duplicate OUI stack
vs `persistence` is tracked in the Phase-3 tribunal (Phase-4 dedupe), not here.

**`core/device.py` — CLEAN.** Pure data model. `update_history` appends and pops
`rx_history`/`tx_history` together (never desyncs); `to_state` is JSON-serializable
(port keys stringified); the `nickname` property is a dict read. Mutated under the
controller lock and read on the UI thread — no race.

**`ui/limit_dialog.py` — CLEAN.** `_apply` already validates the bandwidth input
(`int(sv.get())` guarded against `TclError`/`ValueError`, rejects `kb <= 0` before
calling `tc`) — a prior fix (commit c6bfe88). Runs on the UI thread; no bugs.

**`ui/protection_panel.py` — PP-1 (Low, documented): UI-thread-blocking.**
`toggle_stack`, `toggle_chameleon`, and `update_btns` run `subprocess.run`
(`sysctl`, `ip link show`) **synchronously on the Tk thread** (lines ~116/130/
153/159) to read current state, and the `ctrl.toggle_*` / `apply_static_config`
button handlers run their privileged subprocesses synchronously too — so the
modal freezes for the duration. Same class as DASH-2 / STEALTH-6. Not a crash or
data bug, and all on the UI thread (no cross-thread hazard — `log_cb` is the now
thread-safe `log_tactical`). *Deferred:* the fix (offload the handlers to worker
threads and marshal the widget-state refresh back via `after`) is a broad
multi-handler change across closures with no clean unit-test seam; grouped with
DASH-2 for a focused UI-threading pass. Also noted: the state detection reads the
OS (`"128" in sysctl output`, `"mtu 1492" in ip output`) rather than tracking
app state, which is fragile (false-positive if the host's real TTL/MTU matches).

Verification (sweep): no code changed — full suite **114 passed**, `ruff check .`
clean, `mypy .` clean (63 files), confirming the three files need no fix.

---

## Verification — 2026-11-20 (Phase 8, P4-6 dashboard threading)

Full gates after the P4-6 batch (dashboard engine toggles → off the Tk thread).

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **116 passed** in 0.39s (+1 async_util) | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 8 would reformat / 75 clean — all 8 **pre-existing WIP** (count 10→8 as the P4 batches landed); my 3 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 68 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **32/32** modules import cleanly (+ netutil, osutil, async_util since baseline's 29) | integration (import-level), Linux, non-root |
| **run_async offloads** | with `threading.Thread` patched, `run_async(f)` does **not** run `f` on the caller and schedules a **daemon** thread | unit (patched Thread) |
| **toggles wired** | **6/6** dashboard engine toggles route through `run_async` (confirmed by `inspect.getsource`) | static/unit |
| **Config migration** | unchanged (P4-4 removed the dead keys earlier; the 5 live keys still default) | unit |
| **UI callbacks / shutdown** | log path thread-safe (DASH-1); toggles no longer block the Tk loop | mocked/unit |

### Not verified (honest gaps)
- No live Tk event loop is driven (no display), so the *actual* un-freezing is
  verified by construction (the handlers call `run_async`) + the helper's unit
  test, not by observing a real UI. The `protection_panel` modal residual (PP-1)
  is unchanged and remains a documented follow-up. Manual GUI check still required.

---

## Verification — 2026-11-20 (Phase 8, P4-1 netutil consolidation)

Full gates after the `core/netutil` consolidation (a behavior-preserving refactor
across 7 modules). Extra scrutiny because an interim `sed` attempt had truncated
files — so this pass **functionally** confirms the consolidated validation is
wired correctly in every consumer, not just that they import.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **117 passed** in 0.46s (+3 netutil; all 7 modules' existing validation tests still pass) | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 10 would reformat / 70 clean — all 10 **pre-existing WIP**; my 9 batch files → **already formatted** | static |
| `mypy .` | **Success: no issues in 65 source files** (+ `core/netutil`) | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **30/30** modules import cleanly (+ `core/netutil`) | integration (import-level), Linux, non-root |
| **Consolidated validation wired** | `arp.cut("not-an-ip",…)` → False, **0** commands issued; `IPTManager.add_accounting("not-an-ip")` → False; `tc.limit("not-an-ip",…)` → False (logs "refusing to limit"); `apply_static_config("garbage",…)` → False | unit/mocked — proves `core.netutil.valid_ip`/`valid_cidr` are correctly imported and called in each consumer |
| **Behaviour preserved** | every per-module validation test (arp/iptables/tc/dns_spoof/fingerprint/protector/network_manager) passes unchanged | unit |
| **Config / shutdown / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- `core.netutil` is pure stdlib `ipaddress` — fully unit-covered; no kernel/network
  involved. The wiring check uses mocked subprocess, so it proves the *validation
  short-circuit* (reject-before-command), not real command behaviour.

---

## Verification — 2026-11-20 (Phase 8, tribunal re-verification)

The last batch was **docs-only** — the Phase-3 tribunal re-verification note; `git
show --stat HEAD` confirms only `audit.md` changed (1 file, +27). So the gates can
only confirm nothing regressed, which they do.

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **114 passed** in 0.47s | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 10 would reformat / 68 clean — all **pre-existing WIP**, unchanged | static |
| `mypy .` | **Success: no issues in 63 source files** | static |
| Imports | **29/29** modules import cleanly | integration (import-level), Linux, non-root |

No code changed → no startup/shutdown/config/UI/cleanup behaviour to re-verify
beyond the unregressed suite. (Nothing here exercises a real kernel/network/GUI;
that remains root/lab/manual, as throughout Phase 8.)

---

## Verification — 2026-11-20 (Phase 8, sweep: oui_lookup/device/limit_dialog/protection_panel)

Full gates after the 4-file review (no code changed — this confirms the three
clean files and that nothing regressed).

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **114 passed** in 0.39s | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 10 would reformat / 68 clean — all 10 **pre-existing WIP** (count 13→10 as the ui/network batches landed); nothing new | static |
| `mypy .` | **Success: no issues in 63 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **oui_lookup robustness** | `get_vendor("")` → "Unknown Device"; `get_vendor("a")` → "Unknown Device"; `is_randomized("aa:bb:…")` → True | unit (pure function) |
| **device model** | 35 `update_history` calls → `rx_history`/`tx_history` both capped at 30 (in sync); `to_state()` has the expected keys | unit |
| **limit_dialog / protection_panel** | not exercised (Tk closures, no display) | — (manual) |

### Not verified (honest gaps)
- `limit_dialog`/`protection_panel` are Tk-closure UIs with no unit seam — their
  input-validation (limit_dialog, verified by inspection + prior test) and the
  PP-1 UI-blocking are not exercised against a live Tk event loop (manual).
- No code changed this batch, so there is nothing new to verify beyond "the three
  clean files behave and the suite is unregressed."

---

## Verification — 2026-11-20 (Phase 8, firewall_apex batch)

Full gates after the `system/firewall_apex.py` batch. Passed pre-commit (p2.md);
p8 confirms, nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **104 passed** in 0.40s (3 new firewall) | unit + mocked (patched subprocess) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 13 would reformat / 62 clean — all 13 **pre-existing WIP** (count 17→13 as the system batches landed); my 2 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 60 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Fail-safe / cleanup** | partial build (rule add fails) → `active=False`, `[ERROR: FIREWALL_FAIL - build rolled back]`, **2** `nft delete table` (clean-slate + rollback); success → `active=True`, `[SHIELDS: LOCKED]`; disable → `active=False`, table deleted, `[SHIELDS: DISENGAGED]` | **mocked/unit** — real nft table/chain/rule creation is **root-required + Linux + lab + manual** |
| **Shutdown / config / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- No real nftables ruleset is created, dropped, or rolled back — the verified
  behaviour is the **fail-safe control flow** (rollback on partial build) against
  a fake nft. Whether a real host actually drops/accepts the intended traffic is
  unverified.

---

## Verification — 2026-11-20 (Phase 8, masquerade batch)

Full gates after the `system/masquerade.py` batch. Passed pre-commit (p2.md);
p8 confirms, nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **91 passed** in 0.41s (4 new masquerade) | unit + mocked (patched subprocess) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 17 would reformat / 54 clean — all 17 **pre-existing WIP** (count 18→17); my 2 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 56 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Restoration / cleanup** | disable with a failing TTL restore → **all 3** sysctl writes still attempted, status `[DNA: RESTORE INCOMPLETE]` + logged; all-OK → `[DNA: NATIVE]`; nothing captured → `[DNA: NATIVE]` with 0 writes | **mocked/unit** — real kernel sysctl revert is **root-required + Linux + manual** |
| **Shutdown** | `controller.toggle_nuclear_stealth(False)` calls `apply_stack_masquerade(False)`; `controller.stop()` does not call it directly (stealth-only), noted | mocked/unit |
| **Config / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- No real sysctl (`ip_default_ttl`/`tcp_timestamps`/`tcp_window_scaling`) is read
  or written — the verified behaviour is the restore **isolation + truthful
  status**. The engage/mimic apply was intentionally left unchanged.

---

## Verification — 2026-11-20 (Phase 8, tc batch)

Full gates after the `system/tc_manager.py` batch. Passed pre-commit (p2.md);
p8 confirms, nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **87 passed** in 0.45s (5 new tc; existing `test_tc_burst` still green) | unit + mocked (patched `_tc`) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 18 would reformat / 52 clean — all 18 **pre-existing WIP** (count 19→18); my 2 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 55 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **False-success / cleanup** | `tc class` fails → `limit()` False + no phantom class id; `tc filter` fails → False; all-OK → True; invalid IP → False with **0** tc calls (each logs an error) | **mocked/unit** — real HTB class/filter + actual shaping is **root-required + Linux + lab + manual** |
| **Shutdown** | `teardown()` now resets state under the lock; called from `controller.stop()` inside its isolated try (CTL-1) | mocked/unit |
| **Config / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- No real HTB qdisc/class/filter is installed and no bandwidth is actually
  shaped — the verified behaviour is `limit()`'s **truthful success/failure
  signalling, validation, and state hygiene**.

---

## Verification — 2026-11-20 (Phase 8, stealth batch)

Full gates after the `system/stealth.py` batch. Passed pre-commit (p2.md); p8
confirms, nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **82 passed** in 0.40s (2 new stealth) | unit + mocked (patched subprocess) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 19 would reformat / 50 clean — all 19 **pre-existing WIP** (count 20→19); my 2 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 54 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Restoration / cleanup** | `disengage_stealth` with a failing `hostnamectl` → MAC restore **attempted** (True), nft-table removal **attempted** (True), status `[IDENTITY RESTORE INCOMPLETE]` + logged; all-OK → `[IDENTITY RESTORED]` | **mocked/unit** — real MAC/hostname/nft revert on a NIC is **root-required + Linux + manual** |
| **Shutdown** | `controller.stop()` calls `disengage_stealth` only when `stealth_active`, inside its isolated try (CTL-1) | mocked/unit |
| **Config / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- No real MAC spoof/un-spoof, hostname change, or nft table on a live host — the
  verified behaviour is the restore **control flow + truthful status**.
- The cloak (`engage_mirage_cloak`) was intentionally not modified or exercised.

---

## Verification — 2026-11-20 (Phase 8, mdns batch)

Full gates after the `network/mdns_sniff.py` batch. Passed pre-commit (p2.md);
p8 confirms, nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **80 passed** in 0.35s (2 new mdns) | unit (real scapy packets, no network) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 20 would reformat / 48 clean — the 20 are **pre-existing WIP** (count still dropping 21→20); my 2 files → **already formatted** | static |
| `mypy .` | **Success: no issues in 53 source files** | static |

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Parsing (resource/correctness)** | `qdcount=1` header with **2** real questions → both parse (`Host a`, `Host b`) + the `_googlecast` service label; `qdcount=65535` with 1 record → only `Printer`, no error, no over-call | unit (hand-built scapy packets) |
| **Shutdown / config / UI** | unchanged this batch | — |

### Not verified (honest gaps)
- No live multicast mDNS traffic — the parse is exercised with constructed
  packets. IPv6 mDNS (MDNS-1) and TXT model detection (MDNS-5) remain documented
  gaps, intentionally not expanded (recon reach/accuracy).

---

## Verification — 2026-11-20 (Phase 8, xdp batch)

Full gates after the `network/xdp_engine.py` batch. Passed the full gates
**before commit** (updated p2.md); p8 confirms and found nothing new.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **78 passed** in 0.35s (5 new xdp) | unit + mocked (fake BPF, no kernel) |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 21 would reformat / 46 clean — the 21 are **pre-existing WIP**; `ruff format --check network/xdp_engine.py tests/test_xdp_engine.py` → **2 already formatted** | static |
| `mypy .` | **Success: no issues in 52 source files** | static |

(The pre-existing WIP "would reformat" count keeps dropping — 24→23→22→21 — as
each batch brings one more previously-unformatted file to clean.)

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Shutdown / cleanup** | `unload()` with a raising `remove_xdp` → `_loaded=False`, `_bpf=None`, logs "program may remain attached", 2nd `unload()` is a no-op; `add_drop("1.2.3")` → logs "refusing to drop invalid IPv4", map unchanged; `add_drop("192.168.1.5")` → 4-byte network-order key present | **mocked/unit** — real eBPF attach/detach + packet drop is **root-required + BCC/clang + lab-NIC + manual** |
| **Config migration** | unchanged this batch (missing keys → `DEFAULT_CFG`) | unit |
| **UI callbacks** | unchanged this batch | static/mocked; live Tk = **manual** |

### Not verified (honest gaps)
- No real XDP program is loaded/attached and no packet is dropped — the fixed
  behaviour is the **cleanup state machine and key validation**, verified against
  a fake BPF object.
- No live packets/kernel/GUI anywhere; engine evidence is mocked/static.

---

## Verification — 2026-11-20 (Phase 8, deauth batch)

Full gates after the `network/deauth.py` batch. This batch already passed the
full gates **before commit** (updated p2.md workflow), so p8 is a confirmation —
and it found nothing new, which is the intended outcome of the workflow change.

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **73 passed** in 0.35s (3 new deauth + existing `test_deauth_available…` still green) | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 22 would reformat / 44 clean — the 22 are **pre-existing WIP**; `ruff format --check network/deauth.py tests/test_deauth.py` → **2 already formatted** | static |
| `mypy .` | **Success: no issues in 51 source files** | static |

No newly-introduced failure (contrast the scanner/ipv6 batches, where p8 caught a
committed lint/type error — the per-file-includes-tests step now prevents that).

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Shutdown / cleanup** | `stop_all()` → `_running=False`, `_targets` cleared; a drained `_pmf_loop()` → `_running=False` (so a later start restarts the worker); an inactive manager (`SCAPY_WIFI_OK=False`) starts **0** workers | **mocked/unit** — no real 802.11 frames or monitor-mode NIC; that is **root-required + lab-network + manual** |
| **Config migration** | unchanged this batch (missing keys → `DEFAULT_CFG`) | unit |
| **UI callbacks** | unchanged this batch (wiring test passes) | static/mocked; live Tk = **manual** |

### Not verified (honest gaps)
- No real deauth frames sent, no monitor-mode interface, no AP/client in a lab —
  the fixed behaviour is the **state machine**, not radio-level disconnection.
- No live packets/kernel/GUI anywhere in this suite; engine evidence is
  mocked/static throughout.

---

## Verification — 2026-11-20 (Phase 8, ipv6 batch)

Full gates after the `network/ipv6.py` batch. Labelled by evidence type. **A
green mock proves control flow, not real IPv6/kernel behaviour.**

### Quality gates (actual output)

| Gate | Result | Evidence |
|------|--------|----------|
| `pytest -v` | **70 passed** in 0.72s | unit + mocked |
| `ruff check .` | **All checks passed** | static |
| `ruff format --check .` | 23 would reformat / 42 clean — the 23 are the **pre-existing uncommitted WIP**; **all 23 .py files across my commits are format-clean** | static |
| `mypy .` | **Success: no issues in 50 source files** (after fixing one attr-defined — below) | static |

**mypy caught by this phase (real miss, 2nd occurrence).** `tests/test_ipv6.py`
was committed (ipv6 batch) with `from scapy.all import ICMPv6ND_RA`, which trips
`attr-defined` because the mypy override that silences scapy's dynamic symbols
covers `network.*` but not `tests/*`; my per-file `mypy network/ipv6.py` didn't
check the test. Fixed with a targeted `# type: ignore[attr-defined]`. (Same slip
class as the scanner batch's I001 — per-file checks miss newly-added test files;
`/p8`'s full `mypy .` / `ruff check .` is what catches them.)

### Functional checks (actual output)

| Check | Result | Evidence |
|-------|--------|----------|
| **Imports** | **29/29** modules import cleanly | integration (import-level), Linux, non-root |
| **Shutdown / cleanup** | `IPv6Hijacker.stop()` (when running) sends a withdrawal RA with **routerlifetime=0** — verified live via a patched `sendp`; `Controller.stop()` always reaches `restore_network` once (test_controller_stop) | **mocked/unit** — real target route-drop is **root-required + IPv6 lab + manual** |
| **Config migration** | unchanged this batch (missing keys fall back to `DEFAULT_CFG`) | unit |
| **UI callbacks** | unchanged this batch (wiring test passes) | static/mocked; live Tk = **manual** |

### Not verified (honest gaps)
- The withdrawal RA's **effect** (a real host dropping the bogus route) is
  unverified — needs root + an IPv6 lab.
- No live packets/kernel/GUI; engine evidence is mocked/static throughout.

---

## Verification — 2026-11-20 (Phase 8, scanner batch)

Full gates run after the `network/scanner.py` batch. Every result is labelled by
evidence type. **A green mocked test proves the control flow, not real-kernel /
real-network behaviour.**

### Quality gates (actual output)

| Gate | Result | Evidence type |
|------|--------|---------------|
| `pytest -v` | **68 passed** in 0.81s | unit + mocked (no real sockets/iptables) |
| `ruff check .` | **All checks passed** (after fixing one I001 — see below) | static |
| `ruff format --check .` | **24 would reformat, 40 already formatted** — the 24 are the pre-existing **uncommitted WIP** files I never touched; **all 21 .py files in my commits are format-clean** | static |
| `mypy .` | **Success: no issues in 49 source files** | static |

**I001 caught by this phase (real miss).** `tests/test_scanner.py` was committed
(scanner batch) with an un-sorted import block — my per-file `ruff check` in that
batch ran before the final `ruff format` and I didn't re-check the test file.
`ruff check .` here flagged it; fixed (removed a stray blank line) in this phase.
This is exactly the kind of slip p8 exists to catch.

### Functional checks (actual output)

| Check | Result | Evidence type |
|-------|--------|---------------|
| **Imports** | **29/29** modules across core/network/system/ui import cleanly | integration (import-level), Linux, non-root |
| **Startup structure** | `main.py` parses; top-level calls `_fix_sys_path`, `_check_root`, `_check_deps`. `_check_root` calls `sys.exit(1)` when not root **by design**, so `import main` can't run headless as non-root | static; full GUI startup is **root-required + manual** |
| **Config migration** | `db.get('refresh_ms')` → 1200; `db.get('unknown_key', 42)` → 42; a legacy/partial `config.json` missing newer keys still returns `DEFAULT_CFG` values; `_load(missing)` → default | unit |
| **Shutdown / resource cleanup** | `Controller.stop()` runs every teardown step in isolation and always reaches `restore_network`, exactly once, even when a step raises (`test_controller_stop`); ARP flood/arpspoof, recon sockets, DNS/iptables rules each have a verified cleanup path | **mocked/unit** — real kernel/NIC/iptables teardown is **root-required + manual**, unverified here |
| **UI callbacks** | `test_dashboard_wires_info_and_protection_dialogs` passes (wiring present) | static/mocked; live Tk event loop is **manual** |

### What is NOT verified (honest gaps)

- **No real packet/ARP/iptables/tc/sysctl behaviour** — every engine test mocks
  the subprocess/socket/scapy layer (labelled mocked throughout §Phase-2).
- **No live GUI** — Tk mainloop not driven; no screenshots (Phase-6 work).
- **No root / lab-network run** — restoration correctness is proven only against
  mocked `subprocess`; real-OS revert of promisc/rp_filter/proxy_arp/offloads and
  real FORWARD rule insertion/ordering remain **root-required + manual**.
- `ruff format` on the whole tree still reports the user's **pre-existing 24-file
  WIP drift**, deliberately left untouched (not mine to reformat).

---

## Architecture Verdict — 2026-11-20 (Phase 4)

Assessed against the p1 map and everything the bug hunt surfaced. The guiding
rule: **propose only changes with a named problem; no abstraction without a
concrete problem it solves.** One change is implemented this phase; the rest are
named proposals with a recommended owner/phase.

### Overall shape (verdict: sound for this size — keep)

`main` → `Controller` (the engine/orchestrator) → ~12 subsystems; `Dashboard`
(UI) talks to the controller by method calls + a `log=` callback + the
`on_protection_alert` hook. Layering is **core ← network ← system** with the
controller on top wiring everything. **No import cycles** (all `__init__.py` are
empty; `core.netutil` is a new leaf). The Controller is a large god-object but
that is acceptable for an app of this size — it is not worth a service-layer
abstraction (no concrete problem it would solve). **Keep the architecture.**

### IMPLEMENTED — P4-1: de-duplicate IP validation into `core/netutil.py`

**Problem (named, evidenced):** the identical helper `_valid_ip` was copy-pasted
in **7** modules (`network/arp`, `system/iptables_manager`, `core/protector`,
`system/tc_manager`, `network/dns_spoof`, `network/fingerprint`,
`system/network_manager`), plus `_valid_cidr`/`_valid_dns` in a 8th place — ten
validation sites with drift risk (some used `ip_address`, nm used `ip_interface`
and a comma-split DNS check). This grew directly out of the Phase-2 fixes that
added validation everywhere.
**Change:** new `core/netutil.py` (`valid_ip`, `valid_cidr`, `valid_dns`) — a
dependency leaf (imports only `ipaddress`), so any layer can import it with no
cycle. All 7 modules now `from core.netutil import …`; the 7 local defs and their
now-unused `import ipaddress` are gone. Behaviour is preserved (the existing
per-module validation tests — arp/iptables/tc/dns_spoof/fingerprint/protector/
network_manager — all still pass unchanged), plus a new `tests/test_netutil.py`.
*Verification:* `pytest` **117 passed** (+3), `ruff check .` clean, `mypy .`
clean (65 files), 30/30 modules import.
*(Note: a first attempt with `sed` range-deletion over-matched and truncated four
files; caught immediately via `wc -l` vs HEAD, reverted cleanly from the
per-batch commits, and redone with exact-string replacement — a concrete payoff
of committing every batch.)*

### IMPLEMENTED — P4-1b: fold the MAC-randomization check into `core/netutil`

**Problem (named, evidenced):** the locally-administered-bit (MAC randomization)
check existed in **3** copies — `core/persistence.is_private_mac` and
`core/persistence.is_stealth_mac` (identical logic, same file) and
`network/oui_lookup.is_randomized` — the same `mac[1].upper() in ("2","6","A","E")`
written three times (one even uses a list, two use tuples). `is_private_mac` is
additionally dead (no app caller, only a test).
**Change:** added `core/netutil.randomized_mac(mac)` (single implementation,
with the robust `not mac or len(mac) < 2` guard). The three public helpers now
delegate to it, keeping their names/signatures so all callers and the three
existing tests (`test_is_private_mac`/`test_is_stealth_mac`/`test_is_randomized`)
pass unchanged; added `test_randomized_mac`. No import cycle (`persistence` and
`oui_lookup` both import the leaf `core.netutil`; verified by importing them).
*Verification:* `pytest` **118 passed** (+1), `ruff check .`/`mypy .` clean (65
files), `grep` confirms the `mac[1].upper() in …` logic now lives **only** in
netutil. *(`is_private_mac` is still dead — a P4-3 removal candidate; left in
place here as a thin delegating wrapper to keep this change a pure consolidation.)*

### PROPOSED (named problems, not yet implemented)

**P4-2 — Collapse the 4-way OUI lookup. DONE.**
*Problem:* vendor lookup existed twice — `core/persistence` (`_OUI_DB` static
dict + `lookup_oui` via optional `mac_vendor_lookup`) **and** `network/oui_lookup`
(`FALLBACK_OUI` static dict + `get_vendor` via optional `ouilookup`). Two static
dicts (measured mostly **disjoint** — 136 of FALLBACK's 142 prefixes absent from
`_OUI_DB`), two optional libraries, two lookup implementations, two entry points
that `scanner`/`device` vs the controller intel callbacks picked inconsistently.
*Change:* `FALLBACK_OUI` moved **verbatim** into `persistence` as `_FALLBACK_OUI`
(no risky re-keying — each table keeps its own case, `lookup_oui` now returns
`_OUI_DB.get(upper) or _FALLBACK_OUI.get(lower)`), so the single `lookup_oui` now
resolves the **union** of both tables. `network/oui_lookup` shrank to a thin
presentation layer: `get_vendor` normalises dashes, delegates to `lookup_oui`,
and keeps the privacy-bit/`Unknown Device` output the controller expects; the
redundant `ouilookup` optional library and its per-call `OuiLookup()`
instantiation are gone (dropped from `requirements.txt`). *Result:* **one lookup
function, one optional lib, one entry point** (two data tables, both in one
module). Behaviour preserved — `test_get_vendor_fallback_dict` (incl. the dash
form) still passes, and `lookup_oui` now resolves *more* MACs (the union), which
is additive. No import cycle (`oui_lookup` → `persistence` → `netutil`, verified).
*Verification:* `pytest` **118 passed**, `ruff`/`mypy` clean (65 files), behaviour
spot-check green.

**P4-3 — Remove dead code. DONE (a, b, c; d deferred).**
*Problem:* unreachable code that confuses maintenance.
(a) `IPTManager.add_drop/remove_drop/remove_all_drops/is_dropped/_dropped` — the
DROP half, unreferenced by the app (`network/arp` owns cuts). **Removed**; the
`_dropped` set and the `remove_all_drops()` call in `cleanup()` are gone, the
module docstring updated, and the two tests that exercised it
(`test_iptables_manager::test_drop_bookkeeping` and
`test_iptables_hardening::test_add_drop_*`) were removed / trimmed.
(b) `deauth._enable_monitor` — zero callers. **Removed**, along with its now-unused
`import shutil` and `import subprocess`.
(c) `persistence.is_private_mac` — dead after P4-1b (no app caller; identical to
`is_stealth_mac`). **Removed** with its test.
(d) MDNS-5 TXT branch — **deferred**: it is only dead for its *purpose* (TXT rdata
is a list), but the `isinstance(rdata, bytes)` guard can still trigger for other
record types, so it isn't strictly unreachable; left documented rather than risk
touching the parser. *Grep proof:* after removal, no refs to `.add_drop`
(IPTManager), `is_dropped`, `_enable_monitor`, or `is_private_mac` remain
(`xdp_engine.add_drop` is a distinct, live method). *Verification:* `pytest`
**114 passed** (−4 dead-code tests), `ruff`/`mypy` clean (65 files), 30/30 imports.
*(The full-pytest gate caught that `test_iptables_hardening.py` — a separate file
— also tested the removed `add_drop`; fixed before commit.)*

**P4-4 — Config keys defined but never consumed. DONE.** *Problem:* `DEFAULT_CFG`
in `persistence` defined `arp_interval`/`watchdog_interval`, but `network/arp`
hardcodes `ARP_INTERVAL`/`WATCHDOG_INTERVAL` as class constants and nothing reads
the config keys — so editing them in `config.json` silently did nothing
(misleading). *Change:* **removed** the two dead keys (grep confirmed no reader,
no test ref). Wiring them instead would be adding a feature (user-tunable
attack-timing), which is out of the reliability scope. `DEFAULT_CFG` now holds
only the 5 keys that are actually consumed. *Verification:* `pytest` **114
passed**, `ruff`/`mypy` clean.

**P4-5 — Platform boundary. PARTIALLY DONE (definition centralised; behaviour
unification deferred by design).** *Problem (two halves):* (1) `_IS_WINDOWS =
sys.platform == "win32"` was defined in **6** modules (`traffic`, `arp`,
`protector`, `tc_manager`, `iptables_manager`, `netinfo`); (2) those `_IS_WINDOWS`
branches behave **three** different ways on Windows — silent fake-success
(`iptables_manager`, `tc_manager`), explicit error (`masquerade`, `chameleon`,
`firewall_apex`, `network_manager`), and would-crash-but-caught (`arp`). *Done
(1):* new `core/osutil.py` (`IS_WINDOWS`, a leaf importing only `sys`); the 6
modules now `from core.osutil import IS_WINDOWS as _IS_WINDOWS` (keeping the local
name, so every guard is unchanged) and their now-unused `import sys` is gone.
Behaviour-preserving; `pytest` **115 passed**, `ruff`/`mypy` clean (66 files),
31/31 imports, no cycle. *Deferred (2), with reasoning:* unifying the Windows
behaviour (AGENTS.md: "Windows paths must not silently no-op") is a **behaviour
change on an unsupported, untested platform** — the engine is Linux-only, so these
branches are inactive on the target, and getting a caller contract wrong (e.g.
`_ipt`'s Windows return type) could break the *Linux* path. It also needs a
**product decision**: Windows = explicitly-unsupported (refuse) vs
best-effort-degraded (current). Recommend deciding that first; the single
`osutil.IS_WINDOWS` is now the one place to implement it. This is the one proposed
item I judged **risk > value to force now** — documented rather than rushed.

**P4-6 — UI work on the Tk thread. DONE for the dashboard; protection_panel
residual documented.** *Problem:* the dashboard's engine toggles (`_toggle_nuclear`
/`_toggle_ghost`/`_toggle_arp`/`_toggle_chameleon`/`_toggle_ipv6`/`_on_ttl_change`)
and the protection-panel toggles run ip/nft/sysctl subprocesses **synchronously
on the Tk thread**, freezing the UI for seconds (DASH-2/STEALTH-6; PP-1 for the
modal). *Done (dashboard):* new `ui/async_util.run_async(func)` offloads the work
to a daemon thread; each of the 6 dashboard handlers reads any Tk *widget* state
(e.g. `nuclear_switch.get()`) on the UI thread first, then offloads the
subprocess/controller work — logging flows through the already-thread-safe
`log_tactical` (DASH-1), and none of these handlers write widgets afterwards, so
no back-marshalling is needed. *Regression:* `test_async_util` (asserts the work
is scheduled on a daemon thread, not run on the caller). *Residual (deferred),
PP-1:* `ui/protection_panel`'s modal handlers still call their toggles
synchronously, and its `update_btns()` interleaves subprocess state-reads with Tk
widget writes — offloading that cleanly needs a focused modal rework (the reads
threaded, the widget writes marshalled via `after`), which I did not rush into a
Tk-closure file without a test seam. The main-window freeze — the one users hit
most — is fixed. *Verification:* `pytest` **116 passed** (+1), `ruff`/`mypy` clean
(68 files).

### Not changed (deliberately)

- **Shared global singletons** (`persistence.db`, scanner module-level caches/
  pools, `_ORIG`/`_ORIG_MTU`) are app-wide state with a clear owner; converting
  them to injected objects solves no concrete problem here. Keep. (The one real
  issue — scanner's never-`shutdown()` thread pools, SCAN-4 — is a resource note,
  not an architecture change.)
- **Error propagation** is now consistent after Phase 2 (log + return bool/status,
  isolated cleanup) — no change needed.

---

## Tool & Dependency Tribunal — 2026-11-19 (Phase 3)

Matrix only — no dependency or config changes made in this phase. Evidence is
measured (usage counts via grep, icon size, Tk version, installed versions),
not guessed. Where a true performance benchmark wasn't feasible in this
environment (e.g. scapy vs a rewritten raw-socket engine), that is stated
rather than invented.

Installed: scapy 2.8.0, customtkinter 6.0.0, Pillow 12.3.0, pytest 9.1.1,
ruff 0.17.0, mypy 2.4.0, Python 3.14.8, Tk 8.6.

### Runtime dependencies

| Existing | Candidate | Existing weakness | Candidate advantage | Compatibility | Migration cost | Performance | Maintenance | Verdict |
|---|---|---|---|---|---|---|---|---|
| **scapy 2.8.0** | raw sockets / libpcap / pyroute2 | heavy import; dynamic `scapy.all` symbols defeat mypy `attr-defined` | stdlib sockets = zero deps | used at 15 sites, ~24 layers (ARP, Dot11, DHCP, DNS, ICMPv6, NBNS…) | very high — would reimplement the entire packet engine | scapy send/sniff is slower than raw, but no measured bottleneck | actively maintained, pinned ≥2.7.0 for GHSA-cq46 | **KEEP** |
| **customtkinter 6.0.0** | raw tkinter/ttk (stdlib); PySide6; Dear PyGui | only `dashboard.py` uses it — the 3 dialogs already use stdlib `tkinter`, so the toolkit is **mixed** | ttk removes a dep; Qt is far richer | ctk widgets ≠ tk widgets; theming differs | medium (one window) to high (full Qt) | adequate for this scale | maintained; smaller community than Qt | **KEEP** — but the mixed ctk/tk toolkit is a real smell for the Phase-6 UI rebuild |
| **Pillow 12.3.0** | stdlib `tkinter.PhotoImage(...).subsample(16)` or a pre-sized 64px asset | whole image library pulled in for **one** call | zero deps; Tk 8.6 reads PNG natively | icon is exactly 1024→64 = `subsample(16)` (integer factor, works) | low (one call + ship a 64px icon) | subsample is nearest-neighbour — slightly worse icon quality than PIL resize | maintained, pinned ≥11 for CVEs | **INVESTIGATE** — removable; defer to the Phase-6 asset pass (quality trade-off is a design call) |

### System tools (external binaries)

| Existing | Candidate | Existing weakness | Candidate advantage | Compat | Migration | Perf | Maint | Verdict |
|---|---|---|---|---|---|---|---|---|
| **iptables** (12 call sites) | nftables; pyroute2 | app uses *both* iptables and nft → dual firewall stacks | one backend, netlink-native | core to cut/accounting/REDIRECT | high | fine | stable; iptables-nft shim ubiquitous | **KEEP** — consolidation is a Phase-4 architecture call, not a swap |
| **nftables** (10 call sites) | iptables | only the evasion modules (`stealth`, `firewall_apex`) use it; overlaps iptables role | — | fine | — | fine | stable | **KEEP** (evasion modules are out of the reliability scope anyway) |
| **tc** (3 sites) | pyroute2 (tc via netlink) | string-built HTB commands, fragile parsing | typed netlink, no shell parse | core to bandwidth limit | medium | equivalent | iproute2 ubiquitous | **KEEP** |
| **XDP/eBPF via `bcc`** (1 site, optional) | remove layer; libbpf/bpftool | **redundant** — drops the same cut traffic iptables FORWARD DROP already drops; needs clang+kernel headers | near-zero-CPU drop | optional, degrades to no-op | low to remove | best, but unneeded given iptables | bcc heavy, slower-moving | **INVESTIGATE** — redundant drop layer; keep only if it earns its weight in Phase-7, else REMOVE |

### Optional OUI libraries (redundancy)

| Existing | Weakness | Verdict |
|---|---|---|
| `mac_vendor_lookup` (persistence.py) **and** `ouilookup` (oui_lookup.py) **and** two static dicts (`_OUI_DB`, `FALLBACK_OUI`) | **four** overlapping vendor-lookup mechanisms across two modules | **INVESTIGATE → likely REMOVE one lib + merge the dicts in Phase 4** (dedupe). grep confirms `mac_vendor_lookup`=1 ref, `ouilookup`=1 ref, both single-module. |

### Dev tooling — doing work, or decorative?

| Tool | Config | Doing real work? |
|---|---|---|
| **ruff 0.17.0** | `select = E4/E7/E9/F/I/UP/RUF`, E722 on, targeted ignores | **Yes.** Catches unused/undefined/import-order/pyupgrade defects; E722 enforces the CLAUDE.md no-bare-except rule. Config is justified, not decorative. **KEEP** |
| **pytest 9.1.1** | `testpaths=["tests"]` + `conftest.py` path shim | **Yes**, functional. 26 tests collected. Most older tests are pure-function assertions (would run under unittest too) but pytest is the right tool. **KEEP** |
| **mypy 2.4.0** | `ignore_missing_imports=true`, `attr-defined` disabled for `network.*`/`controller`/`protector`/`netinfo`, untyped bodies unchecked by default | **Partially decorative.** The packet engine — exactly where scapy-shape bugs hide — gets almost no checking: `attr-defined` is off there and most functions are unannotated so their bodies are skipped (14 `annotation-unchecked` notes). It does validate typed modules. **KEEP**, but it is under-powered; a later batch should add annotations + `check_untyped_defs` to specific modules rather than disable the one error code that matters. Honest status: green mypy here is a weak signal for the engine. |

### Summary

- **KEEP (no change):** scapy, customtkinter, iptables, nftables, tc, pytest, ruff.
- **INVESTIGATE:** Pillow (single-use, removable — Phase 6), XDP/`bcc`
  (redundant drop — Phase 7), the 4-way OUI redundancy (dedupe — Phase 4).
- **No REPLACE / no hard REMOVE this phase** → no migration/rollback plans or
  removal greps required yet; the INVESTIGATE items carry their deferral phase.
- **mypy config** is the one piece of tooling whose green status over-promises;
  flagged for strengthening, not removal.

### Re-verification — 2026-11-20 (after the reliability bug hunt)

Re-checked against the codebase after 36 reliability commits. **All verdicts
stand unchanged** — no dependency or external tool was added, removed, or
swapped. Measured deltas since the first tribunal:

- **No new third-party dependency.** Every import added across the whole bug hunt
  is stdlib (`ipaddress`, `logging`, `queue`, `re`, `dataclasses`, …). This
  *reinforces* the "stdlib preferred" principle — e.g. input validation uses
  stdlib `ipaddress` (now at ~10 sites, a Phase-4 dedupe target, not a dep).
- **pytest** — suite grew 22 → **114** tests; still the right tool. KEEP.
- **ruff** — config confirmed **doing real work**: it flagged real defects during
  the hunt, including RUF059 (unused unpacked variable) in two new test files
  that the `tests/*` F841 ignore does not cover — caught pre-commit and fixed.
  Not decorative. KEEP.
- **mypy** — now checks **63** source files, all green, but the
  "under-powered on the engine" assessment **holds**: `attr-defined` is still
  disabled for `network.*`/`controller`/`protector`/`netinfo`, and many
  packet-layer function bodies remain unannotated (so unchecked). Green mypy
  remains a weak signal for the scapy-facing code. KEEP, still flagged for
  strengthening (annotate + `check_untyped_defs` on specific modules).
- **INVESTIGATE items unchanged:** Pillow (single-use, Phase-6), XDP/`bcc`
  (redundant drop layer, Phase-7), 4-way OUI redundancy (Phase-4 dedupe).

No REPLACE/REMOVE actioned → no migration/rollback plans or removal greps needed
this pass.

---

## Tool Tribunal + Upgrade — 2026-11-20 (Phase 3, re-run with bumps)

Re-run of the tribunal **with the upgrade step actioned**. The prior passes
(2026-11-19 / 2026-11-20) produced the matrix but deferred every bump; this pass
applies the outdated-patch bumps p0 found and re-verifies the gates.

**Environment (measured):** Linux (Arch, kernel 7.2.9-arch1-1),
Python **3.14.8**, **Tcl/Tk 8.6** (`tkinter.TkVersion`), project `.venv`.
Pre-bump installed: scapy 2.8.0, customtkinter 6.0.0, Pillow 12.3.0,
pytest 9.1.1, ruff 0.17.0, mypy 2.4.0.

### Python 3.14 verification (scapy + CustomTkinter) — empirical, not release-note mining

Upstream release notes give no explicit "3.14 supported" statement for either
(scapy 2.8.0 notes only drop 3.7/3.8; CustomTkinter has no 3.14 note). The Tk 9.0
Linux breakage reported for some 3.14 builds **does not apply here** — this host's
interpreter bundles **Tcl/Tk 8.6**. Verified by running on 3.14.8, which is a
stronger signal than a changelog line:

- **scapy 2.8.0** — `Ether()/ARP(op=2, …)` builds and byte-encodes (42 bytes);
  `IP/UDP/DNS/Dot11` layers import. ✓ on 3.14.8.
- **customtkinter 6.0.0** — `ctk.CTk()` instantiates and destroys a real window
  on this Tk 8.6 / 3.14.8 host. ✓
- Full suite: **116 tests pass** on 3.14.8. Both are already at the **latest
  published version** (scapy max = 2.8.0, ctk max = 6.0.0), so there is nothing
  to upgrade *to* — verdict KEEP, confirmed current.

### Matrix

| Existing | Candidate | Existing weakness | Candidate advantage | Compatibility | Migration cost | Performance | Maintenance | Verdict |
|---|---|---|---|---|---|---|---|---|
| **scapy 2.8.0** (15 sites, ~24 layers) | raw sockets / libpcap / pyroute2 | heavy import; dynamic `scapy.all` symbols defeat mypy `attr-defined` | stdlib sockets = zero deps | **3.14.8 verified** (packet build/encode ✓); core to the engine | very high (reimplement entire engine) | send/sniff slower than raw, but no measured bottleneck | actively maintained; already latest (2.8.0); floor ≥2.7.0 for GHSA-cq46 | **KEEP** (latest) |
| **customtkinter 6.0.0** (dashboard only) | raw tkinter/ttk (stdlib); PySide6; Dear PyGui | toolkit is **mixed** — 3 dialogs already use stdlib tkinter | ttk drops a dep; Qt is richer | **3.14.8 / Tk 8.6 verified** (`CTk()` window ✓) | medium (one window) → high (Qt) | adequate at this scale | maintained; already latest (6.0.0); smaller community than Qt | **KEEP** (latest; mixed-toolkit smell is a Phase-6 call) |
| **Pillow 12.3.0** | stdlib `PhotoImage(...).subsample(16)` / pre-sized 64px asset | whole image lib for **one** call (`dashboard.py:57`) | zero deps; Tk 8.6 reads PNG natively | `Image.open(...).resize((64,64))` works on **13.0.0** (no removed API hit) | low to remove | subsample is nearest-neighbour (slightly worse) | maintained; CVE floor ≥11.0.0 | **BUMP 12.3.0→13.0.0** (removal still INVESTIGATE → Phase-6) |
| **iptables** (12 sites) | nftables; pyroute2 | app runs **both** iptables + nft (dual stacks) | one netlink-native backend | core to cut/accounting/REDIRECT | high | fine | stable; iptables-nft shim ubiquitous | **KEEP** (consolidation is a Phase-4 call) |
| **nftables** (10 sites) | iptables | only evasion modules use it; overlaps iptables | — | fine | — | fine | stable | **KEEP** (evasion out of reliability scope) |
| **tc** (3 sites) | pyroute2 (tc via netlink) | string-built HTB cmds, fragile parse | typed netlink, no shell parse | core to bandwidth limit | medium | equivalent | iproute2 ubiquitous | **KEEP** |
| **XDP/eBPF via `bcc`** (1 site, optional) | remove layer; libbpf/bpftool | **redundant** — drops traffic iptables FORWARD DROP already drops | near-zero-CPU drop | optional; degrades to no-op | low to remove | best, but unneeded | bcc heavy, slower-moving | **INVESTIGATE → Phase-7** (unchanged) |
| **pytest 9.1.1** | stdlib `unittest` | — (functional, doing real work) | one less dev dep | 116 tests collect+pass on 9.2.0/3.14.8 | trivial bump | n/a | maintained | **BUMP 9.1.1→9.2.0** (KEEP tool) |
| **ruff 0.17.0** | flake8+isort+pyupgrade | — (catches real defects; E722 enforces no-bare-except) | — | selected rule set (E4/E7/E9/F/I/UP/RUF) still clean on 0.17.6 | trivial bump | faster | very active | **BUMP 0.17.0→0.17.6** (KEEP tool) |
| **mypy 2.4.0** | pyright | under-powered on the engine (`attr-defined` off for `network.*`) | — | clean (68 files) on 2.4.1/3.14.8 | trivial bump | n/a | maintained | **BUMP 2.4.0→2.4.1** (KEEP tool; strengthen later) |

**Stdlib-preferred note:** no third-party candidate wins this pass — the only
stdlib swap that genuinely fits (Pillow → `PhotoImage.subsample`) is a quality
trade-off deferred to the Phase-6 asset pass, not a p3 action.

### Verdict outcomes

- **KEEP (no change):** scapy, customtkinter, iptables, nftables, tc — the two
  runtime libs verified current + 3.14-compatible above.
- **BUMP (outdated patches from p0) — ACTIONED:**
  `pip install pillow==13.0.0 pytest==9.2.0 ruff==0.17.6 mypy==2.4.1`
  (+ `mypy_extensions 1.1.0→1.2.0`). Single commit; **p8 re-run green**:

  | Gate | Pre-bump | Post-bump |
  |---|---|---|
  | `pytest -q` | 116 passed | **116 passed** |
  | `ruff check .` | clean | **clean** (0.17.6 adds no new findings in the selected rules) |
  | `ruff format --check .` | 8 would reformat | **8 would reformat** (unchanged deliberate debt) |
  | `mypy .` | Success, 68 files | **Success, 68 files** |
  | icon path `dashboard.py:57` | ok | **ok** on Pillow 13 (`icon.png` → 64×64) |

  No rollback needed (no red). `requirements.txt`: Pillow runtime floor kept at
  the CVE-driven `>=11.0.0` (no new CVE justifies raising a *minimum*; 13.0.0 is
  now the tested-current version); the three dev tools recorded as pinned,
  commented dev deps (file's existing convention for non-runtime deps) so the
  bumped versions are durable and discoverable. No lockfile exists.
- **INVESTIGATE (deferred, unchanged):** Pillow removal → Phase-6; XDP/`bcc`
  redundant drop → Phase-7; 4-way OUI redundancy → Phase-4 dedupe.
- **No REPLACE / no REMOVE** this phase → no migration/rollback or removal-grep
  plans required.

---

## 0. Re-audit — 2026-10-13

**Environment:** Windows 11, Python 3.13.15, project `venv/` (scapy 2.8.0,
customtkinter 6.0.0, Pillow 12.3.0, pytest 9.1.1, ruff 0.17.0; mypy 2.4.0
installed during this pass). The engine is Linux-only; on Windows the UI and
pure logic run, but privileged networking degrades through caught exceptions.

**Project health: good.** All 30 modules (incl. `main`) import cleanly. The
test suite passes. Every Critical/High/Medium finding from the prior audit was
verified still-fixed in the current code (see §2). This pass found no new
Critical/High issues; it found two Medium items (one feature-wiring, one
tooling) and three Low items, all now resolved, plus two Informational notes.

**Does it start?** Verified at the import/headless level: importing `main`
executes the top-level root/dependency checks and loads the full UI stack
without error. A full GUI launch was **not** performed (no attempt to drive the
Tk mainloop headless) and the privileged network engine was **not** exercised
(no root, no live packets) — those require a Linux host with root and are noted
under "Manual testing still required".

### Verification checks actually run

| Check | Result |
|-------|--------|
| `pytest -v` | **22 passed** (19 prior + 3 new regression tests) |
| `ruff check .` | **All checks passed** (with the new `pyproject.toml` rule set) |
| `mypy .` | **Success: no issues found in 39 source files** |
| `ruff format --check .` | **35 files would be reformatted** — intentionally *not* run (see N2) |
| import smoke test (all 30 modules) | **0 failures** |

### New findings this pass

#### N1 — Info popup and Protection panel were wired to nothing — **Medium — FIXED**
- **Location:** `ui/info_dialog.py` (`show_info_dialog`), `ui/protection_panel.py` (`show_protection_panel`), `ui/dashboard.py`.
- **Evidence:** a project-wide grep found no caller or binding for either
  function. The per-device Info popup (ping / traceroute / fingerprint, and the
  `RESET USAGE` button a prior "Critical" fix targeted), plus the kill-switch
  toggle, stealth-profile picker and static-IP config, were unreachable from the
  running UI. `dashboard._on_ttl_change` was a dead handler as well.
- **Fix:** `dashboard` now opens the Info popup on a row double-click
  (`<Double-Button-1>` → `_open_info`) and the Protection panel from a new
  sidebar button (`_open_protection`). Guarded by `tests/test_regressions.py`.

#### N2 — No tool configuration existed — **Medium (tooling) — FIXED**
- **Evidence:** no `pyproject.toml` / ruff / mypy / pytest config. `ruff check .`
  therefore ran ruff 0.17's broad *default* rule set and reported **279** findings
  (non-reproducible as a gate); `mypy` was not installed; `ruff format --check .`
  wanted to rewrite 35/42 files. CLAUDE.md's own verification block could not
  serve as a meaningful gate.
- **Fix:** added `pyproject.toml` pinning:
  - **ruff**: `select = E4,E7,E9,F,I,UP,RUF`, `line-length = 100`; ignores the
    project's intentional patterns (`E701/E702` inline style, `E402` lazy imports,
    `ui/*` star-imports); **E722 (bare-except) kept on** to enforce the CLAUDE.md
    rule. `ruff check --fix` then cleared 67 safe issues (the deferred §1.4
    unused-import / import-order cruft). `ruff check .` is now clean.
  - **pytest**: `testpaths = ["tests"]`.
  - **mypy**: lenient but real; `attr-defined` disabled only for the
    scapy-dynamic / Unix-syscall modules (confirmed false positives — scapy
    exports protocol classes dynamically, and `os.killpg`/`fcntl.ioctl` are
    Linux-only). A handful of correct annotations brought `mypy .` to zero.
  - **Format debt is deliberately not enforced**: `ruff format` would rewrite 35
    files (the column-aligned constant style), which is exactly the "unrelated
    refactor" the project forbids per commit. Documented as remaining Low debt.

#### N3 — `deauth.py` scapy-availability guard was non-functional — **Low — FIXED**
- **Location:** `network/deauth.py`.
- **Evidence:** the `Dot11/…` import was unguarded; the `try/except ImportError`
  wrapped only `SCAPY_WIFI_OK = True`, so the flag could never be `False` and the
  intended graceful degradation was dead code (a missing 802.11 layer would crash
  at import).
- **Fix:** moved the scapy import inside the `try`, with `None` fallbacks.
  Regression test added.

#### N4 — `requirements.txt` floors permitted vulnerable versions — **Low (dependency) — FIXED**
- **Evidence:** `scapy>=2.5.0` allowed <2.7.0, which carries an unsafe-deserialization
  RCE (GHSA-cq46-m9x9-j8w2, fixed in 2.7.0); `Pillow>=10.0.0` allowed the older
  10.x image-parsing CVEs. Installed versions (2.8.0 / 12.3.0) already exceed the
  new floors, so this is a tightening, not an upgrade.
- **Fix:** `scapy>=2.7.0`, `Pillow>=11.0.0` with explanatory comments.

#### N5 — DNS-spoof reply source address after REDIRECT — **Informational (not changed)**
- **Location:** `network/dns_spoof.py`.
- **Observation:** the sniffer reads packets *after* the iptables REDIRECT to
  local 5353 and crafts replies with `src=pkt[IP].dst` (the post-REDIRECT local
  address), and nothing binds 5353. Spoofed answers may originate from the wrong
  source on some stacks. Correctness here depends on live MITM positioning and
  needs a real Linux+root test; left unchanged to avoid speculative edits.

#### N6 — Windows interface detection — **Informational (by design)**
- **Location:** `system/netinfo._detect_network_windows`.
- **Observation:** parses a human-readable adapter description (e.g.
  "Wireless LAN adapter Wi-Fi") not usable as a scapy iface. Consistent with the
  documented Linux-only engine; network features degrade through caught
  exceptions rather than silently claiming success.

---

## 1. Open findings (deferred Low — re-verified still accurate)

Nothing Critical/High/Medium remains open. The four items below were consciously
deferred by the prior audit; each was re-checked against the current code and is
still an accurate description.

### 1.1 `classify_device` mutates `dev.confidence` as a side effect
- **Severity:** Low · **Location:** `core/persistence.py` (`classify_device`)
- The helper writes `dev.confidence` and is called from several threads. The
  write is a single `int` assignment (atomic under the GIL), so the race is
  benign. The clean fix — return `(confidence, label)` — touches ~8 call sites;
  deferred until those paths have coverage.

### 1.2 Device state is serialized but never loaded back
- **Severity:** Low · **Location:** `core/device.py` (`to_state`), `core/persistence.py` (`save_state`)
- `state.json` is written but never read into devices. Either implement
  restore-on-start or drop the serialization — a product decision, not a bug.

### 1.3 Placeholder IPv6 prefix and ad-hoc SSL-CN byte scan
- **Severity:** Low · **Location:** `network/ipv6.py` (`2001:db8:1::`, RFC 3849 doc prefix), `network/recon_engine.py` (`get_ssl_cert_cn` DER byte scanning)
- The IPv6 prefix isn't routable and the SSL CN byte-scan frequently returns
  garbage. A correct cert parse needs `cryptography`; a working prefix needs
  deployment-specific design. Out of scope for a safe correctness pass.

### 1.4 Formatting debt
- **Severity:** Low · **Location:** project-wide
- `ruff format` would rewrite 35/42 files (the column-aligned constant style).
  Deliberately not enforced (see N2) to avoid a whole-repo reformat. The *lint*
  half of the old §1.4 (unused imports, import order) is now cleared by the new
  ruff config + `--fix`.

---

## 2. Resolved (prior engagement — verified still fixed on 2026-10-13)

Each item below was spot-checked against the current source and confirmed
present. Commit hashes are from the original fix.

### Critical
| Was | Location | Fix |
|-----|----------|-----|
| `controller.reset_usage` did not exist (crash on "RESET USAGE") | `ui/info_dialog.py` | `3fb70c4` → `controller.traffic.reset_usage(ip)` ✓ verified |
| `PROFILES.keys()` on a list (crash opening protection panel) | `ui/protection_panel.py` | `3fb70c4` → `[p["name"] for p in PROFILES]` ✓ verified |

### High
| Was | Location | Fix |
|-----|----------|-----|
| DNS-spoof sniffer died permanently on first malformed packet | `network/dns_spoof.py` | `8a83c7f` → per-packet guard + restart loop ✓ |
| Accounting `ACCEPT` could shadow cut `DROP` | `system/iptables_manager.py` | `ae806e5` → append (`-A`) below top-inserted DROP ✓ |
| Synchronous third-party MAC lookup (privacy exfil + blocking) | `core/persistence.py` | `da20e1b` → removed `api.macvendors.com` + `requests` ✓ |

### Medium — concurrency
| Was | Location | Fix |
|-----|----------|-----|
| `self.devices` iterated without the lock | `core/controller.py`, `ui/dashboard.py` | `97bc37b` → `snapshot_devices()` under the lock ✓ |
| `_cut_ips`/`_mac_to_ip` mutated outside the lock | `network/traffic.py` | `499194e` → mutations under `self._lock` ✓ |
| Recon semaphore bound to the wrong event loop | `network/recon_engine.py` | `df666cd` → semaphore created inside the coroutine ✓ |

### Medium — security / side effects
| Was | Location | Fix |
|-----|----------|-----|
| Shell-string recon subprocess with interpolated IPs | `network/recon_engine.py` | `fb6ad05` → `create_subprocess_exec` + `ipaddress` validation ✓ |
| `nft flush ruleset` wiped the host's entire firewall | `system/stealth.py` | `4fd71aa` → only the `hakai_stealth` table ✓ |
| MITM kernel tuning applied as a side effect of detection | `system/netinfo.py`, `core/controller.py` | `a2c68db` → explicit `engage_mitm()` from `start()` ✓ |
| `accept_redirects` restored from the wrong saved value | `system/netinfo.py` | `a2c68db` → capture/restore `_orig_accept_redirects` ✓ |

### Low (prior)
| Was | Location | Fix |
|-----|----------|-----|
| `pkt[DNS].qd` dereferenced without a None guard | `network/recon_engine.py`, `network/mdns_sniff.py` | `a0267f5` ✓ |
| Synthetic "Device (Port:X Open)" stored as a hostname | `network/scanner.py` | `ae67ee5` ✓ |
| Stealth profile selection ignored (always random) | `system/stealth.py`, `core/controller.py` | `3a2457b` ✓ |
| IPv6 hijack toggle could only turn ON | `ui/dashboard.py` | `c32cee2` ✓ |
| Kill-switch blanket `OUTPUT -j DROP`, removed only once | `core/protector.py` | `37a1e52` → marked rule, loop-delete ✓ |
| Masquerade restore used hardcoded TTL/timestamps | `system/masquerade.py` | `c775e8f` → capture/restore originals ✓ |
| Linux-only `ping`/`arp` in MAC resolver | `network/arp.py` | `4e8792d` → OS-correct commands ✓ |
| Dead `deauth()` flood + no-op `_stop_by_mac` | `network/deauth.py` | `2646a0a` ✓ |
| Bare `except:` / `print` in library code | multiple | `5f65731`, `dc0edfc`, `0b5b61b` ✓ |
| Bandwidth-limit input unvalidated | `ui/limit_dialog.py` | `c6bfe88` ✓ |
| `venv`/`__pycache__` tracked in git | repo | `5323b63` ✓ |
| `requests` listed but unused | `requirements.txt` | `95636c1` ✓ (confirmed unused in app code) |

---

## 3. Dependency & tooling summary

- **scapy 2.8.0** ✓ current. Floor raised to `>=2.7.0` (RCE fix, N4).
- **Pillow 12.3.0** ✓ current. Floor raised to `>=11.0.0` (N4).
- **customtkinter 6.0.0** ✓ current; floor left at `>=5.2.0` (no advisory).
- **requests 2.34.2** present in `venv` but unused and not in `requirements.txt`
  — no action needed (can be `pip uninstall`ed locally).
- **mypy 2.4.0** installed this pass and configured; `mypy .` is now a clean gate.
- **pytest / ruff**: configured via `pyproject.toml`; both clean.
- Optional (behind `try/except`): `mac-vendor-lookup`, `ouilookup`, `bcc` — not
  installed, graceful fallbacks confirmed.

---

## 4. Manual / privileged testing still required

These need a Linux host with root and cannot be exercised on the Windows audit box:

- Full GUI launch and the Aegis/Protection toggles against real `nft`/`iptables`/`tc`.
- ARP cut/restore cycle and the watchdog (handle-leak check across repeated cycles).
- DNS spoof end-to-end (relevant to N5).
- IPv6 RA/DHCPv6 spoofing (N5/§1.3).
- WiFi deauth / PMF bypass (needs a monitor-mode adapter).
- Kernel-state capture/restore (sysctl, promisc, nft) on crash and partial-init paths.

---

## 5. How to verify

```
pytest -v                 # 22 tests, all passing
ruff check .              # clean (rule set pinned in pyproject.toml)
mypy .                    # Success: no issues found in 39 source files
ruff format --check .     # reports 35-file format debt — intentionally not enforced
```

---

# Phase 7 — Feature Review (feature-level verdicts)

Scope recap: **reliability & quality only.** Fix crashes/leaks; do *not* improve
offensive/evasion effectiveness; "unreachable ≠ removable — check purpose first."
Reachability below is grepped, not assumed (UI `command=`, `.bind`, Aegis-card
positional callbacks, controller call-sites).

## 7.1 Verdict table

| # | Feature | Entry (reachable?) | Works? | Value | Verdict |
|---|---------|--------------------|--------|-------|---------|
| 1 | Network scan / discovery (nmap + ARP + passive mDNS/SSDP/NBNS/DHCP) | SCAN button → `_start_scan` ✓ | yes (parsers unit-tested) | core | **KEEP** |
| 2 | Device identity / OUI classification | auto on scan ✓ | yes (P4-2 dual-dict OUI) | core | **KEEP** |
| 3 | Cut device (ARP + iptables acct + XDP + deauth) | CUT → `_cmd_cut` ✓ | yes (ARP-1 race fixed) | core (the product) | **KEEP** |
| 4 | Restore device | RESTORE → `_cmd_restore` ✓ | yes (restore hardened) | core | **KEEP** |
| 5 | Bandwidth limit / unlimit (tc HTB) | LIMIT/UNLIMIT ✓ | yes (tc restore hardened) | high | **KEEP** |
| 6 | Rename / nickname | RENAME → `_cmd_rename` ✓ | yes (atomic persist) | medium | **KEEP** |
| 7 | ARP guard (anti-spoof) | Protection panel + Aegis card ✓ | yes (hardened) | high (defensive) | **KEEP** |
| 8 | Self-healing sentry (re-pin gateway) | auto with ARP guard ✓ | yes (hardened) | high (defensive) | **KEEP** |
| 9 | Ghost firewall (nft stealth-drop) | Aegis card `_toggle_ghost` ✓ | yes (restore verified) | medium (defensive) | **KEEP** |
| 10 | Stack masquerade (sysctl TTL) | Protection panel:118 ✓ | yes (sysctl restore) | medium (evasion) | **KEEP** |
| 11 | Chameleon engine (MTU/MSS) | Aegis card `_toggle_chameleon` ✓ | yes | medium (evasion) | **KEEP** |
| 12 | Nuclear stealth (combo) | Aegis switch `_toggle_nuclear` ✓ | yes | medium (evasion) | **KEEP** |
| 13 | Mirage cloak (MAC/hostname spoof) | Protection panel ✓ | yes (restore verified) | medium (evasion) | **KEEP** |
| 14 | IPv6 hijack (RA + DHCPv6) | Aegis card `_toggle_ipv6` ✓ | yes (withdrawal RA on stop) | medium (offensive) | **KEEP** (as-is) |
| 15 | WiFi deauth | wired into cut when WiFi ✓ | yes (DEAUTH-1 lifecycle) | medium (offensive) | **KEEP** (as-is) |
| 16 | XDP/eBPF drop | part of cut ✓ | yes (graceful BCC-absent) | medium | **KEEP** |
| 17 | Device info dialog (ping/traceroute/reset) | double-click → `_open_info` ✓ | yes (marshalled) | medium | **KEEP** |
| 18 | Fingerprint (nmap -O -sV) | info dialog + auto ✓ | yes (`_parse_nmap` pure) | medium | **KEEP** |
| 19 | Traffic accounting (live/total) | table column ✓ | yes (counters hardened) | medium | **KEEP** |
| 20 | Static IP config (nmcli) | Protection panel ✓ | yes (validated) | low (admin) | **KEEP** |
| 21 | **DNS spoof** | `toggle_dns_spoof` has **no caller** ✗ | start path unreachable; stop path wired into restore | offensive | **INVESTIGATE** |
| 22 | **Monitor device** (ARP-spoof w/o drop) | `monitor_device` has **no UI caller** ✗ | code intact, no invocation | offensive (MITM intercept) | **INVESTIGATE** |
| 23 | **Kill-switch** (PROT-3) | Protection panel ✓ | **no** — self-undoes | defensive | **REBUILD** |
| 24 | **Device-state persistence** (`state.json`) | written at ctrl:90 & ctrl:560; `db.state` **never read** ✗ | write-only | low | **INVESTIGATE** |
| 25 | **Dashboard TTL handler** `_on_ttl_change` | **no widget, no bind, no caller** ✗ | dead; feature lives at protection_panel:118 | none | **REMOVE** |

## 7.2 Detail on the non-KEEP verdicts

**#25 `_on_ttl_change` — REMOVE (implemented this batch; see §7.3).**
Defined at `ui/dashboard.py:691`, wired to nothing (no `command=`, no `.bind`, no
call-site). The masquerade feature it would toggle is independently reachable at
`protection_panel.py:118`, so removing the handler orphans nothing. It is the one
clearly-safe, in-scope deletion: dead UI glue, not an engine capability. Note it
was wrapped in `run_async` during P4-6 — i.e. P4-6 threaded dead code; this
removes that artifact too.

**#21 DNS spoof — INVESTIGATE (not actioned; product decision).**
`controller.toggle_dns_spoof` has no UI caller, so the *start* path is
unreachable; only `dns.stop_spoof` runs (harmlessly) from restore/stop. Purpose
is real (DNS-redirect MITM) and the manager + iptables NAT restore logic is
sound. Two coherent resolutions, both the user's call: (a) wire a guarded UI
control, or (b) remove `DnsSpoofManager` + `controller.dns` to shed unreachable
offensive surface. **Not touched** — adding reach would "improve offensive
effectiveness"; removal is a product decision. Left reachable-by-restore-only.

**#22 Monitor device — INVESTIGATE (not actioned; product decision).**
`controller.monitor_device` (ARP-spoof-to-intercept without the drop half) has no
UI caller. Same shape as #21: intact offensive code, no entry point. Keep
documented; wiring or removal is the user's product call, not a reliability fix.

**#23 Kill-switch — REBUILD (not actioned; product decision + behavior change).**
PROT-3 (recorded in Phase 2): `_trigger_kill_switch` inserts a FORWARD DROP then
calls `ctrl.stop()`, whose teardown runs `disable_kill_switch` and *removes the
DROP it just inserted*. Net effect on a detected hijack: everything stops and the
network is **not** cut — the opposite of the armed promise. It genuinely does not
work. The fix is coherent (don't call `ctrl.stop()` from the trigger; leave the
protective DROP in place until manual disarm) but it is a **user-facing behavior
change** (leaves the operator's traffic dropped) on a defensive feature — a
product decision, flagged not forced. Recommended: Option A (persist the DROP,
manual disarm) to match the "network will drop on detection" label.

**#24 `state.json` — INVESTIGATE (not actioned).**
`db.save_state(self.devices)` writes `state.json` (ctrl:90 with an empty device
map at startup, ctrl:560 on explicit save), and `Persistence.__init__` loads
`self.state` (persistence.py:81) — but `self.state`/`db.state` is **never read**
anywhere. So the device-state half of persistence is write-only (config/nickname
persistence is separate and *is* used — keep it). Resolution is either "hydrate
cut/limited state on startup" (a feature) or "stop writing the unused file" (a
cleanup); both change behavior slightly. Low severity, left for a decision.

## 7.3 Implemented this batch

**FEAT-1 (severity: low) — remove dead `_on_ttl_change` handler.**
`ui/dashboard.py` — deleted the unreferenced `_on_ttl_change` method (verdict #25).
No feature lost (masquerade stays reachable via `protection_panel.py:118`); no
test referenced it. This is the only #7 verdict that is safe, in-scope, and not a
product decision. The INVESTIGATE/REBUILD items above are documented and left for
the user — they touch offensive features or change user-facing behavior, which the
"reliability only / don't improve offensive effectiveness / check purpose first"
scope reserves for an explicit decision.
