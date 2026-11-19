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
