# Hakai v3 — Code Audit

Read-only audit of the full application source (`main.py`, `core/`, `network/`, `system/`, `ui/`). `venv/` and `__pycache__/` were excluded. No files were modified by this report.

Findings are grouped by category and ranked by severity within each group. Severity scale:

- **Critical** — crashes a reachable code path, corrupts state, or defeats the feature's core guarantee.
- **High** — wrong results, silent failure of a major feature, or a security/privacy exposure.
- **Medium** — concurrency hazard, cross-platform break, or fragile logic that fails on common inputs.
- **Low** — hygiene, dead code, cosmetic, convention violations.

> **Note:** All Critical items (`3fb70c4`), all three High items (`8a83c7f`, `ae806e5`,
> `da20e1b`), and the three concurrency hazards (`97bc37b`, `499194e`, `df666cd`) are fixed and
> no longer present. They are recorded in §9. The highest-severity remaining findings are the
> **Medium** security / side-effect items in §4–§5.

---

## 1. Correctness — reachable crashes / silent feature death

### 1.1 Unwired dialogs hide latent crashes until hooked up
- **Severity:** Low (dead code today)
- **Location:** `ui/info_dialog.py:14` (`show_info_dialog`) and `ui/protection_panel.py:10` (`show_protection_panel`) — no caller exists in `ui/dashboard.py` or elsewhere.
- **What's wrong:** A large amount of UI (device info, ping/traceroute/fingerprint/reset, all defensive toggles, static-IP config) is unreachable. The two Critical bugs fixed in `3fb70c4` lived here and were only latent because nothing calls these functions.
- **Why it matters:** Features silently don't exist, and regressions in them won't surface until someone wires them.
- **Fix:** Wire them from the dashboard (and re-test), or remove if abandoned.

---

## 2. Logic / robustness

> Fixed since last audit (now in §9): accounting `ACCEPT` could shadow cut `DROP` (`ae806e5`),
> and `lookup_oui` made a synchronous third-party HTTP call per unknown MAC (`da20e1b`).

### 2.1 `mdns_sniff` / `recon_engine` dereference `pkt[...].qd` without a None check
- **Severity:** Low–Medium
- **Location:** `network/recon_engine.py:52` (`pkt[DNS].qd.qname`), `network/mdns_sniff.py:93-95` (`dns.qd[i]`). Both are only shielded by broad `except` blocks that mask the failure. (`network/dns_spoof.py` was fixed in `8a83c7f`.)
- **Why it matters:** Malformed/edge DNS packets throw; depending on the caller this spams restarts (controller intel loop) or silently drops recon data.
- **Fix:** Explicit `if not dns.qd: ...` guards and precise exception handling.

### 2.2 Hostname port-probe fallback stores a fake hostname string
- **Severity:** Low
- **Location:** `network/scanner.py:70-71` sets `hn = f"Device (Port:{port} Open)"`, which later survives `_is_junk_hostname` and is shown as a real hostname.
- **Fix:** Store this as a low-confidence identity hint, not as `hostname`.

### 2.3 `toggle_stealth(profile=...)` silently ignores the selected profile
- **Severity:** Low
- **Location:** `core/controller.py:479-492` passes nothing to `engage_mirage_cloak` (`system/stealth.py:22`), which always does `random.choice(PROFILES)`.
- **Why it matters:** The profile combobox in the protection panel has no effect; "RANDOM" is the only behavior.
- **Fix:** Thread the selected profile name into `engage_mirage_cloak` and select it there.

### 2.4 `_toggle_ipv6` can only turn hijack ON
- **Severity:** Low
- **Location:** `ui/dashboard.py:423-427` always calls `toggle_ipv6_hijack(True, ...)`.
- **Why it matters:** The IPv6 switch cannot be turned off from the UI; `stop()` only happens at shutdown.
- **Fix:** Track state and pass the toggled boolean, mirroring `_toggle_ghost`.

---

## 3. Concurrency

> Fixed since last audit (now in §9): `self.devices` iterated without the lock (`97bc37b`),
> `_cut_ips`/`_mac_to_ip` mutated outside the lock (`499194e`), and the `ReconEngine` semaphore
> bound to the wrong event loop (`df666cd`).

### 3.1 `classify_device` mutates `dev.confidence` as a side effect, called from many threads
- **Severity:** Low
- **Location:** `core/persistence.py:546, 655` set `dev.confidence`; invoked from controller callbacks, the scanner, and the UI refresh loop.
- **Why it matters:** A "classify" helper that writes back into the device makes races harder to reason about and can momentarily report stale confidence.
- **Fix:** Return `(confidence, label)` and assign under the lock, or require the device lock be held.

---

## 4. Security

### 4.1 Shell-string subprocesses with interpolated values in recon
- **Severity:** Medium
- **Location:** `network/recon_engine.py:153` (`create_subprocess_shell(f"dig @{dns_server} -x {ip} +short")`) and `:167` (`"ip -6 neigh show"`).
- **What's wrong:** Uses the shell with f-string interpolation of `ip`/`dns_server`. Nothing validates these as IPs before interpolation; network-derived data flowing into one of these would be command injection. The second call uses the shell for no reason.
- **Why it matters:** Command execution via network-derived data, and the tool runs as root.
- **Fix:** `create_subprocess_exec("dig", "@"+dns_server, "-x", ip, "+short")` (arg list, no shell); validate `ip`/`dns_server` with `ipaddress.ip_address()` first.

### 4.2 `engage_mirage_cloak` runs `nft flush ruleset` — wipes the host's entire nftables config
- **Severity:** Medium
- **Location:** `system/stealth.py:56`.
- **What's wrong:** `nft flush ruleset` deletes *all* nftables rules on the machine, not just Hakai's, with no backup. `disengage_stealth` (`:78`) only deletes the `hakai_stealth` table; the user's original ruleset is gone.
- **Why it matters:** Destructive to any host firewall the operator relies on; not reversible.
- **Fix:** Create/replace only the `hakai_stealth` table; never flush the global ruleset. Save and restore the ruleset if isolation is required.

### 4.3 Kill-switch inserts a blanket `OUTPUT -j DROP`
- **Severity:** Low
- **Location:** `core/protector.py:122-125` inserts `iptables -I OUTPUT 1 -j DROP`; `disable_kill_switch` (`:115-120`) deletes it once.
- **What's wrong:** Drops *all* host egress (including the tool's own ARP-restore packets), and repeated triggers accumulate duplicate rules while removal deletes only one.
- **Fix:** Use a uniquely-marked rule and delete in a loop until absent; consider scoping to the affected interface.

---

## 5. Side-effecting detection / restore correctness

### 5.1 Kernel is reconfigured for MITM as a side effect of *detecting* the network
- **Severity:** Medium
- **Location:** `system/netinfo.py:156-178`, inside `_detect_network_linux`, which `main.py:74` calls at startup before any user action.
- **What's wrong:** Merely launching the app enables `ip_forward`, sets `rp_filter=0`, `proxy_arp=1`, disables send/accept redirects, enables promiscuous mode, and disables NIC offloads — before the operator chooses to do anything.
- **Why it matters:** Detection should be read-only; coupling kernel mutation to it changes the host's routing/filtering posture just by opening the tool, and partial failures leave it half-configured.
- **Fix:** Move all `sysctl`/`ip link`/`ethtool` mutation into an explicit "engage" step; capture/restore each sysctl independently.

### 5.2 `restore_network` restores `accept_redirects` from the wrong saved value
- **Severity:** Medium
- **Location:** `system/netinfo.py:200-202`. Only `_orig_forwarding`, `_orig_rp_filter`, `_orig_redirects` are captured (`:158-160`); `accept_redirects` original is never saved, yet `:202` restores `accept_redirects={info._orig_redirects}` (the send_redirects original).
- **Why it matters:** After exit, `accept_redirects` is left at whatever `send_redirects` happened to be, not its true original.
- **Fix:** Capture `_orig_accept_redirects` separately and restore from it.

### 5.3 `masquerade` restore uses hardcoded values, not captured originals
- **Severity:** Low
- **Location:** `system/masquerade.py:14-18` — the disable path writes `ip_default_ttl=64` and `tcp_timestamps=1` unconditionally.
- **Why it matters:** If the host's real default TTL/timestamps weren't those values, the "restore" is wrong.
- **Fix:** Capture originals on enable and restore them.

---

## 6. Cross-platform

### 6.1 Windows gateway-MAC resolver runs Linux-only `ping`/`arp` syntax
- **Severity:** Low (guarded by try/except, so it silently no-ops)
- **Location:** `network/arp.py:173-175` (`ping -c 1 -W 1`) and `:195-196` (`arp -n`); started unconditionally from `core/controller.py:80-82` when a gateway exists. Windows `ping` uses `-n`/`-w`; `arp -n` is invalid.
- **Why it matters:** On Windows the gateway MAC never resolves, so resolution/guard paths quietly do nothing. (The cut/spoof engine is Linux-only by design, which is fine; the failure is just silent.)
- **Fix:** Branch on `sys.platform`, or skip the resolver on Windows and log that it's unsupported.

---

## 7. Dead code / misleading implementations

### 7.1 `DeauthManager.deauth()` flood is never called; `_stop_by_mac` is a no-op
- **Severity:** Low
- **Location:** `network/deauth.py:117-153` (`deauth` referenced only in the module docstring) and `:161-164` (`_stop_by_mac` is `pass`). Cuts use `start_pmf_bypass` (`core/controller.py:377-378`) instead.
- **Why it matters:** The documented deauth-flood capability doesn't run; `_stop_by_mac` pretends to stop existing floods but does nothing, and `_stops` is keyed by `ip` while `_stop_by_mac` reasons about MACs.
- **Fix:** Remove the unused method or wire it; implement `_stop_by_mac` or delete it.

### 7.2 Device state is serialized but never loaded back
- **Severity:** Low
- **Location:** `core/device.py:67-81` (`to_state`), `core/persistence.py:53-55` (`save_state`), `:46` (`self.state` loaded) — nothing reconstructs devices from `state.json`.
- **Fix:** Implement restore-on-start or drop the serialization.

### 7.3 `fingerprint` callback writes the nickname back to itself
- **Severity:** Low
- **Location:** `core/controller.py:453` `db.set_nickname(dev.mac, dev.nickname)` — `dev.nickname` reads from `db.get_nickname`, so this re-writes the same value (and touches disk) for no effect.
- **Fix:** Remove the line.

### 7.4 Dead/unused locals
- **Severity:** Low
- **Location:** `system/netinfo.py:90` `mask_int = int(mask.replace(".", ""))` computed and never used; `main.py:107` imports `customtkinter as ctk` but never uses `ctk` in `main`.
- **Fix:** Delete.

### 7.5 Non-functional / placeholder network params
- **Severity:** Low
- **Location:** `network/ipv6.py:44` advertises the documentation prefix `2001:db8:1::` (RFC 3849 — not routable) and `fe80::1` as DNS; `network/recon_engine.py:60-86` "SSL CN" extraction is ad-hoc byte-scanning of the DER cert that will frequently return garbage.
- **Fix:** Use a real prefix/DNS for IPv6; parse the cert with `ssl.getpeercert()` / `cryptography` instead of byte scanning.

---

## 8. Conventions & hygiene

### 8.1 Pervasive bare `except:` and broad `except Exception: pass`
- **Severity:** Low (violates the project's stated conventions)
- **Location (bare `except:`):** `network/arp.py:117, 329`; `network/deauth.py:113`; `network/ipv6.py:48, 66`; `core/persistence.py:206`. Plus dozens of `except Exception: pass` that swallow all errors (e.g. `core/controller.py:501`, `system/*`).
- **Why it matters:** CLAUDE.md requires "No bare `except:`" and logging via `logging`. Silent catches are the direct cause of several bugs here being invisible (1.1, 3.3).
- **Fix:** Catch specific exceptions and log via the `logging` module.

### 8.2 `print()` used for diagnostics in library code
- **Severity:** Low
- **Location:** `network/traffic.py:243`, `system/tc_manager.py:66, 73`, plus the `print(...)` banners in `main.py`.
- **Why it matters:** CLAUDE.md: "Log via the `logging` module, never `print` in library code."
- **Fix:** Route through `logging`.

### 8.3 Missing/implicit dependencies in `requirements.txt`
- **Severity:** Low
- **Location:** `requirements.txt` lists scapy, customtkinter, Pillow, requests. Code imports `mac_vendor_lookup` (`core/persistence.py:94`), `ouilookup` (`network/oui_lookup.py:63`) and `bcc` (`network/xdp_engine.py:64`) — all optional via try/except, but undocumented.
- **Fix:** Document optional deps (comment or `requirements-optional.txt`).

### 8.4 `venv/` and `__pycache__/` are tracked in git
- **Severity:** Low
- **Location:** repo root — `git status` shows many tracked `*.pyc` and a committed `venv/` tree; no top-level `.gitignore`.
- **Why it matters:** Bloats the repo, produces noisy diffs (the whole `__pycache__` set shows as modified), and ties the repo to one machine's interpreter.
- **Fix:** Add `.gitignore` (`venv/`, `__pycache__/`, `*.pyc`), and `git rm -r --cached` the tracked artifacts.

### 8.5 Missing type hints; no input validation on the limit entry
- **Severity:** Low
- **Location:** CLAUDE.md requires type hints on every signature; several (`system/stealth.py`, `system/network_manager.py`, `ui/*`) omit them. `ui/limit_dialog.py:46-67` reads `sv.get()` (an `IntVar`) with no bounds — a blank/invalid entry raises `TclError`, and negatives would be passed straight to `tc` as a rate.
- **Fix:** Add annotations; validate the limit is a positive int before calling `limit_device`.

---

## 9. Resolved since last audit

| # | Was | Location | Fixed in |
|---|-----|----------|----------|
| — | Critical: `controller.reset_usage` did not exist | `ui/info_dialog.py:107` | `3fb70c4` → `controller.traffic.reset_usage(ip)` |
| — | Critical: `PROFILES.keys()` on a list | `ui/protection_panel.py:47` | `3fb70c4` → `[p["name"] for p in PROFILES]` |
| — | High: DNS-spoof sniffer died permanently on first malformed packet | `network/dns_spoof.py` | `8a83c7f` → per-packet guard + try/except, sniff restart loop |
| — | High: accounting `ACCEPT` could shadow cut `DROP` | `system/iptables_manager.py` | `ae806e5` → accounting rules appended (`-A`) below top-inserted DROP |
| — | High: synchronous third-party MAC lookup (privacy + blocking) | `core/persistence.py` | `da20e1b` → removed `api.macvendors.com` fallback + `requests` import |
| — | Medium: `self.devices` iterated without the lock (dict-mutation crash) | `core/controller.py`, `ui/dashboard.py` | `97bc37b` → `Controller.snapshot_devices()` under the lock |
| — | Medium: `_cut_ips`/`_mac_to_ip` mutated outside the lock | `network/traffic.py` | `499194e` → mutations moved under `self._lock` |
| — | Medium: recon semaphore bound to the wrong event loop | `network/recon_engine.py` | `df666cd` → semaphore created inside the coroutine |

---

## Summary table (current)

All Critical, High, and concurrency items are fixed (see §9). Remaining, highest first:

| # | Severity | Category | Location |
|---|----------|----------|----------|
| 4.1 | Medium | Shell injection sink | `network/recon_engine.py:153,167` |
| 4.2 | Medium | Destroys host firewall | `system/stealth.py:56` |
| 5.1 | Medium | Side-effecting detection | `system/netinfo.py:156-178` |
| 5.2 | Medium | Wrong restore | `system/netinfo.py:200-202` |
| 2.1 | Low–Med | Edge-case crashes | `recon_engine.py:52`, `mdns_sniff.py:93` |
| 3.1 | Low | Side-effecting classify | `core/persistence.py:546,655` |
| 1.1, 2.2-2.4, 4.3, 5.3, 6.1, 7.x, 8.x | Low | Dead code / cross-platform / conventions / hygiene | see sections |
