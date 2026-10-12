# Hakai v3 — Code Audit

Read-only audit of the full application source (`main.py`, `core/`, `network/`, `system/`, `ui/`). `venv/` and `__pycache__/` were excluded. No files were modified.

Findings are grouped by category and ranked by severity within each group. Severity scale:

- **Critical** — crashes a reachable code path, corrupts state, or defeats the feature's core guarantee.
- **High** — wrong results, silent failure of a major feature, or a security/privacy exposure.
- **Medium** — concurrency hazard, cross-platform break, or fragile logic that fails on common inputs.
- **Low** — hygiene, dead code, cosmetic, convention violations.

---

## 1. Correctness — reachable crashes

### 1.1 `Controller` has no `reset_usage` method — "RESET USAGE" button crashes
- **Severity:** Critical (for the code path that uses it)
- **Location:** `ui/info_dialog.py:107` → calls `controller.reset_usage(ip)`; method only exists on `TrafficCounter` (`network/traffic.py:389`), not on `Controller`.
- **What's wrong:** `Controller` exposes `self.traffic` but has no `reset_usage` passthrough. Clicking "↺ RESET USAGE" raises `AttributeError: 'Controller' object has no attribute 'reset_usage'`.
- **Why it matters:** The handler runs on the Tk main thread; an unhandled exception there can tear down the UI event loop.
- **Fix:** Call `controller.traffic.reset_usage(ip)`, or add `def reset_usage(self, ip): self.traffic.reset_usage(ip)` to `Controller`.

### 1.2 `protection_panel` treats `PROFILES` (a list) as a dict — panel crashes on open
- **Severity:** Critical (for that path)
- **Location:** `ui/protection_panel.py:47` `prof_list = ["RANDOM"] + list(PROFILES.keys())`; `PROFILES` is a `list[dict]` (`system/stealth.py:10`).
- **What's wrong:** `list.keys()` doesn't exist → `AttributeError` the moment `show_protection_panel` builds its widgets.
- **Why it matters:** The entire Protection/Stealth modal is unusable.
- **Fix:** `prof_list = ["RANDOM"] + [p["name"] for p in PROFILES]`. Note `toggle_stealth` ignores the chosen `profile` anyway (see 3.5), so the selection is also non-functional downstream.

### 1.3 DNS-spoof sniffer dies permanently on the first malformed packet
- **Severity:** High
- **Location:** `network/dns_spoof.py:54-87`, specifically `qname = pkt[DNS].qd.qname` at line 72 with no guard, inside `_cb`, and the outer `except Exception: self._running = False` at line 86-87.
- **What's wrong:** A DNS packet with `qr == 0` but `qd is None` (or any other per-packet error) raises inside the `prn` callback. Scapy propagates it out of `sniff`, the `except` sets `self._running = False`, and the loop never restarts — DNS spoofing silently stops for all targets.
- **Why it matters:** One unexpected packet disables the feature with no log.
- **Fix:** Guard `if not pkt[DNS].qd: return` inside `_cb`, wrap the body in its own try/except that only logs, and don't clear `_running` on a per-packet error.

### 1.4 `show_info_dialog` / `show_protection_panel` are defined but never wired
- **Severity:** Low (dead code today) — but see 1.1/1.2: if wired as-is, both crash.
- **Location:** `ui/info_dialog.py:14`, `ui/protection_panel.py:10`. No caller exists in `ui/dashboard.py` or elsewhere.
- **Why it matters:** Significant UI (device info, ping/traceroute/fingerprint, all defensive toggles, static-IP config) is unreachable, and the two bugs above are latent until someone hooks these up.
- **Fix:** Wire them from the dashboard and fix 1.1/1.2 first, or remove if intentionally abandoned.

---

## 2. Concurrency

### 2.1 `self.devices` iterated without the lock while sniffer threads mutate it
- **Severity:** Medium–High
- **Location:** `core/controller.py:323` (`for ip, dev in self.devices.items()`), `:328` (`for ip in self.devices`), `:558` (`update_device_speeds`), plus `ui/dashboard.py:207` and `:223` (`self.ctrl.devices.values()`).
- **What's wrong:** The intel-sniffer callbacks (`_on_intel_*`) add/modify `self.devices` under `self._lock`, but these loops read/iterate it with no lock held. Adding a key during iteration raises `RuntimeError: dictionary changed size during iteration`.
- **Why it matters:** Intermittent crashes during an active scan while mDNS/DHCP intel is arriving — exactly the busy moments.
- **Fix:** Snapshot under the lock before iterating: `with self._lock: items = list(self.devices.items())`, then iterate the copy. `cut_all`/`restore_all` already use `list(...)`; apply the same everywhere, including the UI refresh loop.

### 2.2 `_cut_ips`, `_mac_to_ip` mutated outside the lock
- **Severity:** Medium
- **Location:** `network/traffic.py:88` (`register_device` sets `_mac_to_ip` outside lock), `:92-98` (`mark_cut`/`unmark_cut` mutate `_cut_ips` outside lock) — while `_pkt` (`:274-305`) and `get` (`:338-348`) read them under the lock.
- **What's wrong:** Mixed locked/unlocked access to shared mutable state across the scapy sniffer thread, the iptables poll thread, and the UI thread.
- **Why it matters:** Lost updates and occasional transient-wrong speed/cut state.
- **Fix:** Perform all mutations of `_cut_ips`/`_mac_to_ip` under `self._lock`.

### 2.3 `ReconEngine.semaphore` is bound to the wrong event loop
- **Severity:** Medium (deep recon effectively broken)
- **Location:** `network/recon_engine.py:15` `self.semaphore = asyncio.Semaphore(25)` created at construction; used via `async with self.semaphore` in `run_recon` (`:28`), which runs under a fresh loop created by `asyncio.run(_run())` in `core/controller.py:246` — a new loop per `run_deep_recon` call, per device.
- **What's wrong:** An `asyncio.Semaphore` created outside a running loop (or in a different loop) raises `RuntimeError: ... got Future attached to a different loop` when first awaited under `asyncio.run`. Each device's recon thread spins its own loop, so the shared semaphore cannot be reused across them.
- **Why it matters:** `run_recon` raises; the exception dies silently in the detached thread (`threading.Thread(target=lambda: asyncio.run(_run()))`), so Stages 3–5 recon produces nothing and no error surfaces.
- **Fix:** Create the semaphore inside the coroutine (per-loop), or run all recon on one persistent event loop/thread instead of `asyncio.run` per call.

### 2.4 `classify_device` mutates `dev.confidence` as a side effect, called from many threads
- **Severity:** Low
- **Location:** `core/persistence.py:546, 655` sets `dev.confidence`; invoked from controller callbacks, the scanner, and the UI refresh loop.
- **Why it matters:** A "classify" helper that writes back into the device object makes races harder to reason about and can momentarily report a stale confidence.
- **Fix:** Return `(confidence, label)` and let the caller assign under the lock, or document that it must be called with the device lock held.

---

## 3. Logic / robustness

### 3.1 Accounting `ACCEPT` rules can shadow cut `DROP` rules in FORWARD
- **Severity:** High
- **Location:** `system/iptables_manager.py:30-38` (`add_accounting` inserts `-I FORWARD 1 ... -j ACCEPT`) vs. `network/arp.py:209-217` and `system/iptables_manager.py:53-59` (`add_drop` inserts `-I FORWARD 1 ... -j DROP`). Accounting is (re)applied for every device in `core/controller.py:313-314` on each scan.
- **What's wrong:** Both managers insert at position 1 of the same chain, and iptables is first-match-wins. The relative order of a device's ACCEPT and DROP depends on insertion timing. If an ACCEPT ends up above the DROP (e.g. a scan runs and re-touches ordering while a device is cut, or accounting is added after the drop), the device is **not actually cut**.
- **Why it matters:** The product's core guarantee ("CUT = no internet") can silently fail depending on scan/cut timing.
- **Fix:** Use a dedicated chain with explicit precedence (DROP chain jumped to before the accounting chain), or make the accounting rules match-and-return without `ACCEPT`, or account via a separate chain that cannot shadow DROP. At minimum, always (re)insert DROP above ACCEPT and never re-insert ACCEPT while an IP is in `_dropped`.

### 3.2 `lookup_oui` makes a synchronous third-party HTTP call per unknown MAC
- **Severity:** High (privacy + performance)
- **Location:** `core/persistence.py:202-207` — `requests.get("https://api.macvendors.com/{mac}", timeout=2)`; reachable from `Device.__init__` (`core/device.py:16`) and the scanner fallback paths.
- **What's wrong:** Every MAC not in the local dict/library is sent to an external service, on the calling thread, with a 2 s blocking timeout each.
- **Why it matters:** (a) **Privacy**: the full MAC list of the local network is exfiltrated to a third party. (b) **Performance**: constructing devices or scanning can block for seconds × number of unknown devices. (c) There are **two** parallel vendor systems (`persistence.lookup_oui` and `network/oui_lookup.get_vendor`) with different dicts and behavior, used inconsistently across the code.
- **Fix:** Drop the online fallback (or make it opt-in and async/cached). Consolidate on a single OUI lookup module. Never call it from `Device.__init__` on the hot path.

### 3.3 Kernel is reconfigured for MITM as a side effect of *detecting* the network
- **Severity:** Medium (security posture / surprising side effects)
- **Location:** `system/netinfo.py:156-178`, inside `_detect_network_linux`, which `main.py:74` calls at startup before any user action.
- **What's wrong:** Merely launching the app enables `ip_forward`, sets `rp_filter=0`, `proxy_arp=1`, disables send/accept redirects, puts the NIC in promiscuous mode, and disables NIC offloads — before the operator chooses to do anything.
- **Why it matters:** Detection should be read-only. Coupling kernel mutation to detection means the host's routing/filtering posture changes just by opening the tool, and partial failures leave it half-configured. `restore_network` also restores `accept_redirects` from `_orig_redirects` (the *send_redirects* value — see 3.4), so the revert is wrong.
- **Fix:** Move all `sysctl`/`ip link`/`ethtool` mutation out of detection into an explicit "engage" step, and capture/restore each sysctl independently.

### 3.4 `restore_network` restores `accept_redirects` from the wrong saved value
- **Severity:** Medium
- **Location:** `system/netinfo.py:200-202`. Only `_orig_forwarding`, `_orig_rp_filter`, `_orig_redirects` are captured (`:158-160`); `accept_redirects` original is never saved, yet `:202` restores `accept_redirects={info._orig_redirects}` (the send_redirects original).
- **Why it matters:** After exit, `accept_redirects` is left at whatever `send_redirects` happened to be, not its true original.
- **Fix:** Capture `_orig_accept_redirects` separately and restore from it.

### 3.5 `toggle_stealth(profile=...)` silently ignores the profile
- **Severity:** Low
- **Location:** `core/controller.py:479-492` passes nothing to `engage_mirage_cloak` (`system/stealth.py:22`), which always does `random.choice(PROFILES)`.
- **Why it matters:** The profile combobox in the protection panel has no effect; "RANDOM" is the only behavior.
- **Fix:** Thread the selected profile name into `engage_mirage_cloak` and select it there.

### 3.6 `_toggle_ipv6` can only turn hijack ON
- **Severity:** Low
- **Location:** `ui/dashboard.py:423-427` always calls `toggle_ipv6_hijack(True, ...)`.
- **Why it matters:** The IPv6 switch cannot be turned off from the UI; `stop()` only happens at shutdown.
- **Fix:** Track state and pass the toggled boolean, mirroring `_toggle_ghost`.

### 3.7 `mdns_sniff` / `recon_engine` / `dns_spoof` dereference `pkt[...].qd` without a None check
- **Severity:** Low–Medium
- **Location:** `network/recon_engine.py:52` (`pkt[DNS].qd.qname`), `network/mdns_sniff.py:93-95` (indexes `dns.qd[i]`), `network/dns_spoof.py:72`. Several are only shielded by broad `except` blocks that mask the failure.
- **Why it matters:** Malformed/edge DNS packets throw; depending on the caller this either spams restarts (controller intel loop) or kills a feature (3.3 above).
- **Fix:** Explicit `if not dns.qd: ...` guards and precise exception handling.

### 3.8 Hostname port-probe fallback stores a fake hostname string
- **Severity:** Low
- **Location:** `network/scanner.py:70-71` sets `hn = f"Device (Port:{port} Open)"`, which later survives `_is_junk_hostname` and gets shown as a real hostname.
- **Fix:** Store this as a low-confidence *identity hint*, not as `hostname`.

---

## 4. Security

### 4.1 Shell-string subprocesses with interpolated values in recon
- **Severity:** Medium
- **Location:** `network/recon_engine.py:153` (`create_subprocess_shell(f"dig @{dns_server} -x {ip} +short")`) and `:167` (`"ip -6 neigh show"`).
- **What's wrong:** Using the shell with f-string interpolation of `ip`/`dns_server`. These are normally IPs from scan/gateway data, but nothing validates them as IPs before interpolation; a crafted PTR/hostname flowing into one of these would be command injection. The second call uses the shell for no reason.
- **Why it matters:** Command execution via network-derived data is a classic injection sink, and the tool runs as root.
- **Fix:** Use `create_subprocess_exec("dig", "@"+dns_server, "-x", ip, "+short")` (arg list, no shell), and validate `ip`/`dns_server` with `ipaddress.ip_address()` first.

### 4.2 `engage_mirage_cloak` runs `nft flush ruleset` — wipes the host's entire nftables config
- **Severity:** Medium
- **Location:** `system/stealth.py:56`.
- **What's wrong:** `nft flush ruleset` deletes *all* nftables rules on the machine, not just Hakai's, with no backup/restore. `disengage_stealth` only deletes the `hakai_stealth` table (`:78`); the user's original ruleset is gone.
- **Why it matters:** Destructive to any host firewall the operator relies on; not reversible.
- **Fix:** Create/replace only the `hakai_stealth` table; never flush the global ruleset. If isolation is needed, save and restore the ruleset explicitly.

### 4.3 Kill-switch inserts a blanket `OUTPUT -j DROP`
- **Severity:** Low
- **Location:** `core/protector.py:122-125` inserts `iptables -I OUTPUT 1 -j DROP`; `disable_kill_switch` (`:115-120`) deletes it once.
- **What's wrong:** Drops *all* host egress (including the tool's own ARP-restore packets), and if triggered repeatedly multiple identical rules accumulate while removal deletes only one.
- **Fix:** Use a uniquely-marked rule and delete in a loop until absent; consider scoping to the affected interface rather than all OUTPUT.

---

## 5. Cross-platform

### 5.1 Windows gateway-MAC resolver runs Linux-only `ping`/`arp` syntax
- **Severity:** Low (guarded by try/except, so it silently no-ops)
- **Location:** `network/arp.py:173-175` (`ping -c 1 -W 1`) and `:195-196` (`arp -n`); started unconditionally from `core/controller.py:80-82` when a gateway exists. Windows `ping` uses `-n`/`-w`; `arp -n` is not valid.
- **Why it matters:** On Windows the gateway MAC never resolves, so ARP Guard / resolution paths quietly do nothing. (The actual cut/spoof engine is Linux-only by design, which is fine, but the failure is silent.)
- **Fix:** Branch on `sys.platform`, or skip the resolver on Windows and log that it's unsupported.

### 5.2 `masquerade` restore sets TTL to a hardcoded 64, not the captured original
- **Severity:** Low
- **Location:** `system/masquerade.py:14-18` — disable path writes `ip_default_ttl=64` and `tcp_timestamps=1` unconditionally.
- **Why it matters:** If the host's real default TTL wasn't 64, the "restore" is wrong.
- **Fix:** Capture originals on enable and restore them.

---

## 6. Dead code / misleading implementations

### 6.1 `DeauthManager.deauth()` flood is never called; `_stop_by_mac` is a no-op
- **Severity:** Low
- **Location:** `network/deauth.py:117-153` (`deauth` only referenced in the module docstring) and `:161-164` (`_stop_by_mac` is `pass` with a misleading comment). Cuts use `start_pmf_bypass` (`core/controller.py:377-378`) instead.
- **Why it matters:** The documented deauth-flood capability doesn't run; `_stop_by_mac` pretends to stop existing floods but does nothing, and `_stops` is keyed by `ip` while `_stop_by_mac` reasons about MACs.
- **Fix:** Remove the unused method or wire it; implement `_stop_by_mac` or delete it.

### 6.2 Device state is serialized but never loaded back
- **Severity:** Low
- **Location:** `core/device.py:67-81` (`to_state`), `core/persistence.py:53-55` (`save_state`), `:46` (`self.state` loaded) — nothing ever reconstructs devices from `state.json`.
- **Fix:** Either implement restore-on-start or drop the serialization.

### 6.3 `fingerprint` callback writes the nickname back to itself
- **Severity:** Low
- **Location:** `core/controller.py:453` `db.set_nickname(dev.mac, dev.nickname)` — `dev.nickname` reads from `db.get_nickname`, so this re-writes the same value (and touches disk) for no effect.
- **Fix:** Remove the line.

### 6.4 Dead/unused locals and redundant computation
- **Severity:** Low
- **Location:** `system/netinfo.py:90` `mask_int = int(mask.replace(".", ""))` is computed and never used. `main.py:107` imports `customtkinter as ctk` but never uses `ctk` in `main`.
- **Fix:** Delete.

### 6.5 Non-functional / placeholder network params
- **Severity:** Low
- **Location:** `network/ipv6.py:44` advertises the documentation prefix `2001:db8:1::` (RFC 3849 — not routable) and `fe80::1` as DNS; `network/recon_engine.py:60-86` "SSL CN" extraction is ad-hoc byte-scanning of the DER cert that will frequently return garbage.
- **Why it matters:** These features appear implemented but won't produce correct results.
- **Fix:** Use a real prefix/DNS for IPv6; parse the cert with `cryptography`/`ssl.getpeercert()` text form instead of byte scanning.

---

## 7. Conventions & hygiene

### 7.1 Pervasive bare `except:` and broad `except Exception: pass`
- **Severity:** Low (but violates the project's stated conventions)
- **Location (bare `except:`):** `network/arp.py:117, 329`; `network/deauth.py:113`; `network/ipv6.py:48, 66`; `core/persistence.py:206`. Plus dozens of `except Exception: pass` that swallow all errors silently (e.g. `core/controller.py:501`, `system/*`).
- **Why it matters:** CLAUDE.md requires "No bare `except:` — catch specific exceptions" and logging via `logging`, not silent passes. Silent catches are the direct cause of several bugs above being invisible (1.3, 2.3).
- **Fix:** Catch specific exceptions and log them via the `logging` module.

### 7.2 `print()` used for diagnostics in library code
- **Severity:** Low
- **Location:** `network/traffic.py:243`, `system/tc_manager.py:66, 73`, and the `print(...)` banners in `main.py`.
- **Why it matters:** CLAUDE.md: "Log via the `logging` module, never `print` in library code."
- **Fix:** Route through `logging`.

### 7.3 Missing/implicit dependencies in `requirements.txt`
- **Severity:** Low
- **Location:** `requirements.txt` lists scapy, customtkinter, Pillow, requests. Code imports `mac_vendor_lookup` (`core/persistence.py:94`), `ouilookup` (`network/oui_lookup.py:63`), and `bcc` (`network/xdp_engine.py:64`) — all optional via try/except, but undocumented.
- **Fix:** Add optional deps with a comment (or an `extras`/`requirements-optional.txt`).

### 7.4 `venv/` and `__pycache__/` are tracked in git
- **Severity:** Low
- **Location:** repo root — `git status` shows many tracked `*.pyc` and a committed `venv/` tree; there is no top-level `.gitignore`.
- **Why it matters:** Bloats the repo, causes noisy diffs (the whole `__pycache__` set shows as modified), and ties the repo to one machine's interpreter.
- **Fix:** Add a `.gitignore` with `venv/`, `__pycache__/`, `*.pyc`, `~/.sadok_hakai`, and `git rm -r --cached` the tracked artifacts.

### 7.5 No type hints on many signatures; missing input validation on limit entry
- **Severity:** Low
- **Location:** CLAUDE.md requires type hints on every function signature; several (e.g. `system/stealth.py`, `system/network_manager.py`, `ui/*`) omit them. `ui/limit_dialog.py:46-67` reads `sv.get()` (an `IntVar`) with no bounds — a blank/invalid entry raises `TclError`, and negatives would be passed straight to `tc` as a rate.
- **Fix:** Add annotations; validate the limit is a positive int before calling `limit_device`.

---

## Summary table

| # | Severity | Category | Location |
|---|----------|----------|----------|
| 1.1 | Critical | Crash | `ui/info_dialog.py:107` |
| 1.2 | Critical | Crash | `ui/protection_panel.py:47` |
| 1.3 | High | Silent feature death | `network/dns_spoof.py:72,86` |
| 3.1 | High | Cut can silently fail | `system/iptables_manager.py:30-59`, `network/arp.py:209` |
| 3.2 | High | Privacy + perf | `core/persistence.py:202` |
| 2.1 | Med–High | Concurrency crash | `core/controller.py:323,328,558`; `ui/dashboard.py:207,223` |
| 2.2 | Medium | Concurrency | `network/traffic.py:88,92,98` |
| 2.3 | Medium | Recon broken | `network/recon_engine.py:15`; `core/controller.py:246` |
| 3.3 | Medium | Side-effecting detection | `system/netinfo.py:156-178` |
| 3.4 | Medium | Wrong restore | `system/netinfo.py:200-202` |
| 3.7 | Low–Med | Edge-case crashes | `recon_engine.py:52`, `mdns_sniff.py:93`, `dns_spoof.py:72` |
| 4.1 | Medium | Shell injection sink | `network/recon_engine.py:153,167` |
| 4.2 | Medium | Destroys host firewall | `system/stealth.py:56` |
| 5.1 | Low | Cross-platform no-op | `network/arp.py:173,195` |
| 1.4, 3.5, 3.6, 3.8, 4.3, 5.2, 6.x, 7.x | Low | Dead code / conventions / hygiene | see sections |
