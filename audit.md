# Hakai v3 — Code Audit

Read-only audit of the full application source (`main.py`, `core/`, `network/`,
`system/`, `ui/`), plus dependencies and tooling. `venv/` is excluded.

Severity scale:

- **Critical** — crashes a reachable code path, corrupts state, or defeats the feature's core guarantee.
- **High** — wrong results, silent failure of a major feature, or a security/privacy exposure.
- **Medium** — concurrency hazard, cross-platform break, or fragile logic that fails on common inputs.
- **Low** — hygiene, dead code, cosmetic, convention violations.

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
