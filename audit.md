# Hakai v3 — Code Audit

Read-only audit of the full application source (`main.py`, `core/`, `network/`, `system/`, `ui/`). `venv/` is excluded.

Severity scale:

- **Critical** — crashes a reachable code path, corrupts state, or defeats the feature's core guarantee.
- **High** — wrong results, silent failure of a major feature, or a security/privacy exposure.
- **Medium** — concurrency hazard, cross-platform break, or fragile logic that fails on common inputs.
- **Low** — hygiene, dead code, cosmetic, convention violations.

> **Status:** Every Critical, High, and Medium finding is fixed, along with most Low items and
> the full convention cleanup the project's CLAUDE.md calls out (no bare `except:`, no `print`
> in library code). A pytest suite (19 tests) was added as a regression net. The only open items
> are four **Low** findings deliberately deferred — see §2, each with its rationale.

---

## 1. Open findings

All open findings are **Low** and were consciously deferred this pass. Nothing Critical/High/Medium remains.

### 1.1 `classify_device` mutates `dev.confidence` as a side effect
- **Severity:** Low · **Location:** `core/persistence.py:546, 655`
- **What's wrong:** A "classify" helper writes back into the device object; it's called from several threads.
- **Why deferred:** The write is a single `int` assignment (atomic under the GIL), so the race is benign (a momentarily stale confidence). The clean fix — return `(confidence, label)` — changes the signature and touches ~8 call sites across `controller.py`, `scanner.py`, and `dashboard.py`; the regression risk outweighs the cosmetic benefit until those paths have test coverage.
- **Suggested fix:** Return `(confidence, label)` and assign under the lock, or document that it must be called with the device lock held.

### 1.2 Device state is serialized but never loaded back
- **Severity:** Low · **Location:** `core/device.py:67-81` (`to_state`), `core/persistence.py:53-55` (`save_state`)
- **What's wrong:** `state.json` is written but never read back into devices.
- **Why deferred:** Both directions are behavior changes — implementing restore-on-start is a new feature; deleting the serialization drops a half-built one. Needs a product decision, not a bug fix.
- **Suggested fix:** Either load devices from `state.json` on start, or remove the serialization.

### 1.3 Placeholder IPv6 prefix and ad-hoc SSL-CN byte scan
- **Severity:** Low · **Location:** `network/ipv6.py:44` (`2001:db8:1::`, RFC 3849 doc prefix), `network/recon_engine.py:60-86` (DER byte scanning)
- **What's wrong:** These features look implemented but won't produce correct results — the IPv6 prefix isn't routable, and the SSL CN scan frequently returns garbage.
- **Why deferred:** A correct cert parse needs a new dependency (`cryptography`), and a working IPv6 prefix needs real deployment-specific network design — both out of scope for a safe correctness pass.
- **Suggested fix:** Use a real prefix/DNS for IPv6; parse the cert with `ssl.getpeercert()` / `cryptography`.

### 1.4 Convention / hygiene debt (not individually fixed)
- **Severity:** Low · **Location:** project-wide
- **What's wrong:** `ruff check` still reports ~26 unused imports (F401), the `from ui.theme import *` star-imports in `ui/*` (F403/F405), a few unused locals (F841), and `mypy`/type-hint coverage is incomplete vs. the CLAUDE.md convention.
- **Why deferred:** Clearing these is a repo-wide mechanical sweep (every `ui/` file reads theme constants via star-import; de-starring touches them all). Doing it in this pass would be exactly the "unrelated refactor" the project forbids per commit. The *specific* convention violations the audit named — bare `except:` and `print` in library code — are fixed.
- **Suggested fix:** A dedicated cleanup branch: replace `import *` with explicit names, drop unused imports (`ruff check --fix`), then add type hints and run `mypy`.

---

## 2. Resolved

Fixed and verified this engagement (most-recent commit per item). Each change was compile-checked,
run against the pytest suite, and lint-diffed (ruff `F,E9`) against its baseline to confirm no new defects.

### Critical
| Was | Location | Fix |
|-----|----------|-----|
| `controller.reset_usage` did not exist (crash on "RESET USAGE") | `ui/info_dialog.py` | `3fb70c4` → `controller.traffic.reset_usage(ip)` |
| `PROFILES.keys()` on a list (crash opening protection panel) | `ui/protection_panel.py` | `3fb70c4` → `[p["name"] for p in PROFILES]` |

### High
| Was | Location | Fix |
|-----|----------|-----|
| DNS-spoof sniffer died permanently on first malformed packet | `network/dns_spoof.py` | `8a83c7f` → per-packet guard + try/except, restart loop |
| Accounting `ACCEPT` could shadow cut `DROP` (cut silently fails) | `system/iptables_manager.py` | `ae806e5` → append (`-A`) accounting below top-inserted DROP |
| Synchronous third-party MAC lookup (privacy exfil + blocking) | `core/persistence.py` | `da20e1b` → removed `api.macvendors.com` fallback + `requests` |

### Medium — concurrency
| Was | Location | Fix |
|-----|----------|-----|
| `self.devices` iterated without the lock (dict-mutation crash) | `core/controller.py`, `ui/dashboard.py` | `97bc37b` → `Controller.snapshot_devices()` under the lock |
| `_cut_ips`/`_mac_to_ip` mutated outside the lock | `network/traffic.py` | `499194e` → mutations moved under `self._lock` |
| Recon semaphore bound to the wrong event loop (recon broken) | `network/recon_engine.py` | `df666cd` → semaphore created inside the coroutine |

### Medium — security / side effects
| Was | Location | Fix |
|-----|----------|-----|
| Shell-string recon subprocess with interpolated IPs (injection) | `network/recon_engine.py` | `fb6ad05` → `create_subprocess_exec` + `ipaddress` validation |
| `nft flush ruleset` wiped the host's entire firewall | `system/stealth.py` | `4fd71aa` → delete/recreate only the `hakai_stealth` table |
| MITM kernel tuning applied as a side effect of detection | `system/netinfo.py`, `core/controller.py` | `a2c68db` → explicit `engage_mitm()` called from `start()` |
| `accept_redirects` restored from the wrong saved value | `system/netinfo.py` | `a2c68db` → capture/restore `_orig_accept_redirects` |

### Low
| Was | Location | Fix |
|-----|----------|-----|
| `pkt[DNS].qd` dereferenced without a None guard | `network/recon_engine.py`, `network/mdns_sniff.py` | `a0267f5` |
| Synthetic "Device (Port:X Open)" stored as a hostname | `network/scanner.py` | `ae67ee5` |
| Stealth profile selection ignored (always random) | `system/stealth.py`, `core/controller.py` | `3a2457b` |
| IPv6 hijack toggle could only turn ON | `ui/dashboard.py` | `c32cee2` |
| Kill-switch blanket `OUTPUT -j DROP`, removed only once | `core/protector.py` | `37a1e52` → marked rule, loop-delete |
| Masquerade restore used hardcoded TTL/timestamps | `system/masquerade.py` | `c775e8f` → capture/restore originals |
| Linux-only `ping`/`arp` in MAC resolver (silent no-op on Windows) | `network/arp.py` | `4e8792d` → OS-correct commands |
| Dead `deauth()` flood + no-op `_stop_by_mac` | `network/deauth.py` | `2646a0a` |
| No-op nickname write, dead locals, unused imports | `core/controller.py`, `system/netinfo.py`, `main.py` | `965ce74` |
| Bare `except:` (CLAUDE.md violation) | `network/arp.py`, `network/ipv6.py`, `network/deauth.py` | `5f65731`, `dc0edfc` |
| `print` in library code (CLAUDE.md violation) | `network/traffic.py`, `system/tc_manager.py` | `0b5b61b` → `logging` |
| Bandwidth-limit input unvalidated (TclError / negative rate) | `ui/limit_dialog.py` | `c6bfe88` |
| `venv`/`__pycache__` bytecode tracked in git | repo | `5323b63` → `.gitignore` + untrack |
| `requests` listed but unused; optional deps undocumented | `requirements.txt` | `95636c1` |

### Tooling
| What | Commit |
|------|--------|
| Added pytest suite (19 tests: formatting, classification, sanitization, DHCP/OUI, tc/traffic math, IPTManager) + `conftest.py` | `315cbff` |

---

## 3. How to verify

```
pytest -v            # 19 tests, all passing
ruff check .         # real defects (F,E9) are clean on all changed code;
                     # remaining findings are the §1.4 star-import/unused-import debt
```
