# Lanwarden v3: Sovereign Apex — Full Project Walkthrough

Lanwarden v3 is a modular, high-performance network orchestration and security suite. It is designed for transparent network monitoring, offensive traffic control, and advanced defensive posturing.

---
## 📂 Project Structure

### 🚀 Root
- **`main.py`**: The entry point.
    - Performs root privilege checks.
    - Validates system dependencies (`nft`, `tc` required; `bpftool` optional).
    - Initializes the `Controller` (backend) and `LanwardenWindow` (PySide6 frontend), and installs signal/atexit shutdown hooks.
    - Starts the background Vendor DB synchronization.

---

### 🧠 Core Module (`core/`)
The "brain" of the application, managing state and coordination.

- **`controller.py` (The Orchestrator)**: 
    - The central hub that wires the UI to all network modules.
    - Manages the master list of `devices` and thread-safe access to them.
    - Coordinates offensive actions (Cut, Limit) and ensures cleanup on exit.
    - Key Functions: `start()`, `stop()`, `scan()`, `cut_device()`, `limit_device()`.
- **`device.py`**:
    - Defines the `Device` data model.
    - Stores IP, MAC, Vendor, Hostname, OS guesses, and real-time traffic stats.
- **`persistence.py`**:
    - Data storage in SQLite (WAL): config, nicknames, devices, cut records, and an operation log. Legacy JSON config is imported once on first run.
    - Remembers device nicknames across restarts (keyed by MAC).
- **`identity.py`** / **`oui.py`**:
    - `identity.py`: device classification + mDNS/vendor name sanitization (the confidence-scored label engine), split out of persistence.
    - `oui.py`: MAC OUI → vendor tables and lookup.
- **`protector.py` (Defensive Sentry)**:
    - Monitors the network for adversarial ARP spoofing attacks against the attacker.
    - **ARP Guard**: Locks the Gateway MAC in the kernel to prevent gateway hijacking.
    - **Kill-Switch**: Instantly drops all outbound traffic if a malicious hijack is detected.

---

### 🌐 Network Module (`network/`)
The implementation of various network protocols and attack/monitoring vectors.

- **`traffic.py` (Telemetry Engine)**:
    - 3-Layer traffic counting: `nft` counters (authoritative, via `NftFilter`), `Scapy` (real-time fallback), and `/proc/net/dev` (sanity check).
    - Provides smooth Mbps calculations using a sliding temporal window.
- **`rawsock.py`**:
    - Raw AF_PACKET L2 sender used by the ARP flood (with a Scapy fallback).
- **`scanner.py`**:
    - Multi-stage discovery: `nmap` (Fast) → `Scapy ARP` (Reliable) → `System ARP Table` (Fallback).
    - Includes an async hostname resolver and passive mDNS/SSDP/NBNS discovery.
- **`arp.py`**:
    - High-speed ARP spoofing engine.
    - Supports "Cutting" (dropping target traffic) and "Monitoring" (transparent MITM).
- **`xdp_engine.py` (eBPF XDP)**:
    - Uses eBPF to drop packets at the NIC driver level for zero-CPU "Cuts".
    - Bypasses the entire Linux networking stack for maximum efficiency.
- **`ipv6.py`**:
    - Implements IPv6 RA (Router Advertisement) spoofing and Rogue DHCPv6.
    - Intercepts IPv6 traffic by advertising the attacker as the default IPv6 gateway.
- **`dns_spoof.py`**:
    - Intercepts DNS queries and redirects targets to arbitrary IPs (e.g., a captive portal).
- **`fingerprint.py`**:
    - Performs active OS unmasking using TCP/IP stack analysis and port signature matching.
- **`deauth.py`**:
    - WiFi deauthentication engine for kicking devices off wireless networks (requires Monitor Mode).
- **`oui_lookup.py`**:
    - MAC-to-Vendor presentation layer (privacy-bit handling) over the canonical `core.oui` lookup.

---

### ⚙️ System Module (`system/`)
OS-level utilities and kernel-space management.

- **`netinfo.py`**:
    - Auto-detects the active interface, gateway, and subnet.
    - Handles aggressive kernel tuning (Forwarding, Promiscuous mode, NIC offloading).
    - **Restoration**: Captures original system states to revert changes on exit.
- **`nft_filter.py`** (`NftFilter`):
    - Owns the nft `inet lanwarden` table / `forward` chain: device cuts (DROP, inserted first), byte-accounting (counter ACCEPT, appended), and counter reads. Removal is by exact handle, never a flush. (Replaced the old `iptables_manager`.)
- **`sweep.py`**:
    - Startup orphan sweep: clears app-owned nft tables and kill-switch comments left by a hard kill (including the legacy pre-rename names).
- **`tc_manager.py`**:
    - Manages Linux Traffic Control (`tc`) for per-device bandwidth limiting (shaping).
- **`stealth.py`** / **`masquerade.py`** / **`chameleon.py`** / **`firewall_apex.py`**:
    - Evasion/posture: MAC+hostname "Mirage Cloak" (reusing `GhostFirewall` for a safe drop policy), TTL/stack masquerade, MTU/MSS chameleon, and the ghost firewall. All capture originals and restore on exit.

---

### 🎨 UI Module (`ui/`)
The frontend, built with **PySide6 (Qt)** + **pyqtgraph** (rebuilt from the former CustomTkinter UI).

- **`main_window.py`** (`LanwardenWindow`):
    - The main window: sidebar (Watch / Warden / Keeper / Scope), a real-time device table, a detail pane with live pyqtgraph traffic plots, and a status bar (iface/gw/op/protection/alert/error).
    - Bandwidth limits use a Qt input dialog; protection alerts surface in the status bar.
- **`workers.py`**:
    - `submit()` runs privileged engine calls on a `QThreadPool` off the GUI thread, marshaling result/error/done back via queued signals.
- **`theme.py`**:
    - Flat dark Qt stylesheet (QSS), palette, and the per-state banner styles.

---

## 🛠️ Recent Stability Remediation (May 2026)

### 1. Network Connectivity Fixes
- **IPv6 Toggle**: Moved the disruptive IPv6 RA spoofing from automatic startup to a manual toggle in the Aegis panel. This prevents the host machine from losing its own connection on launch.
- **Kernel Restoration**: Added a full cleanup routine that reverts Promiscuous mode and NIC offloading to original states upon closing the app.

### 2. Telemetry Accuracy
- **Zero Usage Bug**: Fixed a parsing error where `iptables` output with `/32` masks was ignored. 
- **Scapy Fallback**: Refactored the sniffer to support IPv6 and greedy identification, ensuring data usage is counted even when not in a MITM position.

### 3. Offensive Safety
- **Safeguards**: The Controller now explicitly prevents the user from "Cutting" or "Limiting" themselves or the Network Gateway.
