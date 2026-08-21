# Hakai v3: Sovereign Apex — Full Project Walkthrough

Hakai v3 is a modular, high-performance network orchestration and security suite. It is designed for transparent network monitoring, offensive traffic control, and advanced defensive posturing.

---
## 📂 Project Structure

### 🚀 Root
- **`main.py`**: The entry point.
    - Performs root privilege checks.
    - Validates system dependencies (`nmap`, `dsniff`, `iproute2`).
    - Initializes the `Controller` (backend) and `Dashboard` (frontend).
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
    - Handles data storage using a combination of JSON (config) and SQLite (device history).
    - Remembers device nicknames, custom icons, and classification (Known/Stranger).
- **`protector.py` (Defensive Sentry)**:
    - Monitors the network for adversarial ARP spoofing attacks against the attacker.
    - **ARP Guard**: Locks the Gateway MAC in the kernel to prevent gateway hijacking.
    - **Kill-Switch**: Instantly drops all outbound traffic if a malicious hijack is detected.

---

### 🌐 Network Module (`network/`)
The implementation of various network protocols and attack/monitoring vectors.

- **`traffic.py` (Telemetry Engine)**:
    - 3-Layer traffic counting: `iptables` (authoritative), `Scapy` (real-time fallback), and `/proc/net/dev` (sanity check).
    - Provides smooth Mbps calculations using a sliding temporal window.
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
    - Fast MAC-to-Vendor lookup using an internal OUI database.

---

### ⚙️ System Module (`system/`)
OS-level utilities and kernel-space management.

- **`netinfo.py`**:
    - Auto-detects the active interface, gateway, and subnet.
    - Handles aggressive kernel tuning (Forwarding, Promiscuous mode, NIC offloading).
    - **Restoration**: Captures original system states to revert changes on exit.
- **`iptables_manager.py`**:
    - Programmatically manages the `FORWARD` chain for bandwidth accounting and firewall-based cutting.
- **`tc_manager.py`**:
    - Manages Linux Traffic Control (`tc`) for per-device bandwidth limiting (shaping).
- **`stealth.py`**:
    - Logic for "Mirage Cloak"—randomizing the attacker's MAC and Hostname to mimic consumer hardware.
- **`masquerade.py`**:
    - Obfuscates the attacker's TCP/IP stack (e.g., changing TTL to 128 to look like Windows).

---

### 🎨 UI Module (`ui/`)
The modern, demonic-themed frontend built with `customtkinter`.

- **`dashboard.py`**:
    - The main window. Features a real-time device table with live speed/usage stats.
    - Sidebars for tactical logging and "Target Intel" display.
- **`protection_panel.py`**:
    - Interactive dashboard for managing the Aegis defensive suite.
- **`limit_dialog.py`**:
    - Custom pop-up for setting precise KB/s bandwidth limits.
- **`theme.py`**:
    - Defines the Sovereign Apex design system (Colors, Fonts, Spacing).

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
