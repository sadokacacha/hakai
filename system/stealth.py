"""
system/stealth.py — The Sovereign Mirage Engine.
Randomizes host identity across mobile, PC, and TV profiles.
"""
import random
import subprocess
import time

PROFILES = [
    {"name": "iPhone-15-Pro",       "oui": "40:a6:d9", "type": "MOBILE"},
    {"name": "Galaxy-S24-Ultra",    "oui": "dc:e5:78", "type": "MOBILE"},
    {"name": "Pixel-8-Pro",         "oui": "1c:62:b8", "type": "MOBILE"},
    {"name": "MacBook-Pro-M3",      "oui": "c8:6f:1d", "type": "PC"},
    {"name": "Surface-Laptop-5",    "oui": "00:50:f2", "type": "PC"},
    {"name": "Dell-XPS-Highline",   "oui": "d4:3d:7e", "type": "PC"},
    {"name": "Sony-Bravia-4K",      "oui": "00:22:fb", "type": "TV"},
    {"name": "LG-OLED-WebOS",       "oui": "60:c5:47", "type": "TV"},
    {"name": "Samsung-Smart-TV",    "oui": "40:16:3b", "type": "TV"},
]

def engage_mirage_cloak(interface: str = "wlo1", profile_name: str | None = None):
    """
    Tactical Cloak: apply the named Mirage profile, or a random one when
    profile_name is empty/"RANDOM"/unknown.
    """
    if profile_name and profile_name != "RANDOM":
        profile = next((p for p in PROFILES if p["name"] == profile_name), None) or random.choice(PROFILES)
    else:
        profile = random.choice(PROFILES)
    hostname = f"{profile['name']}-{random.randint(10,99)}"
    mac_prefix = profile['oui']

    # 1. Change Hostname
    try:
        subprocess.run(["hostnamectl", "set-hostname", hostname], check=True)
    except Exception: pass
    
    # 2. Extract current SSID for instant re-bind
    try:
        ssid_res = subprocess.run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], capture_output=True, text=True)
        current_ssid = next((line.split(":")[1] for line in ssid_res.stdout.splitlines() if line.startswith("yes")), None)
    except Exception: current_ssid = None

    # 3. Change MAC Address
    new_mac = f"{mac_prefix}:{random.randint(10,99):02x}:{random.randint(10,99):02x}:{random.randint(10,99):02x}"
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["ip", "link", "set", interface, "address", new_mac], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        
        # Instant Re-bind
        if current_ssid:
            subprocess.run(["nmcli", "dev", "wifi", "connect", current_ssid], capture_output=True)
    except Exception: pass
    
    # 4. Engage Ghost Firewall (Silent-Drop) after 1s grace period
    time.sleep(1)
    try:
        # Remove only our own table (if present); never flush the global
        # ruleset — that would destroy the host's existing firewall config
        # with no way to restore it.
        subprocess.run(["nft", "delete", "table", "inet", "hakai_stealth"], capture_output=True)
        subprocess.run(["nft", "add", "table", "inet", "hakai_stealth"], check=True)
        subprocess.run(["nft", "add", "chain", "inet", "hakai_stealth", "input", 
                       "{ type filter hook input priority 0; policy drop; }"], check=True)
        subprocess.run(["nft", "add", "rule", "inet", "hakai_stealth", "input", 
                       "ct state established,related accept"], check=True)
    except Exception: pass
    
    return f"[CLOAKED AS: {hostname}]", new_mac

def disengage_stealth(interface="wlo1", orig_mac=None, orig_hostname="Hakai"):
    """
    Restores the machine to its original identity.
    """
    try:
        subprocess.run(["hostnamectl", "set-hostname", orig_hostname], check=True)
        if orig_mac:
            subprocess.run(["ip", "link", "set", interface, "down"], check=True)
            subprocess.run(["ip", "link", "set", interface, "address", orig_mac], check=True)
            subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        
        # Remove stealth firewall
        subprocess.run(["nft", "delete", "table", "inet", "hakai_stealth"], check=True)
    except Exception: pass
    
    return "[IDENTITY RESTORED]"
