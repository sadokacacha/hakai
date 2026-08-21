import sys
import os
from unittest.mock import MagicMock

# Add current dir to path
sys.path.append(os.getcwd())

from core.controller import Controller
from system.netinfo import NetInfo

def test_scan_no_drop():
    net = NetInfo()
    net.iface = "lo" # Use loopback for safety
    net.my_ip = "127.0.0.1"
    net.gateway = "127.0.0.1"
    net.subnet = "127.0.0.0/24"
    
    c = Controller(net)
    
    # Mock scanner to return a dummy device
    c.scanner.scan = MagicMock(return_value={"127.0.0.2": MagicMock(ip="127.0.0.2", mac="00:11:22:33:44:55", hostname="Target")})
    
    print("Running scan...")
    c.scan()
    
    # Check if monitor_device was called (it shouldn't be anymore)
    # Actually I can't check if it was called unless I mock it, but I can check iptables
    
    import subprocess
    res = subprocess.run(["sudo", "iptables", "-L", "FORWARD", "-n"], capture_output=True, text=True)
    print("IPTables FORWARD chain:")
    print(res.stdout)
    
    if "DROP" in res.stdout and "127.0.0.2" in res.stdout:
        print("FAIL: DROP rule found for 127.0.0.2")
    else:
        print("SUCCESS: No DROP rule found for 127.0.0.2")

if __name__ == "__main__":
    test_scan_no_drop()
