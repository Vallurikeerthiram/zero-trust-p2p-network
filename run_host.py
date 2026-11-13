#!/usr/bin/env python3
"""
Zero-Trust P2P Network — One-Click Swarm Host & Hub Launcher
Starts the P2P Host Node and Web Swarm Portal on this machine,
allowing any phone, tablet, or laptop on the Wi-Fi network to join
instantly by scanning the QR code or clicking the link.
"""

import os
import sys
import subprocess
import webbrowser
import time
import socket

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from src.discovery.stun_client import get_lan_ip

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False


def print_banner(lan_ip: str, web_port: int, p2p_port: int):
    url = f"http://{lan_ip}:{web_port}"
    local_url = f"http://localhost:{web_port}"

    border = "=" * 68
    print("\n" + border)
    print("  🛡️   ZERO-TRUST P2P SWARM NETWORK — LIVE HOST")
    print(border)
    print(f"  💻  On this Laptop:             {local_url}")
    print(f"  📱  On Any Phone / Tablet / PC:  {url}")
    print(f"  🔒  P2P Mesh Port:              {p2p_port} (Bound: 0.0.0.0)")
    print(f"  🌐  Local Wi-Fi IP:             {lan_ip}")
    print(border)
    print("  👉  Tell anyone on your Wi-Fi to scan this QR code or open:")
    print(f"      {url}")
    print("      No installation needed! They enter their name and join.")
    print(border + "\n")

    if HAS_QRCODE:
        try:
            qr = qrcode.QRCode(box_size=1, border=2)
            qr.add_data(url)
            qr.print_ascii(invert=True)
            print()
        except Exception:
            pass


def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    lan_ip = get_lan_ip()
    web_port = 8500
    p2p_port = 8000

    print_banner(lan_ip, web_port, p2p_port)

    dashboard_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "src", "app", "dashboard.py")
    )

    env = os.environ.copy()
    env["SWARM_HUB_MODE"] = "1"
    env["STREAMLIT_PORT"] = str(web_port)
    env["P2P_PORT"] = str(p2p_port)
    env["NODE_NAME"] = "Host_Laptop"
    env["P2P_USERNAME"] = "Host_Laptop"
    env["P2P_HOST"] = "0.0.0.0"
    env["P2P_ADVERTISE_HOST"] = lan_ip
    env["P2P_ENABLE_DISCOVERY"] = "1"
    env["AUTO_DISCOVERY"] = "1"
    env["STORAGE_DIR"] = "node_data_Host"

    os.makedirs("node_data_Host", exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        dashboard_path,
        "--server.port",
        str(web_port),
        "--server.address",
        "0.0.0.0",
        "--server.headless",
        "true",
        "--server.enableCORS",
        "false",
        "--server.enableXsrfProtection",
        "false",
        "--server.enableWebsocketCompression",
        "false",
        "--browser.gatherUsageStats",
        "false",
    ]

    print("🚀 Launching Swarm Hub server...")
    proc = subprocess.Popen(cmd, env=env)

    # Give server 2 seconds to initialize and open local browser
    time.sleep(2.5)
    local_url = f"http://localhost:{web_port}"
    try:
        webbrowser.open(local_url)
    except Exception:
        pass

    print(f"\n[+] Swarm Hub is active. Press Ctrl+C in this terminal to stop the network.\n")

    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n\nShutting down Zero-Trust P2P Swarm Host...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        print("✅ Host cleanly stopped.")


if __name__ == "__main__":
    main()
