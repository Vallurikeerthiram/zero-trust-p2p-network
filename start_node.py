import socket
import os
import sys
import subprocess
import json
import atexit
import argparse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

REGISTRY_FILE = "swarm_registry.json"

def get_free_port(start_port, end_port):
    registry = []
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, 'r') as f:
            try: registry = json.load(f)
            except: pass
            
    # Purge any ports from registry that are no longer listening
    active_registry = []
    for p in registry:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex(('127.0.0.1', p)) == 0:
                active_registry.append(p)
    if active_registry != registry:
        with open(REGISTRY_FILE, 'w') as f:
            json.dump(active_registry, f)
        registry = active_registry

    for port in range(start_port, end_port):
        if port in registry:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return port
    raise Exception("No free ports available in range.")

def register_node(port):
    nodes = []
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, 'r') as f:
            try:
                nodes = json.load(f)
            except json.JSONDecodeError:
                pass
    if port not in nodes:
        nodes.append(port)
    with open(REGISTRY_FILE, 'w') as f:
        json.dump(nodes, f)

def unregister_node(port):
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, 'r') as f:
            try:
                nodes = json.load(f)
            except json.JSONDecodeError:
                return
        if port in nodes:
            nodes.remove(port)
            with open(REGISTRY_FILE, 'w') as f:
                json.dump(nodes, f)

def main():
    parser = argparse.ArgumentParser(description="Start a Zero-Trust P2P Node")
    parser.add_argument("name", nargs="?", default="", help="Optional name for the node (e.g. 'a', 'b', 'alice')")
    args = parser.parse_args()

    node_name = args.name
    print(f"Initializing Zero-Trust P2P Node {f'({node_name})' if node_name else ''}...")
    
    p2p_port = get_free_port(8000, 8100)
    register_node(p2p_port) # Register immediately to prevent race conditions
    st_port = get_free_port(8500, 8600)
    
    atexit.register(unregister_node, p2p_port)
    
    ident = node_name if node_name else str(p2p_port)
    storage_dir = f"node_data_{ident}"
    if not os.path.exists(storage_dir):
        os.makedirs(storage_dir)
        
    print(f"✅ Auto-assigned P2P Port: {p2p_port}")
    print(f"✅ Auto-assigned Dashboard Port: {st_port}")
    print(f"📁 Local Storage Directory: {storage_dir}/")
    print(f"🔗 Joining swarm automatically...")
    print(f"👉 Open your browser to: http://localhost:{st_port}")
    
    dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src', 'app', 'dashboard.py'))
    
    env = os.environ.copy()
    env["P2P_PORT"] = str(p2p_port)
    env["NODE_NAME"] = node_name
    env["STORAGE_DIR"] = storage_dir
    env["AUTO_DISCOVERY"] = "1"
    
    cmd = [sys.executable, "-m", "streamlit", "run", dashboard_path, "--server.port", str(st_port)]
    
    try:
        subprocess.run(cmd, env=env)
    except KeyboardInterrupt:
        print("\nShutting down node...")

if __name__ == "__main__":
    main()
