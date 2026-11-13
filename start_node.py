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

def _safe_read_registry():
    if not os.path.exists(REGISTRY_FILE):
        return []
    for _ in range(5):
        try:
            with open(REGISTRY_FILE, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception:
            import time; time.sleep(0.05)
    return []

def _safe_write_registry(nodes):
    for _ in range(5):
        try:
            with open(REGISTRY_FILE, 'w') as f:
                json.dump(nodes, f)
            return True
        except Exception:
            import time; time.sleep(0.05)
    return False

def get_free_port(start_port, end_port):
    registry = _safe_read_registry()
            
    # Purge any ports from registry that are no longer listening
    active_registry = []
    for p in registry:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                if s.connect_ex(('127.0.0.1', p)) == 0:
                    active_registry.append(p)
        except Exception:
            pass
    if active_registry != registry:
        _safe_write_registry(active_registry)
        registry = active_registry

    for port in range(start_port, end_port):
        if port in registry:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) != 0:
                    return port
        except Exception:
            continue
    raise Exception("No free ports available in range.")

def register_node(port):
    nodes = _safe_read_registry()
    if port not in nodes:
        nodes.append(port)
    _safe_write_registry(nodes)

def unregister_node(port):
    nodes = _safe_read_registry()
    if port in nodes:
        nodes.remove(port)
        _safe_write_registry(nodes)

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
