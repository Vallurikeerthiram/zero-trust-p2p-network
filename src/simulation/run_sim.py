import subprocess
import time
import os
import sys

def main():
    print("Starting Zero-Trust P2P Simulation Swarm...")
    
    dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app', 'dashboard.py'))
    
    nodes = [
        {"name": "a", "p2p_port": "8001", "st_port": "8501"},
        {"name": "b", "p2p_port": "8002", "st_port": "8502"},
        {"name": "c", "p2p_port": "8003", "st_port": "8503"}
    ]
    
    # Pre-populate registry
    import json
    with open("swarm_registry.json", "w") as f:
        json.dump([int(n["p2p_port"]) for n in nodes], f)
        
    processes = []
    
    for node in nodes:
        storage_dir = f"node_data_{node['name']}"
        os.makedirs(storage_dir, exist_ok=True)
        
        env = os.environ.copy()
        env["P2P_PORT"] = node["p2p_port"]
        env["NODE_NAME"] = node["name"]
        env["STORAGE_DIR"] = storage_dir
        env["AUTO_DISCOVERY"] = "1"
        
        # Start streamlit
        cmd = [sys.executable, "-m", "streamlit", "run", dashboard_path, "--server.port", node["st_port"], "--server.headless", "true"]
        
        p = subprocess.Popen(cmd, env=env)
        processes.append(p)
        print(f"Launched Node {node['name']} (P2P: {node['p2p_port']}) - Dashboard at http://localhost:{node['st_port']}")
        time.sleep(2) # staggered start
        
    print("\nSwarm is running. Press Ctrl+C to stop all nodes.")
    
    try:
        for p in processes:
            p.wait()
    except KeyboardInterrupt:
        print("\nShutting down swarm...")
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    main()
