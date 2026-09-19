import subprocess
import time
import os
import sys

def main():
    print("Starting Zero-Trust P2P Simulation Swarm...")
    
    dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'app', 'dashboard.py'))
    
    nodes = [
        {"p2p_port": "8001", "st_port": "8501"},
        {"p2p_port": "8002", "st_port": "8502"},
        {"p2p_port": "8003", "st_port": "8503"}
    ]
    
    processes = []
    
    for node in nodes:
        env = os.environ.copy()
        env["P2P_PORT"] = node["p2p_port"]
        
        # Start streamlit
        cmd = [sys.executable, "-m", "streamlit", "run", dashboard_path, "--server.port", node["st_port"], "--server.headless", "true"]
        
        p = subprocess.Popen(cmd, env=env)
        processes.append(p)
        print(f"Launched Node {node['p2p_port']} - Dashboard at http://localhost:{node['st_port']}")
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
