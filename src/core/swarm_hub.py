import socket
import os
import json
import logging
import threading
from typing import List, Optional

logger = logging.getLogger("SwarmHub")

REGISTRY_FILE = "swarm_registry.json"
_REGISTRY_LOCK = threading.Lock()


def safe_read_registry() -> List[int]:
    """Read the active swarm node port registry safely with retry."""
    if not os.path.exists(REGISTRY_FILE):
        return []
    with _REGISTRY_LOCK:
        for _ in range(5):
            try:
                with open(REGISTRY_FILE, "r") as f:
                    data = json.load(f)
                    return [int(p) for p in data] if isinstance(data, list) else []
            except Exception:
                import time
                time.sleep(0.05)
    return []


def safe_write_registry(nodes: List[int]) -> bool:
    """Write the active swarm node port registry safely with retry."""
    with _REGISTRY_LOCK:
        for _ in range(5):
            try:
                with open(REGISTRY_FILE, "w") as f:
                    json.dump(nodes, f)
                return True
            except Exception:
                import time
                time.sleep(0.05)
    return False


def register_node_port(port: int) -> None:
    """Register a new active listening port in the swarm registry."""
    nodes = safe_read_registry()
    if port not in nodes:
        nodes.append(port)
        safe_write_registry(nodes)


def unregister_node_port(port: int) -> None:
    """Unregister an active listening port from the swarm registry."""
    nodes = safe_read_registry()
    if port in nodes:
        nodes.remove(port)
        safe_write_registry(nodes)


def get_free_port(start_port: int = 8010, end_port: int = 8990) -> int:
    """
    Find a free, unbound TCP port that is neither currently listening
    nor recorded in the swarm registry.
    """
    registry = safe_read_registry()

    # Clean stale ports from registry
    active = []
    for p in registry:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.05)
                if s.connect_ex(("127.0.0.1", p)) == 0:
                    active.append(p)
        except Exception:
            pass
    if active != registry:
        safe_write_registry(active)
        registry = active

    for port in range(start_port, end_port):
        if port in registry:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                return port
        except Exception:
            continue

    raise RuntimeError(f"No free TCP ports available in range {start_port}..{end_port}")
