"""
src/discovery/bootstrap_server.py
Zero-Trust P2P Bootstrap Tracker Server (RFC-compliant REST rendezvous).
Built exclusively with Python standard library http.server.ThreadingHTTPServer.
Zero third-party dependencies.
"""

import sys
import os
import json
import time
import logging
import argparse
import threading
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional, Dict, Any, List

logger = logging.getLogger("BootstrapServer")


class PeerRegistry:
    """
    Thread-safe registry storing active P2P peers with TTL-based expiration.
    """
    def __init__(self, default_ttl: float = 60.0):
        self.default_ttl = float(default_ttl)
        self._peers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register(
        self,
        peer_id: str,
        username: str,
        ip: str,
        port: int,
        lan_ip: Optional[str] = None,
        wan_ip: Optional[str] = None,
        wan_port: Optional[int] = None,
        ttl: Optional[float] = None
    ) -> Dict[str, Any]:
        """Record or update a peer registration with TTL expiration."""
        now = time.time()
        effective_ttl = float(ttl) if ttl is not None else self.default_ttl
        expires_at = now + effective_ttl

        record = {
            "peer_id": peer_id,
            "username": username or "",
            "ip": ip,
            "port": int(port),
            "lan_ip": lan_ip,
            "wan_ip": wan_ip,
            "wan_port": int(wan_port) if wan_port is not None else None,
            "registered_at": now,
            "last_seen": now,
            "expires_at": expires_at
        }
        with self._lock:
            self._peers[peer_id] = record
        return record

    def heartbeat(self, peer_id: str, ttl: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Extend the TTL for an existing active peer. Returns None if peer is not registered or expired."""
        now = time.time()
        effective_ttl = float(ttl) if ttl is not None else self.default_ttl
        with self._lock:
            peer = self._peers.get(peer_id)
            if not peer:
                return None
            if now > peer.get("expires_at", 0):
                del self._peers[peer_id]
                return None
            peer["last_seen"] = now
            peer["expires_at"] = now + effective_ttl
            return peer

    def unregister(self, peer_id: str) -> bool:
        """Immediately remove a peer from the registry."""
        with self._lock:
            return self._peers.pop(peer_id, None) is not None

    def get_active_peers(self, exclude_peer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Prune expired peers and return list of all active peers except exclude_peer_id."""
        now = time.time()
        with self._lock:
            # Prune expired peers
            expired_ids = [pid for pid, p in self._peers.items() if now > p.get("expires_at", 0)]
            for pid in expired_ids:
                del self._peers[pid]

            # Return copies of active peer records
            active = [
                dict(p) for pid, p in self._peers.items()
                if pid != exclude_peer_id
            ]
        return active

    def prune_expired(self) -> int:
        """Manually trigger pruning of expired peers. Returns count of pruned records."""
        now = time.time()
        with self._lock:
            expired_ids = [pid for pid, p in self._peers.items() if now > p.get("expires_at", 0)]
            for pid in expired_ids:
                del self._peers[pid]
            return len(expired_ids)

    def count(self) -> int:
        """Return count of currently active (non-expired) peers."""
        now = time.time()
        with self._lock:
            return sum(1 for p in self._peers.values() if now <= p.get("expires_at", 0))

    def clear(self) -> None:
        """Clear all registry state."""
        with self._lock:
            self._peers.clear()


class BootstrapRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler dispatching REST endpoints for the Bootstrap Tracker.
    """
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        # Route access logs through standard logger instead of stderr
        logger.debug("%s - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))

    @property
    def registry(self) -> PeerRegistry:
        return self.server.registry

    @property
    def ttl(self) -> float:
        return self.server.default_ttl

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Optional[Dict[str, Any]]:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                return {}
            if content_length > 65536:  # 64KB security guard against DoS payload exhaustion
                # Drain unread bytes up to 128KB to avoid Windows TCP RST (WinError 10053)
                try:
                    self.rfile.read(min(content_length, 131072))
                except Exception:
                    pass
                return None
            body = self.rfile.read(content_length)
            return json.loads(body.decode("utf-8"))
        except Exception as e:
            logger.debug(f"JSON parse error: {e}")
            return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')
        if not path:
            path = "/"

        if path == "/peers":
            query = urllib.parse.parse_qs(parsed.query)
            exclude = query.get("exclude", [None])[0]
            peers = self.registry.get_active_peers(exclude_peer_id=exclude)
            self._send_json(200, {"status": "ok", "peers": peers})
        elif path in ("/", "/health", "/status"):
            self._send_json(200, {
                "status": "ok",
                "service": "BootstrapServer",
                "active_peers": self.registry.count()
            })
        else:
            self._send_json(404, {"status": "error", "message": f"Endpoint not found: {self.path}"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')

        payload = self._read_json()
        if payload is None:
            self._send_json(400, {"status": "error", "message": "Invalid JSON or body exceeds 64KB limit"})
            return

        if path == "/register":
            peer_id = payload.get("peer_id")
            if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
                self._send_json(400, {"status": "error", "message": "Missing or invalid 'peer_id'"})
                return
            peer_id = peer_id.strip()

            port = payload.get("port")
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    self._send_json(400, {"status": "error", "message": f"Port out of range (1-65535): {port}"})
                    return
            except (ValueError, TypeError):
                self._send_json(400, {"status": "error", "message": "Missing or invalid 'port'"})
                return

            # Address resolution: if ip omitted or wildcard, use TCP socket remote address
            ip = payload.get("ip")
            client_socket_ip = self.client_address[0]
            if not ip or ip in ("0.0.0.0", "", "::"):
                ip = client_socket_ip

            username = str(payload.get("username", ""))
            lan_ip = payload.get("lan_ip")
            wan_ip = payload.get("wan_ip")
            wan_port = payload.get("wan_port")
            if wan_port is not None:
                try:
                    wan_port = int(wan_port)
                except (ValueError, TypeError):
                    wan_port = None

            record = self.registry.register(
                peer_id=peer_id,
                username=username,
                ip=ip,
                port=port,
                lan_ip=lan_ip,
                wan_ip=wan_ip,
                wan_port=wan_port,
                ttl=self.ttl
            )
            self._send_json(200, {
                "status": "ok",
                "message": "Registered",
                "registered_ip": ip,
                "expires_at": record["expires_at"]
            })

        elif path == "/heartbeat":
            peer_id = payload.get("peer_id")
            if not peer_id or not isinstance(peer_id, str):
                self._send_json(400, {"status": "error", "message": "Missing or invalid 'peer_id'"})
                return
            peer = self.registry.heartbeat(peer_id.strip(), ttl=self.ttl)
            if peer:
                self._send_json(200, {
                    "status": "ok",
                    "message": "Heartbeat extended",
                    "expires_at": peer["expires_at"]
                })
            else:
                self._send_json(404, {"status": "error", "message": "Peer not found or expired"})

        elif path == "/unregister":
            peer_id = payload.get("peer_id")
            if not peer_id or not isinstance(peer_id, str):
                self._send_json(400, {"status": "error", "message": "Missing or invalid 'peer_id'"})
                return
            self.registry.unregister(peer_id.strip())
            self._send_json(200, {"status": "ok", "message": "Unregistered"})

        else:
            self._send_json(404, {"status": "error", "message": f"Endpoint not found: {self.path}"})


class BootstrapServer(ThreadingHTTPServer):
    """
    Standard library Threading HTTP Server implementing rendezvous bootstrap tracking.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host: str = "0.0.0.0", port: int = 9000, ttl: float = 60.0):
        self.host = host
        self.port = port
        self.default_ttl = float(ttl)
        self.registry = PeerRegistry(default_ttl=self.default_ttl)
        self._server_thread: Optional[threading.Thread] = None
        self._is_running = False
        super().__init__((host, port), BootstrapRequestHandler)

    def start(self) -> threading.Thread:
        """Start the server loop in a background daemon thread."""
        if self._is_running:
            return self._server_thread
        self._is_running = True
        self._server_thread = threading.Thread(
            target=self.serve_forever,
            name=f"BootstrapServer-{self.port}",
            daemon=True
        )
        self._server_thread.start()
        logger.info(f"Bootstrap tracker running on http://{self.host}:{self.port} (TTL: {self.default_ttl}s)")
        return self._server_thread

    def stop(self) -> None:
        """Gracefully terminate server and release the listening port."""
        if not self._is_running:
            return
        self._is_running = False
        try:
            self.shutdown()
        except Exception:
            pass
        try:
            self.server_close()
        except Exception:
            pass
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=2.0)
        logger.info("Bootstrap tracker stopped.")


def start_bootstrap_server(host: str = "0.0.0.0", port: int = 9000, ttl: float = 60.0) -> BootstrapServer:
    """Helper factory function to instantiate and start a BootstrapServer."""
    server = BootstrapServer(host=host, port=port, ttl=ttl)
    server.start()
    return server


def main():
    parser = argparse.ArgumentParser(description="Zero-Trust P2P Bootstrap Tracker Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host interface (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9000, help="Listening port (default: 9000)")
    parser.add_argument("--ttl", type=float, default=60.0, help="Peer registration TTL in seconds (default: 60.0)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    server = BootstrapServer(host=args.host, port=args.port, ttl=args.ttl)
    print(f"Starting Zero-Trust Bootstrap Tracker on {args.host}:{args.port} (TTL: {args.ttl}s)...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down bootstrap tracker...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
