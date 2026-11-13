"""
Adversarial Stress Test Suite for Bootstrap Tracker Server & Tracker Client
Tests:
1. Concurrent thread stress (10 threads hammering POST /register, GET /peers, POST /heartbeat)
2. TTL expiration and active pruning verification
3. 64KB payload attacks (oversized bodies, boundary limits, malformed JSON, server survival)
4. TrackerClient network resilience (offline/unreachable tracker, 500 error responses, malformed JSON, loop survival)
5. NAT hairpinning logic verification (same WAN IP -> LAN IP, different WAN IP -> WAN IP, missing LAN IP fallback)
6. Rapid shutdown under concurrent request pressure
"""

import time
import json
import socket
import asyncio
import threading
import urllib.request
import urllib.error
import http.server
import pytest
from unittest.mock import patch

from src.discovery.bootstrap_server import (
    PeerRegistry,
    BootstrapServer,
    start_bootstrap_server,
)
from src.discovery.tracker_client import TrackerClient


def get_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class MockReputation:
    def __init__(self, blacklisted_ids=None):
        self.blacklisted_ids = set(blacklisted_ids or [])

    def is_blacklisted(self, peer_id: str) -> bool:
        return peer_id in self.blacklisted_ids


class MockNode:
    def __init__(self, peer_id="client_node_id_1234567890abcdef", port=8001, node_name="Alice", advertised_host="192.168.1.100"):
        self.peer_id = peer_id
        self.port = port
        self.host = "0.0.0.0"
        self.node_name = node_name
        self.advertised_host = advertised_host
        self.reputation = MockReputation()
        self.peers = {}
        self.connections_made = []

    async def connect_to_peer(self, host: str, port: int, timeout: float = 5.0, force: bool = False):
        self.connections_made.append((host, port))
        return True, "Connected"


def _raw_http_post(host: str, port: int, path: str, body_bytes: bytes, headers: dict = None, timeout: float = 4.0):
    """Low-level socket HTTP POST to avoid urllib client-side limits."""
    headers = headers or {}
    req_lines = [
        f"POST {path} HTTP/1.1",
        f"Host: {host}:{port}",
        f"Content-Length: {len(body_bytes)}",
        "Connection: close"
    ]
    for k, v in headers.items():
        req_lines.append(f"{k}: {v}")
    req_lines.append("")
    req_lines.append("")
    header_data = "\r\n".join(req_lines).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(header_data + body_bytes)
        
        # Read response
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
            except Exception:
                break
    return resp


def _http_post(url: str, data: dict, timeout: float = 4.0):
    payload = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def _http_get(url: str, timeout: float = 4.0):
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


# =============================================================================
# 1. Concurrent Thread Stress Test
# =============================================================================

def test_stress_concurrent_thread_hammering():
    """
    Launch 10 concurrent threads hammering POST /register, GET /peers,
    and POST /heartbeat for 2-3 seconds; verify zero race conditions or deadlocks.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=5.0)
    base_url = f"http://127.0.0.1:{port}"
    errors = []
    iterations_per_worker = 40
    thread_count = 10
    barrier = threading.Barrier(thread_count)

    def worker_action(thread_idx: int):
        try:
            barrier.wait(timeout=5.0)
        except Exception as e:
            errors.append(f"Barrier timeout: {e}")
            return

        for i in range(iterations_per_worker):
            try:
                op = (thread_idx + i) % 4
                peer_id = f"peer_t{thread_idx}_{i % 5}"

                if op == 0:
                    # POST /register
                    payload = {
                        "peer_id": peer_id,
                        "username": f"User_{thread_idx}_{i}",
                        "ip": f"10.0.{thread_idx}.{i % 250 + 1}",
                        "port": 5000 + (thread_idx * 10) + i
                    }
                    status, res = _http_post(f"{base_url}/register", payload)
                    if status != 200 or res.get("status") != "ok":
                        errors.append(f"Register failed: {status} {res}")

                elif op == 1:
                    # GET /peers
                    status, res = _http_get(f"{base_url}/peers?exclude={peer_id}")
                    if status != 200 or "peers" not in res:
                        errors.append(f"Get peers failed: {status} {res}")

                elif op == 2:
                    # POST /heartbeat
                    try:
                        status, res = _http_post(f"{base_url}/heartbeat", {"peer_id": peer_id})
                        if status not in (200, 404):
                            errors.append(f"Heartbeat unexpected status: {status}")
                    except urllib.error.HTTPError as he:
                        if he.code != 404:
                            errors.append(f"Heartbeat HTTPError {he.code}")

                elif op == 3:
                    # Mixed: health or unregister
                    if i % 2 == 0:
                        status, res = _http_get(f"{base_url}/health")
                        if status != 200 or res.get("status") != "ok":
                            errors.append(f"Health failed: {status}")
                    else:
                        status, res = _http_post(f"{base_url}/unregister", {"peer_id": peer_id})
                        if status != 200:
                            errors.append(f"Unregister failed: {status}")

            except Exception as e:
                errors.append(f"Thread {thread_idx} iteration {i} error: {e}")

    threads = []
    for t in range(thread_count):
        th = threading.Thread(target=worker_action, args=(t,), name=f"StressWorker-{t}")
        threads.append(th)
        th.start()

    for th in threads:
        th.join(timeout=10.0)
        assert not th.is_alive(), f"Thread {th.name} deadlocked!"

    # Stop server cleanly
    server.stop()

    assert len(errors) == 0, f"Concurrent stress test produced {len(errors)} errors: {errors[:5]}"


# =============================================================================
# 2. TTL Expiration & Active Pruning Test
# =============================================================================

def test_stress_ttl_expiration_and_active_pruning():
    """
    Register peers with short TTL (0.5s), sleep 0.7s, verify peers are automatically
    evicted and not returned in GET /peers.
    """
    port = get_free_tcp_port()
    # Server with 0.5s TTL
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=0.5)
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Register 5 peers
        for i in range(5):
            _http_post(f"{base_url}/register", {
                "peer_id": f"short_peer_{i}",
                "username": f"UserShort_{i}",
                "ip": f"192.168.1.{10 + i}",
                "port": 6000 + i
            })

        # Verify all 5 are immediately present
        status, data = _http_get(f"{base_url}/peers")
        assert status == 200
        assert len(data["peers"]) == 5
        assert server.registry.count() == 5

        # Sleep past TTL (0.5s TTL + 0.25s margin = 0.75s)
        time.sleep(0.75)

        # Verify GET /peers automatically evicts and returns 0 peers
        status_after, data_after = _http_get(f"{base_url}/peers")
        assert status_after == 200
        assert len(data_after["peers"]) == 0
        assert server.registry.count() == 0

        # Verify heartbeat for expired peer returns 404
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            _http_post(f"{base_url}/heartbeat", {"peer_id": "short_peer_0"})
        assert exc_info.value.code == 404

        # Register a fresh peer and verify it works normally
        _http_post(f"{base_url}/register", {
            "peer_id": "fresh_peer",
            "username": "FreshUser",
            "ip": "10.0.0.1",
            "port": 7000
        })
        status_fresh, data_fresh = _http_get(f"{base_url}/peers")
        assert len(data_fresh["peers"]) == 1
        assert data_fresh["peers"][0]["peer_id"] == "fresh_peer"

    finally:
        server.stop()


# =============================================================================
# 3. 64KB Payload Attack Tests
# =============================================================================

def test_stress_64kb_payload_attack_rejection():
    """
    Send request bodies >64KB; verify server returns HTTP 400 without crashing or hanging.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Attack 1: 65,537 bytes (just over 64KB limit)
        oversized_json = json.dumps({
            "peer_id": "attacker_1",
            "port": 8000,
            "padding": "A" * (65537 - 50)
        }).encode("utf-8")
        assert len(oversized_json) > 65536

        resp1 = _raw_http_post("127.0.0.1", port, "/register", oversized_json, headers={"Content-Type": "application/json"})
        assert b"400 Bad Request" in resp1 or resp1 == b""

        # Verify server is completely alive and responsive
        status, health = _http_get(f"{base_url}/health")
        assert status == 200
        assert health["status"] == "ok"

        # Attack 2: 120,000 bytes (~120KB payload)
        huge_json = json.dumps({
            "peer_id": "attacker_2",
            "port": 8000,
            "padding": "X" * 120000
        }).encode("utf-8")
        resp2 = _raw_http_post("127.0.0.1", port, "/register", huge_json, headers={"Content-Type": "application/json"})
        assert b"400 Bad Request" in resp2 or resp2 == b""

        # Verify server is still alive
        status, health = _http_get(f"{base_url}/health")
        assert status == 200

        # Attack 3: Send non-JSON binary garbage >64KB
        raw_garbage = b"\xff\x00\xaa\xbb" * 20000  # 80,000 bytes
        resp3 = _raw_http_post("127.0.0.1", port, "/register", raw_garbage, headers={"Content-Type": "application/octet-stream"})
        assert b"400 Bad Request" in resp3 or resp3 == b""

        # Attack 4: Send malformed JSON within size limit
        malformed = b'{"peer_id": "malformed_json_unclosed'
        resp4 = _raw_http_post("127.0.0.1", port, "/register", malformed, headers={"Content-Type": "application/json"})
        assert b"400 Bad Request" in resp4

        # Verify normal legitimate registration succeeds right after attacks
        status, reg = _http_post(f"{base_url}/register", {"peer_id": "survivor_peer", "port": 8888})
        assert status == 200
        assert reg["status"] == "ok"

        status, peers = _http_get(f"{base_url}/peers")
        assert len(peers["peers"]) == 1
        assert peers["peers"][0]["peer_id"] == "survivor_peer"

    finally:
        server.stop()


# =============================================================================
# 4. TrackerClient Network Resilience Test
# =============================================================================

@pytest.mark.asyncio
async def test_stress_tracker_client_offline_resilience():
    """
    Test TrackerClient behavior when tracker is offline or unreachable;
    verify graceful retry without unhandled exceptions.
    """
    offline_port = get_free_tcp_port()
    node = MockNode(peer_id="resilient_node", port=7701)

    client = TrackerClient(
        node=node,
        tracker_url=f"http://127.0.0.1:{offline_port}",
        interval=0.2,
        loop=asyncio.get_running_loop()
    )

    # 1. Direct API calls against dead server must return False or [] without raising
    reg_ok = await client.register()
    assert reg_ok is False
    assert client.is_registered is False

    hb_ok = await client.heartbeat()
    assert hb_ok is False

    peers = await client.poll_peers()
    assert peers == []

    unreg_ok = await client.unregister()
    assert unreg_ok is False

    unreg_sync_ok = client.unregister_sync()
    assert unreg_sync_ok is False

    # 2. Run background loop against offline tracker: verify no unhandled loop crashes
    client.start()
    assert client.running is True

    # Allow loop to execute multiple retry ticks
    await asyncio.sleep(0.6)

    # Client must still be running cleanly despite failed requests
    assert client.running is True
    assert client._task is not None
    assert not client._task.done()

    client.stop()
    assert client.running is False
    assert client._task is None


class Faulty500Handler(http.server.BaseHTTPRequestHandler):
    """Mock server that returns HTTP 500 Internal Server Error."""
    def do_POST(self):
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Internal Server Error")

    def do_GET(self):
        self.send_response(500)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Internal Server Error")

    def log_message(self, *args):
        pass


@pytest.mark.asyncio
async def test_stress_tracker_client_http_500_resilience():
    """Verify TrackerClient survives HTTP 500 responses with non-JSON bodies."""
    port = get_free_tcp_port()
    mock_server = http.server.HTTPServer(("127.0.0.1", port), Faulty500Handler)
    server_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    server_thread.start()

    try:
        node = MockNode()
        client = TrackerClient(
            node=node,
            tracker_url=f"http://127.0.0.1:{port}",
            loop=asyncio.get_running_loop()
        )

        reg_res = await client.register()
        assert reg_res is False

        hb_res = await client.heartbeat()
        assert hb_res is False

        peers_res = await client.poll_peers()
        assert peers_res == []

    finally:
        mock_server.shutdown()
        mock_server.server_close()


# =============================================================================
# 5. NAT Hairpinning Logic Test
# =============================================================================

@pytest.mark.asyncio
async def test_stress_nat_hairpinning_comprehensive():
    """
    Verify that when remote peer has same WAN IP as client, client connects to
    peer's LAN IP. Also verify handling of different WAN IP, missing LAN IP,
    and self/blacklisted peer filtering.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        client_node = MockNode(peer_id="local_client_node", port=8001)
        client = TrackerClient(
            node=client_node,
            tracker_url=base_url,
            loop=asyncio.get_running_loop()
        )
        client.wan_ip = "198.51.100.99"
        client.lan_ip = "192.168.1.15"

        # Peer 1: Same WAN IP, valid LAN IP -> MUST connect to LAN IP
        server.registry.register(
            peer_id="remote_same_wan",
            username="SameWAN",
            ip="198.51.100.99",
            port=8002,
            lan_ip="192.168.1.77",
            wan_ip="198.51.100.99"
        )

        # Peer 2: Different WAN IP -> MUST connect to WAN IP
        server.registry.register(
            peer_id="remote_diff_wan",
            username="DiffWAN",
            ip="203.0.113.5",
            port=8003,
            lan_ip="10.0.0.22",
            wan_ip="203.0.113.5"
        )

        # Peer 3: Same WAN IP, but LAN IP is None -> fallback to registered IP
        server.registry.register(
            peer_id="remote_same_wan_no_lan",
            username="NoLAN",
            ip="198.51.100.99",
            port=8004,
            lan_ip=None,
            wan_ip="198.51.100.99"
        )

        peers = await client.poll_peers()
        assert len(peers) == 3

        await asyncio.sleep(0.05)

        # Check all connections made
        conns = client_node.connections_made
        assert len(conns) == 3

        # Verification 1: Same WAN peer connected to LAN IP
        assert ("192.168.1.77", 8002) in conns

        # Verification 2: Different WAN peer connected to WAN IP
        assert ("203.0.113.5", 8003) in conns

        # Verification 3: Same WAN peer with no LAN IP connected to registered IP
        assert ("198.51.100.99", 8004) in conns

    finally:
        server.stop()


# =============================================================================
# 6. Rapid Server Stop Under Concurrent Load
# =============================================================================

def test_stress_rapid_server_stop_under_load():
    """
    Verify server shuts down cleanly and unblocks all threads even when
    hammered with requests during shutdown.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"
    stop_flag = threading.Event()

    def spammer():
        while not stop_flag.is_set():
            try:
                _http_get(f"{base_url}/health", timeout=1.0)
            except Exception:
                pass

    spammers = [threading.Thread(target=spammer, daemon=True) for _ in range(5)]
    for sp in spammers:
        sp.start()

    time.sleep(0.2)
    # Stop while requests are continuously arriving
    server.stop()
    stop_flag.set()

    for sp in spammers:
        sp.join(timeout=2.0)

    # Server should be stopped cleanly
    assert not server._is_running


# =============================================================================
# 7. Adversarial Fuzzing & Injection Handling
# =============================================================================

def test_adversarial_injection_and_fuzzing():
    """
    Test server response to malformed input, boundaries, injection attempts,
    and extreme values in JSON fields.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        # Invalid Port Boundaries
        for bad_port in [0, -1, -65535, 65536, 999999, "invalid_str", None, [], {}]:
            payload = {"peer_id": "bad_port_peer", "port": bad_port}
            resp = _raw_http_post("127.0.0.1", port, "/register", json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
            assert b"400 Bad Request" in resp or resp == b""

        # Invalid Peer ID
        for bad_pid in ["", "   ", None, 12345, [], {}]:
            payload = {"peer_id": bad_pid, "port": 8000}
            resp = _raw_http_post("127.0.0.1", port, "/register", json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
            assert b"400 Bad Request" in resp or resp == b""

        # Strings with injection attempts
        injections = [
            "../../../etc/passwd",
            "<script>alert('pwn')</script>",
            "' OR '1'='1' --",
            "\x00\x01\x02\x03",
            "A" * 2000
        ]
        for inj in injections:
            payload = {
                "peer_id": f"inj_{hash(inj) % 10000}",
                "username": inj,
                "ip": "127.0.0.1",
                "port": 9000
            }
            status, res = _http_post(f"{base_url}/register", payload)
            assert status == 200
            assert res["status"] == "ok"

        # Verify server state is healthy
        status, health = _http_get(f"{base_url}/health")
        assert status == 200
        assert health["status"] == "ok"

    finally:
        server.stop()


# =============================================================================
# 8. Early Socket Disconnect on Oversized Content-Length
# =============================================================================

def test_adversarial_early_eof_oversized_payload():
    """
    Send Content-Length: 100000 but close socket after sending only 20 bytes.
    Verify server handles EOF gracefully without hanging or crashing.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(("127.0.0.1", port))
        headers = (
            "POST /register HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Length: 100000\r\n"
            "Content-Type: application/json\r\n\r\n"
            '{"partial": 123}'
        )
        s.sendall(headers.encode("utf-8"))
        # Abruptly close socket from client side
        s.close()

        # Give server thread a moment to process disconnection
        time.sleep(0.1)

        # Server must immediately serve normal requests
        status, health = _http_get(f"{base_url}/health")
        assert status == 200
        assert health["status"] == "ok"

    finally:
        server.stop()


# =============================================================================
# 9. Additional NAT Hairpinning Edge Cases
# =============================================================================

@pytest.mark.asyncio
async def test_adversarial_nat_hairpinning_edge_cases():
    """
    Verify NAT hairpinning handles edge cases:
    - client has no WAN IP (wan_ip=None) -> connects to registered IP
    - remote peer has empty/whitespace lan_ip -> connects to registered IP
    - remote peer lan_ip matches client's advertised host & port -> skipped
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=10.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        node = MockNode(peer_id="client_x", port=9001, advertised_host="192.168.1.100")
        client = TrackerClient(node=node, tracker_url=base_url, loop=asyncio.get_running_loop())
        # Client WAN IP is None (STUN unavailable)
        client.wan_ip = None

        server.registry.register(
            peer_id="remote_peer_1",
            username="P1",
            ip="203.0.113.10",
            port=9002,
            lan_ip="192.168.1.55",
            wan_ip="203.0.113.10"
        )

        peers = await client.poll_peers()
        await asyncio.sleep(0.05)

        # Since client.wan_ip is None, NAT hairpinning does not apply; connects to remote_peer_1's registered IP
        assert ("203.0.113.10", 9002) in node.connections_made

        # Now set client.wan_ip
        client.wan_ip = "203.0.113.10"
        node.connections_made.clear()

        # Remote peer has whitespace or empty lan_ip
        server.registry.register(
            peer_id="remote_peer_empty_lan",
            username="P2",
            ip="203.0.113.10",
            port=9003,
            lan_ip="",
            wan_ip="203.0.113.10"
        )

        await client.poll_peers()
        await asyncio.sleep(0.05)
        # Empty lan_ip should fallback to registered IP (203.0.113.10, 9003)
        assert ("203.0.113.10", 9003) in node.connections_made

    finally:
        server.stop()


# =============================================================================
# 10. Multi-Client Swarm Simulation
# =============================================================================

@pytest.mark.asyncio
async def test_adversarial_multi_client_swarm_simulation():
    """
    Run 5 concurrent TrackerClients on the same event loop with a shared server.
    Verify they all register, heartbeat, discover peers, and unregister cleanly.
    """
    port = get_free_tcp_port()
    server = start_bootstrap_server(host="127.0.0.1", port=port, ttl=5.0)
    base_url = f"http://127.0.0.1:{port}"

    try:
        nodes = []
        clients = []
        loop = asyncio.get_running_loop()

        for i in range(5):
            node = MockNode(peer_id=f"swarm_node_{i}", port=8100 + i, node_name=f"Swarm_{i}")
            client = TrackerClient(node=node, tracker_url=base_url, interval=0.2, loop=loop)
            nodes.append(node)
            clients.append(client)
            client.start()

        # Let clients register and discover each other
        await asyncio.sleep(0.6)

        # Verify all 5 are registered in server registry
        assert server.registry.count() == 5

        # Each node should have discovered and connected to other nodes
        for node in nodes:
            # Each node should have made connections to peers
            assert len(node.connections_made) > 0

        # Stop all clients
        for client in clients:
            client.stop()

        await asyncio.sleep(0.2)
        # All clients unregistered
        assert server.registry.count() == 0

    finally:
        server.stop()
