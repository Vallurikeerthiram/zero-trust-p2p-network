"""
tests/test_challenger_m10_2_wan_stress.py
Empirical Challenger M10-2 Adversarial Stress Suite:
1. High-concurrency multi-threaded stress on PeerRegistry and BootstrapServer.
2. Server edge cases: rapid shutdown/restart, port reuse, TTL expiration pruning under churn,
   malformed JSON, fuzzing, oversized payload protection, and abrupt TCP disconnections.
3. STUN client adversarial resilience: response packet fuzzing, buffer boundaries,
   malformed attributes, and network timeout bounds.
4. Tracker client zero-trust filtering, offline resilience, and NAT hairpinning.
5. Concurrency stress on connect_to_peer and connect_to_peer_sync across multiple threads and tasks.
"""

import os
import time
import json
import socket
import struct
import asyncio
import threading
import urllib.request
import urllib.error
from http.client import RemoteDisconnected
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple

import pytest

from src.discovery.bootstrap_server import (
    PeerRegistry,
    BootstrapServer,
    start_bootstrap_server,
)
from src.discovery.tracker_client import TrackerClient
from src.discovery.stun_client import (
    MAGIC_COOKIE,
    STUN_BINDING_REQUEST,
    STUN_BINDING_RESPONSE,
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    _build_binding_request,
    _parse_stun_response,
    query_stun_server,
    get_public_ip_and_port,
    resolve_network_addresses,
)
from src.core.p2p_node import P2PNode


def get_free_tcp_port() -> int:
    """Find an available ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# =============================================================================
# 1. High Concurrency Stress on PeerRegistry & BootstrapServer
# =============================================================================

class TestBootstrapRegistryStress:
    """Adversarial multi-threaded stress on internal PeerRegistry."""

    def test_peer_registry_high_concurrency_stress(self):
        """100 threads executing 50 concurrent operations each on PeerRegistry."""
        registry = PeerRegistry(default_ttl=30.0)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(50):
                    peer_id = f"peer_{worker_id}_{i % 10}"
                    op = (worker_id + i) % 6
                    if op == 0:
                        registry.register(
                            peer_id=peer_id,
                            username=f"user_{worker_id}",
                            ip="127.0.0.1",
                            port=10000 + (worker_id % 100),
                            lan_ip="192.168.1.50",
                            wan_ip="203.0.113.1",
                            wan_port=20000 + (worker_id % 100),
                        )
                    elif op == 1:
                        registry.heartbeat(peer_id)
                    elif op == 2:
                        registry.get_active_peers(exclude_peer_id=peer_id)
                    elif op == 3:
                        registry.count()
                    elif op == 4:
                        registry.prune_expired()
                    elif op == 5:
                        registry.unregister(peer_id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)

        assert len(errors) == 0, f"Concurrent registry operations raised errors: {errors}"
        # Validate count invariant
        active_count = registry.count()
        peers = registry.get_active_peers()
        assert active_count == len(peers)

    def test_peer_registry_rapid_ttl_churn(self):
        """Register 100 peers with ultra-short TTL (0.05s) and verify timely pruning and no resurrection."""
        registry = PeerRegistry(default_ttl=0.05)

        for i in range(100):
            registry.register(
                peer_id=f"ephemeral_{i}",
                username=f"e_{i}",
                ip="127.0.0.1",
                port=8000 + i,
                ttl=0.05
            )

        assert registry.count() == 100
        time.sleep(0.12)  # Wait for all records to expire

        # Verify heartbeat cannot revive expired peers
        for i in range(100):
            res = registry.heartbeat(f"ephemeral_{i}")
            assert res is None

        # Verify active peers query returns empty and prunes internal dictionary
        active = registry.get_active_peers()
        assert len(active) == 0
        assert registry.count() == 0

    def test_peer_registry_idempotency_and_update(self):
        """Updating existing peer registration overwrites coordinates and resets TTL."""
        registry = PeerRegistry(default_ttl=60.0)
        registry.register("node_a", "Alice", "10.0.0.1", 5000)
        peers = registry.get_active_peers()
        assert len(peers) == 1
        assert peers[0]["port"] == 5000

        # Update node_a with new port and username
        registry.register("node_a", "AliceUpdated", "10.0.0.2", 6000)
        peers2 = registry.get_active_peers()
        assert len(peers2) == 1
        assert peers2[0]["port"] == 6000
        assert peers2[0]["username"] == "AliceUpdated"
        assert peers2[0]["ip"] == "10.0.0.2"


# =============================================================================
# 2. Bootstrap Server Network Stress & Fuzzing
# =============================================================================

class TestBootstrapServerNetworkStress:
    """Stress-test BootstrapServer over HTTP: high concurrency, malformed JSON, oversized payloads."""

    @pytest.fixture
    def server(self):
        port = get_free_tcp_port()
        srv = BootstrapServer(host="127.0.0.1", port=port, ttl=30.0)
        srv.start()
        time.sleep(0.05)
        yield srv
        srv.stop()

    def test_concurrent_http_requests(self, server):
        """50 concurrent clients making 200 simultaneous HTTP requests."""
        url = f"http://127.0.0.1:{server.port}"
        errors = []
        statuses = []

        def client_task(client_id: int):
            try:
                # 1. Register
                reg_payload = json.dumps({
                    "peer_id": f"http_peer_{client_id}",
                    "username": f"user_{client_id}",
                    "ip": "127.0.0.1",
                    "port": 7000 + client_id
                }).encode("utf-8")
                req = urllib.request.Request(f"{url}/register", data=reg_payload, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=5.0) as resp:
                    statuses.append(resp.status)

                # 2. Heartbeat
                hb_payload = json.dumps({"peer_id": f"http_peer_{client_id}"}).encode("utf-8")
                req_hb = urllib.request.Request(f"{url}/heartbeat", data=hb_payload, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req_hb, timeout=5.0) as resp:
                    statuses.append(resp.status)

                # 3. Get peers
                with urllib.request.urlopen(f"{url}/peers", timeout=5.0) as resp:
                    statuses.append(resp.status)

                # 4. Health
                with urllib.request.urlopen(f"{url}/health", timeout=5.0) as resp:
                    statuses.append(resp.status)

            except Exception as e:
                errors.append(e)

        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [executor.submit(client_task, i) for i in range(50)]
            for f in as_completed(futures):
                f.result()

        assert len(errors) == 0, f"HTTP concurrent stress errors: {errors}"
        assert len(statuses) == 200
        assert all(s == 200 for s in statuses)
        assert server.registry.count() == 50

    def test_malformed_json_syntax_and_field_fuzzing(self, server):
        """Fuzz server with truncated JSON, raw non-JSON, empty body, invalid types."""
        url = f"http://127.0.0.1:{server.port}"

        fuzz_cases = [
            b'{"incomplete": ',                       # Truncated JSON
            b'NOT_JSON_AT_ALL',                        # Plaintext
            b'',                                       # Empty payload
            json.dumps({"peer_id": "p"}).encode(),     # Missing port
            json.dumps({"port": 8000}).encode(),       # Missing peer_id
            json.dumps({"peer_id": "   ", "port": 8000}).encode(), # Whitespace peer_id
            json.dumps({"peer_id": 12345, "port": 8000}).encode(),  # Non-string peer_id
            json.dumps({"peer_id": "p", "port": -5}).encode(),      # Negative port
            json.dumps({"peer_id": "p", "port": 0}).encode(),       # Port 0
            json.dumps({"peer_id": "p", "port": 70000}).encode(),   # Port > 65535
            json.dumps({"peer_id": "p", "port": "abc"}).encode(),   # String port not digit
        ]

        for payload in fuzz_cases:
            req = urllib.request.Request(
                f"{url}/register",
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=2.0)
            assert exc_info.value.code == 400

    def test_bootstrap_server_non_dict_json_vulnerability(self, server):
        """
        Adversarial Test: Server behavior when receiving valid JSON that is NOT a dictionary (e.g. list or integer).
        Empirical finding: bootstrap_server.py does not verify isinstance(payload, dict), causing
        AttributeError on payload.get(...) and unhandled RemoteDisconnected crash.
        """
        url = f"http://127.0.0.1:{server.port}"
        non_dict_payloads = [
            b'[1, 2, 3]',    # JSON list
            b'12345',        # JSON integer
            b'"a string"',   # JSON string
            b'true',         # JSON boolean
        ]
        vulnerability_confirmed = []
        for pl in non_dict_payloads:
            req = urllib.request.Request(
                f"{url}/register",
                data=pl,
                headers={"Content-Type": "application/json"}
            )
            try:
                urllib.request.urlopen(req, timeout=2.0)
            except urllib.error.HTTPError as e:
                pass
            except (RemoteDisconnected, ConnectionResetError) as e:
                vulnerability_confirmed.append(pl)

        # Confirm empirical vulnerability: unhandled AttributeError causes connection drop
        assert len(vulnerability_confirmed) == len(non_dict_payloads), (
            f"Vulnerability reproduction failed: expected all non-dict payloads to trigger disconnect, got {vulnerability_confirmed}"
        )

    def test_oversized_payload_protection(self, server):
        """Server rejects payloads exceeding 64KB with HTTP 400."""
        url = f"http://127.0.0.1:{server.port}"
        oversized_data = json.dumps({
            "peer_id": "p_oversized",
            "port": 8000,
            "junk": "X" * 70000
        }).encode("utf-8")

        assert len(oversized_data) > 65536

        req = urllib.request.Request(
            f"{url}/register",
            data=oversized_data,
            headers={"Content-Type": "application/json"}
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=3.0)
        assert exc_info.value.code == 400

    def test_rapid_shutdown_restart_port_reuse(self):
        """Verify server port can be immediately rebound on restart without WinError 10048."""
        port = get_free_tcp_port()
        srv1 = BootstrapServer(host="127.0.0.1", port=port, ttl=30.0)
        srv1.start()
        time.sleep(0.05)

        # Register peer on srv1
        reg_payload = json.dumps({"peer_id": "p1", "port": 8001}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{port}/register", data=reg_payload)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            assert resp.status == 200

        # Terminate srv1
        srv1.stop()

        # Immediately start srv2 on identical port
        srv2 = BootstrapServer(host="127.0.0.1", port=port, ttl=30.0)
        try:
            srv2.start()
            time.sleep(0.05)

            # Register peer on srv2
            req2 = urllib.request.Request(f"http://127.0.0.1:{port}/register", data=reg_payload)
            with urllib.request.urlopen(req2, timeout=2.0) as resp2:
                assert resp2.status == 200
        finally:
            srv2.stop()

    def test_abrupt_client_disconnect(self, server):
        """Raw socket disconnects abruptly without completing HTTP request; server remains healthy."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", server.port))
        # Send partial request
        s.sendall(b"POST /register HTTP/1.1\r\nContent-Length: 1000\r\n\r\npartial")
        # Abruptly close
        s.close()

        time.sleep(0.05)
        # Verify server is still completely responsive to new requests
        with urllib.request.urlopen(f"http://127.0.0.1:{server.port}/health", timeout=2.0) as resp:
            assert resp.status == 200

    def test_not_found_endpoints(self, server):
        """Unknown endpoints return HTTP 404."""
        url = f"http://127.0.0.1:{server.port}"
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(f"{url}/unknown_route", timeout=2.0)
        assert exc_info.value.code == 404

        req = urllib.request.Request(f"{url}/unknown_post", data=b"{}", headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as exc_info2:
            urllib.request.urlopen(req, timeout=2.0)
        assert exc_info2.value.code == 404


# =============================================================================
# 3. STUN Client Adversarial Packet Fuzzing & Offline Resilience
# =============================================================================

class TestSTUNClientAdversarialResilience:
    """Stress-test STUN packet parser, timeout boundaries, and offline fallbacks."""

    def test_parse_stun_response_packet_fuzzing(self):
        """Fuzz _parse_stun_response with truncated buffers, corrupt headers, and invalid attributes."""
        tx_id = os.urandom(12)

        # 1. Zero bytes
        assert _parse_stun_response(b"", tx_id) is None

        # 2. Header shorter than 20 bytes
        for length in [1, 5, 10, 19]:
            assert _parse_stun_response(b"X" * length, tx_id) is None

        # 3. Wrong message type (not 0x0101)
        wrong_type = struct.pack("!HHI12s", 0x0001, 0, MAGIC_COOKIE, tx_id)
        assert _parse_stun_response(wrong_type, tx_id) is None

        # 4. Corrupted magic cookie
        corrupt_cookie = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, 0, 0x12345678, tx_id)
        assert _parse_stun_response(corrupt_cookie, tx_id) is None

        # 5. Mismatched transaction ID
        wrong_tx_id = os.urandom(12)
        mismatched_tx = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, 0, MAGIC_COOKIE, wrong_tx_id)
        assert _parse_stun_response(mismatched_tx, tx_id) is None

        # 6. Malicious attribute length exceeding buffer (buffer overrun defense)
        malicious_attr = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, 100, MAGIC_COOKIE, tx_id)
        malicious_attr += struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, 500)
        assert _parse_stun_response(malicious_attr, tx_id) is None

        # 7. Valid XOR-MAPPED-ADDRESS attribute
        expected_ip = "198.51.100.42"
        expected_port = 45678
        x_port = expected_port ^ (MAGIC_COOKIE >> 16)
        ip_int = struct.unpack("!I", socket.inet_aton(expected_ip))[0]
        x_ip = ip_int ^ MAGIC_COOKIE
        attr_data = struct.pack("!BBHI", 0x00, 0x01, x_port, x_ip)  # Family 0x01 IPv4

        valid_packet = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(attr_data) + 4, MAGIC_COOKIE, tx_id)
        valid_packet += struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(attr_data)) + attr_data

        parsed = _parse_stun_response(valid_packet, tx_id)
        assert parsed == (expected_ip, expected_port)

        # 8. Valid fallback MAPPED-ADDRESS attribute
        mapped_data = struct.pack("!BBHI", 0x00, 0x01, expected_port, ip_int)
        valid_fallback = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(mapped_data) + 4, MAGIC_COOKIE, tx_id)
        valid_fallback += struct.pack("!HH", ATTR_MAPPED_ADDRESS, len(mapped_data)) + mapped_data

        parsed_fallback = _parse_stun_response(valid_fallback, tx_id)
        assert parsed_fallback == (expected_ip, expected_port)

    def test_stun_query_offline_timeout(self):
        """Querying a closed / non-responsive IP times out gracefully and returns None."""
        t0 = time.time()
        res = query_stun_server("127.0.0.1", 59998, timeout=0.1)
        elapsed = time.time() - t0
        assert res is None
        assert elapsed < 0.5

    def test_get_public_ip_and_port_offline_resilience(self):
        """When all configured STUN servers fail, returns (None, None) without crashing."""
        offline_servers = [("127.0.0.1", 59997), ("127.0.0.1", 59996)]
        ip, port = get_public_ip_and_port(custom_servers=offline_servers, timeout=0.1)
        assert ip is None
        assert port is None

    def test_resolve_network_addresses_fallback(self):
        """resolve_network_addresses returns valid LAN fallback structure when STUN fails."""
        res = resolve_network_addresses(local_port=8080, stun_host="127.0.0.1", stun_port=59995)
        assert res["is_nat_traversed"] is False
        assert res["wan_ip"] is None
        assert res["lan_port"] == 8080
        assert res["lan_ip"] is not None
        assert f":8080" in res["primary_reachable_address"]


# =============================================================================
# 4. Tracker Client Offline Resilience & Zero-Trust Defense
# =============================================================================

class MockReputation:
    def __init__(self, blacklisted=None):
        self._blacklisted = set(blacklisted or [])

    def is_blacklisted(self, peer_id: str) -> bool:
        return peer_id in self._blacklisted


class MockNode:
    def __init__(self, peer_id="client_node_aaa", port=8001, node_name="Alice", advertised_host=None):
        self.peer_id = peer_id
        self.port = port
        self.host = "127.0.0.1"
        self.advertised_host = advertised_host
        self.node_name = node_name
        self.reputation = MockReputation()
        self.peers = {}
        self.connections_made = []

    async def connect_to_peer(self, host: str, port: int, timeout: float = 5.0, force: bool = False):
        self.connections_made.append((host, port))
        return True, "Connected"


class TestTrackerClientAdversarialResilience:
    """Stress-test TrackerClient under network failure, malicious responses, and loop churn."""

    @pytest.mark.asyncio
    async def test_tracker_client_offline_graceful_failure(self):
        """TrackerClient methods return clean failure codes when tracker server is unreachable."""
        node = MockNode()
        client = TrackerClient(node, tracker_url="http://127.0.0.1:59994", interval=1.0)

        # 1. register -> False
        assert await client.register() is False
        assert client.is_registered is False

        # 2. heartbeat -> False
        assert await client.heartbeat() is False

        # 3. poll_peers -> empty list
        assert await client.poll_peers() == []

        # 4. unregister -> False
        assert await client.unregister() is False
        assert client.unregister_sync() is False

    @pytest.mark.asyncio
    async def test_tracker_client_zero_trust_peer_filtering(self):
        """TrackerClient strictly filters self-connections, blacklisted peers, and malformed ports."""
        node = MockNode(peer_id="my_local_node_id", port=8001)
        node.reputation._blacklisted.add("blacklisted_peer_id")
        node.peers[("127.0.0.1", 9005)] = ("already_connected_peer", 9005)

        client = TrackerClient(node, tracker_url="http://127.0.0.1:9000")

        mock_response = {
            "status": "ok",
            "peers": [
                # 1. Self connection by peer_id
                {"peer_id": "my_local_node_id", "username": "Self", "ip": "10.0.0.5", "port": 8001},
                # 2. Self connection by IP & Port
                {"peer_id": "other_id_1", "username": "LoopbackSelf", "ip": "127.0.0.1", "port": 8001},
                # 3. Blacklisted peer
                {"peer_id": "blacklisted_peer_id", "username": "Malicious", "ip": "10.0.0.9", "port": 9002},
                # 4. Malformed port
                {"peer_id": "bad_port_peer", "username": "BadPort", "ip": "10.0.0.10", "port": "not_int"},
                # 5. Missing port
                {"peer_id": "missing_port_peer", "username": "NoPort", "ip": "10.0.0.11", "port": None},
                # 6. Missing IP
                {"peer_id": "missing_ip_peer", "username": "NoIp", "ip": "", "port": 9004},
                # 7. Already connected peer
                {"peer_id": "already_connected_peer", "username": "Connected", "ip": "127.0.0.1", "port": 9005},
                # 8. Legitimate new peer
                {"peer_id": "legit_peer_id", "username": "Bob", "ip": "10.0.0.20", "port": 9006},
            ]
        }

        with unittest_mock_sync_get(client, mock_response):
            peers = await client.poll_peers()
            assert len(peers) == 8

        # Allow dispatched connect tasks to run
        await asyncio.sleep(0.05)

        # Verify ONLY the legitimate peer was connected
        assert len(node.connections_made) == 1
        assert node.connections_made[0] == ("10.0.0.20", 9006)

    @pytest.mark.asyncio
    async def test_tracker_client_nat_hairpinning_resolution(self):
        """When peer shares same public WAN IP, client connects via LAN IP instead."""
        node = MockNode(peer_id="node_a", port=8001)
        client = TrackerClient(node, tracker_url="http://127.0.0.1:9000")
        client.wan_ip = "198.51.100.1"  # Our WAN IP

        mock_response = {
            "status": "ok",
            "peers": [
                {
                    "peer_id": "peer_b",
                    "username": "SameRouterNode",
                    "ip": "198.51.100.1",        # WAN IP matching our WAN IP
                    "wan_ip": "198.51.100.1",
                    "lan_ip": "192.168.1.150",   # LAN IP
                    "port": 8002
                }
            ]
        }

        with unittest_mock_sync_get(client, mock_response):
            await client.poll_peers()

        await asyncio.sleep(0.05)
        assert len(node.connections_made) == 1
        assert node.connections_made[0] == ("192.168.1.150", 8002)

    def test_tracker_client_rapid_lifecycle(self):
        """Repeatedly starting and stopping TrackerClient does not leak threads or raise unhandled exceptions."""
        loop = asyncio.new_event_loop()
        node = MockNode()
        try:
            for _ in range(3):
                client = TrackerClient(node, tracker_url="http://127.0.0.1:59993", loop=loop)
                client.start()
                assert client.running is True
                client.stop()
                assert client.running is False
            # Drain cancelled tasks to avoid unawaited coroutine warnings on close
            loop.run_until_complete(asyncio.sleep(0))
        finally:
            loop.close()


def unittest_mock_sync_get(client: TrackerClient, return_val: Any):
    """Context manager to mock _sync_get on TrackerClient."""
    from unittest.mock import patch
    return patch.object(client, "_sync_get", return_value=return_val)


# =============================================================================
# 5. Concurrency Stress on connect_to_peer and connect_to_peer_sync
# =============================================================================

class TestPeerConnectionConcurrencyStress:
    """Stress-test P2PNode's connect_to_peer and connect_to_peer_sync under race conditions."""

    @pytest.mark.asyncio
    async def test_connect_to_peer_sync_event_loop_deadlock_guard(self, tmp_path):
        """Calling connect_to_peer_sync from within an event loop fails fast to avoid deadlock."""
        port = get_free_tcp_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        node.loop = asyncio.get_running_loop()
        try:
            success, msg = node.connect_to_peer_sync("127.0.0.1", 9999)
            assert success is False
            assert "Cannot call connect_to_peer_sync from the event loop thread" in msg
        finally:
            node.stop()

    def test_connect_to_peer_sync_multithreaded_concurrency(self, tmp_path):
        """20 OS threads simultaneously call connect_to_peer_sync on node without thread contention deadlock."""
        port = get_free_tcp_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))

        loop = asyncio.new_event_loop()
        node.loop = loop
        t = threading.Thread(target=loop.run_forever, daemon=True)
        t.start()

        target_port = get_free_tcp_port()
        results = []

        try:
            def worker(idx: int):
                success, msg = node.connect_to_peer_sync("127.0.0.1", target_port, timeout=0.5)
                results.append((idx, success, msg))

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(worker, i) for i in range(20)]
                for f in as_completed(futures):
                    f.result()

            assert len(results) == 20
            for idx, success, msg in results:
                assert success is False
                assert "Connection" in msg or "timed out" in msg
        finally:
            node.stop()
            loop.call_soon_threadsafe(loop.stop)
            t.join(timeout=1.0)

    @pytest.mark.asyncio
    async def test_connect_to_peer_self_connection_matrix(self, tmp_path):
        """connect_to_peer rejects all loopback/self permutations immediately without network I/O."""
        port = get_free_tcp_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host="192.168.1.99")
        try:
            self_variants = [
                "127.0.0.1",
                "localhost",
                "0.0.0.0",
                "::1",
                "127.0.0.2",
                "127.10.20.30",
                "192.168.1.99",
            ]
            for host in self_variants:
                success, msg = await node.connect_to_peer(host, port)
                assert success is False
                assert msg == "Cannot connect to self"
        finally:
            node.stop()

    @pytest.mark.asyncio
    async def test_connect_to_peer_concurrent_race_condition(self, tmp_path):
        """Multiple concurrent tasks connect to the same target peer simultaneously; exactly one registers, others report already connected."""
        port_a = get_free_tcp_port()
        port_b = get_free_tcp_port()

        node_a = P2PNode("127.0.0.1", port_a, db_path=str(tmp_path / "repa.db"), storage_dir=str(tmp_path / "sa"), node_name="NodeA")
        node_b = P2PNode("127.0.0.1", port_b, db_path=str(tmp_path / "repb.db"), storage_dir=str(tmp_path / "sb"), node_name="NodeB")

        server_b = await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)
        try:
            # Concurrently launch 10 connect_to_peer calls from node_a to node_b
            tasks = [
                asyncio.create_task(node_a.connect_to_peer(node_b.host, node_b.port, timeout=3.0))
                for _ in range(10)
            ]
            results = await asyncio.gather(*tasks)

            assert len(results) == 10
            # All calls succeeded (either fresh connection or already connected)
            assert all(r[0] is True for r in results)

            # Node A must contain exactly ONE peer entry for Node B in node_a.peers
            matching_peers = [p for p in node_a.peers.keys() if p[1] == port_b]
            assert len(matching_peers) == 1
            assert node_a.peers[(node_b.host, node_b.port)][0] == node_b.peer_id
        finally:
            server_b.close()
            await server_b.wait_closed()
            node_a.stop()
            node_b.stop()
