"""
Unit and Integration Tests for LAN Auto-Discovery UDP Beacon (Feature F29)
"""

import json
import time
import socket
import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from src.discovery.lan_beacon import LanBeacon


def get_free_udp_port() -> int:
    """Find a free UDP port on localhost for isolated testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class MockReputation:
    def __init__(self, blacklisted_ids=None):
        self.blacklisted_ids = set(blacklisted_ids or [])

    def is_blacklisted(self, peer_id: str) -> bool:
        return peer_id in self.blacklisted_ids


class MockNode:
    def __init__(self, peer_id="node_a_peer_id_1234567890abcdef", port=8001, node_name="Alice", advertised_host="192.168.1.100"):
        self.peer_id = peer_id
        self.port = port
        self.node_name = node_name
        self.advertised_host = advertised_host
        self.reputation = MockReputation()
        self.peers = {}
        self.connections_made = []

    async def connect_to_peer(self, host: str, port: int, timeout: float = 5.0, force: bool = False):
        self.connections_made.append((host, port))
        return True, "Connected"


# =============================================================================
# 1. Initialization & Socket Configuration
# =============================================================================

def test_lan_beacon_init_defaults():
    node = MockNode()
    beacon = LanBeacon(node)
    assert beacon.node is node
    assert beacon.broadcast_port == 50050
    assert beacon.interval == 1.5
    assert not beacon.running
    assert beacon._rx_sock is None
    assert beacon._tx_sock is None
    assert beacon._tasks == []
    assert beacon._recent_attempts == {}


def test_socket_creation_and_options():
    udp_port = get_free_udp_port()
    node = MockNode()
    beacon = LanBeacon(node, broadcast_port=udp_port)

    beacon._create_sockets()
    try:
        assert beacon._rx_sock is not None
        assert beacon._tx_sock is not None
        assert beacon._rx_sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0
        assert beacon._rx_sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) != 0
        assert beacon._tx_sock.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST) != 0

        # Verify rx socket is non-blocking
        assert beacon._rx_sock.gettimeout() == 0.0
    finally:
        beacon._rx_sock.close()
        beacon._tx_sock.close()


# =============================================================================
# 2. Payload Construction & Broadcast Transmission
# =============================================================================

def test_payload_structure():
    node = MockNode(peer_id="alice_peer_id_123", port=9001, node_name="Alice", advertised_host="10.0.0.5")
    beacon = LanBeacon(node)

    raw_bytes = beacon._build_payload()
    payload = json.loads(raw_bytes.decode('utf-8'))

    assert payload["type"] == "DISCOVERY_BEACON"
    assert payload["peer_id"] == "alice_peer_id_123"
    assert payload["username"] == "Alice"
    assert payload["tcp_port"] == 9001
    assert payload["advertised_host"] == "10.0.0.5"
    assert isinstance(payload["timestamp"], (int, float))
    assert abs(payload["timestamp"] - time.time()) < 5.0


def test_send_broadcast_mock():
    node = MockNode()
    beacon = LanBeacon(node)
    beacon.running = True
    beacon._tx_sock = MagicMock()

    beacon.send_broadcast()
    assert beacon._tx_sock.sendto.called
    data_sent, dest = beacon._tx_sock.sendto.call_args[0]
    assert dest == ('<broadcast>', beacon.broadcast_port)
    parsed = json.loads(data_sent.decode('utf-8'))
    assert parsed["peer_id"] == node.peer_id


def test_send_broadcast_noop_when_not_running():
    node = MockNode()
    beacon = LanBeacon(node)
    beacon.running = False
    beacon._tx_sock = MagicMock()

    beacon.send_broadcast()
    assert not beacon._tx_sock.sendto.called


# =============================================================================
# 3. Beacon Validation & Security Filtering
# =============================================================================

@pytest.mark.asyncio
async def test_listen_loop_drops_self_beacon():
    node = MockNode(peer_id="self_id_12345")
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True

    self_msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "self_id_12345",
        "username": "SelfNode",
        "tcp_port": 8001,
        "advertised_host": "192.168.1.100"
    }

    mock_rx = MagicMock()
    beacon._rx_sock = mock_rx

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(self_msg).encode('utf-8'), ('192.168.1.100', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    assert len(node.connections_made) == 0


@pytest.mark.asyncio
async def test_listen_loop_drops_blacklisted_peer():
    node = MockNode(peer_id="my_id")
    node.reputation = MockReputation(blacklisted_ids=["bad_peer_666"])
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True

    bad_msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "bad_peer_666",
        "username": "MaliciousNode",
        "tcp_port": 9999,
        "advertised_host": "192.168.1.66"
    }

    mock_rx = MagicMock()
    beacon._rx_sock = mock_rx

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(bad_msg).encode('utf-8'), ('192.168.1.66', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    assert len(node.connections_made) == 0


@pytest.mark.asyncio
async def test_listen_loop_filters_invalid_payloads():
    node = MockNode()
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    invalid_samples = [
        b"not-json{{{",
        json.dumps(["not", "a", "dict"]).encode('utf-8'),
        json.dumps({"type": "WRONG_TYPE", "peer_id": "peer1", "tcp_port": 8000}).encode('utf-8'),
        json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "", "tcp_port": 8000}).encode('utf-8'),
        json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": -5}).encode('utf-8'),
        json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": 999999}).encode('utf-8'),
        json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": "not-a-port"}).encode('utf-8'),
    ]

    effects = [(data, ('192.168.1.50', 50050)) for data in invalid_samples]
    effects.append(asyncio.CancelledError())

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=effects):
        await beacon._listen_loop()

    assert len(node.connections_made) == 0


# =============================================================================
# 4. Target Host Resolution & Sanitization
# =============================================================================

@pytest.mark.asyncio
async def test_target_host_resolution_prefers_advertised_host():
    node = MockNode(peer_id="my_id")
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    valid_msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "remote_peer_1",
        "username": "Bob",
        "tcp_port": 8002,
        "advertised_host": "192.168.1.102"
    }

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(valid_msg).encode('utf-8'), ('10.0.0.1', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    await asyncio.sleep(0.05)
    assert len(node.connections_made) == 1
    assert node.connections_made[0] == ("192.168.1.102", 8002)


@pytest.mark.asyncio
async def test_target_host_resolution_falls_back_to_socket_ip_when_wildcard():
    node = MockNode(peer_id="my_id")
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    valid_msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "remote_peer_2",
        "username": "Charlie",
        "tcp_port": 8003,
        "advertised_host": "0.0.0.0"  # wildcard should trigger fallback
    }

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(valid_msg).encode('utf-8'), ('192.168.1.205', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    await asyncio.sleep(0.05)
    assert len(node.connections_made) == 1
    assert node.connections_made[0] == ("192.168.1.205", 8003)


@pytest.mark.asyncio
async def test_defense_in_depth_sanitizes_loopback_from_external_interface():
    node = MockNode(peer_id="my_id")
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    # Remote peer mistakenly advertised 127.0.0.1 over a real LAN IP 192.168.1.88
    msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "remote_peer_loopback",
        "username": "Dave",
        "tcp_port": 8004,
        "advertised_host": "127.0.0.1"
    }

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(msg).encode('utf-8'), ('192.168.1.88', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    await asyncio.sleep(0.05)
    assert len(node.connections_made) == 1
    # Target host must be rewritten to remote socket IP 192.168.1.88
    assert node.connections_made[0] == ("192.168.1.88", 8004)


# =============================================================================
# 5. Deduplication Logic
# =============================================================================

@pytest.mark.asyncio
async def test_connection_deduplication_active_peer_skipped():
    node = MockNode(peer_id="my_id")
    # Peer already active in node.peers
    node.peers[("192.168.1.55", 8005)] = ("peer_55", "Peer55")

    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "peer_55",
        "username": "Peer55",
        "tcp_port": 8005,
        "advertised_host": "192.168.1.55"
    }

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (json.dumps(msg).encode('utf-8'), ('192.168.1.55', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    assert len(node.connections_made) == 0


@pytest.mark.asyncio
async def test_connection_deduplication_cooldown_and_pruning():
    node = MockNode(peer_id="my_id")
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    msg = {
        "type": "DISCOVERY_BEACON",
        "peer_id": "peer_rapid",
        "username": "RapidNode",
        "tcp_port": 8006,
        "advertised_host": "192.168.1.99"
    }
    encoded = json.dumps(msg).encode('utf-8')

    # Seed an expired attempt in _recent_attempts (>30s ago)
    old_key = ("old_peer", 9000)
    beacon._recent_attempts[old_key] = time.time() - 40.0

    # Deliver two rapid packets from peer_rapid
    with patch.object(beacon.loop, "sock_recvfrom", side_effect=[
        (encoded, ('192.168.1.99', 50050)),
        (encoded, ('192.168.1.99', 50050)),
        asyncio.CancelledError()
    ]):
        await beacon._listen_loop()

    await asyncio.sleep(0.05)
    # Only 1 connection made due to 3.0s cooldown
    assert len(node.connections_made) == 1
    # Expired key must have been pruned
    assert old_key not in beacon._recent_attempts


# =============================================================================
# 6. Lifecycle Management & Windows WinError 995 Handling
# =============================================================================

@pytest.mark.asyncio
async def test_start_and_stop_lifecycle():
    port = get_free_udp_port()
    node = MockNode()
    beacon = LanBeacon(node, broadcast_port=port, interval=0.5)

    beacon.start()
    assert beacon.running
    assert len(beacon._tasks) == 2
    assert beacon._rx_sock is not None
    assert beacon._tx_sock is not None

    # Wait briefly for startup burst
    await asyncio.sleep(0.2)

    # Clean stop
    beacon.stop()
    assert not beacon.running
    assert len(beacon._tasks) == 0
    assert beacon._rx_sock is None
    assert beacon._tx_sock is None

    # Idempotent stop check
    beacon.stop()
    assert not beacon.running


@pytest.mark.asyncio
async def test_listen_loop_handles_winerror_995_on_shutdown():
    """Simulate Windows closing a socket during pending sock_recvfrom (WinError 995)."""
    node = MockNode()
    beacon = LanBeacon(node, loop=asyncio.get_running_loop())
    beacon.running = True
    beacon._rx_sock = MagicMock()

    # When socket closes during shutdown, sock_recvfrom raises ConnectionResetError or OSError
    def fake_recvfrom(*args, **kwargs):
        beacon.running = False  # Node initiates stop
        raise ConnectionResetError("[WinError 995] The I/O operation has been aborted")

    with patch.object(beacon.loop, "sock_recvfrom", side_effect=fake_recvfrom):
        # Must exit cleanly without throwing unhandled exceptions
        await beacon._listen_loop()

    assert not beacon.running


# =============================================================================
# 7. End-to-End Multi-Node LAN Discovery Simulation
# =============================================================================

@pytest.mark.asyncio
async def test_two_nodes_end_to_end_discovery():
    port = get_free_udp_port()
    loop = asyncio.get_running_loop()

    node_a = MockNode(peer_id="node_a_hex", port=7001, node_name="Alice", advertised_host="127.0.0.1")
    node_b = MockNode(peer_id="node_b_hex", port=7002, node_name="Bob", advertised_host="127.0.0.1")

    beacon_a = LanBeacon(node_a, broadcast_port=port, interval=1.0, loop=loop)
    beacon_b = LanBeacon(node_b, broadcast_port=port, interval=1.0, loop=loop)

    beacon_a.start()
    beacon_b.start()

    try:
        # Wait up to 1.5s for mutual discovery burst to complete
        for _ in range(30):
            if len(node_a.connections_made) >= 1 and len(node_b.connections_made) >= 1:
                break
            await asyncio.sleep(0.05)

        assert any(p == 7002 for h, p in node_a.connections_made)
        assert any(p == 7001 for h, p in node_b.connections_made)
    finally:
        beacon_a.stop()
        beacon_b.stop()
