"""
Empirical Adversarial Challenge Suite: LAN Auto-Discovery UDP Beacon (Feature F29)
Target: src/discovery/lan_beacon.py

Stress Tests:
1. Sub-second discovery verification (<1.0s mutual discovery across 2 and 3 nodes on port 50050, plus real P2PNode handshake)
2. Self-beacon rejection under flood (500 self-beacons blasted, 0 self-connections)
3. Socket re-use and concurrent binding with SO_REUSEADDR on Windows (port 50050)
4. Corrupted datagram resilience (random bytes, truncated JSON, bad types, oversized datagrams >4KB, port 0, 70000)
5. Rapid lifecycle stress (20 start/stop cycles, checking task/descriptor leaks)
6. Adversarial edge cases (cooldown rate-limiting, blacklist rejection under flood, boundary ports, real P2PNode discovery)
"""

import asyncio
import json
import os
import socket
import time
import pytest
from typing import Set, Tuple, List, Dict, Any

from src.discovery.lan_beacon import LanBeacon
from src.core.p2p_node import P2PNode


class EmpiricalMockReputation:
    def __init__(self, blacklisted_ids=None):
        self.blacklisted_ids = set(blacklisted_ids or [])

    def is_blacklisted(self, peer_id: str) -> bool:
        return peer_id in self.blacklisted_ids


class EmpiricalMockNode:
    def __init__(self, name: str, port: int, peer_id: str, advertised_host: str = "127.0.0.1"):
        self.node_name = name
        self.port = port
        self.peer_id = peer_id
        self.advertised_host = advertised_host
        self.reputation = EmpiricalMockReputation()
        self.peers: Dict[Tuple[str, int], Tuple[str, str]] = {}
        self.connections_made: List[Tuple[str, int]] = []
        self.connection_attempts: Set[Tuple[str, int]] = set()

    async def connect_to_peer(self, host: str, port: int, timeout: float = 5.0, force: bool = False):
        self.connections_made.append((host, port))
        self.connection_attempts.add((host, port))
        return True, "Connected"


# =============================================================================
# Challenge 1: Sub-Second Discovery Verification (< 1.0s)
# =============================================================================

@pytest.mark.asyncio
async def test_sub_second_discovery_two_nodes_port_50050():
    """Verify that 2 independent nodes on port 50050 discover each other in <1.0s."""
    loop = asyncio.get_running_loop()
    node1 = EmpiricalMockNode("Node1", 9101, "peer_id_node_1_subsecond_test", "127.0.0.1")
    node2 = EmpiricalMockNode("Node2", 9102, "peer_id_node_2_subsecond_test", "127.0.0.1")

    beacon1 = LanBeacon(node1, broadcast_port=50050, interval=1.5, loop=loop)
    beacon2 = LanBeacon(node2, broadcast_port=50050, interval=1.5, loop=loop)

    t_start = time.perf_counter()
    beacon1.start()
    beacon2.start()

    discovered = False
    elapsed = 0.0
    try:
        # Wait up to 1.0s
        for _ in range(50):
            await asyncio.sleep(0.02)
            has_1_found_2 = any(p == 9102 for h, p in node1.connections_made)
            has_2_found_1 = any(p == 9101 for h, p in node2.connections_made)
            if has_1_found_2 and has_2_found_1:
                elapsed = time.perf_counter() - t_start
                discovered = True
                break

        assert discovered, f"Mutual discovery failed within timeout! Connections: n1={node1.connections_made}, n2={node2.connections_made}"
        assert elapsed < 1.0, f"Discovery exceeded sub-second SLA: took {elapsed:.4f}s"
    finally:
        beacon1.stop()
        beacon2.stop()


@pytest.mark.asyncio
async def test_sub_second_discovery_three_nodes_port_50050():
    """Verify that 3 independent nodes on port 50050 discover each other in <1.0s."""
    loop = asyncio.get_running_loop()
    node1 = EmpiricalMockNode("Node1", 9201, "peer_id_node_3way_1", "127.0.0.1")
    node2 = EmpiricalMockNode("Node2", 9202, "peer_id_node_3way_2", "127.0.0.1")
    node3 = EmpiricalMockNode("Node3", 9203, "peer_id_node_3way_3", "127.0.0.1")

    nodes = [node1, node2, node3]
    beacons = [LanBeacon(n, broadcast_port=50050, interval=1.5, loop=loop) for n in nodes]

    t_start = time.perf_counter()
    for b in beacons:
        b.start()

    discovered = False
    elapsed = 0.0
    try:
        # Check that each node discovers the other 2 nodes
        for _ in range(50):
            await asyncio.sleep(0.02)
            n1_ports = {p for h, p in node1.connections_made}
            n2_ports = {p for h, p in node2.connections_made}
            n3_ports = {p for h, p in node3.connections_made}

            if {9202, 9203}.issubset(n1_ports) and {9201, 9203}.issubset(n2_ports) and {9201, 9202}.issubset(n3_ports):
                elapsed = time.perf_counter() - t_start
                discovered = True
                break

        assert discovered, (
            f"3-way discovery incomplete! "
            f"n1={node1.connections_made}, n2={node2.connections_made}, n3={node3.connections_made}"
        )
        assert elapsed < 1.0, f"3-way discovery took {elapsed:.4f}s >= 1.0s"
    finally:
        for b in beacons:
            b.stop()


@pytest.mark.asyncio
async def test_sub_second_discovery_real_p2p_nodes(tmp_path):
    """Verify 2 full P2PNode instances with enable_discovery=True mutually discover & handshake in <1.0s."""
    db1 = str(tmp_path / "n1_rep.db")
    db2 = str(tmp_path / "n2_rep.db")
    st1 = str(tmp_path / "n1_storage")
    st2 = str(tmp_path / "n2_storage")

    node1 = P2PNode(host="0.0.0.0", port=9251, db_path=db1, storage_dir=st1, node_name="AliceReal", enable_discovery=True, beacon_port=50050)
    node2 = P2PNode(host="0.0.0.0", port=9252, db_path=db2, storage_dir=st2, node_name="BobReal", enable_discovery=True, beacon_port=50050)

    t1 = asyncio.create_task(node1.start_server())
    t2 = asyncio.create_task(node2.start_server())

    t_start = time.perf_counter()
    connected = False
    elapsed = 0.0
    try:
        for _ in range(50):
            await asyncio.sleep(0.02)
            n1_peers = [p[0] for p in node1.peers.values()]
            n2_peers = [p[0] for p in node2.peers.values()]
            if node2.peer_id in n1_peers and node1.peer_id in n2_peers:
                elapsed = time.perf_counter() - t_start
                connected = True
                break

        assert connected, f"Real P2PNodes failed mutual connection! n1_peers={node1.peers}, n2_peers={node2.peers}"
        assert elapsed < 1.0, f"Real P2PNode discovery took {elapsed:.4f}s >= 1.0s"
    finally:
        node1.stop()
        node2.stop()
        t1.cancel()
        t2.cancel()


# =============================================================================
# Challenge 2: Self-Beacon Rejection Under Flood
# =============================================================================

@pytest.mark.asyncio
async def test_self_beacon_flood_rejection():
    """Blast 500 self-beacons to UDP port 50050; verify 0 connections are triggered."""
    loop = asyncio.get_running_loop()
    my_peer_id = "self_peer_flood_protection_id_9999"
    my_port = 9301
    node = EmpiricalMockNode("SelfNode", my_port, my_peer_id, "127.0.0.1")
    beacon = LanBeacon(node, broadcast_port=50050, interval=1.5, loop=loop)

    beacon.start()
    try:
        await asyncio.sleep(0.05)

        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = {
            "type": "DISCOVERY_BEACON",
            "peer_id": my_peer_id,
            "username": "SelfNode",
            "tcp_port": my_port,
            "advertised_host": "127.0.0.1",
            "timestamp": time.time()
        }
        raw_data = json.dumps(payload).encode('utf-8')

        # Flood 500 self-beacons directly
        for _ in range(500):
            tx.sendto(raw_data, ('127.0.0.1', 50050))
        tx.close()

        # Let the event loop process inbound queue
        await asyncio.sleep(0.3)

        assert len(node.connections_made) == 0, f"Self-connections triggered under flood: {node.connections_made}"
    finally:
        beacon.stop()


# =============================================================================
# Challenge 3: Socket Re-use & Concurrent Binding on Windows (SO_REUSEADDR)
# =============================================================================

def test_concurrent_udp_binding_windows_reuseaddr():
    """Verify that multiple UDP sockets bind concurrently to port 50050 on Windows."""
    socks = []
    try:
        for _ in range(5):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.bind(('', 50050))
            socks.append(s)

        assert len(socks) == 5
        for s in socks:
            assert s.getsockname()[1] == 50050
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


@pytest.mark.asyncio
async def test_concurrent_beacons_port_50050_coexistence():
    """Verify 4 LanBeacon instances can coexist on port 50050 without socket collisions."""
    loop = asyncio.get_running_loop()
    beacons = []
    nodes = []
    try:
        for i in range(4):
            n = EmpiricalMockNode(f"CoexistNode{i}", 9400 + i, f"peer_coexist_{i}", "127.0.0.1")
            b = LanBeacon(n, broadcast_port=50050, interval=1.5, loop=loop)
            nodes.append(n)
            beacons.append(b)
            b.start()

        # All 4 should be running concurrently
        for b in beacons:
            assert b.running
            assert b._rx_sock is not None
            assert b._tx_sock is not None

        await asyncio.sleep(0.2)
    finally:
        for b in beacons:
            b.stop()


# =============================================================================
# Challenge 4: Corrupted Datagram Resilience
# =============================================================================

@pytest.mark.asyncio
async def test_corrupted_datagram_resilience_and_clean_survival():
    """
    Send adversarial payloads:
    - Random garbage bytes (16B, 128B, 1024B)
    - Malformed and truncated JSON
    - Missing fields
    - Invalid types (non-dict, wrong type, non-str peer_id, string port)
    - Out of range ports (port 0, port 70000, port -1)
    - Oversized datagrams (> 4KB, up to 32KB)
    Verify receiver does not crash, ignores all invalid datagrams, and processes a subsequent valid beacon.
    """
    loop = asyncio.get_running_loop()
    node = EmpiricalMockNode("TargetNode", 9500, "peer_target_resilience", "127.0.0.1")
    beacon = LanBeacon(node, broadcast_port=50050, interval=1.5, loop=loop)

    beacon.start()
    try:
        await asyncio.sleep(0.05)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        adversarial_payloads = [
            # 1. Random noise
            os.urandom(16),
            os.urandom(128),
            os.urandom(1024),
            # 2. Malformed JSON
            b"{not json}",
            b'{"type": "DISCOVERY_BEACON", "peer_id": ',
            b'{"type": "DISCOVERY_BEACON", "peer_id": "test"',
            b"",
            b"   \n\r  ",
            # 3. Non-dictionary JSON
            json.dumps(["not", "a", "dict"]).encode('utf-8'),
            json.dumps(123456).encode('utf-8'),
            json.dumps("string-only").encode('utf-8'),
            json.dumps(None).encode('utf-8'),
            # 4. Wrong message types
            json.dumps({"type": "WRONG_TYPE", "peer_id": "p1", "tcp_port": 8000}).encode('utf-8'),
            json.dumps({"type": "", "peer_id": "p1", "tcp_port": 8000}).encode('utf-8'),
            # 5. Missing / Invalid peer_id
            json.dumps({"type": "DISCOVERY_BEACON", "tcp_port": 8000}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "", "tcp_port": 8000}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": 12345, "tcp_port": 8000}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": ["list"], "tcp_port": 8000}).encode('utf-8'),
            # 6. Invalid / Out-of-bounds TCP ports
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": 0}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": -1}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": 70000}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": 65536}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": "invalid_str"}).encode('utf-8'),
            json.dumps({"type": "DISCOVERY_BEACON", "peer_id": "p1", "tcp_port": None}).encode('utf-8'),
            # 7. Oversized datagrams (> 4096 bytes)
            b"A" * 5000,
            b"B" * 8192,
            b"C" * 16384,
            b"D" * 32768,
        ]

        for payload in adversarial_payloads:
            try:
                tx.sendto(payload, ('127.0.0.1', 50050))
            except Exception:
                pass  # OS level send failure for huge datagrams is acceptable

        await asyncio.sleep(0.3)

        # Confirm 0 invalid connections were made
        assert len(node.connections_made) == 0, f"Unexpected connections made from bad payloads: {node.connections_made}"
        assert beacon.running, "Beacon crashed or stopped running after receiving bad datagrams!"

        # Deliver a VALID beacon to prove the listener is alive and fully functional
        good_payload = {
            "type": "DISCOVERY_BEACON",
            "peer_id": "good_peer_post_resilience_test",
            "username": "GoodPeer",
            "tcp_port": 9555,
            "advertised_host": "127.0.0.1",
            "timestamp": time.time()
        }
        tx.sendto(json.dumps(good_payload).encode('utf-8'), ('127.0.0.1', 50050))
        tx.close()

        await asyncio.sleep(0.1)

        # The good peer MUST be discovered
        assert len(node.connections_made) == 1, f"Failed to discover good peer after flood: {node.connections_made}"
        assert node.connections_made[0] == ("127.0.0.1", 9555)
    finally:
        beacon.stop()


# =============================================================================
# Challenge 5: Rapid Lifecycle Stress (20 Cycles)
# =============================================================================

@pytest.mark.asyncio
async def test_rapid_lifecycle_stress_20_cycles():
    """
    Rapidly call start() and stop() 20 times in a loop.
    Verify:
    1. Zero descriptor leaks (sockets are closed each cycle)
    2. Zero hanging background tasks
    3. Listener successfully restarts on cycle 20 and can discover a peer
    """
    loop = asyncio.get_running_loop()
    node = EmpiricalMockNode("LifecycleNode", 9600, "peer_lifecycle_test", "127.0.0.1")
    beacon = LanBeacon(node, broadcast_port=50050, interval=1.0, loop=loop)

    for cycle in range(20):
        beacon.start()
        assert beacon.running, f"Cycle {cycle}: beacon failed to start"
        assert len(beacon._tasks) == 2, f"Cycle {cycle}: expected 2 tasks, got {len(beacon._tasks)}"
        assert beacon._rx_sock is not None, f"Cycle {cycle}: rx_sock is None"
        assert beacon._tx_sock is not None, f"Cycle {cycle}: tx_sock is None"

        # Brief pause on some iterations to let tasks spin up
        if cycle % 5 == 0:
            await asyncio.sleep(0.02)

        beacon.stop()
        assert not beacon.running, f"Cycle {cycle}: beacon still running after stop"
        assert len(beacon._tasks) == 0, f"Cycle {cycle}: tasks not cleared"
        assert beacon._rx_sock is None, f"Cycle {cycle}: rx_sock not cleared"
        assert beacon._tx_sock is None, f"Cycle {cycle}: tx_sock not cleared"

    # Start once more and confirm it receives datagrams
    beacon.start()
    try:
        await asyncio.sleep(0.05)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        valid_msg = {
            "type": "DISCOVERY_BEACON",
            "peer_id": "peer_cycle_21",
            "username": "CyclePeer",
            "tcp_port": 9601,
            "advertised_host": "127.0.0.1",
            "timestamp": time.time()
        }
        tx.sendto(json.dumps(valid_msg).encode('utf-8'), ('127.0.0.1', 50050))
        tx.close()

        await asyncio.sleep(0.1)
        assert len(node.connections_made) == 1
        assert node.connections_made[0] == ("127.0.0.1", 9601)
    finally:
        beacon.stop()


# =============================================================================
# Challenge 6: Adversarial Edge Cases
# =============================================================================

@pytest.mark.asyncio
async def test_blacklisted_peer_flood_rejection():
    """Verify blacklisted peers cannot trigger connections even if flooding beacons."""
    loop = asyncio.get_running_loop()
    node = EmpiricalMockNode("GuardNode", 9700, "peer_guard_test", "127.0.0.1")
    node.reputation.blacklisted_ids.add("malicious_attacker_666")

    beacon = LanBeacon(node, broadcast_port=50050, interval=1.5, loop=loop)
    beacon.start()
    try:
        await asyncio.sleep(0.05)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        bad_payload = {
            "type": "DISCOVERY_BEACON",
            "peer_id": "malicious_attacker_666",
            "username": "Attacker",
            "tcp_port": 9701,
            "advertised_host": "192.168.1.200",
            "timestamp": time.time()
        }
        raw_data = json.dumps(bad_payload).encode('utf-8')

        for _ in range(100):
            tx.sendto(raw_data, ('127.0.0.1', 50050))
        tx.close()

        await asyncio.sleep(0.2)
        assert len(node.connections_made) == 0, f"Attacker triggered connections: {node.connections_made}"
    finally:
        beacon.stop()


@pytest.mark.asyncio
async def test_port_boundary_limits():
    """Verify port 1 and port 65535 are accepted, while port 0 and 65536 are rejected."""
    loop = asyncio.get_running_loop()
    node = EmpiricalMockNode("BoundaryNode", 9800, "peer_boundary_test", "127.0.0.1")
    beacon = LanBeacon(node, broadcast_port=50050, interval=1.5, loop=loop)
    beacon.start()
    try:
        await asyncio.sleep(0.05)
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Port 0 (rejected)
        tx.sendto(json.dumps({
            "type": "DISCOVERY_BEACON", "peer_id": "p_0", "tcp_port": 0, "advertised_host": "127.0.0.1"
        }).encode('utf-8'), ('127.0.0.1', 50050))

        # Port 65536 (rejected)
        tx.sendto(json.dumps({
            "type": "DISCOVERY_BEACON", "peer_id": "p_65536", "tcp_port": 65536, "advertised_host": "127.0.0.1"
        }).encode('utf-8'), ('127.0.0.1', 50050))

        # Port 1 (valid boundary)
        tx.sendto(json.dumps({
            "type": "DISCOVERY_BEACON", "peer_id": "p_1", "tcp_port": 1, "advertised_host": "127.0.0.1"
        }).encode('utf-8'), ('127.0.0.1', 50050))

        # Port 65535 (valid boundary)
        tx.sendto(json.dumps({
            "type": "DISCOVERY_BEACON", "peer_id": "p_65535", "tcp_port": 65535, "advertised_host": "127.0.0.1"
        }).encode('utf-8'), ('127.0.0.1', 50050))

        tx.close()
        await asyncio.sleep(0.2)

        ports_connected = [p for h, p in node.connections_made]
        assert 0 not in ports_connected
        assert 65536 not in ports_connected
        assert 1 in ports_connected
        assert 65535 in ports_connected
    finally:
        beacon.stop()
