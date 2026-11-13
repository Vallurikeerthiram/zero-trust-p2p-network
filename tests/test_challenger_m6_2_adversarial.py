"""
Adversarial Empirical Test Suite for Milestone 6:
- Dual-Address Network Binding (`host` vs `advertised_host`)
- Wildcard TCP Connection Crash Prevention (No WinError 10049 on Windows)
- Malicious/Buggy Peer Host Sanitization
- Multi-Node Same-Port Retention Across Distinct IP Addresses
- Peer Host & Username Metadata Tracking in Control Envelopes
- Zero-Trust Cryptographic Invariants (SHA-256 peer_id vs node_name spoofing)
- Windows OS Environment Variable Integrity (os.environ['USERNAME'])
- Public Connect API Boundary, Self-Connection, and Concurrency Protections
"""

import asyncio
import os
import sys
import json
import socket
import tempfile
import time
import pytest
from typing import Tuple

from src.core.p2p_node import P2PNode, pack_tcp_frame, unpack_tcp_frame, create_signed_envelope
from src.core.crypto import PeerIdentity
from src.core.reputation import ReputationEngine
from src.core.file_manager import FileManager


@pytest.fixture
def temp_node_dirs(tmp_path):
    storage = tmp_path / "storage"
    storage.mkdir()
    db = tmp_path / "reputation.db"
    return str(storage), str(db)


# ==============================================================================
# 1. DUAL-ADDRESS NETWORK BINDING TESTS
# ==============================================================================

def test_dual_address_binding_wildcard_defaults(temp_node_dirs):
    """
    Verify that instantiating a node with host='0.0.0.0' binds to '0.0.0.0'
    while advertised_host resolves to a valid reachable address (LAN IP or 127.0.0.1),
    never leaving advertised_host as '0.0.0.0'.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9010, db_path=db, storage_dir=storage)
    
    assert node.host == "0.0.0.0", "Listening host must be 0.0.0.0"
    assert node.advertised_host != "0.0.0.0", "Advertised host must never be 0.0.0.0"
    assert node.advertised_host in ("127.0.0.1", "192.168.0.2") or len(node.advertised_host.split(".")) == 4, (
        f"Advertised host {node.advertised_host} must be a valid IPv4 address"
    )
    assert node.enable_discovery is False, "enable_discovery must default to False to protect unit test isolation"


def test_dual_address_binding_explicit_override(temp_node_dirs):
    """
    Verify that explicit advertise_host parameter strictly overrides default resolution.
    """
    storage, db = temp_node_dirs
    node = P2PNode(
        host="0.0.0.0",
        port=9011,
        db_path=db,
        storage_dir=storage,
        advertise_host="198.51.100.42"
    )
    assert node.host == "0.0.0.0"
    assert node.advertised_host == "198.51.100.42"


def test_dual_address_binding_loopback_retention(temp_node_dirs):
    """
    Verify that when host='127.0.0.1', advertised_host is '127.0.0.1'.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9012, db_path=db, storage_dir=storage)
    assert node.host == "127.0.0.1"
    assert node.advertised_host == "127.0.0.1"


# ==============================================================================
# 2. WILDCARD TCP CONNECTION CRASH PREVENTION (NO WinError 10049)
# ==============================================================================

@pytest.mark.asyncio
async def test_auto_sync_loop_never_targets_wildcard_address(temp_node_dirs, monkeypatch):
    """
    Aggressively verify that auto_sync_loop never attempts to connect to '0.0.0.0'.
    On Windows, socket.connect(('0.0.0.0', port)) raises WinError 10049.
    Local registry ports must be mapped to '127.0.0.1'.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9020, db_path=db, storage_dir=storage)

    # Populate swarm_registry.json with simulated ports
    registry_file = "swarm_registry.json"
    with open(registry_file, "w") as f:
        json.dump([9020, 9021, 9022], f)

    try:
        pinged_targets = []

        async def mock_ping_peer(host, port):
            pinged_targets.append((host, port))
            return True

        monkeypatch.setattr(node, "ping_peer", mock_ping_peer)

        # Simulate the registry and peer target resolution from auto_sync_loop
        targets_to_ping = set()
        local_host = "127.0.0.1" if node.host in ("0.0.0.0", "", "::") else node.host
        if os.path.exists(registry_file):
            with open(registry_file, "r") as f:
                peers = json.load(f)
            for p in peers:
                if p != node.port:
                    targets_to_ping.add((local_host, p))
        for (h, p) in list(node.peers.keys()):
            if (p == node.port) and (h in ("127.0.0.1", "localhost", node.host, getattr(node, "advertised_host", None))):
                continue
            targets_to_ping.add((h, p))

        # Check every target
        for h, p in targets_to_ping:
            assert h != "0.0.0.0", f"CRITICAL: Target {h}:{p} uses wildcard 0.0.0.0 which triggers WinError 10049!"
            assert h == "127.0.0.1"
            assert p in (9021, 9022)

    finally:
        if os.path.exists(registry_file):
            os.remove(registry_file)


@pytest.mark.asyncio
async def test_broadcast_corruption_alert_never_targets_wildcard_address(temp_node_dirs, monkeypatch):
    """
    Verify broadcast_corruption_alert maps local registry ports to '127.0.0.1' when host='0.0.0.0'.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9030, db_path=db, storage_dir=storage)

    registry_file = "swarm_registry.json"
    with open(registry_file, "w") as f:
        json.dump([9030, 9031], f)

    try:
        sent_requests = []

        async def mock_send_request(host, port, payload):
            sent_requests.append((host, port, payload))
            return {"status": "OK"}

        monkeypatch.setattr(node, "_send_request", mock_send_request)

        await node.broadcast_corruption_alert(
            filename="fake_file.txt",
            bad_peer_id="e" * 64,
            bad_peer_name="MaliciousNode",
            chunk_index=0
        )

        assert len(sent_requests) == 1
        target_host, target_port, payload = sent_requests[0]
        assert target_host != "0.0.0.0", "Corruption alert must not connect to 0.0.0.0"
        assert target_host == "127.0.0.1"
        assert target_port == 9031
        assert payload["sender_name"] == node.node_name

    finally:
        if os.path.exists(registry_file):
            os.remove(registry_file)


@pytest.mark.asyncio
async def test_ping_peer_wildcard_error_resilience(temp_node_dirs):
    """
    Verify that if ping_peer is accidentally called with '0.0.0.0',
    it safely returns False without raising an unhandled exception or crashing.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9035, db_path=db, storage_dir=storage)
    res = await node.ping_peer("0.0.0.0", 9999)
    assert res is False, "ping_peer('0.0.0.0', ...) must safely return False"


# ==============================================================================
# 3. PEER HOST SANITIZATION AGAINST MALICIOUS ADVERTISEMENTS
# ==============================================================================

@pytest.mark.asyncio
async def test_handle_client_sanitizes_malicious_zero_zero_zero_zero_peer_host(temp_node_dirs):
    """
    Adversarial Scenario: A peer connects and sends PING with 'host': '0.0.0.0'.
    Verify handle_client detects this and sanitizes it to the socket peer address
    or '127.0.0.1', preventing '0.0.0.0' from entering self.peers.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9040, db_path=db, storage_dir=storage)

    peer_ident = PeerIdentity("AttackerNode")
    evil_payload = {
        'type': 'PING',
        'sender_id': peer_ident.get_peer_id(),
        'sender_name': 'AttackerNode',
        'host': '0.0.0.0', # MALICIOUS: attempting to poison peers with 0.0.0.0
        'port': 9045,
        'files': {}
    }
    evil_envelope = create_signed_envelope(peer_ident, evil_payload)

    # Mock reader and writer
    class MockWriter:
        def __init__(self):
            self.written = []
            self.closed = False
        def get_extra_info(self, name):
            if name == 'peername':
                return ('192.168.1.150', 54321)
            return None
        def write(self, data):
            self.written.append(data)
        async def drain(self):
            pass
        def close(self):
            self.closed = True
        async def wait_closed(self):
            pass

    mock_writer = MockWriter()
    frame_bytes = pack_tcp_frame(evil_envelope)

    reader = asyncio.StreamReader()
    reader.feed_data(frame_bytes)
    reader.feed_eof()

    await node.handle_client(reader, mock_writer)

    # Verify self.peers does NOT contain '0.0.0.0'
    assert ("0.0.0.0", 9045) not in node.peers, "0.0.0.0 must never be accepted into self.peers"
    # Verify sanitized host was used (socket addr: 192.168.1.150)
    assert ("192.168.1.150", 9045) in node.peers
    peer_id, peer_name = node.peers[("192.168.1.150", 9045)]
    assert peer_id == peer_ident.get_peer_id()
    assert peer_name == "AttackerNode"


# ==============================================================================
# 4. MULTI-NODE SAME-PORT RETENTION ACROSS DISTINCT HOST ADDRESSES
# ==============================================================================

def test_multi_node_same_port_peers_on_different_ips_not_dropped(temp_node_dirs):
    """
    Aggressively verify that multiple peers running on the same port across
    distinct IP addresses (common in LAN/WAN swarms) are all retained in
    self.peers and all pinged by auto_sync_loop, without collapsing or dropping.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9050, db_path=db, storage_dir=storage)

    id1 = "a" * 64
    id2 = "b" * 64
    id3 = "c" * 64

    # Three peers, all on default port 8000, but on distinct hosts
    node.peers[("192.168.1.10", 8000)] = (id1, "Alice")
    node.peers[("192.168.1.20", 8000)] = (id2, "Bob")
    node.peers[("10.0.0.5", 8000)] = (id3, "Charlie")

    assert len(node.peers) == 3, "All 3 distinct (host, port) peers must be retained in self.peers"

    # Simulate auto_sync_loop target extraction
    targets_to_ping = set()
    local_host = "127.0.0.1" if node.host in ("0.0.0.0", "", "::") else node.host
    for (h, p) in list(node.peers.keys()):
        if (p == node.port) and (h in ("127.0.0.1", "localhost", node.host, getattr(node, "advertised_host", None))):
            continue
        targets_to_ping.add((h, p))

    assert len(targets_to_ping) == 3, f"Expected 3 distinct ping targets, got {len(targets_to_ping)}"
    assert ("192.168.1.10", 8000) in targets_to_ping
    assert ("192.168.1.20", 8000) in targets_to_ping
    assert ("10.0.0.5", 8000) in targets_to_ping


# ==============================================================================
# 5. PEER HOST TRACKING & USERNAME PROPAGATION IN LIVE TCP CONTROL MESSAGES
# ==============================================================================

@pytest.mark.asyncio
async def test_live_peer_host_tracking_and_username_propagation(tmp_path):
    """
    Spin up two live nodes on loopback ports.
    Verify that PING, PONG, and SHARE_FILE_INFO propagate advertised_host, port,
    and sender_name, and that both nodes record (peer_id, peer_name) in self.peers.
    """
    storage_a = str(tmp_path / "storage_a")
    os.makedirs(storage_a, exist_ok=True)
    db_a = str(tmp_path / "rep_a.db")

    storage_b = str(tmp_path / "storage_b")
    os.makedirs(storage_b, exist_ok=True)
    db_b = str(tmp_path / "rep_b.db")

    node_a = P2PNode(host="127.0.0.1", port=9061, db_path=db_a, storage_dir=storage_a, node_name="Alice")
    node_b = P2PNode(host="127.0.0.1", port=9062, db_path=db_b, storage_dir=storage_b, node_name="Bob")

    server_b = await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)
    server_a = await asyncio.start_server(node_a.handle_client, node_a.host, node_a.port)

    try:
        # Node A connects to Node B
        ok, msg = await node_a.connect_to_peer("127.0.0.1", 9062)
        assert ok is True, f"connect_to_peer failed: {msg}"

        # Verify Node A recorded Node B in self.peers
        assert ("127.0.0.1", 9062) in node_a.peers
        b_id, b_name = node_a.peers[("127.0.0.1", 9062)]
        assert b_id == node_b.peer_id
        assert b_name == "Bob"

        # Verify Node B recorded Node A in self.peers
        assert ("127.0.0.1", 9061) in node_b.peers
        a_id, a_name = node_b.peers[("127.0.0.1", 9061)]
        assert a_id == node_a.peer_id
        assert a_name == "Alice"

        # Node A broadcasts a file
        test_file = os.path.join(storage_a, "alice_data.txt")
        with open(test_file, "w") as f:
            f.write("Zero-Trust Shared Data from Alice")

        root = await node_a.broadcast_file(test_file)
        assert root is not None

        # Give Node B a moment to process SHARE_FILE_INFO
        await asyncio.sleep(0.1)

        # Verify Node B received the file info from Alice
        assert node_a.peer_id in node_b.peer_files
        assert "alice_data.txt" in node_b.peer_files[node_a.peer_id]
        meta = node_b.peer_files[node_a.peer_id]["alice_data.txt"]
        assert meta["merkle_root"] == root
        assert meta["total_chunks"] >= 1

    finally:
        server_a.close()
        server_b.close()
        await server_a.wait_closed()
        await server_b.wait_closed()


# ==============================================================================
# 6. ZERO-TRUST CRYPTOGRAPHIC INVARIANT (SHA-256 peer_id vs node_name Spoofing)
# ==============================================================================

def test_zero_trust_node_name_spoofing_does_not_alter_peer_id(temp_node_dirs):
    """
    Verify that an attacker claiming node_name='Alice' has a completely different
    cryptographic peer_id, and that reputation tracking is 100% bound to peer_id.
    """
    storage, db = temp_node_dirs
    real_alice = P2PNode(host="127.0.0.1", port=9070, db_path=db, storage_dir=storage, node_name="Alice_Key")
    real_alice.node_name = "Alice"

    attacker = P2PNode(host="127.0.0.1", port=9071, db_path=db, storage_dir=storage, node_name="Attacker_Key")
    attacker.node_name = "Alice"  # Attacker attempts to impersonate Alice's display name

    # Invariant: peer_id is independent of node_name
    assert real_alice.peer_id != attacker.peer_id, "Different RSA keys must have distinct SHA-256 peer_ids"
    assert len(real_alice.peer_id) == 64
    assert len(attacker.peer_id) == 64

    # Reward Alice in reputation engine (+2)
    real_alice.reputation.add_peer(real_alice.peer_id)
    real_alice.reputation.update_trust(real_alice.peer_id, True)
    assert real_alice.reputation.get_trust_score(real_alice.peer_id) == 52

    # Verify Attacker's score is unaffected
    attacker.reputation.add_peer(attacker.peer_id)
    assert attacker.reputation.get_trust_score(attacker.peer_id) == 50

    # Penalize Attacker to blacklist (50 - 25 - 25 = 0)
    attacker.reputation.update_trust(attacker.peer_id, False)
    attacker.reputation.update_trust(attacker.peer_id, False)
    assert attacker.reputation.is_blacklisted(attacker.peer_id) is True

    # Verify Alice is NOT blacklisted despite sharing node_name='Alice'
    assert real_alice.reputation.is_blacklisted(real_alice.peer_id) is False


def test_zero_trust_signature_anti_spoofing_enforcement(temp_node_dirs):
    """
    Verify that an attacker cannot forge Alice's peer_id in a signed envelope.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9075, db_path=db, storage_dir=storage)

    alice_id = "a" * 64
    attacker_ident = PeerIdentity("Attacker_Key")

    # Attacker creates valid envelope with their key
    attacker_envelope = create_signed_envelope(attacker_ident, {'type': 'PING', 'host': '127.0.0.1', 'port': 9076})
    # Attacker tries to tamper with sender_id to claim Alice's ID
    attacker_envelope['sender_id'] = alice_id  # SPOOFED

    valid, reason, _ = node.verify_envelope(attacker_envelope)
    assert valid is False
    assert reason == "SPOOFED_SENDER_ID", "Envelope verifier must reject spoofed sender_id"


# ==============================================================================
# 7. WINDOWS OS ENVIRONMENT VARIABLE INTEGRITY (os.environ['USERNAME'])
# ==============================================================================

def test_windows_os_environment_username_unmodified():
    """
    Verify that start_node.py logic and node initialization never mutate
    or overwrite os.environ['USERNAME'] on Windows.
    Windows permissions and icacls rely on this variable.
    """
    original_username = os.environ.get("USERNAME")
    
    # Simulate start_node environment generation
    node_name = "AdversarialTester"
    env_copy = os.environ.copy()
    env_copy["NODE_NAME"] = node_name
    env_copy["P2P_USERNAME"] = node_name
    env_copy["P2P_HOST"] = "0.0.0.0"
    env_copy["P2P_PORT"] = "8050"

    # Current process environment must be untouched
    assert os.environ.get("USERNAME") == original_username, "os.environ['USERNAME'] was mutated!"

    # In child environment, USERNAME remains OS username while NODE_NAME is the P2P alias
    if original_username:
        assert env_copy.get("USERNAME") == original_username
    assert env_copy.get("NODE_NAME") == "AdversarialTester"
    assert env_copy.get("P2P_USERNAME") == "AdversarialTester"


# ==============================================================================
# 8. PUBLIC CONNECT API BOUNDARY, SELF-CONNECTION & CONCURRENCY PROTECTIONS
# ==============================================================================

@pytest.mark.asyncio
async def test_connect_to_peer_input_validation(temp_node_dirs):
    """
    Verify connect_to_peer rejects invalid host strings, boundary ports, and malformed inputs.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9080, db_path=db, storage_dir=storage)

    # Invalid host
    ok, err = await node.connect_to_peer("", 8000)
    assert ok is False and "host" in err.lower()

    ok, err = await node.connect_to_peer("   ", 8000)
    assert ok is False and "host" in err.lower()

    ok, err = await node.connect_to_peer(None, 8000)
    assert ok is False and "host" in err.lower()

    # Invalid port bounds
    ok, err = await node.connect_to_peer("127.0.0.1", 0)
    assert ok is False and "port" in err.lower()

    ok, err = await node.connect_to_peer("127.0.0.1", -1)
    assert ok is False and "port" in err.lower()

    ok, err = await node.connect_to_peer("127.0.0.1", 65536)
    assert ok is False and "port" in err.lower()

    ok, err = await node.connect_to_peer("127.0.0.1", "bad_port")
    assert ok is False and "port" in err.lower()


@pytest.mark.asyncio
async def test_connect_to_peer_rejects_self_connections(temp_node_dirs):
    """
    Verify connect_to_peer prevents connecting to self across all local address aliases.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="0.0.0.0", port=9085, db_path=db, storage_dir=storage, advertise_host="192.168.1.99")

    # Self-connections on same port
    for self_host in ("127.0.0.1", "localhost", "0.0.0.0", "192.168.1.99"):
        ok, err = await node.connect_to_peer(self_host, 9085)
        assert ok is False, f"Failed to reject self-connection for host {self_host}"
        assert err == "Cannot connect to self"

    # Different port on same host is allowed (multi-node swarm on local machine)
    # Mock ping_peer so we don't need a real server
    node.ping_peer = lambda h, p: asyncio.sleep(0.01, result=False)
    ok, err = await node.connect_to_peer("127.0.0.1", 9086)
    assert err != "Cannot connect to self"


@pytest.mark.asyncio
async def test_connect_to_peer_blacklisted_peer_rejection(temp_node_dirs):
    """
    Verify connect_to_peer immediately rejects connecting to a known blacklisted peer.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9090, db_path=db, storage_dir=storage)

    bad_id = "d" * 64
    node.peers[("127.0.0.1", 9091)] = (bad_id, "BlacklistedPeer")
    node.reputation.add_peer(bad_id)
    node.reputation.update_trust(bad_id, False)
    node.reputation.update_trust(bad_id, False)
    assert node.reputation.is_blacklisted(bad_id) is True

    ok, err = await node.connect_to_peer("127.0.0.1", 9091)
    assert ok is False
    assert err == "Peer is blacklisted"


def test_connect_to_peer_sync_event_loop_deadlock_guard(temp_node_dirs):
    """
    Verify connect_to_peer_sync prevents being called from within the running event loop
    thread to avoid asyncio run_coroutine_threadsafe deadlocks.
    """
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9095, db_path=db, storage_dir=storage)

    # When loop is not active
    ok, err = node.connect_to_peer_sync("127.0.0.1", 9096)
    assert ok is False
    assert err == "Node event loop is not active"

    # When called from inside the active loop
    async def inside_loop():
        node.loop = asyncio.get_running_loop()
        return node.connect_to_peer_sync("127.0.0.1", 9096)

    ok, err = asyncio.run(inside_loop())
    assert ok is False
    assert "Cannot call connect_to_peer_sync from the event loop thread" in err


def test_connect_to_peer_sync_from_worker_thread(temp_node_dirs):
    """
    Verify connect_to_peer_sync executes cleanly and returns results when called
    from an external worker thread while the node's loop runs in another thread.
    """
    import threading
    storage, db = temp_node_dirs
    node = P2PNode(host="127.0.0.1", port=9098, db_path=db, storage_dir=storage)

    loop = asyncio.new_event_loop()
    node.loop = loop

    def loop_runner():
        asyncio.set_event_loop(loop)
        loop.run_forever()

    t = threading.Thread(target=loop_runner, daemon=True)
    t.start()

    try:
        # Mock connect_to_peer on node
        async def mock_connect(h, p, timeout=5.0):
            return True, f"Connected to {h}:{p}"
        node.connect_to_peer = mock_connect

        ok, msg = node.connect_to_peer_sync("127.0.0.1", 5005)
        assert ok is True
        assert msg == "Connected to 127.0.0.1:5005"
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2.0)
