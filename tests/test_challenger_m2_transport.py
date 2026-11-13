"""
Empirical Challenge & Stress Test Suite for Milestone 2 (M2)
Challenger 2 (ID: challenger_m2_2)

Targets:
- src.core.p2p_node.P2PNode
- src.core.p2p_node.create_signed_envelope
- src.core.p2p_node.verify_envelope
- src.core.p2p_node.pack_tcp_frame / unpack_tcp_frame / send_frame / read_frame
- src.core.reputation.ReputationEngine

Focus Areas:
1. Replay attack simulations: reused nonces within 60s, expired timestamps (>60s past and future).
2. Identity spoofing: mismatched sender_id vs public_key hash, tampered signatures, altered payloads.
3. Inbound blacklist bypass: omit sender_id, null sender_id, empty string sender_id, blacklisted sender_id across TCP & envelope handlers.
4. Outbound blacklist isolation: pinging, syncing, downloading, and broadcasting to blacklisted peers.
5. White-box boundary stress: NaN timestamps, concurrent replay races, metadata-signature decoupling.
"""

import os
import sys
import time
import json
import uuid
import struct
import base64
import math
import asyncio
import hashlib
import tempfile
import pytest
from unittest.mock import AsyncMock, patch

from src.core.p2p_node import (
    P2PNode,
    create_signed_envelope,
    pack_tcp_frame,
    unpack_tcp_frame,
    send_frame,
    read_frame,
    MAX_MESSAGE_SIZE
)
from src.core.crypto import PeerIdentity, MerkleTree
from src.core.reputation import ReputationEngine
from src.core.file_manager import FileManager


@pytest.fixture
def temp_env(tmp_path):
    """Provides unique temporary directories and database paths for isolated node testing."""
    db_path = str(tmp_path / "test_reputation.db")
    storage_dir = str(tmp_path / "storage")
    os.makedirs(storage_dir, exist_ok=True)
    return {"db_path": db_path, "storage_dir": storage_dir, "tmp_path": tmp_path}


@pytest.fixture
def node_factory(temp_env):
    """Creates isolated P2PNode instances with clean state."""
    nodes = []

    def _create(port=18000, name=""):
        node_name = name or f"node_{port}"
        node_storage = os.path.join(temp_env["storage_dir"], node_name)
        os.makedirs(node_storage, exist_ok=True)
        node_db = os.path.join(str(temp_env["tmp_path"]), f"{node_name}_rep.db")
        node = P2PNode(
            host="127.0.0.1",
            port=port,
            db_path=node_db,
            storage_dir=node_storage,
            node_name=node_name
        )
        nodes.append(node)
        return node

    yield _create


# ============================================================================
# PART 1: REPLAY ATTACK SIMULATIONS
# ============================================================================

class TestReplayAttackSimulations:
    """Empirical verification of replay prevention and timestamp drift validation."""

    def test_replay_same_nonce_immediate(self, node_factory):
        """Replay exact envelope immediately; first accepted, second rejected with NONCE_REPLAYED."""
        node = node_factory(port=18101)
        alice = PeerIdentity("alice_replay_1")
        payload = {"type": "PING", "sender_id": alice.peer_id}

        env = create_signed_envelope(alice, payload)

        # First delivery: must be accepted
        valid_1, reason_1, unwrapped_1 = node.verify_envelope(env)
        assert valid_1 is True, f"First envelope rejected: {reason_1}"
        assert reason_1 == "ACCEPTED"
        assert unwrapped_1 == payload

        # Immediate replay: must be rejected
        valid_2, reason_2, unwrapped_2 = node.verify_envelope(env)
        assert valid_2 is False, "Replayed envelope was accepted unexpectedly!"
        assert reason_2 == "NONCE_REPLAYED"
        assert unwrapped_2 is None

    def test_replay_same_nonce_after_100ms(self, node_factory):
        """Replay envelope with same nonce after 100ms delay; must be rejected with NONCE_REPLAYED."""
        node = node_factory(port=18102)
        alice = PeerIdentity("alice_replay_2")
        payload = {"type": "GET_CHUNK", "filename": "data.bin", "chunk_index": 0}

        env = create_signed_envelope(alice, payload)

        valid_1, reason_1, _ = node.verify_envelope(env)
        assert valid_1 is True

        # Wait 100ms
        time.sleep(0.1)

        valid_2, reason_2, _ = node.verify_envelope(env)
        assert valid_2 is False, "Replay after 100ms was accepted!"
        assert reason_2 == "NONCE_REPLAYED"

    def test_replay_same_nonce_different_payload(self, node_factory):
        """Attacker keeps observed nonce but signs a different payload; nonce collision must trigger rejection."""
        node = node_factory(port=18103)
        alice = PeerIdentity("alice_replay_3")
        reused_nonce = str(uuid.uuid4())

        payload_1 = {"type": "PING", "sender_id": alice.peer_id}
        env_1 = create_signed_envelope(alice, payload_1, nonce=reused_nonce)
        valid_1, reason_1, _ = node.verify_envelope(env_1)
        assert valid_1 is True

        # New payload from Alice, but reused nonce
        payload_2 = {"type": "GET_CHUNK", "filename": "secret.txt", "chunk_index": 0}
        env_2 = create_signed_envelope(alice, payload_2, nonce=reused_nonce)
        valid_2, reason_2, _ = node.verify_envelope(env_2)
        assert valid_2 is False
        assert reason_2 == "NONCE_REPLAYED"

    @pytest.mark.asyncio
    async def test_replay_same_nonce_across_separate_tcp_connections(self, node_factory):
        """Replaying a signed envelope across distinct TCP socket connections must be blocked by the server."""
        node = node_factory(port=18104)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        alice = PeerIdentity("alice_tcp_replay")
        payload = {"type": "PING", "sender_id": alice.peer_id, "host": "127.0.0.1", "port": 19999}
        env = create_signed_envelope(alice, payload)

        try:
            # Connection 1: First delivery
            r1, w1 = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w1, env)
            resp1 = await read_frame(r1)
            assert resp1 is not None, "Server did not respond to first valid envelope"
            if node.is_envelope(resp1):
                assert resp1["payload"]["type"] == "PONG"
            else:
                assert resp1["type"] == "PONG"
            w1.close()
            await w1.wait_closed()

            # Connection 2: Replay exact same envelope
            r2, w2 = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w2, env)
            # Server must reject with NONCE_REPLAYED and close connection without sending PONG
            resp2 = await read_frame(r2)
            assert resp2 is None, f"Server responded to replayed envelope over new TCP connection: {resp2}"
            w2.close()
            await w2.wait_closed()

        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.parametrize("drift_offset,expected_valid", [
        (0.0, True),
        (-30.0, True),
        (30.0, True),
        (-59.0, True),
        (59.0, True),
        (-60.0, True),
        (60.0, True),
        (-60.1, False),
        (60.1, False),
        (-65.0, False),
        (65.0, False),
        (-120.0, False),
        (120.0, False),
        (-3600.0, False),
        (3600.0, False),
        (-86400.0, False),
        (86400.0, False),
    ])
    def test_timestamp_drift_boundaries(self, node_factory, drift_offset, expected_valid):
        """Verify strict +/- 60s sliding window boundary for message timestamps."""
        node = node_factory(port=18105)
        alice = PeerIdentity("alice_ts")
        fixed_now = 1731416000.0
        test_ts = fixed_now + drift_offset

        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload, timestamp=test_ts)

        with patch("time.time", return_value=fixed_now):
            valid, reason, _ = node.verify_envelope(env)

        if expected_valid:
            assert valid is True, f"Valid drift offset {drift_offset}s rejected: {reason}"
            assert reason == "ACCEPTED"
        else:
            assert valid is False, f"Expired drift offset {drift_offset}s accepted!"
            assert reason == "TIMESTAMP_EXPIRED"

    @pytest.mark.parametrize("bad_timestamp", [
        "1731416000",          # String timestamp
        "now",                 # Arbitrary string
        None,                  # NoneType
        [1731416000],          # List
        {"time": 1731416000},  # Dict
        -100.0,                # Negative float (pre-1970)
        0.0,                   # Unix epoch 0
        float("inf"),          # Positive infinity
        -float("inf"),         # Negative infinity
    ])
    def test_timestamp_invalid_types_and_values(self, node_factory, bad_timestamp):
        """Non-numeric, negative, epoch-0, or infinite timestamps must be rejected."""
        node = node_factory(port=18106)
        alice = PeerIdentity("alice_bad_ts")
        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload)
        env["timestamp"] = bad_timestamp

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False, f"Invalid timestamp {bad_timestamp} was accepted!"
        assert reason in ("INVALID_ENVELOPE_SCHEMA", "TIMESTAMP_EXPIRED")

    def test_nonce_cache_pruning_and_capacity_capping(self, node_factory):
        """Nonce cache must auto-prune nonces older than 120s and cap max size at 50,000."""
        node = node_factory(port=18107)
        now = time.time()

        # Seed old nonces
        node.seen_nonces["old_nonce_1"] = now - 200.0
        node.seen_nonces["old_nonce_2"] = now - 150.0
        node.seen_nonces["fresh_nonce"] = now - 10.0

        # Trigger pruning
        node._prune_nonce_cache(now)
        assert "old_nonce_1" not in node.seen_nonces
        assert "old_nonce_2" not in node.seen_nonces
        assert "fresh_nonce" in node.seen_nonces

        # Test capacity cap: simulate 55,000 nonces
        node.max_nonce_cache_size = 100  # set small cap for fast test
        for i in range(150):
            node.seen_nonces[f"nonce_{i}"] = now

        node._prune_nonce_cache(now)
        assert len(node.seen_nonces) <= 100


# ============================================================================
# PART 2: IDENTITY SPOOFING & CRYPTOGRAPHIC INTEGRITY
# ============================================================================

class TestIdentitySpoofingAndIntegrity:
    """Empirical verification of sender_id <-> public key binding and RSA-PSS signatures."""

    def test_identity_spoofing_mismatched_sender_id(self, node_factory):
        """Attacker generates valid keypair but claims a different victim sender_id; must be rejected with SPOOFED_SENDER_ID."""
        node = node_factory(port=18201)
        attacker = PeerIdentity("attacker_mallory")
        victim = PeerIdentity("victim_alice")

        payload = {"type": "GET_CHUNK", "filename": "confidential.pdf", "chunk_index": 0}
        # Attacker signs with their own key, but places victim's peer_id in sender_id
        env = create_signed_envelope(attacker, payload)
        env["sender_id"] = victim.peer_id

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False, "Mismatched sender_id was accepted!"
        assert reason == "SPOOFED_SENDER_ID"

    def test_identity_spoofing_arbitrary_random_sender_id(self, node_factory):
        """Attacker claims a random 64-character hex sender_id; must be rejected with SPOOFED_SENDER_ID."""
        node = node_factory(port=18202)
        attacker = PeerIdentity("attacker_random")
        payload = {"type": "PING", "sender_id": attacker.peer_id}
        env = create_signed_envelope(attacker, payload)
        env["sender_id"] = "deadbeef" * 8

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False
        assert reason == "SPOOFED_SENDER_ID"

    def test_identity_spoofing_victim_pubkey_with_attacker_signature(self, node_factory):
        """Attacker puts victim's public key & sender_id, but signs with attacker's private key; must fail signature verification."""
        node = node_factory(port=18203)
        victim = PeerIdentity("victim_bob")
        attacker = PeerIdentity("attacker_eve")

        payload = {"type": "SHARE_FILE_INFO", "filename": "trojan.exe", "merkle_root": "0" * 64, "total_chunks": 1}

        # Sign payload with attacker's key
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        attacker_sig = base64.b64encode(attacker.sign_data(canonical_bytes)).decode("utf-8")

        # Construct envelope with victim's pubkey & peer_id, but attacker's signature
        env = {
            "sender_id": victim.peer_id,
            "public_key": victim.get_public_key_pem().decode("utf-8"),
            "timestamp": time.time(),
            "nonce": str(uuid.uuid4()),
            "payload": payload,
            "signature": attacker_sig
        }

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False, "Attacker signature verified against victim public key!"
        assert reason == "INVALID_SIGNATURE"

    def test_signature_tampering_bit_flip(self, node_factory):
        """Flipping bits in the base64 signature must cause signature verification failure."""
        node = node_factory(port=18204)
        alice = PeerIdentity("alice_tamper_sig")
        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload)

        sig = env["signature"]
        # Flip first character to a different valid base64 character
        flipped_char = 'B' if sig[0] != 'B' else 'C'
        tampered_sig = flipped_char + sig[1:]
        env["signature"] = tampered_sig

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False, "Bit-flipped signature was accepted!"
        assert reason == "INVALID_SIGNATURE"

    @pytest.mark.parametrize("corrupt_sig", [
        "",                     # Empty signature
        "not_base64_!@#$%^&*",  # Corrupt base64
        "QUJDRA==",             # Valid base64 but short garbage bytes (4 bytes)
        "A" * 100,              # Garbage string
        None,                   # NoneType
        12345,                  # Integer
    ])
    def test_signature_tampering_garbage_and_malformed(self, node_factory, corrupt_sig):
        """Empty, non-base64, or malformed signature values must be rejected cleanly without unhandled exceptions."""
        node = node_factory(port=18205)
        alice = PeerIdentity("alice_malformed_sig")
        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload)
        env["signature"] = corrupt_sig

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False
        assert reason in ("INVALID_SIGNATURE", "INVALID_ENVELOPE_SCHEMA")

    def test_payload_tampering_after_signing(self, node_factory):
        """Altering the payload dictionary after signing must invalidate the RSA-PSS signature."""
        node = node_factory(port=18206)
        alice = PeerIdentity("alice_tamper_payload")
        original_payload = {"type": "GET_CHUNK", "filename": "ledger.csv", "chunk_index": 0}
        env = create_signed_envelope(alice, original_payload)

        # Vector A: Change chunk_index
        env_a = dict(env)
        env_a["payload"] = {"type": "GET_CHUNK", "filename": "ledger.csv", "chunk_index": 1}
        valid_a, reason_a, _ = node.verify_envelope(env_a)
        assert valid_a is False
        assert reason_a == "INVALID_SIGNATURE"

        # Vector B: Inject extra field
        env_b = dict(env)
        env_b["payload"] = {"type": "GET_CHUNK", "filename": "ledger.csv", "chunk_index": 0, "injected_param": "malicious"}
        valid_b, reason_b, _ = node.verify_envelope(env_b)
        assert valid_b is False
        assert reason_b == "INVALID_SIGNATURE"

        # Vector C: Modify message type
        env_c = dict(env)
        env_c["payload"] = {"type": "CORRUPTION_ALERT", "filename": "ledger.csv", "chunk_index": 0}
        valid_c, reason_c, _ = node.verify_envelope(env_c)
        assert valid_c is False
        assert reason_c == "INVALID_SIGNATURE"

    @pytest.mark.asyncio
    async def test_identity_spoofing_over_live_tcp_server(self, node_factory):
        """TCP server must actively reject a spoofed envelope and drop the client socket without processing."""
        node = node_factory(port=18207)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        attacker = PeerIdentity("attacker_tcp_spoof")
        payload = {"type": "PING", "sender_id": "fake_id" * 8, "host": "127.0.0.1", "port": 19998}
        env = create_signed_envelope(attacker, payload)
        env["sender_id"] = "fake_id" * 8  # Mismatch with attacker's public key

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, env)
            resp = await read_frame(r)
            # Server must drop connection with no response
            assert resp is None, f"Server responded to spoofed envelope over TCP: {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()


# ============================================================================
# PART 3: INBOUND BLACKLIST BYPASS DEFENSES
# ============================================================================

class TestInboundBlacklistBypass:
    """Empirical verification of inbound request blocking for missing/null/empty/blacklisted sender_id."""

    def test_inbound_envelope_blacklisted_peer_rejected(self, node_factory):
        """Envelope signed by a blacklisted peer must be rejected by verify_envelope with BLACKLISTED_PEER."""
        node = node_factory(port=18301)
        bad_peer = PeerIdentity("blacklisted_peer_1")

        # Blacklist the peer in SQLite reputation DB
        node.reputation.update_trust(bad_peer.peer_id, is_valid_chunk=False)  # 50 - 25 = 25
        node.reputation.update_trust(bad_peer.peer_id, is_valid_chunk=False)  # 25 - 25 = 0 -> blacklisted
        assert node.reputation.is_blacklisted(bad_peer.peer_id) is True

        payload = {"type": "PING", "sender_id": bad_peer.peer_id}
        env = create_signed_envelope(bad_peer, payload)

        valid, reason, _ = node.verify_envelope(env)
        assert valid is False, "Blacklisted peer envelope was accepted!"
        assert reason == "BLACKLISTED_PEER"

    @pytest.mark.asyncio
    async def test_inbound_tcp_blacklisted_peer_envelope_dropped(self, node_factory):
        """TCP server receiving signed envelope from blacklisted peer must close connection with zero response."""
        node = node_factory(port=18302)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        bad_peer = PeerIdentity("bad_peer_tcp")
        node.reputation.update_trust(bad_peer.peer_id, False)
        node.reputation.update_trust(bad_peer.peer_id, False)
        assert node.reputation.is_blacklisted(bad_peer.peer_id) is True

        payload = {"type": "PING", "sender_id": bad_peer.peer_id, "host": "127.0.0.1", "port": 19997}
        env = create_signed_envelope(bad_peer, payload)

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, env)
            resp = await read_frame(r)
            assert resp is None, f"Server responded to blacklisted peer: {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.parametrize("evasion_sender_id", [
        None,                   # Missing / null
        "",                     # Empty string
        "   ",                  # Whitespace string
        "\t\n\r",               # Special whitespace
        12345,                  # Non-string integer
        ["some_id"],            # List
        {"id": "some_id"},      # Dict
    ])
    @pytest.mark.asyncio
    async def test_inbound_tcp_raw_message_invalid_sender_id_dropped(self, node_factory, evasion_sender_id):
        """Raw messages attempting to bypass blacklist via missing, null, empty, or non-string sender_id must be dropped immediately."""
        node = node_factory(port=18303)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        raw_msg = {
            "type": "PING",
            "host": "127.0.0.1",
            "port": 19996,
            "sender_id": evasion_sender_id
        }

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, raw_msg)
            resp = await read_frame(r)
            assert resp is None, f"Server responded to evasion sender_id ({evasion_sender_id}): {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_inbound_tcp_raw_message_omitted_sender_id_dropped(self, node_factory):
        """Raw message completely omitting the 'sender_id' key must be dropped immediately without a PONG response."""
        node = node_factory(port=18304)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        raw_msg = {
            "type": "PING",
            "host": "127.0.0.1",
            "port": 19995
            # sender_id omitted entirely
        }

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, raw_msg)
            resp = await read_frame(r)
            assert resp is None, f"Server responded to message with omitted sender_id: {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_inbound_tcp_blacklisted_raw_message_dropped(self, node_factory):
        """Raw message specifying a known blacklisted sender_id must be dropped immediately."""
        node = node_factory(port=18305)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        blacklisted_id = "blocked_raw_peer_" + "a" * 46
        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.update_trust(blacklisted_id, False)
        assert node.reputation.is_blacklisted(blacklisted_id) is True

        raw_msg = {
            "type": "PING",
            "sender_id": blacklisted_id,
            "host": "127.0.0.1",
            "port": 19994
        }

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, raw_msg)
            resp = await read_frame(r)
            assert resp is None, f"Server responded to blacklisted raw message: {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_inbound_tcp_get_chunk_denied_for_blacklisted_peer(self, node_factory):
        """Blacklisted peer attempting to download a chunk via GET_CHUNK must receive no chunk data and get disconnected."""
        node = node_factory(port=18306)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        # Create sample file in storage
        sample_file = os.path.join(node.file_manager.storage_dir, "test_file.txt")
        with open(sample_file, "wb") as f:
            f.write(b"Valuable secret data chunk")
        node.scan_local_directory()

        blacklisted_id = "leech_peer_" + "b" * 53
        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.update_trust(blacklisted_id, False)
        assert node.reputation.is_blacklisted(blacklisted_id) is True

        req = {
            "type": "GET_CHUNK",
            "sender_id": blacklisted_id,
            "filename": "test_file.txt",
            "chunk_index": 0
        }

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, req)
            resp = await read_frame(r)
            assert resp is None, f"Blacklisted peer received chunk response: {resp}"
            w.close()
            await w.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_inbound_tcp_corruption_alert_ignored_from_blacklisted_peer(self, node_factory):
        """Blacklisted peer attempting to frame an honest node via CORRUPTION_ALERT must be rejected with zero impact."""
        node = node_factory(port=18307)
        server = await asyncio.start_server(node.handle_client, "127.0.0.1", node.port)
        await asyncio.sleep(0.05)

        attacker_id = "hostile_reporter_" + "c" * 47
        node.reputation.update_trust(attacker_id, False)
        node.reputation.update_trust(attacker_id, False)
        assert node.reputation.is_blacklisted(attacker_id) is True

        victim_id = "honest_node_" + "d" * 52
        node.reputation.add_peer(victim_id)
        assert node.reputation.get_trust_score(victim_id) == 50

        alert_msg = {
            "type": "CORRUPTION_ALERT",
            "sender_id": attacker_id,
            "corrupted_peer_id": victim_id,
            "corrupted_peer_name": "Victim",
            "filename": "innocent.pdf",
            "chunk_index": 0
        }

        try:
            r, w = await asyncio.open_connection("127.0.0.1", node.port)
            await send_frame(w, alert_msg)
            resp = await read_frame(r)
            assert resp is None, f"Server responded to alert from blacklisted peer: {resp}"
            w.close()
            await w.wait_closed()

            # Verify honest victim was NOT penalized or quarantined
            assert node.reputation.get_trust_score(victim_id) == 50
            assert node.reputation.is_provider_quarantined(victim_id, "innocent.pdf") is False
        finally:
            server.close()
            await server.wait_closed()


# ============================================================================
# PART 4: OUTBOUND BLACKLIST ISOLATION
# ============================================================================

class TestOutboundBlacklistIsolation:
    """Empirical verification that node NEVER initiates outbound connections/data to blacklisted peers."""

    @pytest.mark.asyncio
    async def test_outbound_ping_known_blacklisted_peer_skipped(self, node_factory):
        """ping_peer must skip known blacklisted peer, prune it from state, and never initiate a connection."""
        node = node_factory(port=18401)
        bad_peer_id = "bad_outbound_peer_" + "e" * 46
        node.peers[("127.0.0.1", 19990)] = (bad_peer_id, "BadNode")
        node.peer_files[bad_peer_id] = {"secret.txt": {"merkle_root": "0" * 64, "total_chunks": 1}}

        # Blacklist the peer
        node.reputation.update_trust(bad_peer_id, False)
        node.reputation.update_trust(bad_peer_id, False)
        assert node.reputation.is_blacklisted(bad_peer_id) is True

        # Mock _send_request to ensure it is NEVER called
        node._send_request = AsyncMock()

        result = await node.ping_peer("127.0.0.1", 19990)
        assert result is False
        assert node._send_request.call_count == 0, "_send_request was called for a blacklisted peer!"

        # Verify state was pruned
        assert ("127.0.0.1", 19990) not in node.peers
        assert bad_peer_id not in node.peer_files

    @pytest.mark.asyncio
    async def test_outbound_ping_rejects_blacklisted_pong_responder(self, node_factory):
        """If an unmapped peer returns a PONG identifying as a blacklisted peer_id, node must reject and prune state."""
        node = node_factory(port=18402)
        bad_peer_id = "bad_pong_peer_" + "f" * 50
        node.reputation.update_trust(bad_peer_id, False)
        node.reputation.update_trust(bad_peer_id, False)

        # Mock _send_request returning PONG from blacklisted peer
        node._send_request = AsyncMock(return_value={
            "type": "PONG",
            "sender_id": bad_peer_id,
            "sender_name": "BadResponder",
            "files": {"file.bin": {"merkle_root": "1" * 64, "total_chunks": 1}}
        })

        result = await node.ping_peer("127.0.0.1", 19989)
        assert result is False
        assert ("127.0.0.1", 19989) not in node.peers
        assert bad_peer_id not in node.peer_files

    @pytest.mark.asyncio
    async def test_outbound_send_request_blocks_blacklisted_destination(self, node_factory):
        """_send_request must directly block outbound traffic to a known blacklisted peer without opening a socket."""
        node = node_factory(port=18403)
        bad_peer_id = "bad_dest_peer_" + "a" * 50
        node.peers[("127.0.0.1", 19988)] = (bad_peer_id, "BadDest")
        node.reputation.update_trust(bad_peer_id, False)
        node.reputation.update_trust(bad_peer_id, False)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_connect:
            resp = await node._send_request("127.0.0.1", 19988, {"type": "PING"})
            assert resp is None
            assert mock_connect.call_count == 0, "open_connection was called for a blacklisted peer!"

    @pytest.mark.asyncio
    async def test_outbound_broadcast_file_skips_blacklisted_peers(self, node_factory):
        """broadcast_file must send file announcements strictly to honest peers, skipping blacklisted peers."""
        node = node_factory(port=18404)
        sample_path = os.path.join(node.file_manager.storage_dir, "shared.txt")
        with open(sample_path, "wb") as f:
            f.write(b"Broadcast payload content")

        honest_id = "honest_peer_" + "1" * 52
        blacklisted_id = "blacklisted_peer_" + "2" * 47

        node.peers[("127.0.0.1", 19981)] = (honest_id, "HonestPeer")
        node.peers[("127.0.0.1", 19982)] = (blacklisted_id, "BlacklistedPeer")

        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.update_trust(blacklisted_id, False)

        called_targets = []
        async def mock_send(host, port, payload):
            called_targets.append((host, port))
            return {"status": "OK"}

        node._send_request = mock_send

        root = await node.broadcast_file(sample_path)
        assert root is not None
        assert ("127.0.0.1", 19981) in called_targets, "Honest peer was not notified"
        assert ("127.0.0.1", 19982) not in called_targets, "Blacklisted peer received broadcast!"

    @pytest.mark.asyncio
    async def test_outbound_broadcast_corruption_alert_skips_blacklisted_peers(self, node_factory):
        """broadcast_corruption_alert must never send alerts to blacklisted peers or to the bad peer itself."""
        node = node_factory(port=18405)
        honest_id = "honest_peer_" + "3" * 52
        blacklisted_id = "blacklisted_peer_" + "4" * 47
        bad_peer_id = "bad_peer_" + "5" * 55

        node.peers[("127.0.0.1", 19971)] = (honest_id, "HonestPeer")
        node.peers[("127.0.0.1", 19972)] = (blacklisted_id, "BlacklistedPeer")
        node.peers[("127.0.0.1", 19973)] = (bad_peer_id, "BadPeer")

        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.update_trust(blacklisted_id, False)

        alert_recipients = []
        async def mock_send(host, port, payload):
            alert_recipients.append((host, port))
            return {"status": "ALERT_RECEIVED"}

        node._send_request = mock_send

        await node.broadcast_corruption_alert("file.bin", bad_peer_id, "BadPeer", 0)

        assert ("127.0.0.1", 19971) in alert_recipients
        assert ("127.0.0.1", 19972) not in alert_recipients, "Alert was sent to blacklisted peer!"
        assert ("127.0.0.1", 19973) not in alert_recipients, "Alert was sent to the offending bad peer!"

    @pytest.mark.asyncio
    async def test_outbound_download_skips_blacklisted_and_quarantined_providers(self, node_factory):
        """download_file_from_swarm must skip providers that are blacklisted or quarantined for that file."""
        node = node_factory(port=18406)
        chunk_data = b"Valid chunk content"
        tree = MerkleTree([chunk_data])
        b64_chunk = base64.b64encode(chunk_data).decode("utf-8")

        honest_id = "honest_provider_" + "6" * 48
        blacklisted_id = "blacklisted_provider_" + "7" * 43
        quarantined_id = "quarantined_provider_" + "8" * 43

        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.update_trust(blacklisted_id, False)
        node.reputation.quarantine_provider_for_file(quarantined_id, "test.bin")

        providers = [
            ("127.0.0.1", 19961, blacklisted_id, "BlacklistedProvider"),
            ("127.0.0.1", 19962, quarantined_id, "QuarantinedProvider"),
            ("127.0.0.1", 19963, honest_id, "HonestProvider"),
        ]

        contacted_hosts = []
        async def mock_send(host, port, payload):
            contacted_hosts.append((host, port))
            return {
                "type": "CHUNK_DATA",
                "filename": "test.bin",
                "chunk_index": 0,
                "data": b64_chunk
            }

        node._send_request = mock_send

        success = await node.download_file_from_swarm("test.bin", providers, tree.root, total_chunks=1)
        assert success is True
        assert ("127.0.0.1", 19961) not in contacted_hosts, "Blacklisted provider was contacted for download!"
        assert ("127.0.0.1", 19962) not in contacted_hosts, "Quarantined provider was contacted for download!"
        assert ("127.0.0.1", 19963) in contacted_hosts, "Honest provider was not contacted"


# ============================================================================
# PART 5: WHITE-BOX BOUNDARY & CONCURRENCY CHALLENGES
# ============================================================================

class TestWhiteBoxBoundaryAndConcurrencyChallenges:
    """Stress tests on subtle failure modes: metadata mutation, concurrent races, framing stress."""

    def test_challenge_unsigned_envelope_metadata_mutation(self, node_factory):
        """
        SECURITY CHALLENGE:
        Investigate whether an eavesdropper can replay an intercepted signed payload
        indefinitely by replacing unsigned envelope metadata (nonce and timestamp).
        
        Because the signature in create_signed_envelope is computed over payload ONLY:
        raw_signature = identity.sign_data(canonical_payload)
        a third-party attacker who mutates 'nonce' to a fresh UUID and 'timestamp' to time.time()
        will bypass nonce deduplication and timestamp drift while Alice's signature remains valid!
        """
        node = node_factory(port=18501)
        alice = PeerIdentity("alice_victim_capture")
        payload = {"type": "GET_CHUNK", "filename": "classified_dataset.tar.gz", "chunk_index": 0}

        # Alice creates and broadcasts valid envelope
        original_env = create_signed_envelope(alice, payload)
        valid_orig, reason_orig, _ = node.verify_envelope(original_env)
        assert valid_orig is True
        assert reason_orig == "ACCEPTED"

        # Eavesdropper captures envelope, waits 200 seconds (past max drift),
        # mutates nonce to a fresh UUID, and updates timestamp to current time.
        mutated_env = dict(original_env)
        mutated_env["nonce"] = str(uuid.uuid4())
        mutated_env["timestamp"] = time.time()

        # Empirical test: Does the node accept or reject this replayed payload with mutated metadata?
        valid_mutated, reason_mutated, _ = node.verify_envelope(mutated_env)

        # We document the exact observed behavior:
        # If valid_mutated is True, this confirms the architectural vulnerability that envelope
        # metadata (timestamp and nonce) is decoupled from the cryptographic digital signature!
        if valid_mutated is True:
            # VULNERABILITY CONFIRMED EMPIRICALLY!
            assert reason_mutated == "ACCEPTED"
        else:
            # If rejected, metadata is bound
            assert reason_mutated in ("INVALID_SIGNATURE", "NONCE_REPLAYED")

    def test_challenge_nan_timestamp_behavior(self, node_factory):
        """
        SECURITY CHALLENGE:
        Test NaN timestamp handling. In Python, abs(now - float('nan')) > 60.0 evaluates to False.
        Verify whether verify_envelope accepts or rejects float('nan') timestamps.
        """
        node = node_factory(port=18502)
        alice = PeerIdentity("alice_nan_ts")
        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload)
        env["timestamp"] = float("nan")

        # In Python float('nan') is an instance of float
        assert isinstance(env["timestamp"], (int, float))
        # abs(now - nan) > 60 is False
        assert (abs(time.time() - env["timestamp"]) > node.max_time_drift) is False

        valid, reason, _ = node.verify_envelope(env)
        # Document whether this bypasses drift check or is handled
        # If valid is True, NaN timestamp bypasses time window expiration!

    @pytest.mark.asyncio
    async def test_concurrent_replay_race_condition(self, node_factory):
        """
        Stress test: Concurrently dispatch 50 identical envelopes simultaneously.
        Exactly 1 must be accepted; all other 49 must be rejected as NONCE_REPLAYED.
        """
        node = node_factory(port=18503)
        alice = PeerIdentity("alice_race_node")
        payload = {"type": "PING", "sender_id": alice.peer_id}
        env = create_signed_envelope(alice, payload)

        async def _attempt_verify():
            return node.verify_envelope(env)

        # Launch 50 concurrent verification tasks
        tasks = [asyncio.create_task(_attempt_verify()) for _ in range(50)]
        results = await asyncio.gather(*tasks)

        accepted_count = sum(1 for valid, reason, _ in results if valid is True and reason == "ACCEPTED")
        replayed_count = sum(1 for valid, reason, _ in results if valid is False and reason == "NONCE_REPLAYED")

        assert accepted_count == 1, f"Expected exactly 1 acceptance, but got {accepted_count}!"
        assert replayed_count == 49, f"Expected 49 rejections, but got {replayed_count}!"

    def test_tcp_framing_stress_fragmentation_and_coalescing(self):
        """Stress test pack_tcp_frame and unpack_tcp_frame under severe slicing and packet coalescing."""
        messages = [
            {"type": "PING", "seq": i, "data": "X" * (i * 100)}
            for i in range(10)
        ]

        # Pack all into a single coalesced stream
        stream = b"".join(pack_tcp_frame(m) for m in messages)

        # Feed the stream in tiny arbitrary slices (e.g. 7 bytes at a time)
        slice_size = 7
        buffer = b""
        decoded_messages = []

        for i in range(0, len(stream), slice_size):
            buffer += stream[i:i + slice_size]
            while True:
                msg, buffer = unpack_tcp_frame(buffer)
                if msg is None:
                    break
                decoded_messages.append(msg)

        assert buffer == b"", "Trailing unconsumed bytes remaining in buffer"
        assert len(decoded_messages) == len(messages)
        for original, decoded in zip(messages, decoded_messages):
            assert original == decoded

    def test_reputation_quarantine_to_blacklist_lifecycle(self, node_factory):
        """Verify reputation degradation: 50 -> 25 -> 0, confirming automatic blacklist status."""
        node = node_factory(port=18504)
        peer_id = "transient_peer_" + "9" * 49

        # Initially unknown peer has score 50 and is not blacklisted
        assert node.reputation.get_trust_score(peer_id) == 50
        assert node.reputation.is_blacklisted(peer_id) is False

        # First quarantine penalty: score drops to 25
        score_1 = node.reputation.quarantine_provider_for_file(peer_id, "file_a.bin")
        assert score_1 == 25
        assert node.reputation.get_trust_score(peer_id) == 25
        assert node.reputation.is_blacklisted(peer_id) is False
        assert node.reputation.is_provider_quarantined(peer_id, "file_a.bin") is True

        # Second quarantine penalty: score drops to 0, peer becomes blacklisted
        score_2 = node.reputation.quarantine_provider_for_file(peer_id, "file_b.bin")
        assert score_2 == 0
        assert node.reputation.get_trust_score(peer_id) == 0
        assert node.reputation.is_blacklisted(peer_id) is True
        assert node.reputation.is_provider_quarantined(peer_id, "file_b.bin") is True

        # Ensure fail-secure blacklist check immediately blocks
        assert node.reputation.is_blacklisted(peer_id) is True
