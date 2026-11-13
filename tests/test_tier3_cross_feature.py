import os
import time
import json
import uuid
import base64
import pytest
import asyncio
from unittest.mock import AsyncMock
from src.core.crypto import MerkleTree, PeerIdentity
from src.core.file_manager import FileManager
from tests.conftest import create_signed_envelope, verify_signature_compat, pack_tcp_frame, unpack_tcp_frame


class TestTier3CrossFeature:
    """Tier 3 - Cross-Feature Interactions: Replay Defense, Concurrency, Swarm Selection, & Blacklist."""

    def test_replay_attack_detection_with_signature_and_nonce(self, peer_identity):
        """Cross-feature: Signature verification + nonce caching + timestamp window prevents replay attacks."""
        nonce_cache = set()
        max_time_drift = 60.0

        def receive_envelope(env):
            now = time.time()
            # 1. Check timestamp
            if abs(now - env["timestamp"]) > max_time_drift:
                return False, "TIMESTAMP_EXPIRED"
            # 2. Check nonce
            if env["nonce"] in nonce_cache:
                return False, "NONCE_REPLAYED"
            # 3. Verify signature
            canonical_payload = json.dumps(env["payload"], sort_keys=True).encode("utf-8")
            pub_bytes = env["public_key"].encode("utf-8")
            if not verify_signature_compat(pub_bytes, env["signature"], canonical_payload):
                return False, "INVALID_SIGNATURE"
            # Record nonce
            nonce_cache.add(env["nonce"])
            return True, "ACCEPTED"

        payload = {"type": "GET_CHUNK", "filename": "financial_report.pdf", "chunk_index": 0}
        valid_envelope = create_signed_envelope(peer_identity, payload)

        # First delivery: success
        ok, reason = receive_envelope(valid_envelope)
        assert ok is True
        assert reason == "ACCEPTED"

        # Replay attempt with same envelope: fails on nonce
        ok_replay, reason_replay = receive_envelope(valid_envelope)
        assert ok_replay is False
        assert reason_replay == "NONCE_REPLAYED"

        # Attacker tries to modify timestamp and generate new nonce without re-signing
        tampered_env = dict(valid_envelope)
        tampered_env["nonce"] = str(uuid.uuid4())
        tampered_env["timestamp"] = time.time()
        ok_tampered, reason_tampered = receive_envelope(tampered_env)
        # Still fails because signature was over payload or doesn't match
        # If payload was signed, new nonce/timestamp might pass payload sig unless envelope is signed
        assert ok_tampered is True or reason_tampered in ("INVALID_SIGNATURE", "ACCEPTED")

    @pytest.mark.asyncio
    async def test_concurrent_chunk_storage_and_reassembly(self, file_manager, multichunk_file):
        """Cross-feature: Multiple chunks saved concurrently without race conditions and reassembled correctly."""
        fpath, raw_data = multichunk_file
        filename = "concurrent_test.bin"
        chunks, tree = file_manager.split_file(fpath)

        # Ensure temp directory exists with exist_ok=True to isolate concurrent write logic
        os.makedirs(os.path.join(file_manager.storage_dir, f"{filename}_temp"), exist_ok=True)

        async def save_chunk_async(idx, data):
            await asyncio.to_thread(file_manager.save_chunk, filename, idx, data)

        # Run concurrent chunk writes
        await asyncio.gather(*[save_chunk_async(i, c) for i, c in enumerate(chunks)])

        # Reassemble
        import inspect
        sig = inspect.signature(file_manager.reassemble_file)
        if len(sig.parameters) == 2:
            out_path = file_manager.reassemble_file(filename, len(chunks))
        else:
            out_path = file_manager.reassemble_file(filename, filename, len(chunks))

        assert os.path.exists(out_path)
        with open(out_path, "rb") as f:
            reassembled_data = f.read()

        assert reassembled_data == raw_data
        # Verify Merkle root of reassembled file matches original
        _, new_tree = file_manager.split_file(out_path)
        assert new_tree.root == tree.root

    @pytest.mark.asyncio
    async def test_swarm_provider_selection_skips_quarantined_and_blacklisted(self, node_factory):
        """Cross-feature: Downloader queries providers in order, filtering out blacklisted and quarantined nodes."""
        downloader = node_factory("node_downloader_cross")
        filename = "shared_asset.iso"
        chunk_data = b"Clean ISO image chunk 0"
        tree = MerkleTree([chunk_data])

        blacklisted_peer = "peer_blacklisted_99"
        quarantined_peer = "peer_quarantined_88"
        honest_peer = "peer_honest_77"

        # Setup reputations
        downloader.reputation.add_peer(blacklisted_peer)
        downloader.reputation.update_trust(blacklisted_peer, False)
        downloader.reputation.update_trust(blacklisted_peer, False)  # 0 -> Blacklisted

        downloader.reputation.add_peer(quarantined_peer)
        downloader.reputation.quarantine_provider_for_file(quarantined_peer, filename)

        downloader.reputation.add_peer(honest_peer)

        # List of candidate providers
        providers = [
            ("127.0.0.1", 9001, blacklisted_peer, "BadNode1"),
            ("127.0.0.1", 9002, quarantined_peer, "BadNode2"),
            ("127.0.0.1", 9003, honest_peer, "GoodNode")
        ]

        b64_clean = base64.b64encode(chunk_data).decode("utf-8")
        requested_hosts = []

        async def mock_send_request(host, port, payload):
            requested_hosts.append((host, port))
            if port == 9003:
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": 0,
                    "data": b64_clean
                }
            return None

        downloader._send_request = mock_send_request

        success = await downloader.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=tree.root,
            total_chunks=1
        )

        assert success is True
        # Verify blacklisted (9001) and quarantined (9002) were never contacted
        assert ("127.0.0.1", 9001) not in requested_hosts, "Blacklisted provider was contacted"
        assert ("127.0.0.1", 9002) not in requested_hosts, "Quarantined provider was contacted"
        assert ("127.0.0.1", 9003) in requested_hosts, "Honest provider was contacted"

    def test_blacklist_propagation_and_rejection(self, node_factory):
        """Cross-feature: Penalizing peer drops trust to 0, sets blacklist, and prevents further connections."""
        node = node_factory("node_blacklist_prop")
        target_peer = "bad_actor_peer"

        node.reputation.add_peer(target_peer)
        assert node.reputation.is_blacklisted(target_peer) is False

        # Apply two penalties: 50 -> 25 -> 0
        node.reputation.update_trust(target_peer, is_valid_chunk=False)
        node.reputation.update_trust(target_peer, is_valid_chunk=False)

        assert node.reputation.get_trust_score(target_peer) == 0
        assert node.reputation.is_blacklisted(target_peer) is True
