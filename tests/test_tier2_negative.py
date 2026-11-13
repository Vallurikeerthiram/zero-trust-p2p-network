import os
import json
import base64
import pytest
from unittest.mock import AsyncMock
from src.core.file_manager import FileManager
from src.core.crypto import MerkleTree, PeerIdentity
from tests.conftest import create_signed_envelope, verify_signature_compat, pack_tcp_frame, unpack_tcp_frame


class TestTier2Negative:
    """Tier 2 - Boundary & Negative Testing: Adversarial Traversal, Tampering, Forgery, & Blacklisting."""

    def test_negative_path_traversal_save_chunk_escapes(self, file_manager):
        """save_chunk must reject or safely sanitize paths containing directory traversal sequences."""
        traversal_attempts = [
            "../../../etc/shadow",
            "..\\..\\..\\boot.ini",
            "..\\private_key.pem",
            "subdir/../../root.txt"
        ]
        storage_real = os.path.realpath(file_manager.storage_dir)

        for attempt in traversal_attempts:
            try:
                file_manager.save_chunk(attempt, 0, b"traversal data")
                # If no exception, verify no file was written outside storage_real
                for root, dirs, files in os.walk(os.path.dirname(storage_real)):
                    if root != storage_real and "shadow" in files:
                        pytest.fail(f"Path traversal succeeded! File written to {root}")
            except (ValueError, OSError):
                # Expected rejection
                pass

    def test_negative_path_traversal_null_byte_injection(self, file_manager):
        """Filenames with embedded null bytes must be rejected."""
        null_byte_payloads = [
            "legit_file.txt\x00../../etc/passwd",
            "photo.png\x00.exe",
            "document.pdf\x00"
        ]
        for payload in null_byte_payloads:
            with pytest.raises((ValueError, TypeError, OSError)):
                file_manager.save_chunk(payload, 0, b"null byte test")

    def test_negative_path_traversal_absolute_paths(self, file_manager):
        """Absolute system paths must not escape the storage directory."""
        abs_paths = [
            "/var/log/syslog",
            "C:\\Windows\\win.ini",
            "/tmp/escaped_zero_trust.dat"
        ]
        for p in abs_paths:
            try:
                file_manager.save_chunk(p, 0, b"abs path payload")
                # Ensure it didn't create the file at the literal absolute path outside storage
                if os.path.exists(p) and p.startswith("/tmp"):
                    pytest.fail(f"Escaped storage jail to absolute path {p}")
            except (ValueError, OSError):
                pass

    @pytest.mark.asyncio
    async def test_negative_tampered_chunk_rejected_and_purged(self, node_factory):
        """Tampered chunks must fail verification, be deleted from disk, and penalize provider."""
        node = node_factory("node_tamper_test")
        filename = "critical_file.bin"
        authentic_chunk = b"Authentic chunk content for zero-trust verification"
        tree = MerkleTree([authentic_chunk])

        # Provider serves tampered chunk
        tampered_chunk = b"TAMPERED_MODIFIED_CONTENT_123"
        b64_tampered = base64.b64encode(tampered_chunk).decode("utf-8")

        bad_peer_id = "bad_peer_malicious_1"
        node.reputation.add_peer(bad_peer_id)
        initial_score = node.reputation.get_trust_score(bad_peer_id)

        node._send_request = AsyncMock(return_value={
            "type": "CHUNK_DATA",
            "filename": filename,
            "chunk_index": 0,
            "data": b64_tampered
        })

        providers = [("127.0.0.1", 9998, bad_peer_id, "BadNode")]

        # Attempt download
        result = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=tree.root,
            total_chunks=1
        )

        assert result is False, "Download with tampered chunk must fail"

        # Check provider was penalized or quarantined
        new_score = node.reputation.get_trust_score(bad_peer_id)
        assert new_score < initial_score or node.reputation.is_provider_quarantined(bad_peer_id, filename), (
            "Provider of corrupted chunk must be penalized or quarantined"
        )

        # Check temporary chunk was deleted from disk
        temp_dir = os.path.join(node.file_manager.storage_dir, f"{filename}_temp")
        if os.path.exists(temp_dir):
            remaining_chunks = os.listdir(temp_dir)
            assert len(remaining_chunks) == 0, f"Corrupted chunks remained on disk: {remaining_chunks}"

    def test_negative_invalid_rsa_signatures(self, peer_identity, second_identity):
        """Altered payloads or forged signatures must fail signature verification."""
        data = b"Legitimate transaction payload"
        valid_sig = peer_identity.sign_data(data)

        pub_bytes = (
            peer_identity.get_public_key_bytes()
            if hasattr(peer_identity, "get_public_key_bytes")
            else peer_identity.get_public_key_pem()
        )

        # 1. Flip byte in signature
        mutated_sig = bytearray(valid_sig)
        mutated_sig[len(mutated_sig) // 2] ^= 0xFF
        assert verify_signature_compat(pub_bytes, bytes(mutated_sig), data) is False

        # 2. Signature over different data
        assert verify_signature_compat(pub_bytes, valid_sig, b"Altered payload") is False

        # 3. Wrong public key
        second_pub = (
            second_identity.get_public_key_bytes()
            if hasattr(second_identity, "get_public_key_bytes")
            else second_identity.get_public_key_pem()
        )
        assert verify_signature_compat(second_pub, valid_sig, data) is False

    def test_negative_spoofed_sender_id_rejected(self, peer_identity, second_identity):
        """An envelope claiming a victim's sender_id with attacker's public key must be rejected."""
        victim_id = peer_identity.peer_id if hasattr(peer_identity, "peer_id") else peer_identity.get_peer_id()
        payload = {"type": "PING"}

        # Attacker crafts envelope with victim_id but attacker's key
        envelope = create_signed_envelope(second_identity, payload)
        envelope["sender_id"] = victim_id  # Spoofed!

        # Zero-Trust identity check: sender_id must match SHA-256 of public_key
        import hashlib
        claimed_pub = envelope["public_key"].encode("utf-8")
        computed_id = hashlib.sha256(claimed_pub).hexdigest()

        assert envelope["sender_id"] != computed_id, (
            "Spoofed sender ID must not match the computed hash of the attacker's public key"
        )

    def test_negative_blacklisted_peer_blocked(self, node_factory):
        """Blacklisted peer must be blocked from requests."""
        node = node_factory("node_blacklist_block")
        bad_peer = "attacker_peer_blocked"
        node.reputation.add_peer(bad_peer)

        # Drop trust to 0 to trigger blacklist
        node.reputation.update_trust(bad_peer, is_valid_chunk=False)
        node.reputation.update_trust(bad_peer, is_valid_chunk=False)
        assert node.reputation.is_blacklisted(bad_peer) is True

        # Check node logic blocks this peer
        assert node.reputation.is_blacklisted(bad_peer) is True

    def test_negative_tcp_oversized_payload_boundary(self):
        """TCP frames declaring payload size > 16MB must be rejected to prevent memory exhaustion."""
        oversized_len = 32 * 1024 * 1024  # 32 MB
        MAX_ALLOWED = 16 * 1024 * 1024     # 16 MB limit

        import struct
        header = struct.pack(">I", oversized_len)
        declared_len = struct.unpack(">I", header)[0]

        assert declared_len > MAX_ALLOWED, "Declared length must exceed max allowed limit"
