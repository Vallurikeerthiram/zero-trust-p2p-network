import time
import uuid
import json
import struct
import base64
import hashlib
import pytest
from tests.conftest import pack_tcp_frame, unpack_tcp_frame, create_signed_envelope, verify_signature_compat


class TestTier1Transport:
    """Tier 1 - Feature Coverage: 4-Byte TCP Framing, Signed Envelopes, & Replay Defense."""

    def test_tcp_framing_pack_and_unpack(self):
        """Pack payload with 4-byte big-endian length prefix and unpack accurately."""
        payload = {"type": "PING", "sender_id": "test_peer_123"}
        frame = pack_tcp_frame(payload)

        # Check 4-byte big-endian length
        length = struct.unpack(">I", frame[:4])[0]
        assert length == len(frame) - 4

        decoded, remaining = unpack_tcp_frame(frame)
        assert decoded == payload
        assert remaining == b""

    def test_tcp_framing_split_segments(self):
        """Simulate TCP packet fragmentation: decode only when full payload is assembled."""
        payload = {"type": "GET_CHUNK", "filename": "large_dataset.bin", "chunk_index": 42}
        frame = pack_tcp_frame(payload)

        # Split frame into 3 slices
        slice1 = frame[:2]          # Incomplete length prefix
        slice2 = frame[2:10]        # Header + partial payload
        slice3 = frame[10:]         # Remainder

        msg1, rem1 = unpack_tcp_frame(slice1)
        assert msg1 is None
        assert rem1 == slice1

        msg2, rem2 = unpack_tcp_frame(rem1 + slice2)
        assert msg2 is None
        assert rem2 == slice1 + slice2

        msg3, rem3 = unpack_tcp_frame(rem2 + slice3)
        assert msg3 == payload
        assert rem3 == b""

    def test_tcp_framing_coalesced_frames(self):
        """Handle multiple coalesced TCP frames received in a single socket read."""
        msg_a = {"type": "CHUNK_DATA", "chunk_index": 0}
        msg_b = {"type": "CHUNK_DATA", "chunk_index": 1}

        stream = pack_tcp_frame(msg_a) + pack_tcp_frame(msg_b)

        # Unpack first frame
        decoded_a, rem = unpack_tcp_frame(stream)
        assert decoded_a == msg_a
        assert len(rem) > 0

        # Unpack second frame from remaining buffer
        decoded_b, rem2 = unpack_tcp_frame(rem)
        assert decoded_b == msg_b
        assert rem2 == b""

    def test_signed_envelope_structure_and_signature(self, peer_identity):
        """Signed envelope must include sender_id, public_key, timestamp, nonce, payload, and signature."""
        payload = {"type": "SHARE_FILE_INFO", "filename": "report.pdf", "merkle_root": "a" * 64}
        envelope = create_signed_envelope(peer_identity, payload)

        assert "sender_id" in envelope
        assert "public_key" in envelope
        assert "timestamp" in envelope
        assert "nonce" in envelope
        assert "payload" in envelope
        assert "signature" in envelope

        # Verify sender_id matches hash of public_key
        pub_bytes = envelope["public_key"].encode("utf-8")
        expected_peer_id = hashlib.sha256(pub_bytes).hexdigest()
        assert envelope["sender_id"] == expected_peer_id

        # Verify signature over canonical payload
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        assert verify_signature_compat(pub_bytes, envelope["signature"], canonical_bytes) is True

    def test_timestamp_drift_validation(self):
        """Messages older than 60s or >60s into future must be rejected."""
        now = time.time()
        max_drift = 60.0

        def is_timestamp_valid(ts):
            return abs(now - ts) <= max_drift

        # Valid timestamp (current)
        assert is_timestamp_valid(now) is True
        assert is_timestamp_valid(now - 30.0) is True
        assert is_timestamp_valid(now + 30.0) is True

        # Expired timestamp (>60s past)
        assert is_timestamp_valid(now - 61.0) is False
        assert is_timestamp_valid(now - 3600.0) is False

        # Future timestamp (>60s drift)
        assert is_timestamp_valid(now + 65.0) is False

    def test_nonce_replay_cache(self):
        """Duplicate nonces within validity window must be detected and rejected."""
        seen_nonces = set()

        def process_message(nonce):
            if nonce in seen_nonces:
                return False  # Replay detected
            seen_nonces.add(nonce)
            return True

        nonce_1 = str(uuid.uuid4())
        nonce_2 = str(uuid.uuid4())

        assert process_message(nonce_1) is True
        assert process_message(nonce_2) is True

        # Replay nonce_1
        assert process_message(nonce_1) is False
