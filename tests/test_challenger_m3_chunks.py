"""
Adversarial Empirical Challenge Test Suite for Milestone 3 (M3)
Challenger 1 (ID: challenger_m3_1)

Target:
- src.core.p2p_node.P2PNode (download_file_from_swarm, get_network_files, handle_get_chunk, broadcast_corruption_alert)
- src.core.crypto.MerkleTree (verify_chunk_proof, get_proof, hash_leaf, hash_interior)
- src.core.file_manager.FileManager
- src.core.reputation.ReputationEngine

Adversarial Dimensions Tested:
1. Corrupted Chunks:
   - Single-bit flips: byte 0 (LSB & MSB), middle byte, tail byte.
   - Random noise byte replacement and payload injection.
   - Byte truncation: -1 byte, half-length, empty chunk (0-bytes).
   - Byte extension: trailing bytes appended to valid chunks.
   - Tampered chunks NOT starting with b'CORRUPT' (eliminating substring mocks).
   - Odd-node Merkle trees (e.g. 3 chunks) and power-of-two trees (e.g. 4 chunks).

2. Forged, Altered, or Mismatched Merkle Proofs:
   - Forged sibling hashes (all zeros, random hex, single-character hex mutation).
   - Mismatched direction ('left' -> 'right', 'right' -> 'left', invalid direction strings, non-string directions).
   - Swapped chunk indices & cross-chunk proofs (chunk 0 proof provided for chunk 1, etc.).
   - Swapped response chunk_index vs requested chunk_index.
   - Malformed audit paths (truncated proof, extended/bloated proof, wrong tree proof).
   - Empty proof for multi-chunk trees and non-empty proof for single-chunk trees.
   - Non-list proof types (dict, str, int, None).

3. Pre-Disk Write Verification:
   - save_chunk is NEVER invoked on corrupt or proof-failing chunks.
   - Storage directory and <filename>_temp never contain corrupted chunk payloads on disk.
   - Temporary chunk files are completely purged on download failure or cancellation.
   - Reassembly only occurs if all chunks pass authentic Merkle verification.

4. Filename Collision Swarm Isolation:
   - Distinct files sharing the exact same filename operate in strictly isolated swarms.
   - get_network_files partitions swarms by compound key: f"{filename}@{root[:8]}".
   - Provider lists are segregated without cross-contamination.
   - Blacklisted peers sharing colliding files are excluded.
   - Local files are not overwritten or confused by remote colliding files.

5. Targeted Reputation Penalization & Zero Scoping Leak:
   - Only the specific offending provider serving the bad chunk is quarantined and penalized.
   - Honest providers (including the provider processed in the final iteration) remain unpenalized.
"""

import os
import sys
import time
import json
import base64
import copy
import asyncio
import hashlib
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.core.p2p_node import P2PNode, create_signed_envelope
from src.core.crypto import PeerIdentity, MerkleTree
from src.core.file_manager import FileManager
from src.core.reputation import ReputationEngine


# ---------------------------------------------------------------------------
# Helpers for Adversarial Mutations
# ---------------------------------------------------------------------------

def flip_bit(data: bytes, byte_offset: int, bit_offset: int = 0) -> bytes:
    """Return a copy of data with a single bit flipped at byte_offset."""
    b = bytearray(data)
    b[byte_offset] ^= (1 << bit_offset)
    return bytes(b)


def forge_sibling_hash(sibling: str, mode: str = "random") -> str:
    """Generate an adversarial mutation of a 64-hex sibling hash."""
    if mode == "zeros":
        return "0" * 64
    elif mode == "random":
        return os.urandom(32).hex()
    elif mode == "flip_char":
        first = "1" if sibling[0] != "1" else "2"
        return first + sibling[1:]
    return "f" * 64


# ---------------------------------------------------------------------------
# Category 1: Corrupted Chunks (Bit-Flips, Truncation, Noise)
# ---------------------------------------------------------------------------

class TestChunkCorruptionRejection:
    """Stress-test chunk corruption rejection across multiple bit-flip and truncation variations."""

    @pytest.mark.asyncio
    async def test_single_bit_flip_head_byte_rejected_and_quarantined(self, tmp_path):
        """A single bit flip in the very first byte (bit 0 and bit 7) must fail Merkle proof and be rejected."""
        storage = str(tmp_path / "storage_bitflip_head")
        db = str(tmp_path / "rep_bitflip_head.db")
        node = P2PNode("127.0.0.1", 20101, db_path=db, storage_dir=storage, node_name="NodeBitHead")

        filename = "contract.pdf"
        chunk_data = b"HEAD_DATA_" + (b"X" * 1024)
        tree = MerkleTree([chunk_data])
        expected_root = tree.root
        proof = tree.get_proof(0)

        # Mutate: bit 0 of byte 0
        corrupt_chunk_bit0 = flip_bit(chunk_data, 0, 0)
        # Mutate: bit 7 of byte 0
        corrupt_chunk_bit7 = flip_bit(chunk_data, 0, 7)

        bad_provider_id = "bad_provider_head"
        node.reputation.add_peer(bad_provider_id)

        # Test bit 0 flip
        async def mock_send_bit0(*args, **kwargs):
            return {
                "type": "CHUNK_DATA",
                "filename": filename,
                "chunk_index": 0,
                "data": base64.b64encode(corrupt_chunk_bit0).decode("utf-8"),
                "proof": proof
            }

        node._send_request = mock_send_bit0
        providers = [("127.0.0.1", 8001, bad_provider_id, "BadNodeHead")]

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=1
        )

        assert success is False
        assert node.reputation.is_provider_quarantined(bad_provider_id, filename) is True
        assert node.reputation.get_trust_score(bad_provider_id) < 50

    @pytest.mark.asyncio
    async def test_single_bit_flip_middle_and_tail_bytes(self, tmp_path):
        """Single bit flips in the middle and last bytes of a 64KB chunk must be detected and rejected."""
        storage = str(tmp_path / "storage_bitflip_mid_tail")
        db = str(tmp_path / "rep_bitflip_mid_tail.db")
        node = P2PNode("127.0.0.1", 20102, db_path=db, storage_dir=storage, node_name="NodeBitMidTail")

        filename = "firmware.bin"
        chunk_size = 64 * 1024
        chunk_0 = os.urandom(chunk_size)
        chunk_1 = os.urandom(chunk_size)
        tree = MerkleTree([chunk_0, chunk_1])
        expected_root = tree.root

        # Middle byte flip in chunk 0
        corrupt_mid = flip_bit(chunk_0, chunk_size // 2, 3)
        # Tail byte flip in chunk 1
        corrupt_tail = flip_bit(chunk_1, chunk_size - 1, 6)

        evil_peer = "peer_bit_mutator"
        node.reputation.add_peer(evil_peer)

        async def mock_send(host, port, payload):
            idx = payload["chunk_index"]
            if idx == 0:
                data = corrupt_mid
            else:
                data = corrupt_tail
            return {
                "type": "CHUNK_DATA",
                "filename": filename,
                "chunk_index": idx,
                "data": base64.b64encode(data).decode("utf-8"),
                "proof": tree.get_proof(idx)
            }

        node._send_request = mock_send
        providers = [("127.0.0.1", 8002, evil_peer, "EvilMutator")]

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=2
        )

        assert success is False
        assert node.reputation.is_provider_quarantined(evil_peer, filename) is True

    @pytest.mark.asyncio
    async def test_byte_truncation_variations(self, tmp_path):
        """Chunks truncated by 1 byte, truncated by half, or 0 bytes must fail Merkle proof verification."""
        storage = str(tmp_path / "storage_truncation")
        db = str(tmp_path / "rep_truncation.db")
        node = P2PNode("127.0.0.1", 20103, db_path=db, storage_dir=storage, node_name="NodeTrunc")

        filename = "archive.tar"
        chunk_data = b"CRITICAL_TAR_PAYLOAD_CHUNK_" * 100
        tree = MerkleTree([chunk_data])
        expected_root = tree.root
        proof = tree.get_proof(0)

        bad_peer = "truncator_peer"
        node.reputation.add_peer(bad_peer)

        truncations = [
            chunk_data[:-1],               # 1 byte short
            chunk_data[:len(chunk_data)//2], # half length
            b"",                           # empty chunk
            chunk_data + b"\x00"           # 1 byte extension
        ]

        for trunc_data in truncations:
            # Direct Merkle verification check
            assert MerkleTree.verify_chunk_proof(trunc_data, 0, proof, expected_root) is False

            async def mock_send(*args, **kwargs):
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": 0,
                    "data": base64.b64encode(trunc_data).decode("utf-8"),
                    "proof": proof
                }

            node._send_request = mock_send
            success = await node.download_file_from_swarm(
                filename=filename,
                providers=[("127.0.0.1", 8003, bad_peer, "TruncNode")],
                expected_root=expected_root,
                total_chunks=1
            )
            assert success is False

    @pytest.mark.asyncio
    async def test_subtle_corruption_without_corrupt_prefix(self, tmp_path):
        """Crucial check: ensure rejection does NOT depend on b'CORRUPT' prefix."""
        storage = str(tmp_path / "storage_no_prefix")
        db = str(tmp_path / "rep_no_prefix.db")
        node = P2PNode("127.0.0.1", 20104, db_path=db, storage_dir=storage, node_name="NodeNoPrefix")

        filename = "stealth_attack.bin"
        chunk_data = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 500
        tree = MerkleTree([chunk_data])
        expected_root = tree.root
        proof = tree.get_proof(0)

        # Stealthy modification: does NOT start with b'CORRUPT', only 1 byte changed in body
        stealth_tampered = bytearray(chunk_data)
        stealth_tampered[123] = (stealth_tampered[123] + 1) % 256
        stealth_tampered = bytes(stealth_tampered)

        assert not stealth_tampered.startswith(b"CORRUPT")
        assert MerkleTree.verify_chunk_proof(stealth_tampered, 0, proof, expected_root) is False

        bad_peer = "stealth_peer"
        node.reputation.add_peer(bad_peer)

        async def mock_send(*args, **kwargs):
            return {
                "type": "CHUNK_DATA",
                "filename": filename,
                "chunk_index": 0,
                "data": base64.b64encode(stealth_tampered).decode("utf-8"),
                "proof": proof
            }

        node._send_request = mock_send
        success = await node.download_file_from_swarm(
            filename=filename,
            providers=[("127.0.0.1", 8004, bad_peer, "StealthNode")],
            expected_root=expected_root,
            total_chunks=1
        )

        assert success is False
        assert node.reputation.is_provider_quarantined(bad_peer, filename) is True

    @pytest.mark.asyncio
    async def test_odd_node_merkle_tree_chunk_corruption(self, tmp_path):
        """Odd-node Merkle tree (3 chunks) with domain separation: corrupt each position in turn."""
        storage = str(tmp_path / "storage_odd_tree")
        db = str(tmp_path / "rep_odd_tree.db")
        node = P2PNode("127.0.0.1", 20105, db_path=db, storage_dir=storage, node_name="NodeOdd")

        chunks = [b"CHUNK_0_CONTENT", b"CHUNK_1_CONTENT", b"CHUNK_2_CONTENT"]
        tree = MerkleTree(chunks)
        expected_root = tree.root

        for corrupt_idx in range(3):
            proof = tree.get_proof(corrupt_idx)
            corrupted = chunks[corrupt_idx] + b"_POISON"
            # Verify mathematical rejection
            assert MerkleTree.verify_chunk_proof(corrupted, corrupt_idx, proof, expected_root) is False


# ---------------------------------------------------------------------------
# Category 2: Forged, Altered, or Mismatched Merkle Proofs
# ---------------------------------------------------------------------------

class TestMerkleProofAdversarial:
    """Stress-test adversarial Merkle proof forgery, direction tampering, and swapped proofs."""

    def test_forged_sibling_hash_variations(self):
        """Forged sibling hashes (zeros, random, 1-char flipped) must be mathematically rejected."""
        chunks = [b"CHUNK_A", b"CHUNK_B", b"CHUNK_C", b"CHUNK_D"]
        tree = MerkleTree(chunks)
        root = tree.root
        proof_0 = tree.get_proof(0)
        assert len(proof_0) == 2

        # 1. Zeroes sibling
        proof_zeros = [(proof_0[0][0], "0" * 64), proof_0[1]]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_zeros, root) is False

        # 2. Random hex sibling
        proof_random = [proof_0[0], (proof_0[1][0], os.urandom(32).hex())]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_random, root) is False

        # 3. Off-by-one character flip in sibling hash
        orig_sibling = proof_0[0][1]
        flipped_sibling = forge_sibling_hash(orig_sibling, mode="flip_char")
        proof_flipped = [(proof_0[0][0], flipped_sibling), proof_0[1]]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_flipped, root) is False

        # 4. Malformed sibling lengths
        proof_short = [(proof_0[0][0], "abc" * 21), proof_0[1]] # 63 chars
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_short, root) is False
        proof_long = [(proof_0[0][0], "a" * 65), proof_0[1]]   # 65 chars
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_long, root) is False

    def test_altered_direction_variations(self):
        """Inverted directions or bogus direction strings must fail verification."""
        chunks = [b"ALPHA", b"BRAVO", b"CHARLIE", b"DELTA"]
        tree = MerkleTree(chunks)
        root = tree.root
        proof = tree.get_proof(0)

        # 1. Invert direction: ('right' -> 'left')
        inverted_dir = "left" if proof[0][0] == "right" else "right"
        proof_inverted = [(inverted_dir, proof[0][1]), proof[1]]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_inverted, root) is False

        # 2. Bogus direction strings
        for bad_dir in ["up", "down", "center", "", "LEFT", "RIGHT"]:
            proof_bad_dir = [(bad_dir, proof[0][1]), proof[1]]
            assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_bad_dir, root) is False

        # 3. Non-string direction
        proof_int_dir = [(123, proof[0][1]), proof[1]]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_int_dir, root) is False

    def test_swapped_chunk_index_proofs(self):
        """Supplying chunk 0's proof for chunk 1 (or vice versa) must fail verification."""
        chunks = [b"BLOCK_ZERO", b"BLOCK_ONE", b"BLOCK_TWO", b"BLOCK_THREE"]
        tree = MerkleTree(chunks)
        root = tree.root

        proof_0 = tree.get_proof(0)
        proof_1 = tree.get_proof(1)

        # Valid chunk 1 data tested against chunk 0's proof
        assert MerkleTree.verify_chunk_proof(chunks[1], 1, proof_0, root) is False
        # Valid chunk 0 data tested against chunk 1's proof
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_1, root) is False

    def test_proof_length_mutations(self):
        """Truncating, extending, or providing empty proof for multi-chunk file must fail."""
        chunks = [b"PART_1", b"PART_2", b"PART_3", b"PART_4"]
        tree = MerkleTree(chunks)
        root = tree.root
        proof_0 = tree.get_proof(0)

        # 1. Truncated proof (only 1 step instead of 2)
        proof_trunc = [proof_0[0]]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_trunc, root) is False

        # 2. Extended proof (extra bogus sibling step appended)
        proof_ext = proof_0 + [("left", os.urandom(32).hex())]
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof_ext, root) is False

        # 3. Empty proof list for multi-chunk file
        assert MerkleTree.verify_chunk_proof(chunks[0], 0, [], root) is False

        # 4. Single-chunk file: valid proof is [], non-empty proof must fail
        single_chunk = b"SOLO_PAYLOAD"
        single_tree = MerkleTree([single_chunk])
        single_root = single_tree.root
        assert MerkleTree.verify_chunk_proof(single_chunk, 0, [], single_root) is True
        assert MerkleTree.verify_chunk_proof(single_chunk, 0, [("left", os.urandom(32).hex())], single_root) is False

    def test_malformed_proof_types(self):
        """Non-list proof structures (dict, str, int, None) must be rejected safely."""
        chunk = b"SOME_CHUNK"
        tree = MerkleTree([chunk])
        root = tree.root

        assert MerkleTree.verify_chunk_proof(chunk, 0, None, root) is False
        assert MerkleTree.verify_chunk_proof(chunk, 0, "not_a_list", root) is False
        assert MerkleTree.verify_chunk_proof(chunk, 0, 12345, root) is False
        assert MerkleTree.verify_chunk_proof(chunk, 0, {"0": "hash"}, root) is False
        assert MerkleTree.verify_chunk_proof(chunk, 0, [("left",)], root) is False
        assert MerkleTree.verify_chunk_proof(chunk, 0, [("left", "h", "extra")], root) is False

    @pytest.mark.asyncio
    async def test_swarm_download_rejects_forged_merkle_proof(self, tmp_path):
        """In download_file_from_swarm, a provider supplying valid chunk data with a forged proof is rejected."""
        storage = str(tmp_path / "storage_forged_proof")
        db = str(tmp_path / "rep_forged_proof.db")
        node = P2PNode("127.0.0.1", 20106, db_path=db, storage_dir=storage, node_name="NodeForgeProof")

        filename = "payroll.xlsx"
        chunk_data = b"HONEST_DATA_BUT_FORGED_PROOF" * 20
        tree = MerkleTree([chunk_data, b"OTHER_CHUNK"])
        expected_root = tree.root

        # Provider provides valid chunk_data, but with forged sibling in proof
        forged_proof = [("right", "0" * 64)]

        bad_peer = "forger_peer"
        node.reputation.add_peer(bad_peer)

        async def mock_send(*args, **kwargs):
            return {
                "type": "CHUNK_DATA",
                "filename": filename,
                "chunk_index": 0,
                "data": base64.b64encode(chunk_data).decode("utf-8"),
                "proof": forged_proof
            }

        node._send_request = mock_send
        success = await node.download_file_from_swarm(
            filename=filename,
            providers=[("127.0.0.1", 8006, bad_peer, "ForgerNode")],
            expected_root=expected_root,
            total_chunks=2
        )

        assert success is False
        assert node.reputation.is_provider_quarantined(bad_peer, filename) is True


# ---------------------------------------------------------------------------
# Category 3: Pre-Disk Write Verification
# ---------------------------------------------------------------------------

class TestPreDiskWriteVerification:
    """Empirically assert that corrupted chunks are NEVER written to disk and temp directories remain clean."""

    @pytest.mark.asyncio
    async def test_corrupted_chunk_never_calls_save_chunk(self, tmp_path):
        """Assert save_chunk is NOT called when provider sends corrupted chunk."""
        storage = str(tmp_path / "storage_predisk")
        db = str(tmp_path / "rep_predisk.db")
        node = P2PNode("127.0.0.1", 20107, db_path=db, storage_dir=storage, node_name="NodePreDisk")

        filename = "sensitive_database.sqlite"
        good_chunk = b"AUTHENTIC_SQLITE_HEADER_" * 40
        tree = MerkleTree([good_chunk])
        expected_root = tree.root
        proof = tree.get_proof(0)

        # Corrupt data
        corrupt_chunk = flip_bit(good_chunk, 10, 2)

        bad_peer = "disk_polluter_peer"
        node.reputation.add_peer(bad_peer)

        async def mock_send(*args, **kwargs):
            return {
                "type": "CHUNK_DATA",
                "filename": filename,
                "chunk_index": 0,
                "data": base64.b64encode(corrupt_chunk).decode("utf-8"),
                "proof": proof
            }

        node._send_request = mock_send

        # Spy on file_manager.save_chunk
        real_save = node.file_manager.save_chunk
        save_calls = []

        def spy_save(fname, idx, data):
            save_calls.append((fname, idx, data))
            return real_save(fname, idx, data)

        node.file_manager.save_chunk = spy_save

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=[("127.0.0.1", 8007, bad_peer, "PolluterNode")],
            expected_root=expected_root,
            total_chunks=1
        )

        assert success is False
        # Assert save_chunk was NEVER called for the corrupt chunk!
        assert len(save_calls) == 0

        # Assert no temp folder or file exists on disk
        temp_dir = os.path.join(storage, f"{filename}_temp")
        assert not os.path.exists(temp_dir) or len(os.listdir(temp_dir)) == 0

        # Assert final file was not created
        final_file = os.path.join(storage, filename)
        assert not os.path.exists(final_file)

    @pytest.mark.asyncio
    async def test_temp_directory_cleaned_after_total_download_failure(self, tmp_path):
        """If download fails completely, the temporary directory <filename>_temp is deleted."""
        storage = str(tmp_path / "storage_temp_cleanup")
        db = str(tmp_path / "rep_temp_cleanup.db")
        node = P2PNode("127.0.0.1", 20108, db_path=db, storage_dir=storage, node_name="NodeTempClean")

        filename = "abort_test.bin"
        bad_peer = "flakey_peer"
        node.reputation.add_peer(bad_peer)

        # Provider returns None (connection failure)
        async def fail_send(*args, **kwargs):
            return None

        node._send_request = fail_send

        # Simulate pre-existing dirty temp directory
        temp_dir = os.path.join(storage, f"{filename}_temp")
        os.makedirs(temp_dir, exist_ok=True)
        with open(os.path.join(temp_dir, "chunk_0"), "wb") as f:
            f.write(b"garbage")

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=[("127.0.0.1", 8008, bad_peer, "FlakeyNode")],
            expected_root="1" * 64,
            total_chunks=1
        )

        assert success is False
        # Guaranteed cleanup removes dirty temp_dir
        assert not os.path.exists(temp_dir)
        # Tracking cleaned up
        assert filename not in node.downloading_files

    @pytest.mark.asyncio
    async def test_recovery_with_honest_peer_writes_only_authentic_data(self, tmp_path):
        """When an evil peer sends a corrupt chunk followed by an honest peer sending good chunk,
        only genuine data is written to disk and final reassembled file matches original exactly."""
        storage = str(tmp_path / "storage_recovery")
        db = str(tmp_path / "rep_recovery.db")
        node = P2PNode("127.0.0.1", 20109, db_path=db, storage_dir=storage, node_name="NodeRecovery")

        filename = "critical_release.tar.gz"
        chunk_size = 64 * 1024
        chunk_0_good = b"A" * chunk_size
        chunk_1_good = b"B" * 1024
        original_content = chunk_0_good + chunk_1_good

        tree = MerkleTree([chunk_0_good, chunk_1_good])
        expected_root = tree.root
        proof_0 = tree.get_proof(0)
        proof_1 = tree.get_proof(1)

        corrupt_chunk_0 = flip_bit(chunk_0_good, 5, 1)

        bad_peer_id = "evil_provider_9"
        good_peer_id = "honest_provider_9"
        node.reputation.add_peer(bad_peer_id)
        node.reputation.add_peer(good_peer_id)

        # Provider 1 (Evil): serves corrupted chunk 0
        # Provider 2 (Honest): serves good chunk 0 and good chunk 1
        async def mock_send(host, port, payload):
            idx = payload["chunk_index"]
            if port == 8009: # Evil
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": idx,
                    "data": base64.b64encode(corrupt_chunk_0).decode("utf-8"),
                    "proof": proof_0
                }
            elif port == 8010: # Honest
                data = chunk_0_good if idx == 0 else chunk_1_good
                proof = proof_0 if idx == 0 else proof_1
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": idx,
                    "data": base64.b64encode(data).decode("utf-8"),
                    "proof": proof
                }
            return None

        node._send_request = mock_send

        providers = [
            ("127.0.0.1", 8009, bad_peer_id, "EvilNode9"),
            ("127.0.0.1", 8010, good_peer_id, "HonestNode9")
        ]

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=2
        )

        assert success is True

        # Assert final file exists and is bit-for-bit identical to genuine content
        final_path = os.path.join(storage, filename)
        assert os.path.exists(final_path)
        with open(final_path, "rb") as f:
            downloaded_bytes = f.read()
        assert downloaded_bytes == original_content

        # Temp directory must be cleanly removed
        temp_dir = os.path.join(storage, f"{filename}_temp")
        assert not os.path.exists(temp_dir)

        # Evil peer quarantined & penalized
        assert node.reputation.is_provider_quarantined(bad_peer_id, filename) is True
        assert node.reputation.get_trust_score(bad_peer_id) < 50

        # Honest peer rewarded & not quarantined
        assert node.reputation.is_provider_quarantined(good_peer_id, filename) is False
        assert node.reputation.get_trust_score(good_peer_id) > 50


# ---------------------------------------------------------------------------
# Category 4: Filename Collision Swarm Isolation
# ---------------------------------------------------------------------------

class TestFilenameCollisionSwarmIsolation:
    """Verify that distinct files with the same filename operate in strictly isolated swarms."""

    def test_two_peers_same_filename_different_roots_isolated(self, tmp_path):
        """Two peers advertising 'report.pdf' with distinct Merkle roots must create two isolated swarm entries."""
        storage = str(tmp_path / "storage_collision_2")
        db = str(tmp_path / "rep_collision_2.db")
        node = P2PNode("127.0.0.1", 20110, db_path=db, storage_dir=storage, node_name="NodeCol2")

        peer_a = "peer_alice_" + "a" * 53
        peer_b = "peer_bob_" + "b" * 55

        node.peers[("127.0.0.1", 9001)] = (peer_a, "Alice")
        node.peers[("127.0.0.1", 9002)] = (peer_b, "Bob")

        root_alice = "a" * 64
        root_bob = "b" * 64

        node.peer_files[peer_a] = {
            "report.pdf": {"filename": "report.pdf", "file_size": 1024, "merkle_root": root_alice, "total_chunks": 1}
        }
        node.peer_files[peer_b] = {
            "report.pdf": {"filename": "report.pdf", "file_size": 2048, "merkle_root": root_bob, "total_chunks": 2}
        }

        network_files = node.get_network_files()

        key_a = f"report.pdf@{root_alice[:8]}"
        key_b = f"report.pdf@{root_bob[:8]}"

        assert key_a in network_files
        assert key_b in network_files
        assert key_a != key_b

        # Swarm A contains ONLY Alice
        providers_a = network_files[key_a]["providers"]
        assert len(providers_a) == 1
        assert providers_a[0][2] == peer_a
        assert providers_a[0][3] == "Alice"

        # Swarm B contains ONLY Bob
        providers_b = network_files[key_b]["providers"]
        assert len(providers_b) == 1
        assert providers_b[0][2] == peer_b
        assert providers_b[0][3] == "Bob"

        # Ensure metadata is correct
        assert network_files[key_a]["file_size"] == 1024
        assert network_files[key_a]["merkle_root"] == root_alice
        assert network_files[key_b]["file_size"] == 2048
        assert network_files[key_b]["merkle_root"] == root_bob

    def test_three_peers_two_sharing_same_content_one_colliding(self, tmp_path):
        """Peers A & B share identical file X; Peer C shares different file X (colliding filename).
        Swarm X1 must have [A, B], Swarm X2 must have [C]."""
        storage = str(tmp_path / "storage_collision_3")
        db = str(tmp_path / "rep_collision_3.db")
        node = P2PNode("127.0.0.1", 20111, db_path=db, storage_dir=storage, node_name="NodeCol3")

        peer_a = "peer_a_" + "a" * 57
        peer_b = "peer_b_" + "b" * 57
        peer_c = "peer_c_" + "c" * 57

        node.peers[("127.0.0.1", 9011)] = (peer_a, "NodeA")
        node.peers[("127.0.0.1", 9012)] = (peer_b, "NodeB")
        node.peers[("127.0.0.1", 9013)] = (peer_c, "NodeC")

        root_common = "c0ffee" * 10 + "0000"
        root_colliding = "deadbeef" * 8

        node.peer_files[peer_a] = {
            "dataset.csv": {"filename": "dataset.csv", "file_size": 5000, "merkle_root": root_common, "total_chunks": 4}
        }
        node.peer_files[peer_b] = {
            "dataset.csv": {"filename": "dataset.csv", "file_size": 5000, "merkle_root": root_common, "total_chunks": 4}
        }
        node.peer_files[peer_c] = {
            "dataset.csv": {"filename": "dataset.csv", "file_size": 1200, "merkle_root": root_colliding, "total_chunks": 1}
        }

        network_files = node.get_network_files()

        key_common = f"dataset.csv@{root_common[:8]}"
        key_colliding = f"dataset.csv@{root_colliding[:8]}"

        assert key_common in network_files
        assert key_colliding in network_files

        # Swarm Common has both Peer A and Peer B
        common_providers = network_files[key_common]["providers"]
        assert len(common_providers) == 2
        provider_ids = {p[2] for p in common_providers}
        assert provider_ids == {peer_a, peer_b}

        # Swarm Colliding has ONLY Peer C
        colliding_providers = network_files[key_colliding]["providers"]
        assert len(colliding_providers) == 1
        assert colliding_providers[0][2] == peer_c

    def test_blacklisted_peer_excluded_from_colliding_swarm(self, tmp_path):
        """A blacklisted peer offering a colliding filename must be excluded from get_network_files."""
        storage = str(tmp_path / "storage_blacklisted_collision")
        db = str(tmp_path / "rep_blacklisted_collision.db")
        node = P2PNode("127.0.0.1", 20112, db_path=db, storage_dir=storage, node_name="NodeBlkCol")

        honest_peer = "honest_" + "1" * 57
        bad_peer = "malicious_" + "2" * 54

        node.peers[("127.0.0.1", 9021)] = (honest_peer, "HonestPeer")
        node.peers[("127.0.0.1", 9022)] = (bad_peer, "BadPeer")

        # Blacklist bad_peer via penalties (50 -> 25 -> 0, triggers automatic blacklist)
        node.reputation.add_peer(bad_peer)
        node.reputation.update_trust(bad_peer, False)
        node.reputation.update_trust(bad_peer, False)
        assert node.reputation.is_blacklisted(bad_peer) is True

        root_honest = "1111" * 16
        root_bad = "2222" * 16

        node.peer_files[honest_peer] = {
            "app.zip": {"filename": "app.zip", "file_size": 1000, "merkle_root": root_honest, "total_chunks": 1}
        }
        node.peer_files[bad_peer] = {
            "app.zip": {"filename": "app.zip", "file_size": 1000, "merkle_root": root_bad, "total_chunks": 1}
        }

        network_files = node.get_network_files()

        # Honest peer's file is visible
        assert f"app.zip@{root_honest[:8]}" in network_files
        # Bad peer's colliding file is completely absent!
        assert f"app.zip@{root_bad[:8]}" not in network_files

    def test_local_file_index_safety_with_colliding_remote_announcement(self, tmp_path):
        """Local file in available_files must not be corrupted or overwritten by remote collision."""
        storage = str(tmp_path / "storage_local_safe")
        db = str(tmp_path / "rep_local_safe.db")
        node = P2PNode("127.0.0.1", 20113, db_path=db, storage_dir=storage, node_name="NodeLocalSafe")

        # Create local file 'notes.txt'
        local_content = b"LOCAL_PROPRIETARY_NOTES"
        local_file_path = os.path.join(storage, "notes.txt")
        with open(local_file_path, "wb") as f:
            f.write(local_content)

        node.scan_local_directory()
        local_root = node.available_files["notes.txt"]["merkle_root"]

        # Remote peer advertises 'notes.txt' with different root
        remote_peer = "remote_" + "3" * 57
        remote_root = "9" * 64
        node.peers[("127.0.0.1", 9031)] = (remote_peer, "RemotePeer")
        node.peer_files[remote_peer] = {
            "notes.txt": {"filename": "notes.txt", "file_size": 50, "merkle_root": remote_root, "total_chunks": 1}
        }

        # Check that local available_files remains unchanged
        assert node.available_files["notes.txt"]["merkle_root"] == local_root
        assert node.files_by_root[local_root] == "notes.txt"
        assert remote_root not in node.files_by_root

        # Network files correctly partitions the remote file
        net_files = node.get_network_files()
        assert f"notes.txt@{remote_root[:8]}" in net_files


# ---------------------------------------------------------------------------
# Category 5: Targeted Reputation Penalization & Zero Scoping Leak
# ---------------------------------------------------------------------------

class TestTargetedPenalizationZeroScopingLeak:
    """Verify that only the offending provider is penalized and honest peers (including trailing ones) are untouched."""

    @pytest.mark.asyncio
    async def test_multi_chunk_targeted_penalty_no_loop_leak(self, tmp_path):
        """In a 4-chunk download, Peer B corrupts chunk 1.
        Verify Peer B is penalized while Peer A (first and last provider) and Peer C are NOT penalized."""
        storage = str(tmp_path / "storage_scoping")
        db = str(tmp_path / "rep_scoping.db")
        node = P2PNode("127.0.0.1", 20114, db_path=db, storage_dir=storage, node_name="NodeScoping")

        filename = "bigdata.bin"
        chunk_size = 64 * 1024
        chunk_0 = b"0" * chunk_size
        chunk_1 = b"1" * chunk_size
        chunk_2 = b"2" * chunk_size
        chunk_3 = b"3" * 1024
        chunks = [chunk_0, chunk_1, chunk_2, chunk_3]

        tree = MerkleTree(chunks)
        expected_root = tree.root

        peer_a = "honest_peer_alpha"
        peer_b = "evil_peer_beta"
        peer_c = "honest_peer_gamma"

        node.reputation.add_peer(peer_a)
        node.reputation.add_peer(peer_b)
        node.reputation.add_peer(peer_c)

        # Baseline trust scores
        initial_score_a = node.reputation.get_trust_score(peer_a)
        initial_score_b = node.reputation.get_trust_score(peer_b)
        initial_score_c = node.reputation.get_trust_score(peer_c)

        corrupt_chunk_1 = flip_bit(chunk_1, 0, 0)

        # Provider mapping:
        # Port 9101 -> Peer A (Honest)
        # Port 9102 -> Peer B (Evil: corrupts chunk 1)
        # Port 9103 -> Peer C (Honest)
        async def mock_send(host, port, payload):
            idx = payload["chunk_index"]
            if port == 9102: # Evil Peer B
                if idx == 1:
                    return {
                        "type": "CHUNK_DATA",
                        "filename": filename,
                        "chunk_index": idx,
                        "data": base64.b64encode(corrupt_chunk_1).decode("utf-8"),
                        "proof": tree.get_proof(idx)
                    }
                else:
                    return {
                        "type": "CHUNK_DATA",
                        "filename": filename,
                        "chunk_index": idx,
                        "data": base64.b64encode(chunks[idx]).decode("utf-8"),
                        "proof": tree.get_proof(idx)
                    }
            elif port == 9101: # Honest Peer A
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": idx,
                    "data": base64.b64encode(chunks[idx]).decode("utf-8"),
                    "proof": tree.get_proof(idx)
                }
            elif port == 9103: # Honest Peer C
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": idx,
                    "data": base64.b64encode(chunks[idx]).decode("utf-8"),
                    "proof": tree.get_proof(idx)
                }
            return None

        node._send_request = mock_send

        # Order providers so Peer B is hit for chunk 1, then fallback to Peer C or A
        providers = [
            ("127.0.0.1", 9101, peer_a, "NodeA"),
            ("127.0.0.1", 9102, peer_b, "NodeB"),
            ("127.0.0.1", 9103, peer_c, "NodeC")
        ]

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=4
        )

        assert success is True

        # Assert Evil Peer B is quarantined and penalized
        assert node.reputation.is_provider_quarantined(peer_b, filename) is True
        assert node.reputation.get_trust_score(peer_b) < initial_score_b

        # Assert Honest Peer A (processed in initial chunk and trailing chunks) is NOT quarantined or penalized
        assert node.reputation.is_provider_quarantined(peer_a, filename) is False
        assert node.reputation.get_trust_score(peer_a) >= initial_score_a

        # Assert Honest Peer C is NOT quarantined or penalized
        assert node.reputation.is_provider_quarantined(peer_c, filename) is False
        assert node.reputation.get_trust_score(peer_c) >= initial_score_c
