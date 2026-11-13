import hashlib
import os
import random
import pytest
from src.core.crypto import MerkleTree, PeerIdentity


class TestChallengerMerkleTreeOddSizes:
    """
    Challenge 1 & 2: Odd tree sizes (1, 3, 5, 7, 9, 15, 31, 33) and CVE-2012-2459 resistance.
    Empirically verify that odd-node promotion preserves proof validity and prevents duplicate collisions.
    """

    ODD_SIZES = [1, 3, 5, 7, 9, 15, 31, 33]

    @pytest.mark.parametrize("size", ODD_SIZES)
    def test_odd_tree_proof_generation_and_verification_all_chunks(self, size):
        """Every chunk in an odd-sized tree must generate a valid verifiable Merkle proof."""
        chunks = [f"odd_chunk_{size}_{i}_{os.urandom(8).hex()}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        assert tree.root is not None
        assert len(tree.root) == 64

        for idx in range(size):
            proof = tree.get_proof(idx)
            assert isinstance(proof, list), f"Proof for index {idx} in tree size {size} must be a list"

            # Verify chunk with proof
            verified = MerkleTree.verify_chunk_proof(chunks[idx], idx, proof, tree.root)
            assert verified is True, f"Failed verification for chunk {idx}/{size}"

            # Verify backwards-compatible method
            legacy_verified = MerkleTree.verify_chunk(chunks[idx], idx, size, tree.root, proof)
            assert legacy_verified is True, f"Failed legacy verification for chunk {idx}/{size}"

    @pytest.mark.parametrize("size", ODD_SIZES)
    def test_cve_2012_2459_no_duplicate_trailing_collision(self, size):
        """
        CVE-2012-2459 Attack: In Bitcoin Merkle trees, an odd node was duplicated,
        making [C0, C1, C2] collide with [C0, C1, C2, C2].
        Verify that MerkleTree([C_0...C_{N-1}]) NEVER collides with [C_0...C_{N-1}, C_{N-1}].
        """
        chunks = [f"payload_{size}_{i}".encode("utf-8") for i in range(size)]
        tree_original = MerkleTree(chunks)

        # Duplicate the last chunk
        chunks_dup = list(chunks) + [chunks[-1]]
        tree_dup = MerkleTree(chunks_dup)

        assert tree_original.root != tree_dup.root, (
            f"CVE-2012-2459 COLLISION DETECTED for size {size}! "
            f"Original root: {tree_original.root}, Duplicate root: {tree_dup.root}"
        )

    @pytest.mark.parametrize("size", [3, 5, 7, 9, 15, 31, 33])
    def test_cve_2012_2459_intermediate_level_duplicate_resistance(self, size):
        """
        Verify that duplicating any arbitrary chunk or intermediate node does not
        yield a collision with the original tree.
        """
        chunks = [f"unique_chunk_{size}_{i}".encode("utf-8") for i in range(size)]
        tree_orig = MerkleTree(chunks)

        for dup_idx in range(size):
            # Insert a duplicate at dup_idx + 1
            chunks_dup = chunks[:dup_idx + 1] + [chunks[dup_idx]] + chunks[dup_idx + 1:]
            tree_dup = MerkleTree(chunks_dup)
            assert tree_orig.root != tree_dup.root, (
                f"Collision when duplicating chunk {dup_idx} in tree size {size}"
            )


class TestChallengerMerkleProofAdversarialMutations:
    """
    Stress-test sibling Merkle proofs under chunk mutation, sibling tampering,
    direction alteration, proof truncation, and out-of-bounds boundary indices.
    """

    @pytest.mark.parametrize("size", [1, 3, 5, 7, 9, 15, 31, 33])
    def test_chunk_data_mutation_rejection(self, size):
        """Mutated chunk payload must ALWAYS be rejected."""
        chunks = [f"data_block_{size}_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        for idx in range(size):
            proof = tree.get_proof(idx)
            # Mutate chunk by appending a byte
            corrupted_chunk = chunks[idx] + b"\xff"
            assert MerkleTree.verify_chunk_proof(corrupted_chunk, idx, proof, tree.root) is False, (
                f"Corrupted chunk {idx}/{size} unexpectedly accepted"
            )

            # Mutate chunk by bit flip
            corrupted_chunk2 = bytes([chunks[idx][0] ^ 0x01]) + chunks[idx][1:]
            assert MerkleTree.verify_chunk_proof(corrupted_chunk2, idx, proof, tree.root) is False, (
                f"Bit-flipped chunk {idx}/{size} unexpectedly accepted"
            )

    @pytest.mark.parametrize("size", [3, 5, 7, 9, 15, 31, 33])
    def test_sibling_hash_tampering_rejection(self, size):
        """Tampered sibling hash in proof must ALWAYS be rejected."""
        chunks = [f"data_block_{size}_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        for idx in range(size):
            proof = tree.get_proof(idx)
            if not proof:
                continue

            # Tamper each sibling hash in the proof
            for step_i in range(len(proof)):
                direction, sib = proof[step_i]
                # Flip last hex character of sibling
                tampered_char = '0' if sib[-1] != '0' else '1'
                tampered_sib = sib[:-1] + tampered_char
                tampered_proof = list(proof)
                tampered_proof[step_i] = (direction, tampered_sib)

                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, tampered_proof, tree.root) is False, (
                    f"Tampered sibling at step {step_i} for chunk {idx}/{size} unexpectedly accepted"
                )

    @pytest.mark.parametrize("size", [3, 5, 7, 9, 15, 31, 33])
    def test_direction_tampering_rejection(self, size):
        """Flipping sibling direction (left <-> right) must be rejected."""
        # Use distinct chunks to prevent symmetry
        chunks = [f"distinct_unique_data_{size}_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        for idx in range(size):
            proof = tree.get_proof(idx)
            for step_i in range(len(proof)):
                direction, sib = proof[step_i]
                inverted_direction = "left" if direction == "right" else "right"
                tampered_proof = list(proof)
                tampered_proof[step_i] = (inverted_direction, sib)

                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, tampered_proof, tree.root) is False, (
                    f"Inverted direction at step {step_i} for chunk {idx}/{size} unexpectedly accepted"
                )

    @pytest.mark.parametrize("size", [3, 5, 7, 9, 15, 31, 33])
    def test_proof_truncation_rejection(self, size):
        """Truncated proof (missing steps) must be rejected."""
        chunks = [f"truncation_test_{size}_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        for idx in range(size):
            proof = tree.get_proof(idx)
            if len(proof) > 1:
                # Remove last step
                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof[:-1], tree.root) is False
                # Remove first step
                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof[1:], tree.root) is False

    @pytest.mark.parametrize("size", [1, 3, 5, 7, 9, 15, 31, 33])
    def test_expected_root_mismatch_rejection(self, size):
        """Proof verification with mismatched root must be rejected."""
        chunks = [f"root_mismatch_{size}_{i}".encode("utf-8") for i in range(size)]
        tree = MerkleTree(chunks)

        for idx in range(size):
            proof = tree.get_proof(idx)
            fake_root = "deadbeef" * 8
            assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof, fake_root) is False


class TestChallengerBoundaryAndEdgeCases:
    """
    Test boundary indices, 0-byte root, single-byte chunks, and malformed inputs.
    """

    def test_zero_byte_file_root_and_proof(self):
        """0-byte file (empty chunks list) must produce SHA-256(b'') and empty proof."""
        empty_tree = MerkleTree([])
        expected_empty_root = hashlib.sha256(b"").hexdigest()

        assert empty_tree.root == expected_empty_root
        assert empty_tree.get_proof(0) == []
        assert empty_tree.get_proof(-1) == []
        assert empty_tree.get_proof(1) == []

        # Empty chunk with empty proof and empty root must verify
        assert MerkleTree.verify_chunk_proof(b"", 0, [], expected_empty_root) is True

        # Non-empty chunk with empty root must reject
        assert MerkleTree.verify_chunk_proof(b"data", 0, [], expected_empty_root) is False

        # Non-empty proof with empty root must reject
        assert MerkleTree.verify_chunk_proof(b"", 0, [("left", "0" * 64)], expected_empty_root) is False

    def test_single_byte_chunks_odd_trees(self):
        """Trees composed of single-byte chunks must work cleanly."""
        chunks = [bytes([i]) for i in range(7)]
        tree = MerkleTree(chunks)
        assert tree.root is not None
        for i in range(7):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_chunk_proof(chunks[i], i, proof, tree.root) is True
            assert MerkleTree.verify_chunk_proof(b"\xff", i, proof, tree.root) is False

    def test_out_of_bounds_get_proof(self):
        """get_proof with out-of-bounds indices must return empty list without crashing."""
        chunks = [b"chunk_0", b"chunk_1", b"chunk_2"]
        tree = MerkleTree(chunks)

        assert tree.get_proof(-1) == []
        assert tree.get_proof(-999) == []
        assert tree.get_proof(3) == []
        assert tree.get_proof(100) == []

    def test_malformed_proof_structures_gracefully_rejected(self):
        """Malformed proof structures in verify_chunk_proof must return False without unhandled exceptions."""
        valid_chunk = b"valid_data"
        tree = MerkleTree([valid_chunk, b"sibling_data"])
        valid_root = tree.root

        malformed_proofs = [
            None,
            "not_a_list",
            12345,
            [("only_one_element",)],
            [("invalid_direction", "0" * 64)],
            [("left", "short_hash")],
            [("left", "g" * 64)],  # non-hex
            [("left", None)],
            [(None, "0" * 64)],
            [[1, 2, 3]],
        ]

        for p in malformed_proofs:
            assert MerkleTree.verify_chunk_proof(valid_chunk, 0, p, valid_root) is False

    def test_malformed_root_and_chunk_inputs_gracefully_rejected(self):
        """Invalid roots or chunk data must return False without crashing."""
        proof = [("right", "0" * 64)]

        invalid_roots = [None, "", 12345, "short", "z" * 64]
        for r in invalid_roots:
            assert MerkleTree.verify_chunk_proof(b"chunk", 0, proof, r) is False

        invalid_chunks = [None, 12345, [], {}]
        for c in invalid_chunks:
            assert MerkleTree.verify_chunk_proof(c, 0, proof, "0" * 64) is False


class TestChallengerSecondPreimageResistance:
    """
    Second-preimage attacks: verify that RFC 6962 leaf (\\x00) and interior (\\x01)
    domain separation prevents leaf-interior collision and graph-reinterpretation attacks.
    """

    def test_leaf_vs_interior_domain_separation_direct(self):
        """Same 64-byte payload hashed as leaf vs interior must produce different hashes."""
        payload_64 = os.urandom(64)
        leaf_hash = MerkleTree.hash_leaf(payload_64)

        left_32 = payload_64[:32].hex()
        right_32 = payload_64[32:].hex()
        interior_hash = MerkleTree.hash_interior(left_32, right_32)

        assert leaf_hash != interior_hash, (
            "Second-preimage failure: leaf hash and interior hash collided for identical input bytes!"
        )

    def test_second_preimage_tree_reinterpretation_attack(self):
        """
        Attacker attempts to forge a 1-leaf tree whose leaf equals the concatenation
        of left and right child hashes of a 2-leaf tree.
        Tree A: 2 chunks [C0, C1]. Root = hash_interior(hash_leaf(C0), hash_leaf(C1)).
        Attacker creates Tree B with 1 chunk = left_bytes + right_bytes.
        Root B = hash_leaf(left_bytes + right_bytes).
        Because of domain separation (\\x00 vs \\x01), Root A != Root B.
        """
        c0 = b"original_chunk_0"
        c1 = b"original_chunk_1"
        tree_a = MerkleTree([c0, c1])

        h0 = bytes.fromhex(tree_a.levels[0][0])
        h1 = bytes.fromhex(tree_a.levels[0][1])

        # Malicious single chunk consisting of concatenated child hashes
        c_forged = h0 + h1
        tree_b = MerkleTree([c_forged])

        assert tree_a.root != tree_b.root, (
            "Second-preimage attack succeeded! 2-chunk tree root collided with forged 1-chunk tree!"
        )

    def test_second_preimage_interior_reinterpretation_3_chunk_promoted_node(self):
        """
        In a 3-chunk tree [C0, C1, C2]:
        Level 0: h0, h1, h2
        Level 1: h01 = hash_interior(h0, h1), h2 (promoted)
        Level 2: root = hash_interior(h01, h2)

        Attacker tries to submit a 2-chunk tree [C01_prime, C2] where C01_prime's leaf hash
        attempts to match h01.
        Due to domain separation, hash_leaf(C01_prime) cannot equal hash_interior(h0, h1).
        """
        c0 = b"chunk_zero"
        c1 = b"chunk_one"
        c2 = b"chunk_two"
        tree_3 = MerkleTree([c0, c1, c2])

        h0 = bytes.fromhex(tree_3.levels[0][0])
        h1 = bytes.fromhex(tree_3.levels[0][1])

        # Attempted preimage for h01
        forged_c01 = h0 + h1
        tree_2_attempt = MerkleTree([forged_c01, c2])

        assert tree_3.root != tree_2_attempt.root, (
            "Second-preimage attack succeeded on promoted node in 3-chunk tree!"
        )


class TestChallengerRandomizedStressHarness:
    """
    Randomized stress harness over 50 random tree sizes (from 1 to 65 chunks)
    with randomized byte payloads.
    """

    def test_random_trees_fuzz_proofs_and_mutations(self):
        rng = random.Random(42)
        sizes = [rng.randint(1, 65) for _ in range(50)]

        for size in sizes:
            chunks = [os.urandom(rng.randint(1, 512)) for _ in range(size)]
            tree = MerkleTree(chunks)
            assert len(tree.root) == 64

            # Pick 3 random chunks to verify thoroughly
            test_indices = rng.sample(range(size), min(3, size))
            for idx in test_indices:
                proof = tree.get_proof(idx)
                # Valid verification
                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof, tree.root) is True

                # Mutated chunk
                corrupted = chunks[idx] + b"\x00"
                assert MerkleTree.verify_chunk_proof(corrupted, idx, proof, tree.root) is False

                # Wrong root
                assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof, "a" * 64) is False


class TestChallengerLargeOddTrees:
    """Stress testing large odd tree structures (> 1000 chunks) and boundary nodes."""

    def test_large_odd_tree_1025_chunks(self):
        """1025 chunks (2^10 + 1): Odd node promoted all the way up through 10 levels."""
        chunks = [f"large_chunk_{i}".encode("utf-8") for i in range(1025)]
        tree = MerkleTree(chunks)

        assert tree.root is not None
        assert len(tree.root) == 64

        # Test first, middle, and the odd-promoted last leaf (index 1024)
        for idx in [0, 512, 1024]:
            proof = tree.get_proof(idx)
            assert MerkleTree.verify_chunk_proof(chunks[idx], idx, proof, tree.root) is True
            # Tamper check
            assert MerkleTree.verify_chunk_proof(chunks[idx] + b"!", idx, proof, tree.root) is False

        # Verify CVE-2012-2459 resistance on 1025 chunks
        dup_chunks = list(chunks) + [chunks[-1]]
        tree_dup = MerkleTree(dup_chunks)
        assert tree.root != tree_dup.root, "CVE-2012-2459 collision on 1025-chunk tree!"


class TestChallengerPeerIdentity:
    """Stress test PeerIdentity RSA-PSS cryptographic signatures and permission controls."""

    def test_peer_identity_key_generation_and_export(self, tmp_path):
        key_path = str(tmp_path / "test_ident.pem")
        ident = PeerIdentity(key_path=key_path)

        assert ident.peer_id is not None
        assert len(ident.peer_id) == 64

        pub_pem = ident.get_public_key_pem()
        assert b"BEGIN PUBLIC KEY" in pub_pem
        assert ident.get_public_key_bytes() == pub_pem

        # Derivation check
        expected_peer_id = hashlib.sha256(pub_pem).hexdigest()
        assert ident.peer_id == expected_peer_id

    def test_peer_identity_sign_and_verify_permutations(self, tmp_path):
        ident = PeerIdentity(key_path=str(tmp_path / "sign_ident.pem"))
        pub_pem = ident.get_public_key_pem()

        msg_bytes = b"Cryptographic verification payload"
        msg_str = "Cryptographic verification payload"
        msg_bytearray = bytearray(msg_bytes)

        sig = ident.sign_data(msg_bytes)
        assert len(sig) == 256  # 2048-bit RSA produces 256-byte signature

        # Orientation 1: (pub, sig, data)
        assert PeerIdentity.verify_signature(pub_pem, sig, msg_bytes) is True
        # Orientation 2: (pub, data, sig)
        assert PeerIdentity.verify_signature(pub_pem, msg_bytes, sig) is True

        # String data sign and verify
        sig_str = ident.sign_data(msg_str)
        assert PeerIdentity.verify_signature(pub_pem, sig_str, msg_str) is True

        # Bytearray data sign and verify
        sig_ba = ident.sign_data(msg_bytearray)
        assert PeerIdentity.verify_signature(pub_pem, sig_ba, msg_bytearray) is True

        # Base64 signature
        import base64
        sig_b64 = base64.b64encode(sig).decode("utf-8")
        assert PeerIdentity.verify_signature(pub_pem, sig_b64, msg_bytes) is True

    def test_peer_identity_signature_adversarial_rejections(self, tmp_path):
        ident_alice = PeerIdentity(key_path=str(tmp_path / "alice.pem"))
        ident_bob = PeerIdentity(key_path=str(tmp_path / "bob.pem"))

        data = b"Alice authentic message"
        sig_alice = ident_alice.sign_data(data)

        # 1. Tampered data
        assert PeerIdentity.verify_signature(ident_alice.get_public_key_pem(), sig_alice, data + b"_tampered") is False

        # 2. Tampered signature
        tampered_sig = bytes([sig_alice[0] ^ 0xFF]) + sig_alice[1:]
        assert PeerIdentity.verify_signature(ident_alice.get_public_key_pem(), tampered_sig, data) is False

        # 3. Wrong public key (Bob verifies Alice's signature)
        assert PeerIdentity.verify_signature(ident_bob.get_public_key_pem(), sig_alice, data) is False

        # 4. Garbage public key
        assert PeerIdentity.verify_signature(b"NOT_A_PEM_KEY", sig_alice, data) is False

        # 5. Invalid sign data type
        with pytest.raises(TypeError):
            ident_alice.sign_data(12345)

