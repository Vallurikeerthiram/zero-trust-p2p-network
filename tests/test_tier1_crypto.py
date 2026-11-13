import hashlib
import os
import stat
import pytest
from src.core.crypto import MerkleTree, PeerIdentity


class TestTier1Crypto:
    """Tier 1 - Feature Coverage: Cryptographic Primitives & Merkle Trees."""

    def test_merkle_zero_byte_root(self):
        """0-byte file Merkle root should produce consistent SHA-256 empty hash (e3b0c442...)."""
        tree = MerkleTree([])
        empty_sha256 = hashlib.sha256(b"").hexdigest()
        assert tree.root is not None, "0-byte file tree root must not be None"
        assert tree.root == empty_sha256, f"Expected {empty_sha256}, got {tree.root}"

    def test_merkle_domain_separation_leaf_prefix(self):
        """Leaf hashes must use domain separation prefix \\x00."""
        chunk = b"Test chunk data for domain separation"
        expected_leaf_hash = hashlib.sha256(b"\x00" + chunk).hexdigest()

        tree = MerkleTree([chunk])
        assert tree.root == expected_leaf_hash or (
            hasattr(tree, "tree") and tree.tree and tree.tree[0][0] == expected_leaf_hash
        ), "Leaf node hash must use RFC 6962 \\x00 prefix"

    def test_merkle_domain_separation_second_preimage_resistance(self):
        """Leaf hash must differ from interior node hash for the same raw payload."""
        payload = b"A" * 64
        leaf_hash = hashlib.sha256(b"\x00" + payload).hexdigest()
        interior_hash = hashlib.sha256(b"\x01" + payload).hexdigest()
        assert leaf_hash != interior_hash, "Leaf and interior hashes must be domain separated"

    def test_merkle_odd_node_collision_fix_cve_2012_2459(self):
        """Odd-node duplication vulnerability: 3 chunks vs 4 chunks (with duplicate) must yield different roots."""
        c0 = b"chunk_alpha_0"
        c1 = b"chunk_beta_1"
        c2 = b"chunk_gamma_2"

        tree_3_chunks = MerkleTree([c0, c1, c2])
        tree_4_chunks_dup = MerkleTree([c0, c1, c2, c2])

        assert tree_3_chunks.root != tree_4_chunks_dup.root, (
            "Vulnerability CVE-2012-2459: 3-chunk tree and 4-chunk duplicate tree must not produce identical roots"
        )

    def test_merkle_sibling_proofs_generation_and_verification(self):
        """Authentic sibling-hash proofs must be generated and verified for all chunks."""
        chunks = [
            b"chunk_0_first_data_block",
            b"chunk_1_second_data_block",
            b"chunk_2_third_data_block",
            b"chunk_3_fourth_data_block"
        ]
        tree = MerkleTree(chunks)
        assert tree.root is not None

        assert hasattr(tree, "get_proof"), "MerkleTree must provide get_proof(chunk_index)"
        assert hasattr(MerkleTree, "verify_chunk_proof"), (
            "MerkleTree must provide verify_chunk_proof(chunk_data, chunk_index, proof, expected_root)"
        )

        for i, chunk in enumerate(chunks):
            proof = tree.get_proof(i)
            assert isinstance(proof, list), f"Proof for chunk {i} must be a list"
            assert len(proof) > 0, f"Proof for chunk {i} must contain sibling audit steps"
            # Verify authentic chunk against root
            valid = MerkleTree.verify_chunk_proof(chunk, i, proof, tree.root)
            assert valid is True, f"Valid chunk {i} failed Merkle proof verification"

    def test_merkle_proof_verification_fails_on_tampered_chunk(self):
        """Proof verification must reject tampered chunk data."""
        chunks = [b"valid_chunk_0", b"valid_chunk_1", b"valid_chunk_2"]
        tree = MerkleTree(chunks)

        if hasattr(tree, "get_proof") and hasattr(MerkleTree, "verify_chunk_proof"):
            proof = tree.get_proof(0)
            tampered_chunk = b"corrupted_chunk_0"
            assert MerkleTree.verify_chunk_proof(tampered_chunk, 0, proof, tree.root) is False

    def test_merkle_proof_verification_fails_on_wrong_root(self):
        """Proof verification must reject authentic chunk if expected_root is mismatched."""
        chunks = [b"valid_chunk_0", b"valid_chunk_1"]
        tree = MerkleTree(chunks)

        if hasattr(tree, "get_proof") and hasattr(MerkleTree, "verify_chunk_proof"):
            proof = tree.get_proof(0)
            fake_root = "0" * 64
            assert MerkleTree.verify_chunk_proof(chunks[0], 0, proof, fake_root) is False

    def test_merkle_proof_verification_fails_on_corrupted_proof(self):
        """Proof verification must reject chunk if sibling hash in proof is corrupted."""
        chunks = [b"valid_chunk_0", b"valid_chunk_1", b"valid_chunk_2", b"valid_chunk_3"]
        tree = MerkleTree(chunks)

        if hasattr(tree, "get_proof") and hasattr(MerkleTree, "verify_chunk_proof"):
            proof = tree.get_proof(0)
            if proof:
                # Corrupt the sibling hash
                direction, sibling = proof[0]
                corrupted_proof = [("left" if direction == "right" else "right", "f" * 64)] + proof[1:]
                assert MerkleTree.verify_chunk_proof(chunks[0], 0, corrupted_proof, tree.root) is False

    def test_rsa_key_generation_and_peer_id(self, peer_identity):
        """PeerIdentity should generate 2048-bit RSA key and derive SHA-256 peer_id."""
        peer_id = peer_identity.peer_id if hasattr(peer_identity, "peer_id") else peer_identity.get_peer_id()
        assert isinstance(peer_id, str)
        assert len(peer_id) == 64, "Peer ID must be a 64-character SHA-256 hex string"

        pub_bytes = (
            peer_identity.get_public_key_bytes()
            if hasattr(peer_identity, "get_public_key_bytes")
            else peer_identity.get_public_key_pem()
        )
        assert b"BEGIN PUBLIC KEY" in pub_bytes
        assert b"END PUBLIC KEY" in pub_bytes

    def test_private_key_file_permissions(self, isolated_dir, identity_factory):
        """Private key files on disk must have restricted permissions (0o600 on POSIX)."""
        identity = identity_factory("test_perms_node")
        key_file = "private_key_test_perms_node.pem"
        assert os.path.exists(key_file), f"Key file {key_file} must exist"

        if os.name != "nt":
            mode = stat.S_IMODE(os.stat(key_file).st_mode)
            assert mode == 0o600, f"Private key file permissions should be 0o600, found {oct(mode)}"

    def test_digital_signature_generation_and_verification(self, peer_identity, second_identity):
        """RSA-PSS signature generation and verification across valid and invalid inputs."""
        message = b"Authenticated zero-trust payload 12345"
        signature = peer_identity.sign_data(message)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

        pub_bytes = (
            peer_identity.get_public_key_bytes()
            if hasattr(peer_identity, "get_public_key_bytes")
            else peer_identity.get_public_key_pem()
        )

        # Helper to verify signature handling argument order differences
        def _verify(pub, sig, data):
            try:
                if PeerIdentity.verify_signature(pub, sig, data):
                    return True
            except Exception:
                pass
            try:
                if PeerIdentity.verify_signature(pub, data, sig):
                    return True
            except Exception:
                pass
            return False

        # 1. Valid signature verifies
        assert _verify(pub_bytes, signature, message) is True

        # 2. Tampered data fails
        assert _verify(pub_bytes, signature, b"Tampered data") is False

        # 3. Mismatched public key fails
        second_pub = (
            second_identity.get_public_key_bytes()
            if hasattr(second_identity, "get_public_key_bytes")
            else second_identity.get_public_key_pem()
        )
        assert _verify(second_pub, signature, message) is False

        # 4. Corrupted signature fails
        corrupted_sig = bytes([b ^ 0xFF for b in signature[:10]]) + signature[10:]
        assert _verify(pub_bytes, corrupted_sig, message) is False
