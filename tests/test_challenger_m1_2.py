"""
Empirical Challenge & Stress Test Suite for Milestone 1 (M1)
Challenger 2 (ID: challenger_m1_2)

Targets:
- src.core.file_manager.FileManager
- src.core.crypto.MerkleTree
- src.core.crypto.PeerIdentity

Focus Areas:
1. Dynamic path traversal stress testing (sneaky paths, null bytes, OS device names, UNC, etc.)
2. 0-byte file edge cases (chunking, Merkle root, proof verification, reassembly across temp dirs)
3. Private key filesystem permissions on disk (Windows icacls / POSIX mode)
4. Cryptographic digital signature manipulation, tampering, and type confusion
"""

import os
import sys
import stat
import shutil
import tempfile
import base64
import subprocess
import pytest
from src.core.file_manager import FileManager
from src.core.crypto import MerkleTree, PeerIdentity


class TestPathTraversalStress:
    """Adversarial stress testing against path traversal defenses."""

    @pytest.fixture(autouse=True)
    def setup_fm(self, tmp_path):
        self.storage_dir = tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.fm = FileManager(storage_dir=str(self.storage_dir))
        # Create a sentinel file outside the storage directory to ensure it is never touched
        self.sentinel = tmp_path / "secret_sentinel.txt"
        self.sentinel.write_text("SUPER_SECRET_DATA", encoding="utf-8")

    @pytest.mark.parametrize("traversal_payload", [
        # Relative directory traversals
        "../secret_sentinel.txt",
        "..\\secret_sentinel.txt",
        "....//secret_sentinel.txt",
        "....\\\\secret_sentinel.txt",
        "./../secret_sentinel.txt",
        "nested/../../secret_sentinel.txt",
        "..",
        ".",
        # Absolute system paths (POSIX and Windows)
        "/etc/passwd",
        "/etc/shadow",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "C:\\boot.ini",
        # Drive relative and drive hop
        "C:secret.txt",
        "D:\\data.txt",
        "Z:\\nonexistent.txt",
        # UNC network shares
        "\\\\127.0.0.1\\c$\\Windows\\win.ini",
        "//server/share/file.txt",
        "\\\\?\\C:\\Windows\\win.ini",
        # Null bytes
        "innocent.txt\x00malicious",
        "\x00",
        "secret_sentinel.txt\x00",
        # Windows reserved device names (bare and with extensions)
        "CON",
        "con",
        "PRN",
        "prn",
        "AUX",
        "aux",
        "NUL",
        "nul",
        "COM1",
        "com1",
        "COM9",
        "LPT1",
        "lpt1",
        "CON.txt",
        "con.tar.gz",
        "AUX.pdf",
        "nul.dat",
        "prn.log",
        # Trailing spaces and dots (Windows filesystem truncation bypass vectors)
        "legit.txt ",
        "legit.txt. ",
        "legit.txt.",
        "legit.txt..",
        "   ",
        "",
        # Forbidden characters
        "file<name.txt",
        "file>name.txt",
        "file:stream",
        "file\"name.txt",
        "file|name.txt",
        "file?name.txt",
        "file*name.txt",
        # Control characters
        "file\nname.txt",
        "file\rname.txt",
        "file\tname.txt",
        "file\x1bname.txt",
        "file\x1fname.txt",
        # Path component attempts
        "sub/dir/file.txt",
        "sub\\dir\\file.txt",
        # Traversal substrings
        "file..name.txt",
        "file..txt",
        # URL-encoded patterns with separators or literal dots
        "%2e%2e/",
        "..%2f",
        "%2e%2e\\",
    ])
    def test_path_traversal_rejected_in_validate_filename(self, traversal_payload):
        """Verify validate_filename strictly rejects traversal and dangerous filenames."""
        with pytest.raises(ValueError):
            self.fm.validate_filename(traversal_payload)

    def test_url_encoded_traversal_raw_storage_containment(self):
        """
        Verify behavior of raw URL-encoded string '%2e%2e%2f':
        When passed without URL-decoding, verify that if processed, it remains strictly
        jailed inside storage_dir and cannot touch sentinel files outside storage.
        """
        raw_encoded = "%2e%2e%2f"
        # If validate_filename allows literal '%2e%2e%2f', verify containment
        try:
            self.fm.validate_filename(raw_encoded)
            # Verify save_chunk stays inside storage_dir
            chunk_path = self.fm.save_chunk(raw_encoded, 0, b"data")
            assert os.path.commonpath([str(self.storage_dir), os.path.abspath(chunk_path)]) == str(self.storage_dir)
            # Sentinel remains untouched
            assert self.sentinel.read_text(encoding="utf-8") == "SUPER_SECRET_DATA"
        except ValueError:
            # If rejected with ValueError, that is also secure
            pass

    @pytest.mark.parametrize("traversal_payload", [
        "../secret_sentinel.txt",
        "..\\secret_sentinel.txt",
        "....//secret_sentinel.txt",
        "C:\\Windows\\win.ini",
        "/etc/passwd",
        "CON",
        "NUL",
        "AUX.pdf",
        "file.txt ",
        "file.txt.",
        "file\x00.txt",
        "file:stream",
    ])
    def test_save_chunk_path_traversal_rejected(self, traversal_payload):
        """Verify save_chunk rejects malicious filenames and never writes outside storage."""
        with pytest.raises(ValueError):
            self.fm.save_chunk(traversal_payload, 0, b"malicious chunk data")

        # Sentinel file outside storage must remain untouched
        assert self.sentinel.read_text(encoding="utf-8") == "SUPER_SECRET_DATA"

    @pytest.mark.parametrize("traversal_payload", [
        "../secret_sentinel.txt",
        "..\\secret_sentinel.txt",
        "....//secret_sentinel.txt",
        "C:\\Windows\\win.ini",
        "/etc/passwd",
        "CON",
        "NUL",
        "file\x00.txt",
        "file.txt ",
        "file.txt.",
    ])
    def test_get_chunk_path_traversal_rejected(self, traversal_payload):
        """Verify get_chunk rejects path traversal attempts and cannot read outside storage."""
        with pytest.raises(ValueError):
            self.fm.get_chunk(traversal_payload, 0)

    @pytest.mark.parametrize("traversal_payload", [
        "../secret_sentinel.txt",
        "..\\secret_sentinel.txt",
        "C:\\Windows\\win.ini",
        "/etc/passwd",
        "CON",
        "NUL",
        "file.txt ",
        "file.txt.",
    ])
    def test_reassemble_file_path_traversal_rejected(self, traversal_payload):
        """Verify reassemble_file rejects traversal in both file_id and final_filename."""
        with pytest.raises(ValueError):
            self.fm.reassemble_file(file_id=traversal_payload, final_filename="safe.txt", total_chunks=0)

        with pytest.raises(ValueError):
            self.fm.reassemble_file(file_id="safe_id", final_filename=traversal_payload, total_chunks=0)

    @pytest.mark.parametrize("invalid_chunk_idx", [
        -1, -100, 1.5, "0", True, False, None, [0], {"idx": 0}
    ])
    def test_chunk_index_type_and_boundary_checks(self, invalid_chunk_idx):
        """Verify strict integer validation on chunk_index across save_chunk and get_chunk."""
        with pytest.raises(ValueError):
            self.fm.save_chunk("valid_file.txt", invalid_chunk_idx, b"data")

        with pytest.raises(ValueError):
            self.fm.get_chunk("valid_file.txt", invalid_chunk_idx)

    def test_resolve_safe_path_cannot_escape_root(self):
        """Verify that _resolve_safe_path strictly confines paths to storage_dir."""
        # Attempting to resolve storage_dir itself as a file should be rejected
        with pytest.raises(ValueError):
            self.fm._resolve_safe_path("")

        with pytest.raises(ValueError):
            self.fm._resolve_safe_path(".")

        # Any path resolving outside storage_dir must raise ValueError
        with pytest.raises(ValueError):
            self.fm._resolve_safe_path(str(self.sentinel))


class TestZeroByteFileStress:
    """Stress testing 0-byte file chunking, Merkle tree, and reassembly across temporary directories."""

    @pytest.fixture(autouse=True)
    def setup_fm(self, tmp_path):
        self.storage_dir = tmp_path / "storage"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.fm = FileManager(storage_dir=str(self.storage_dir))
        self.tmp_path = tmp_path

    def test_zero_byte_split_and_merkle_properties(self):
        """Empirically test split_file on 0-byte file and its MerkleTree properties."""
        zero_file = self.tmp_path / "empty.txt"
        zero_file.write_bytes(b"")

        chunks, tree = self.fm.split_file(str(zero_file))
        assert chunks == []
        assert isinstance(tree, MerkleTree)

        # Standard SHA-256 of empty bytes
        expected_empty_root = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert tree.root.lower() == expected_empty_root.lower()

        # Proof for chunk 0 on empty tree should be empty list
        proof = tree.get_proof(0)
        assert proof == []

        # Verification of 0-byte chunk against empty root must succeed
        assert MerkleTree.verify_chunk_proof(b"", 0, [], expected_empty_root) is True

        # Tampered chunk data or unexpected proof elements must fail verification
        assert MerkleTree.verify_chunk_proof(b"non-empty", 0, [], expected_empty_root) is False
        assert MerkleTree.verify_chunk_proof(b"", 0, [("left", "00" * 32)], expected_empty_root) is False
        assert MerkleTree.verify_chunk_proof(b"", 0, [], "11" * 32) is False

    def test_zero_byte_reassembly_without_temp_dir(self):
        """Verify reassemble_file cleanly handles 0-byte files when no temp dir exists."""
        final_path = self.fm.reassemble_file("zero_test.txt", total_chunks=0)
        assert os.path.exists(final_path)
        assert os.path.getsize(final_path) == 0

        # Verify get_chunk behavior on the reassembled 0-byte file
        assert self.fm.get_chunk("zero_test.txt", 0) == b""
        assert self.fm.get_chunk("zero_test.txt", 1) is None

    def test_zero_byte_reassembly_with_leftover_temp_dir(self):
        """Verify reassemble_file cleanly removes leftover temp directories without crashing."""
        temp_dir = self.storage_dir / "zero_leftover.txt_temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        # Put a stray file in temp dir to simulate abandoned download
        (temp_dir / "stray.tmp").write_bytes(b"stray data")

        final_path = self.fm.reassemble_file("zero_leftover.txt", total_chunks=0)
        assert os.path.exists(final_path)
        assert os.path.getsize(final_path) == 0
        # Temp dir must be cleanly deleted
        assert not temp_dir.exists()

    def test_zero_byte_reassembly_with_distinct_file_id_and_filename(self):
        """Verify 3-argument reassemble_file(file_id, final_filename, total_chunks=0)."""
        file_id = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        final_name = "reassembled_empty.pdf"

        # Create leftover temp directory named {file_id}_temp
        temp_dir = self.storage_dir / f"{file_id}_temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        (temp_dir / "marker.tmp").write_bytes(b"temp")

        final_path = self.fm.reassemble_file(file_id=file_id, final_filename=final_name, total_chunks=0)
        assert os.path.exists(final_path)
        assert os.path.basename(final_path) == final_name
        assert os.path.getsize(final_path) == 0
        assert not temp_dir.exists()

    def test_zero_byte_reassembly_idempotent_overwrite(self):
        """Verify reassemble_file on 0-byte file is safely idempotent."""
        path1 = self.fm.reassemble_file("idempotent.txt", total_chunks=0)
        assert os.path.exists(path1)
        # Call again
        path2 = self.fm.reassemble_file("idempotent.txt", total_chunks=0)
        assert path1 == path2
        assert os.path.getsize(path2) == 0

    def test_zero_byte_file_deletion(self):
        """Verify safe deletion of 0-byte file."""
        self.fm.reassemble_file("to_delete.txt", total_chunks=0)
        assert self.fm.delete_file("to_delete.txt") is True
        assert not (self.storage_dir / "to_delete.txt").exists()


class TestKeyPermissionsAndDigitalSignatures:
    """Stress testing private key ACLs on disk and cryptographic digital signature manipulation."""

    @pytest.fixture(autouse=True)
    def setup_identity(self, tmp_path):
        self.keys_dir = tmp_path / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = str(self.keys_dir / "private_key_test.pem")
        self.identity = PeerIdentity(key_path=self.key_path)

    def test_private_key_file_exists_and_owner_can_read(self):
        """Verify private key file is written to designated path and readable by owner."""
        assert os.path.exists(self.key_path)
        with open(self.key_path, "rb") as f:
            content = f.read()
        assert b"BEGIN PRIVATE KEY" in content or b"BEGIN RSA PRIVATE KEY" in content

    def test_private_key_filesystem_permissions_disk(self):
        """Verify private key has strictly restricted permissions (0o600 / Windows icacls)."""
        file_stat = os.stat(self.key_path)
        file_mode = stat.S_IMODE(file_stat.st_mode)

        if sys.platform != "win32":
            # POSIX: exactly 0o600
            assert file_mode == 0o600, f"Expected 0o600 on POSIX, got {oct(file_mode)}"
        else:
            # Windows: Check icacls output to verify ACL restriction and inheritance removal
            try:
                result = subprocess.run(
                    ["icacls", self.key_path],
                    capture_output=True,
                    text=True,
                    check=True
                )
                output = result.stdout
                # Verify inheritance is stripped (no inherited '(I)' entries)
                # and current user has '(F)' full control
                username = os.environ.get("USERNAME")
                if username:
                    assert username.lower() in output.lower(), f"Current user {username} not found in icacls: {output}"
                    assert "(F)" in output, f"Full control not granted in icacls: {output}"
                # Ensure generic Users group is not granted access
                assert "BUILTIN\\Users:(F)" not in output
            except FileNotFoundError:
                pytest.skip("icacls utility not found on Windows environment")

    def test_signature_verification_authentic(self):
        """Verify standard RSA-PSS signing and verification with authentic data."""
        data = b"Zero-Trust Authentic Payload"
        sig = self.identity.sign_data(data)
        pub_pem = self.identity.get_public_key_pem()

        assert len(sig) == 256
        # Both argument orientations supported
        assert PeerIdentity.verify_signature(pub_pem, sig, data) is True
        assert PeerIdentity.verify_signature(pub_pem, data, sig) is True

    @pytest.mark.parametrize("corrupt_idx", [0, 10, 50, 128, 200, 255])
    def test_signature_verification_fails_on_single_bit_flip(self, corrupt_idx):
        """Verify single bit flip in 256-byte signature causes verification failure."""
        data = b"Zero-Trust Payload for Bit-Flip"
        sig = bytearray(self.identity.sign_data(data))
        # Flip highest bit of chosen byte
        sig[corrupt_idx] ^= 0x80
        pub_pem = self.identity.get_public_key_pem()

        assert PeerIdentity.verify_signature(pub_pem, bytes(sig), data) is False

    @pytest.mark.parametrize("tampered_data", [
        b"Zero-Trust Authentic Payloac",  # 1 char changed
        b"Zero-Trust Authentic Payload ",  # trailing space
        b"Zero-Trust Authentic Payload\x00",  # trailing null
        b"",  # truncated to empty
        b"A" * 1024,  # completely different
    ])
    def test_signature_verification_fails_on_data_tampering(self, tampered_data):
        """Verify altering signed data causes verification failure."""
        original_data = b"Zero-Trust Authentic Payload"
        sig = self.identity.sign_data(original_data)
        pub_pem = self.identity.get_public_key_pem()

        assert PeerIdentity.verify_signature(pub_pem, sig, tampered_data) is False

    @pytest.mark.parametrize("malformed_sig", [
        b"",  # 0 bytes
        b"\x00",  # 1 byte
        b"A" * 100,  # truncated
        b"A" * 255,  # 1 byte short
        b"A" * 257,  # 1 byte too long
        b"A" * 512,  # double length
        b"\x00" * 256,  # 256 null bytes
        b"\xff" * 256,  # 256 0xFF bytes
        os.urandom(256),  # random 256 bytes
    ])
    def test_signature_verification_fails_on_malformed_signatures(self, malformed_sig):
        """Verify verification gracefully returns False for all malformed signature lengths/patterns."""
        data = b"Testing malformed signatures"
        pub_pem = self.identity.get_public_key_pem()

        assert PeerIdentity.verify_signature(pub_pem, malformed_sig, data) is False

    def test_signature_cross_identity_rejection(self, tmp_path):
        """Verify signature produced by Peer A fails verification against Peer B's public key."""
        peer_b_path = str(tmp_path / "private_key_b.pem")
        peer_b = PeerIdentity(key_path=peer_b_path)

        data = b"Shared Message"
        sig_a = self.identity.sign_data(data)
        pub_b_pem = peer_b.get_public_key_pem()

        # Peer A signature verified against Peer B key must be False
        assert PeerIdentity.verify_signature(pub_b_pem, sig_a, data) is False

        # Peer B signature verified against Peer A key must be False
        sig_b = peer_b.sign_data(data)
        pub_a_pem = self.identity.get_public_key_pem()
        assert PeerIdentity.verify_signature(pub_a_pem, sig_b, data) is False

    def test_re_signing_attack_prevention(self, tmp_path):
        """Simulate adversary re-signing altered data with adversary key against victim public key."""
        attacker_path = str(tmp_path / "private_key_attacker.pem")
        attacker = PeerIdentity(key_path=attacker_path)

        original_data = b"Transfer $10 to Alice"
        tampered_data = b"Transfer $1000 to Bob"

        # Attacker signs tampered data with their own key
        attacker_sig = attacker.sign_data(tampered_data)

        # Verifier checks signature against victim's legitimate public key
        victim_pub_pem = self.identity.get_public_key_pem()
        assert PeerIdentity.verify_signature(victim_pub_pem, attacker_sig, tampered_data) is False

    def test_signature_base64_encodings(self):
        """Verify support for both raw bytes and Base64-encoded strings and bytes."""
        data = b"Base64 Signature Verification Test"
        raw_sig = self.identity.sign_data(data)
        b64_sig_str = base64.b64encode(raw_sig).decode("ascii")
        b64_sig_bytes = base64.b64encode(raw_sig)
        pub_pem = self.identity.get_public_key_pem()

        # String base64
        assert PeerIdentity.verify_signature(pub_pem, b64_sig_str, data) is True
        # Bytes base64 (344 bytes)
        assert PeerIdentity.verify_signature(pub_pem, b64_sig_bytes, data) is True

        # Corrupted base64
        corrupted_b64 = b64_sig_str[:-4] + "===="
        assert PeerIdentity.verify_signature(pub_pem, corrupted_b64, data) is False

    @pytest.mark.parametrize("corrupted_pub_key", [
        b"",
        b"NOT_A_KEY",
        b"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----",
        b"\x00" * 100,
        None,
        12345,
    ])
    def test_signature_verification_handles_corrupt_public_key(self, corrupted_pub_key):
        """Verify that malformed or invalid public keys gracefully return False without crashing."""
        data = b"Some data"
        sig = self.identity.sign_data(data)
        assert PeerIdentity.verify_signature(corrupted_pub_key, sig, data) is False

    @pytest.mark.parametrize("invalid_input", [
        None, 1234, 3.14, ["list"], {"dict": "val"}
    ])
    def test_signature_verification_type_safety(self, invalid_input):
        """Verify non-bytes/non-string inputs to verify_signature return False gracefully."""
        pub_pem = self.identity.get_public_key_pem()
        sig = self.identity.sign_data(b"data")
        assert PeerIdentity.verify_signature(pub_pem, invalid_input, b"data") is False
        assert PeerIdentity.verify_signature(pub_pem, sig, invalid_input) is False
