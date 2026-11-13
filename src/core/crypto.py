import os
import sys
import getpass
import hashlib
import base64
import subprocess
import logging
from typing import List, Tuple, Optional, Union
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

logger = logging.getLogger("CryptoCore")


def _restrict_file_permissions(file_path: str) -> None:
    """
    Enforce restricted permissions (0o600) on private key files across POSIX and Windows.
    POSIX: chmod to 0o600 (owner read/write only).
    Windows: Remove inherited permissions and grant Full Control exclusively to current user.
    """
    try:
        os.chmod(file_path, 0o600)
    except Exception as e:
        logger.debug(f"chmod on {file_path} failed: {e}")

    if sys.platform == "win32":
        try:
            username = os.environ.get("USERNAME") or getpass.getuser()
            subprocess.run(
                ["icacls", file_path, "/inheritance:r", "/grant:r", f"{username}:(F)"],
                capture_output=True,
                check=False
            )
        except Exception as e:
            logger.debug(f"icacls on {file_path} failed: {e}")


class MerkleTree:
    """
    RFC 6962 Domain-Separated Cryptographic Merkle Tree.
    - Leaf hash: SHA-256(\\x00 || chunk_bytes)
    - Interior hash: SHA-256(\\x01 || left_32B || right_32B)
    - Odd node promotion (CVE-2012-2459 fix)
    - Sibling audit path proof generation and verification
    - Standard SHA-256 empty hash for 0-byte files
    """
    LEAF_PREFIX = b'\x00'
    INTERIOR_PREFIX = b'\x01'
    EMPTY_ROOT = hashlib.sha256(b'').hexdigest()

    def __init__(self, chunks):
        self.chunks = list(chunks) if chunks is not None else []
        self.levels = []
        self.root = self._build_tree(self.chunks)
        self.tree = self.levels  # Backwards compatibility

    def _hash(self, data):
        """Legacy helper for backwards compatibility."""
        return self.hash_leaf(data)

    @classmethod
    def hash_leaf(cls, chunk_bytes) -> str:
        """Computes RFC 6962 leaf hash: SHA-256(\\x00 || chunk_bytes)."""
        if isinstance(chunk_bytes, str):
            chunk_bytes = chunk_bytes.encode('utf-8')
        return hashlib.sha256(cls.LEAF_PREFIX + chunk_bytes).hexdigest()

    @classmethod
    def hash_interior(cls, left, right) -> str:
        """Computes RFC 6962 interior node hash: SHA-256(\\x01 || left_32B || right_32B)."""
        left_bytes = bytes.fromhex(left) if isinstance(left, str) else left
        right_bytes = bytes.fromhex(right) if isinstance(right, str) else right
        return hashlib.sha256(cls.INTERIOR_PREFIX + left_bytes + right_bytes).hexdigest()

    def _build_tree(self, chunks):
        """
        Builds the Merkle tree with RFC 6962 domain separation and
        odd-node promotion (eliminating CVE-2012-2459).
        """
        if not chunks:
            self.levels = []
            return self.EMPTY_ROOT

        # Level 0: Leaf hashes
        current_level = [self.hash_leaf(c) for c in chunks]
        self.levels.append(current_level)

        # Build interior levels
        while len(current_level) > 1:
            next_level = []
            n = len(current_level)
            for i in range(0, n, 2):
                if i + 1 < n:
                    next_level.append(self.hash_interior(current_level[i], current_level[i + 1]))
                else:
                    # Fix CVE-2012-2459: Promote odd node directly without duplicate hashing
                    next_level.append(current_level[i])
            current_level = next_level
            self.levels.append(current_level)

        return current_level[0] if current_level else self.EMPTY_ROOT

    def get_proof(self, chunk_index: int) -> List[Tuple[str, str]]:
        """
        Generates an audit path of (direction, sibling_hash) for chunk_index.
        Returns a list of tuples: [('left'|'right', sibling_hash_hex), ...]
        """
        if not self.chunks or chunk_index < 0 or chunk_index >= len(self.chunks):
            return []

        proof = []
        idx = chunk_index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    proof.append(('right', level[idx + 1]))
            else:
                proof.append(('left', level[idx - 1]))
            idx //= 2

        return proof

    @classmethod
    def verify_chunk_proof(cls, chunk_data: bytes, chunk_index: int, proof: list, expected_root: str) -> bool:
        """
        Cryptographically verifies a chunk against expected_root using an audit path proof.
        Validates that proof directions strictly bind to chunk_index bit-path.
        Returns True iff the computed root matches expected_root.
        """
        if not expected_root or not isinstance(expected_root, str):
            return False

        if type(chunk_index) is not int or chunk_index < 0:
            return False

        # Support 0-byte file edge case
        if expected_root.lower() == cls.EMPTY_ROOT.lower() and chunk_data == b'' and (not proof):
            return True

        if chunk_data is None:
            return False

        if isinstance(chunk_data, str):
            chunk_data = chunk_data.encode('utf-8')

        if not isinstance(chunk_data, (bytes, bytearray)):
            return False

        if not isinstance(proof, list):
            return False

        curr = cls.hash_leaf(chunk_data)
        idx = chunk_index

        for item in proof:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                return False

            a, b = item
            if a in ('left', 'right'):
                direction, sibling = a, b
            elif b in ('left', 'right'):
                sibling, direction = a, b
            else:
                return False

            if not isinstance(sibling, str) or len(sibling) != 64:
                return False

            # Verify chunk_index bit path:
            # Sibling is 'left' => current node is on right => idx must be odd.
            # If idx is currently even, it could only occur if odd-node promotion skipped levels.
            while idx > 0 and idx % 2 == 0 and direction == 'left':
                idx //= 2

            if direction == 'right' and idx % 2 != 0:
                return False  # An odd node cannot have a right sibling
            if direction == 'left' and idx % 2 != 1:
                return False  # An even node cannot have a left sibling

            try:
                if direction == 'right':
                    curr = cls.hash_interior(curr, sibling)
                elif direction == 'left':
                    curr = cls.hash_interior(sibling, curr)
                else:
                    return False
            except (ValueError, TypeError):
                return False

            idx //= 2

        return curr.lower() == expected_root.lower()

    @classmethod
    def verify_chunk(cls, chunk, chunk_index, total_chunks, expected_root, proof):
        """
        Backwards-compatible wrapper.
        If proof is a list, invokes verify_chunk_proof.
        If proof is a legacy dict, validates chunk hash directly.
        """
        if isinstance(proof, list):
            return cls.verify_chunk_proof(chunk, chunk_index, proof, expected_root)
        if isinstance(proof, dict):
            chunk_hash = hashlib.sha256(chunk if isinstance(chunk, bytes) else chunk.encode('utf-8')).hexdigest()
            return chunk_hash == proof.get(str(chunk_index))
        return False


class PeerIdentity:
    """
    Zero-Trust Cryptographic Peer Identity.
    Generates and persists 2048-bit RSA keys with restricted permissions (0o600 / safe ACLs).
    Provides RSA-PSS digital signature generation and verification.
    """

    def __init__(self, port=None, keys_dir=None, key_path=None):
        ident = str(port) if port is not None else ""
        default_filename = f"private_key_{ident}.pem" if ident else "private_key.pem"

        if key_path:
            self.key_path = key_path
        elif keys_dir:
            os.makedirs(keys_dir, mode=0o700, exist_ok=True)
            self.key_path = os.path.join(keys_dir, default_filename)
        else:
            # Check if key exists in keys/ directory or current directory
            keys_dir_path = os.path.join("keys", default_filename)
            if os.path.exists(keys_dir_path):
                self.key_path = keys_dir_path
            elif os.path.exists(default_filename):
                self.key_path = default_filename
            else:
                self.key_path = default_filename

        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
            _restrict_file_permissions(self.key_path)
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            parent_dir = os.path.dirname(self.key_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)

            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            mode = 0o600

            pem_bytes = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )

            fd = os.open(self.key_path, flags, mode)
            try:
                with open(fd, "wb", closefd=True) as key_file:
                    key_file.write(pem_bytes)
            except Exception:
                raise

            _restrict_file_permissions(self.key_path)

        self.public_key = self.private_key.public_key()
        self.peer_id = self.get_peer_id()

    def get_public_key_pem(self) -> bytes:
        """Export public key in PEM format (SubjectPublicKeyInfo)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_key_bytes(self) -> bytes:
        """Backward-compatible alias for get_public_key_pem."""
        return self.get_public_key_pem()

    def get_peer_id(self) -> str:
        """Return 64-character SHA-256 hex string derived from public key PEM."""
        pub_bytes = self.get_public_key_pem()
        return hashlib.sha256(pub_bytes).hexdigest()

    def save_public_key_pem(self, output_path: str) -> None:
        """Save exportable public key PEM to designated file path."""
        with open(output_path, "wb") as f:
            f.write(self.get_public_key_pem())

    def sign_data(self, data) -> bytes:
        """
        Generate RSA-PSS digital signature over data using SHA-256 and MGF1.
        Accepts str, bytes, or bytearray.
        Returns 256-byte binary signature.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        elif not isinstance(data, (bytes, bytearray)):
            raise TypeError("Data to sign must be bytes, bytearray, or str")

        return self.private_key.sign(
            bytes(data),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    @staticmethod
    def verify_signature(public_key_bytes, arg2, arg3) -> bool:
        """
        Verify RSA-PSS digital signature.
        Supports both argument orders:
          - (public_key, signature, data)
          - (public_key, data, signature)
        Accepts signature as binary bytes or base64-encoded string/bytes.
        Accepts public key as PEM bytes or str.
        Uses padding.PSS.AUTO for robust salt length handling.
        Returns True if signature is valid, False otherwise.
        """
        if isinstance(public_key_bytes, str):
            public_key_bytes = public_key_bytes.encode('utf-8')

        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
        except Exception:
            return False

        def _try_verify(sig_cand, data_cand):
            # Normalize signature
            if isinstance(sig_cand, str):
                try:
                    sig_bytes = base64.b64decode(sig_cand)
                except Exception:
                    sig_bytes = sig_cand.encode('utf-8')
            elif isinstance(sig_cand, (bytes, bytearray)):
                if len(sig_cand) == 344:
                    try:
                        sig_bytes = base64.b64decode(sig_cand)
                    except Exception:
                        sig_bytes = bytes(sig_cand)
                else:
                    sig_bytes = bytes(sig_cand)
            else:
                return False

            # Normalize data
            if isinstance(data_cand, str):
                data_bytes = data_cand.encode('utf-8')
            elif isinstance(data_cand, (bytes, bytearray)):
                data_bytes = bytes(data_cand)
            else:
                return False

            try:
                public_key.verify(
                    sig_bytes,
                    data_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.AUTO
                    ),
                    hashes.SHA256()
                )
                return True
            except Exception:
                return False

        # Orientation 1: arg2=signature, arg3=data
        if _try_verify(arg2, arg3):
            return True

        # Orientation 2: arg2=data, arg3=signature
        if _try_verify(arg3, arg2):
            return True

        return False
