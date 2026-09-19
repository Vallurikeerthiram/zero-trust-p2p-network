import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class MerkleTree:
    def __init__(self, chunks):
        self.chunks = chunks
        self.tree = []
        self.root = self._build_tree(chunks)

    def _hash(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    def _build_tree(self, chunks):
        if not chunks:
            return None
            
        current_level = [self._hash(chunk) for chunk in chunks]
        self.tree.append(current_level)
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i] # Duplicate if odd
                next_level.append(self._hash(combined))
            current_level = next_level
            self.tree.append(current_level)
            
        return current_level[0] if current_level else None

    @staticmethod
    def verify_chunk(chunk, chunk_index, total_chunks, expected_root, proof):
        """
        In a full implementation, this would use the proof array to verify a chunk 
        against the root. For our simplified version to keep network traffic low,
        we can recompute the root if we have all chunks, or verify individual 
        chunks if we transmit the tree. 
        For our P2P Zero-Trust model, we will validate the chunk hash directly if
        we have the expected tree or full proof.
        """
        # A simple hashing check for now, in a real scenario we'd use the proof
        chunk_hash = hashlib.sha256(chunk if isinstance(chunk, bytes) else chunk.encode('utf-8')).hexdigest()
        # The proof should contain the expected hash at this index
        return chunk_hash == proof.get(str(chunk_index))


class PeerIdentity:
    def __init__(self, port=None):
        key_path = f"private_key_{port}.pem" if port else "private_key.pem"
        
        if os.path.exists(key_path):
            with open(key_path, "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
        else:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            with open(key_path, "wb") as key_file:
                key_file.write(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def get_peer_id(self):
        # Peer ID is the hash of the public key
        pub_bytes = self.get_public_key_bytes()
        return hashlib.sha256(pub_bytes).hexdigest()

    def sign_data(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(public_key_bytes, signature, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            public_key = serialization.load_pem_public_key(public_key_bytes)
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
