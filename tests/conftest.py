import os
import sys
import json
import time
import uuid
import socket
import struct
import base64
import pytest
from pathlib import Path

# Add project root and local src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCAL_SRC = PROJECT_ROOT / "src"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(LOCAL_SRC) not in sys.path:
    sys.path.insert(0, str(LOCAL_SRC))

try:
    import src
    if hasattr(src, '__path__') and str(LOCAL_SRC) not in src.__path__:
        src.__path__.insert(0, str(LOCAL_SRC))
except Exception:
    pass

from src.core.crypto import PeerIdentity, MerkleTree
from src.core.file_manager import FileManager
from src.core.reputation import ReputationEngine
from src.core.p2p_node import P2PNode


def find_free_port():
    """Find an available TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def pack_tcp_frame(data: dict) -> bytes:
    """Encode a dictionary into a 4-byte big-endian length-prefixed TCP frame."""
    payload = json.dumps(data).encode('utf-8')
    return struct.pack('>I', len(payload)) + payload


def unpack_tcp_frame(buffer: bytes):
    """Decode a single 4-byte length-prefixed frame from a bytes buffer."""
    if len(buffer) < 4:
        return None, buffer
    msg_len = struct.unpack('>I', buffer[:4])[0]
    if len(buffer) < 4 + msg_len:
        return None, buffer
    payload = buffer[4:4 + msg_len]
    return json.loads(payload.decode('utf-8')), buffer[4 + msg_len:]


def create_signed_envelope(identity: PeerIdentity, payload: dict, timestamp=None, nonce=None) -> dict:
    """Wrap a payload dictionary in a signed message envelope conforming to PROJECT.md."""
    if timestamp is None:
        timestamp = time.time()
    if nonce is None:
        nonce = str(uuid.uuid4())
    
    canonical_payload = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = identity.sign_data(canonical_payload)
    sig_b64 = base64.b64encode(signature).decode('utf-8')
    
    pub_bytes = identity.get_public_key_bytes() if hasattr(identity, 'get_public_key_bytes') else identity.get_public_key_pem()
    pub_str = pub_bytes.decode('utf-8') if isinstance(pub_bytes, bytes) else str(pub_bytes)
    
    peer_id = identity.peer_id if hasattr(identity, 'peer_id') else identity.get_peer_id()
    
    return {
        'sender_id': peer_id,
        'public_key': pub_str,
        'timestamp': timestamp,
        'nonce': nonce,
        'payload': payload,
        'signature': sig_b64
    }


def verify_signature_compat(public_key, signature, data) -> bool:
    """Cross-compatible signature verifier trying both (pub, sig, data) and (pub, data, sig)."""
    if isinstance(public_key, str):
        public_key = public_key.encode('utf-8')
    if isinstance(signature, str):
        signature = base64.b64decode(signature)
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    try:
        if PeerIdentity.verify_signature(public_key, signature, data):
            return True
    except Exception:
        pass
    try:
        if PeerIdentity.verify_signature(public_key, data, signature):
            return True
    except Exception:
        pass
    return False


@pytest.fixture
def isolated_dir(tmp_path, monkeypatch):
    """Chdir into a temporary directory so all relative paths and keys stay isolated."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def temp_storage_dir(tmp_path):
    storage = tmp_path / "test_storage"
    storage.mkdir(parents=True, exist_ok=True)
    return str(storage)


@pytest.fixture
def temp_db_path(tmp_path):
    db_file = tmp_path / "test_reputation.db"
    return str(db_file)


@pytest.fixture
def file_manager(temp_storage_dir):
    return FileManager(storage_dir=temp_storage_dir)


@pytest.fixture
def reputation_engine(temp_db_path):
    return ReputationEngine(db_path=temp_db_path)


@pytest.fixture
def identity_factory(isolated_dir):
    def _create(port_or_name=None):
        name = port_or_name or f"id_{uuid.uuid4().hex[:8]}"
        return PeerIdentity(name)
    return _create


@pytest.fixture
def peer_identity(identity_factory):
    return identity_factory("node_primary")


@pytest.fixture
def second_identity(identity_factory):
    return identity_factory("node_secondary")


@pytest.fixture
def zero_byte_file(temp_storage_dir):
    fpath = os.path.join(temp_storage_dir, "empty_file.dat")
    with open(fpath, "wb") as f:
        pass
    return fpath


@pytest.fixture
def small_file(temp_storage_dir):
    fpath = os.path.join(temp_storage_dir, "small_file.txt")
    data = b"Hello, Zero-Trust P2P File Sharing! This is a test file for chunking."
    with open(fpath, "wb") as f:
        f.write(data)
    return fpath, data


@pytest.fixture
def multichunk_file(temp_storage_dir):
    fpath = os.path.join(temp_storage_dir, "multi_chunk.bin")
    # 3 chunks of 64KB + 128 bytes = 196736 bytes
    chunk_size = 1024 * 64
    data = os.urandom(chunk_size * 3 + 128)
    with open(fpath, "wb") as f:
        f.write(data)
    return fpath, data


@pytest.fixture
def node_factory(isolated_dir):
    created_servers = []

    def _create(node_name=None, port=None):
        p = port or find_free_port()
        name = node_name or f"node_{p}"
        db = f"rep_{name}.db"
        storage = f"store_{name}"
        os.makedirs(storage, exist_ok=True)
        node = P2PNode(
            host="127.0.0.1",
            port=p,
            db_path=db,
            storage_dir=storage,
            node_name=name
        )
        return node

    yield _create


@pytest.fixture(autouse=True)
def guard_offline_stun(monkeypatch):
    """Ensure NO test queries live Google STUN servers over the internet."""
    try:
        monkeypatch.setattr(
            "src.discovery.stun_client.PUBLIC_STUN_SERVERS",
            [("127.0.0.1", 19302), ("127.0.0.1", 19303)],
        )
    except Exception:
        pass

