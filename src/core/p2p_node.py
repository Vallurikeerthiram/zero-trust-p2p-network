import asyncio
import json
import logging
import base64
import os
import time
import struct
import uuid
import hashlib
from typing import Optional, Tuple, Dict, Any, Union, List
from .crypto import PeerIdentity, MerkleTree
from .reputation import ReputationEngine
from .file_manager import FileManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("P2PNode")

# Framing Constants
HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB maximum payload limit to guard against DoS

def pack_tcp_frame(data: dict) -> bytes:
    """
    Encode a dictionary into a 4-byte big-endian length-prefixed TCP frame.
    Wire format: [4 bytes: uint32 length][N bytes: utf-8 json payload]
    Raises ValueError if encoded payload exceeds MAX_MESSAGE_SIZE.
    """
    payload = json.dumps(data).encode('utf-8')
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Payload size {len(payload)} exceeds MAX_MESSAGE_SIZE ({MAX_MESSAGE_SIZE})")
    return struct.pack('>I', len(payload)) + payload

def unpack_tcp_frame(buffer: bytes):
    """
    Decode a single 4-byte length-prefixed frame from a raw bytes buffer.
    Returns:
        (decoded_dict, remaining_buffer) if a complete valid frame is found.
        (None, buffer) if the buffer contains an incomplete frame.
    Raises:
        ValueError if the declared length is <= 0 or exceeds MAX_MESSAGE_SIZE.
    """
    if len(buffer) < HEADER_SIZE:
        return None, buffer
    msg_len = struct.unpack('>I', buffer[:HEADER_SIZE])[0]
    if msg_len <= 0 or msg_len > MAX_MESSAGE_SIZE:
        raise ValueError(f"Invalid frame length: {msg_len} (must be 1..{MAX_MESSAGE_SIZE})")
    if len(buffer) < HEADER_SIZE + msg_len:
        return None, buffer
    payload = buffer[HEADER_SIZE:HEADER_SIZE + msg_len]
    return json.loads(payload.decode('utf-8')), buffer[HEADER_SIZE + msg_len:]

async def send_frame(writer: asyncio.StreamWriter, message: dict) -> None:
    """
    Serialize message to JSON, prepend 4-byte big-endian length prefix,
    write to StreamWriter, and drain buffer.
    """
    frame_bytes = pack_tcp_frame(message)
    writer.write(frame_bytes)
    await writer.drain()

DEFAULT_FRAME_TIMEOUT = 15.0

async def _read_frame_raw(reader: asyncio.StreamReader) -> Optional[dict]:
    try:
        header = await reader.readexactly(HEADER_SIZE)
    except asyncio.IncompleteReadError as e:
        if e.partial:
            logger.warning(f"Connection dropped after partial header ({len(e.partial)} bytes)")
        return None
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        return None

    msg_len = struct.unpack('>I', header)[0]
    if msg_len <= 0 or msg_len > MAX_MESSAGE_SIZE:
        logger.warning(f"Rejected frame declaring invalid length: {msg_len} bytes (max {MAX_MESSAGE_SIZE})")
        return None

    try:
        payload_bytes = await reader.readexactly(msg_len)
    except asyncio.IncompleteReadError as e:
        logger.warning(f"Connection dropped during frame payload read: received {len(e.partial)} of {msg_len} bytes")
        return None
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        return None

    try:
        return json.loads(payload_bytes.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        logger.error(f"Malformed JSON payload in frame: {e}")
        return None

async def read_frame(reader: asyncio.StreamReader, timeout: Optional[float] = DEFAULT_FRAME_TIMEOUT) -> Optional[dict]:
    """
    Read a 4-byte big-endian length-prefixed JSON frame from an asyncio StreamReader
    with optional timeout protection against Slowloris hangs.
    """
    try:
        if timeout is not None and timeout > 0:
            return await asyncio.wait_for(_read_frame_raw(reader), timeout=timeout)
        return await _read_frame_raw(reader)
    except asyncio.TimeoutError:
        logger.warning(f"Frame read timed out after {timeout}s")
        return None

def create_signed_envelope(identity_or_node: Any, payload: dict, timestamp: Optional[float] = None, nonce: Optional[str] = None) -> dict:
    """
    Wrap a payload dictionary in a cryptographically signed message envelope (F10).
    Canonical JSON serialization (sort_keys=True) is signed with RSA-PSS SHA-256.
    """
    if hasattr(identity_or_node, 'identity'):
        identity = identity_or_node.identity
    else:
        identity = identity_or_node

    if timestamp is None:
        timestamp = time.time()
    if nonce is None:
        nonce = str(uuid.uuid4())

    canonical_payload = json.dumps(payload, sort_keys=True).encode('utf-8')
    raw_signature = identity.sign_data(canonical_payload)
    sig_b64 = base64.b64encode(raw_signature).decode('utf-8')

    pub_bytes = identity.get_public_key_pem() if hasattr(identity, 'get_public_key_pem') else identity.get_public_key_bytes()
    pub_str = pub_bytes.decode('utf-8') if isinstance(pub_bytes, bytes) else str(pub_bytes)
    peer_id = identity.peer_id if hasattr(identity, 'peer_id') else identity.get_peer_id()

    return {
        'sender_id': peer_id,
        'public_key': pub_str,
        'timestamp': float(timestamp),
        'nonce': str(nonce),
        'payload': payload,
        'signature': sig_b64
    }

def is_envelope(data: Any) -> bool:
    """Check if data structure matches signed envelope specification."""
    if not isinstance(data, dict):
        return False
    required_keys = ("sender_id", "public_key", "timestamp", "nonce", "payload", "signature")
    return all(k in data for k in required_keys)

class P2PNode:
    def __init__(self, host, port, db_path="reputation.db", storage_dir="storage", node_name=""):
        self.host = host
        self.port = port
        self.node_name = node_name
        self.identity = PeerIdentity(node_name if node_name else str(port))
        self.peer_id = self.identity.get_peer_id()
        self.reputation = ReputationEngine(db_path)
        self.file_manager = FileManager(storage_dir)
        
        # Local state
        self.peers = {} # (host, port) -> (peer_id, peer_name)
        self.peer_files = {} # peer_id -> {filename: {merkle_root, total_chunks}}
        self.available_files = {} # filename -> {'filename': filename, 'file_size': size, 'merkle_root': root, 'file_id': root, 'total_chunks': n} (LOCAL ONLY)
        self.files_by_root = {} # merkle_root -> filename
        self.file_trees = {} # filename -> MerkleTree instance
        self.downloading_files = {} # filename -> {'expected_root': root, 'chunks': {}}
        self.file_mtimes = {} # filename -> mtime
        self.corrupted_chunks = {} # filename -> set of chunk_indices
        self.security_alerts = [] # [{'timestamp', 'reporter', 'bad_peer', 'bad_peer_id', 'filename', 'chunk_index'}]
        self.loop = None
        import threading
        self.state_lock = threading.RLock()

        # Replay protection state
        self.seen_nonces = {} # nonce -> timestamp recorded
        self.nonce_cache = self.seen_nonces # alias for compatibility
        self.max_time_drift = 60.0
        self.max_nonce_cache_age = 120.0
        self.max_nonce_cache_size = 50000

    def create_signed_envelope(self, payload: dict, timestamp: Optional[float] = None, nonce: Optional[str] = None) -> dict:
        """Wrap payload in a cryptographically signed message envelope."""
        return create_signed_envelope(self.identity, payload, timestamp=timestamp, nonce=nonce)

    def _prune_nonce_cache(self, now: float) -> None:
        """Prune nonces older than max_nonce_cache_age (120s) and enforce size cap."""
        cutoff = now - self.max_nonce_cache_age
        expired_keys = [k for k, ts in self.seen_nonces.items() if ts < cutoff]
        for k in expired_keys:
            del self.seen_nonces[k]

        if len(self.seen_nonces) > self.max_nonce_cache_size:
            excess = len(self.seen_nonces) - self.max_nonce_cache_size
            keys_to_remove = list(self.seen_nonces.keys())[:excess]
            for k in keys_to_remove:
                del self.seen_nonces[k]

    @staticmethod
    def is_envelope(data: Any) -> bool:
        """Check if data structure matches signed envelope specification."""
        return is_envelope(data)

    def verify_envelope(self, envelope: dict) -> Tuple[bool, str, Optional[dict]]:
        """
        Cryptographically verify an inbound envelope and perform replay checks (F10, F11, F12).
        Returns (is_valid: bool, reason: str, unwrapped_payload: Optional[dict]).
        """
        if not self.is_envelope(envelope):
            return False, "INVALID_ENVELOPE_SCHEMA", None

        # Step 1: Type & Field Validation
        sender_id = envelope.get('sender_id')
        public_key = envelope.get('public_key')
        timestamp = envelope.get('timestamp')
        nonce = envelope.get('nonce')
        payload = envelope.get('payload')
        signature = envelope.get('signature')

        if not isinstance(sender_id, str) or not isinstance(public_key, str):
            return False, "INVALID_ENVELOPE_SCHEMA", None
        if not isinstance(timestamp, (int, float)) or not isinstance(nonce, str):
            return False, "INVALID_ENVELOPE_SCHEMA", None
        if not isinstance(payload, dict) or not isinstance(signature, (str, bytes)):
            return False, "INVALID_ENVELOPE_SCHEMA", None

        # Step 2: Anti-Spoofing Identity Binding
        expected_id = hashlib.sha256(public_key.encode('utf-8')).hexdigest()
        if sender_id.lower() != expected_id.lower():
            return False, "SPOOFED_SENDER_ID", None

        # Step 3: Timestamp Drift Validation (F11)
        now = time.time()
        if abs(now - float(timestamp)) > self.max_time_drift:
            return False, "TIMESTAMP_EXPIRED", None

        # Step 4: Nonce Cache Replay Deduplication (F11)
        self._prune_nonce_cache(now)
        if nonce in self.seen_nonces:
            return False, "NONCE_REPLAYED", None

        # Step 5: Blacklist Check (F12)
        if self.reputation.is_blacklisted(sender_id):
            return False, "BLACKLISTED_PEER", None

        # Step 6: RSA-PSS Signature Verification (F10)
        canonical_payload = json.dumps(payload, sort_keys=True).encode('utf-8')
        try:
            is_valid_sig = PeerIdentity.verify_signature(public_key, signature, canonical_payload)
        except Exception:
            is_valid_sig = False

        if not is_valid_sig:
            return False, "INVALID_SIGNATURE", None

        # Step 7: Record Nonce & Accept
        self.seen_nonces[nonce] = now
        return True, "ACCEPTED", payload

    def set_corrupted_chunks(self, filename, chunk_indices):
        """Configure which chunks this node will intentionally tamper with when served."""
        self.corrupted_chunks[filename] = set(int(i) for i in chunk_indices)
        logger.warning(f"Configured corrupted chunks for {filename}: {self.corrupted_chunks[filename]}")

    def get_corrupted_chunks(self, filename):
        return self.corrupted_chunks.get(filename, set())

    def delete_local_file(self, filename):
        """Deletes a file from the local storage directory and removes from sharing."""
        file_path = os.path.join(self.file_manager.storage_dir, filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                logger.info(f"Deleted local file {filename}")
            except Exception as e:
                logger.error(f"Error removing file {filename}: {e}")
        if filename in self.available_files:
            root = self.available_files[filename].get('merkle_root')
            if root and getattr(self, 'files_by_root', {}).get(root) == filename:
                del self.files_by_root[root]
            del self.available_files[filename]
        if hasattr(self, 'file_trees') and filename in self.file_trees:
            del self.file_trees[filename]
        if filename in self.file_mtimes:
            del self.file_mtimes[filename]
        if filename in self.corrupted_chunks:
            del self.corrupted_chunks[filename]
        self.scan_local_directory()
        return True

    async def broadcast_corruption_alert(
        self,
        filename: str,
        bad_peer_id: str,
        bad_peer_name: str,
        chunk_index: int,
        chunk_data: Optional[Union[bytes, str]] = None,
        expected_root: Optional[str] = None,
        proof: Optional[list] = None,
        signed_response: Optional[dict] = None
    ):
        """Broadcast a security alert across the swarm that bad_peer_id served a corrupted chunk for filename (F17)."""
        b64_data = None
        if chunk_data is not None:
            if isinstance(chunk_data, (bytes, bytearray)):
                b64_data = base64.b64encode(chunk_data).decode('utf-8')
            else:
                b64_data = str(chunk_data)

        exp_root = expected_root
        if not exp_root:
            if filename in self.downloading_files:
                exp_root = self.downloading_files[filename].get('expected_root')
            elif filename in self.available_files:
                exp_root = self.available_files[filename].get('merkle_root')

        alert_payload = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': self.peer_id,
            'sender_name': self.node_name,
            'corrupted_peer_id': bad_peer_id,
            'corrupted_peer_name': bad_peer_name,
            'filename': filename,
            'chunk_index': chunk_index,
            'chunk_data': b64_data,
            'expected_root': exp_root,
            'proof': proof,
            'signed_response': signed_response,
            'reason': f"Corrupted chunk #{chunk_index} detected during transfer"
        }
        
        # Record locally
        self.security_alerts.append({
            'timestamp': time.strftime("%H:%M:%S"),
            'reporter': self.node_name if self.node_name else "Me",
            'bad_peer': bad_peer_name,
            'bad_peer_id': bad_peer_id,
            'filename': filename,
            'chunk_index': chunk_index
        })
        
        # Broadcast to all connected peers and registry nodes except the bad peer and blacklisted peers
        targets = set()
        for (host, port), peer_val in list(self.peers.items()):
            p_id = peer_val[0] if isinstance(peer_val, tuple) else str(peer_val)
            if p_id != bad_peer_id and not self.reputation.is_blacklisted(p_id):
                targets.add((host, port))
                
        registry_path = "swarm_registry.json"
        if os.path.exists(registry_path):
            try:
                with open(registry_path, 'r') as f:
                    reg_ports = json.load(f)
                for rp in reg_ports:
                    if rp != self.port:
                        peer_tuple = self.peers.get((self.host, rp))
                        target_id = peer_tuple[0] if isinstance(peer_tuple, tuple) else None
                        if target_id != bad_peer_id and (target_id is None or not self.reputation.is_blacklisted(target_id)):
                            targets.add((self.host, rp))
            except Exception:
                pass
                
        for host, port in targets:
            try:
                await self._send_request(host, port, alert_payload)
            except Exception as e:
                logger.error(f"Failed to send CORRUPTION_ALERT to {host}:{port}: {e}")

    def verify_corruption_proof(self, alert_payload: dict, reporter_id: str) -> Tuple[bool, str]:
        """
        Cryptographically verify the proof of corruption in a CORRUPTION_ALERT (F17).
        Enforces zero-trust: requires verifiable proof before altering trust/reputation.
        Returns (is_valid: bool, reason: str).
        """
        if not isinstance(alert_payload, dict):
            return False, "INVALID_PAYLOAD_TYPE"

        bad_peer_id = alert_payload.get('corrupted_peer_id') or alert_payload.get('bad_peer_id')
        if not bad_peer_id or not isinstance(bad_peer_id, str) or not bad_peer_id.strip():
            return False, "MISSING_OR_INVALID_BAD_PEER_ID"

        if reporter_id and bad_peer_id.lower() == reporter_id.lower():
            return False, "CANNOT_REPORT_SELF"

        filename = alert_payload.get('filename')
        if not filename or not isinstance(filename, str):
            return False, "MISSING_FILENAME"

        expected_root = alert_payload.get('expected_root') or alert_payload.get('merkle_root') or alert_payload.get('file_id')
        if not expected_root or not isinstance(expected_root, str) or len(expected_root) != 64:
            return False, "MISSING_OR_INVALID_EXPECTED_ROOT"

        chunk_index = alert_payload.get('chunk_index')
        if chunk_index is None or not isinstance(chunk_index, int) or chunk_index < 0:
            return False, "MISSING_OR_INVALID_CHUNK_INDEX"

        raw_chunk_b64 = alert_payload.get('chunk_data')
        if not raw_chunk_b64:
            return False, "MISSING_CHUNK_DATA"

        if isinstance(raw_chunk_b64, str):
            try:
                chunk_bytes = base64.b64decode(raw_chunk_b64)
            except Exception:
                chunk_bytes = raw_chunk_b64.encode('utf-8')
        elif isinstance(raw_chunk_b64, (bytes, bytearray)):
            chunk_bytes = bytes(raw_chunk_b64)
        else:
            return False, "INVALID_CHUNK_DATA_TYPE"

        signed_resp = alert_payload.get('signed_response') or alert_payload.get('signed_receipt')
        has_verified_provider_sig = False
        prov_payload = None

        if signed_resp:
            if not isinstance(signed_resp, dict):
                return False, "INVALID_SIGNED_RESPONSE_SCHEMA"
            prov_id = signed_resp.get('sender_id')
            prov_pub = signed_resp.get('public_key')
            prov_sig = signed_resp.get('signature')
            prov_payload = signed_resp.get('payload')

            if not prov_id or not prov_pub or not prov_sig or not prov_payload:
                return False, "INCOMPLETE_SIGNED_RESPONSE"

            if prov_id.lower() != bad_peer_id.lower():
                return False, "SIGNED_RESPONSE_PROVIDER_MISMATCH"

            expected_prov_id = hashlib.sha256(prov_pub.encode('utf-8')).hexdigest()
            if prov_id.lower() != expected_prov_id.lower():
                return False, "SPOOFED_PROVIDER_PUBLIC_KEY"

            canonical = json.dumps(prov_payload, sort_keys=True).encode('utf-8')
            if not PeerIdentity.verify_signature(prov_pub, prov_sig, canonical):
                return False, "INVALID_PROVIDER_SIGNATURE"

            prov_chunk_b64 = prov_payload.get('data')
            if prov_chunk_b64 is not None:
                try:
                    prov_chunk_bytes = base64.b64decode(prov_chunk_b64)
                except Exception:
                    prov_chunk_bytes = prov_chunk_b64.encode('utf-8')
                if prov_chunk_bytes != chunk_bytes:
                    return False, "CHUNK_DATA_MISMATCH_WITH_SIGNED_RESPONSE"
            else:
                return False, "SIGNED_RESPONSE_MISSING_CHUNK_DATA"

            # Anti-Framing Binding 1: Chunk Index
            prov_idx = prov_payload.get('chunk_index')
            if prov_idx is not None and prov_idx != chunk_index:
                return False, "CHUNK_INDEX_MISMATCH_WITH_SIGNED_RESPONSE"

            # Anti-Framing Binding 2: Filename
            prov_fname = prov_payload.get('filename')
            if prov_fname and prov_fname != filename:
                return False, "FILENAME_MISMATCH_WITH_SIGNED_RESPONSE"

            # Anti-Framing Binding 3: Merkle Root
            prov_root = prov_payload.get('merkle_root') or prov_payload.get('file_id')
            if prov_root and str(prov_root).lower() != expected_root.lower():
                return False, "ROOT_MISMATCH_WITH_SIGNED_RESPONSE"

            # Anti-Framing Binding 4: Proof match if both present
            prov_proof = prov_payload.get('proof')
            if prov_proof is not None and alert_payload.get('proof') is not None:
                if alert_payload.get('proof') != prov_proof:
                    return False, "PROOF_MISMATCH_WITH_SIGNED_RESPONSE"

            has_verified_provider_sig = True

        # Anti-framing Check 1: Check against local file if available
        if filename in self.available_files:
            local_root = self.available_files[filename].get('merkle_root')
            if local_root and local_root.lower() == expected_root.lower():
                local_path = os.path.join(self.file_manager.storage_dir, filename)
                try:
                    real_chunk = self.file_manager.get_chunk(local_path, chunk_index)
                    if real_chunk is not None:
                        if chunk_bytes == real_chunk:
                            return False, "CHUNK_IS_NOT_CORRUPT_FRAMING_ATTACK"
                        elif has_verified_provider_sig:
                            return True, "PROVEN_CORRUPT_LOCAL_VERIFICATION"
                except Exception:
                    pass

        # Anti-framing Check 2: Check Merkle audit proof
        if has_verified_provider_sig:
            prov_proof = prov_payload.get('proof') if isinstance(prov_payload, dict) else None
            if prov_proof is None:
                # Provider never signed a Merkle proof; reporter cannot inject unauthenticated proof
                return False, "MISSING_CRYPTOGRAPHIC_PROOF"
            proof = prov_proof
        else:
            proof = alert_payload.get('proof')

        if proof is not None:
            if not isinstance(proof, list):
                return False, "INVALID_PROOF_FORMAT"
            is_valid = MerkleTree.verify_chunk_proof(chunk_bytes, chunk_index, proof, expected_root)
            if is_valid:
                return False, "CHUNK_PASSES_MERKLE_VERIFICATION_FRAMING_ATTACK"
            elif has_verified_provider_sig:
                return True, "PROVEN_CORRUPT_MERKLE_PROOF_FAILURE"

        return False, "MISSING_CRYPTOGRAPHIC_PROOF"

    def scan_local_directory(self) -> list:
        """
        Scans the assigned storage directory and updates local file index (F14).
        Returns list of newly discovered filenames for active P2P gossip (F19).
        """
        if not os.path.exists(self.file_manager.storage_dir):
            return []
            
        current_files = os.listdir(self.file_manager.storage_dir)
        
        # Remove deleted files from internal state
        files_to_remove = [f for f in list(self.available_files.keys()) if f not in current_files]
        for fname in files_to_remove:
            root = self.available_files.get(fname, {}).get('merkle_root')
            if root and getattr(self, 'files_by_root', {}).get(root) == fname:
                del self.files_by_root[root]
            if hasattr(self, 'file_trees') and fname in self.file_trees:
                del self.file_trees[fname]
            del self.available_files[fname]
            if fname in self.file_mtimes:
                del self.file_mtimes[fname]
            if fname in self.corrupted_chunks:
                del self.corrupted_chunks[fname]
            
        new_files = []
        if not hasattr(self, 'files_by_root'):
            self.files_by_root = {}
        if not hasattr(self, 'file_trees'):
            self.file_trees = {}

        for filename in current_files:
            try:
                self.file_manager.validate_filename(filename)
            except ValueError:
                continue

            file_path = os.path.join(self.file_manager.storage_dir, filename)
            if os.path.isfile(file_path):
                mtime = os.path.getmtime(file_path)
                file_size = os.path.getsize(file_path)

                # Re-index if new or modified
                if filename not in self.file_mtimes or self.file_mtimes[filename] != mtime:
                    chunks, tree = self.file_manager.split_file(file_path)
                    self.available_files[filename] = {
                        'filename': filename,
                        'file_size': file_size,
                        'merkle_root': tree.root,
                        'file_id': tree.root,
                        'total_chunks': len(chunks)
                    }
                    self.files_by_root[tree.root] = filename
                    self.file_trees[filename] = tree
                    self.file_mtimes[filename] = mtime
                    new_files.append(filename)
                    
        if new_files or files_to_remove:
            logger.info(f"Local directory updated. Now sharing {len(self.available_files)} files.")
        return new_files
        
    async def auto_sync_loop(self):
        """Continuously syncs with all known peers in the registry to get latest files."""
        while True:
            try:
                new_files = self.scan_local_directory()
                
                # Active gossip: automatically broadcast newly discovered files to connected peers (F19)
                for fname in new_files:
                    fpath = os.path.join(self.file_manager.storage_dir, fname)
                    if os.path.exists(fpath):
                        try:
                            await self.broadcast_file(fpath)
                        except Exception as e:
                            logger.error(f"Error gossiping new file {fname}: {e}")

                # Periodically prune any blacklisted peers from active registry
                for (h, p), p_info in list(self.peers.items()):
                    p_id = p_info[0] if isinstance(p_info, tuple) else p_info
                    if self.reputation.is_blacklisted(p_id):
                        self.peers.pop((h, p), None)
                        self.peer_files.pop(p_id, None)

                registry_path = "swarm_registry.json"
                ports_to_ping = set()
                if os.path.exists(registry_path):
                    try:
                        with open(registry_path, 'r') as f:
                            peers = json.load(f)
                        for p in peers:
                            if p != self.port:
                                ports_to_ping.add(p)
                    except Exception:
                        pass
                for (h, p) in list(self.peers.keys()):
                    if p != self.port:
                        ports_to_ping.add(p)
                        
                tasks_to_ping = []
                for p in ports_to_ping:
                    peer_entry = self.peers.get((self.host, p))
                    if peer_entry:
                        p_id = peer_entry[0] if isinstance(peer_entry, tuple) else peer_entry
                        if self.reputation.is_blacklisted(p_id):
                            continue
                    tasks_to_ping.append(self.ping_peer(self.host, p))
                if tasks_to_ping:
                    await asyncio.gather(*tasks_to_ping, return_exceptions=True)
            except Exception as loop_err:
                logger.error(f"Unexpected error in auto_sync_loop iteration: {loop_err}")
                
            await asyncio.sleep(2) # Ping everyone every 2 seconds
        
    async def start_server(self):
        self.loop = asyncio.get_running_loop()
        self.scan_local_directory()
        asyncio.create_task(self.auto_sync_loop())
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info(f"Node started on {self.host}:{self.port} - ID: {self.peer_id[:8]}...")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        try:
            while True:
                message = await read_frame(reader)
                if not message:
                    break

                if self.is_envelope(message):
                    valid, reason, payload = self.verify_envelope(message)
                    if not valid:
                        logger.warning(f"Connection from {addr} rejected: {reason}")
                        break
                    sender_id = message['sender_id']
                    msg_payload = payload
                else:
                    logger.warning(f"Connection from {addr} rejected: unenveloped/unsigned message prohibited in Zero-Trust mode.")
                    break

                msg_type = msg_payload.get('type')

                async def send_response(resp_dict):
                    resp_envelope = self.create_signed_envelope(resp_dict)
                    await send_frame(writer, resp_envelope)

                if msg_type == 'PING':
                    if 'host' in msg_payload and 'port' in msg_payload:
                        sender_name = msg_payload.get('sender_name', 'Unknown')
                        self.peers[(msg_payload['host'], msg_payload['port'])] = (sender_id, sender_name)
                        self.reputation.add_peer(sender_id)
                        if 'files' in msg_payload:
                            self.peer_files[sender_id] = msg_payload['files']
                        
                    response = {
                        'type': 'PONG',
                        'sender_id': self.peer_id,
                        'sender_name': self.node_name,
                        'files': self.available_files
                    }
                    await send_response(response)

                elif msg_type == 'GET_CHUNK':
                    await self.handle_get_chunk(msg_payload, writer, sender_id=sender_id, send_response=send_response)

                elif msg_type == 'SHARE_FILE_INFO':
                    raw_filename = msg_payload.get('filename')
                    try:
                        clean_filename = self.file_manager.validate_filename(raw_filename)
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Rejected SHARE_FILE_INFO with invalid filename {raw_filename!r}: {e}")
                        break
                    if sender_id not in self.peer_files:
                        self.peer_files[sender_id] = {}
                    self.peer_files[sender_id][clean_filename] = {
                        'filename': clean_filename,
                        'file_size': msg_payload.get('file_size', 0),
                        'merkle_root': msg_payload.get('merkle_root'),
                        'file_id': msg_payload.get('file_id') or msg_payload.get('merkle_root'),
                        'total_chunks': msg_payload.get('total_chunks', 0)
                    }
                    response = {'status': 'OK', 'sender_id': self.peer_id}
                    await send_response(response)

                elif msg_type == 'CORRUPTION_ALERT':
                    bad_peer_id = msg_payload.get('corrupted_peer_id') or msg_payload.get('bad_peer_id')
                    bad_peer_name = msg_payload.get('corrupted_peer_name', 'Unknown')
                    fname = msg_payload.get('filename')
                    idx = msg_payload.get('chunk_index', 0)
                    reporter = msg_payload.get('sender_name', sender_id)

                    is_valid_proof, reason = self.verify_corruption_proof(msg_payload, sender_id)
                    if not is_valid_proof:
                        logger.warning(
                            f"Rejected unverified CORRUPTION_ALERT from {reporter} accusing {bad_peer_name} ({bad_peer_id}): {reason}"
                        )
                        response = {'status': 'ALERT_REJECTED', 'reason': reason, 'sender_id': self.peer_id}
                        await send_response(response)
                    else:
                        logger.warning(
                            f"🚨 Verified Swarm Alert from {reporter}: Peer {bad_peer_name} served corrupted chunk {idx} for {fname}!"
                        )
                        self.reputation.quarantine_provider_for_file(
                            bad_peer_id, fname, reason=f"Cryptographically verified corruption reported by {reporter}", reporter_id=sender_id
                        )

                        self.security_alerts.append({
                            'timestamp': time.strftime("%H:%M:%S"),
                            'reporter': reporter,
                            'bad_peer': bad_peer_name,
                            'bad_peer_id': bad_peer_id,
                            'filename': fname,
                            'chunk_index': idx
                        })

                        response = {'status': 'ALERT_RECEIVED', 'sender_id': self.peer_id}
                        await send_response(response)

        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def handle_get_chunk(self, message, writer, sender_id=None, send_response=None):
        req_sender = sender_id or message.get('sender_id')
        if not req_sender or self.reputation.is_blacklisted(req_sender):
            logger.warning(f"GET_CHUNK rejected for invalid or blacklisted peer: {req_sender}")
            return

        filename = message.get('filename')
        file_id = message.get('file_id') or message.get('merkle_root')
        chunk_index = message.get('chunk_index')

        if chunk_index is None or type(chunk_index) is not int or chunk_index < 0:
            logger.warning(f"Invalid chunk_index in GET_CHUNK: {chunk_index!r}")
            return

        # Path sanitization: strictly validate filename syntax if present
        if filename:
            try:
                self.file_manager.validate_filename(filename)
            except ValueError as e:
                logger.warning(f"Rejected GET_CHUNK with invalid filename '{filename}': {e}")
                err_resp = {'error': f"Invalid filename: {e}", 'sender_id': self.peer_id}
                if send_response:
                    await send_response(err_resp)
                else:
                    await send_frame(writer, self.create_signed_envelope(err_resp))
                return

        # Resolve local file: check file_id / merkle_root first
        local_filename = None
        if file_id and hasattr(self, 'files_by_root') and file_id in self.files_by_root:
            local_filename = self.files_by_root[file_id]
        elif filename and filename in self.available_files:
            # If both file_id and filename provided, verify no root mismatch
            if file_id:
                expected_local_root = self.available_files[filename].get('merkle_root')
                if expected_local_root and expected_local_root != file_id:
                    logger.warning(f"Root mismatch in GET_CHUNK for {filename}: requested {file_id[:8]} != local {expected_local_root[:8]}")
                    err_resp = {'error': 'Merkle root mismatch', 'sender_id': self.peer_id}
                    if send_response:
                        await send_response(err_resp)
                    else:
                        await send_frame(writer, self.create_signed_envelope(err_resp))
                    return
            local_filename = filename
        elif filename:
            local_filename = filename

        if not local_filename:
            err_resp = {'error': 'File not found', 'sender_id': self.peer_id}
            if send_response:
                await send_response(err_resp)
            else:
                await send_frame(writer, self.create_signed_envelope(err_resp))
            return

        file_path = os.path.join(self.file_manager.storage_dir, local_filename)
        chunk_data = self.file_manager.get_chunk(file_path, chunk_index)

        if chunk_data is not None:
            # Handle adversarial corruption simulation
            corrupted_indices = self.corrupted_chunks.get(local_filename, set())
            if chunk_index in corrupted_indices:
                logger.warning(f"Adversarial attack active: Serving deliberately CORRUPTED chunk {chunk_index} for {local_filename}!")
                chunk_data = b'CORRUPT_POISONED_CHUNK_' + chunk_data

            b64_chunk = base64.b64encode(chunk_data).decode('utf-8')

            # Fetch Merkle proof from tree cache
            proof = []
            tree = getattr(self, 'file_trees', {}).get(local_filename)
            if tree is None and os.path.exists(file_path):
                try:
                    _, tree = self.file_manager.split_file(file_path)
                    if not hasattr(self, 'file_trees'):
                        self.file_trees = {}
                    self.file_trees[local_filename] = tree
                except Exception:
                    tree = None

            if tree is not None:
                try:
                    proof = tree.get_proof(chunk_index)
                except Exception as e:
                    logger.warning(f"Failed to generate proof for chunk {chunk_index}: {e}")
                    proof = []

            actual_root = tree.root if tree else self.available_files.get(local_filename, {}).get('merkle_root', '')

            response = {
                'type': 'CHUNK_DATA',
                'sender_id': self.peer_id,
                'filename': local_filename,
                'file_id': actual_root,
                'merkle_root': actual_root,
                'chunk_index': chunk_index,
                'data': b64_chunk,
                'proof': proof
            }
        else:
            response = {'error': 'Chunk not found', 'sender_id': self.peer_id}

        if send_response is not None:
            await send_response(response)
        else:
            resp_env = self.create_signed_envelope(response)
            await send_frame(writer, resp_env)

    async def _send_request(self, host, port, payload, timeout: float = 10.0):
        peer_entry = self.peers.get((host, port))
        if peer_entry:
            dest_peer_id = peer_entry[0] if isinstance(peer_entry, tuple) else peer_entry
            if self.reputation.is_blacklisted(dest_peer_id):
                logger.warning(f"Blocking outbound request to blacklisted peer {dest_peer_id[:8]} at {host}:{port}")
                return None

        writer = None
        try:
            connect_coro = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
            
            if self.is_envelope(payload):
                envelope = payload
            else:
                envelope = self.create_signed_envelope(payload)

            await send_frame(writer, envelope)
            
            response = await read_frame(reader, timeout=timeout)
            if response is None:
                return None

            if self.is_envelope(response):
                valid, reason, unwrapped = self.verify_envelope(response)
                if not valid:
                    logger.warning(f"Response envelope verification failed from {host}:{port}: {reason}")
                    return None
                if isinstance(unwrapped, dict):
                    # Attach signed envelope receipt for non-repudiation proof (F17)
                    unwrapped['_envelope'] = {
                        'sender_id': response.get('sender_id'),
                        'public_key': response.get('public_key'),
                        'timestamp': response.get('timestamp'),
                        'nonce': response.get('nonce'),
                        'payload': response.get('payload'),
                        'signature': response.get('signature')
                    }
                return unwrapped

            return response
        except asyncio.TimeoutError:
            logger.warning(f"Connection/request to {host}:{port} timed out after {timeout}s")
            return None
        except Exception as e:
            logger.error(f"Connection error to {host}:{port}: {e}")
            return None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def ping_peer(self, host, port):
        # 1. Pre-check: skip if peer already known to be blacklisted
        if (host, port) in self.peers:
            known_peer_id = self.peers[(host, port)][0]
            if self.reputation.is_blacklisted(known_peer_id):
                logger.info(f"Skipping PING to blacklisted peer {known_peer_id[:8]} at {host}:{port}")
                self.peers.pop((host, port), None)
                self.peer_files.pop(known_peer_id, None)
                return False

        payload = {
            'type': 'PING', 
            'sender_id': self.peer_id,
            'sender_name': self.node_name,
            'host': self.host,
            'port': self.port,
            'files': self.available_files
        }
        response = await self._send_request(host, port, payload)
        if response and response.get('type') == 'PONG':
            peer_id = response.get('sender_id')
            # 2. Post-check: Validate returned peer_id
            if not peer_id or not isinstance(peer_id, str) or not peer_id.strip():
                logger.warning(f"Received PONG lacking valid sender_id from {host}:{port}. Rejecting.")
                return False

            if self.reputation.is_blacklisted(peer_id):
                logger.warning(f"Received PONG from blacklisted peer {peer_id[:8]} at {host}:{port}. Pruning state.")
                self.peers.pop((host, port), None)
                self.peer_files.pop(peer_id, None)
                return False

            peer_name = response.get('sender_name', 'Unknown')
            self.peers[(host, port)] = (peer_id, peer_name)
            self.reputation.add_peer(peer_id)
            
            # Sync files
            if 'files' in response:
                self.peer_files[peer_id] = response['files']
            return True
        else:
            # PING failed, peer might be offline
            if (host, port) in self.peers:
                dead_peer_id, _ = self.peers.pop((host, port))
                if dead_peer_id in self.peer_files:
                    del self.peer_files[dead_peer_id]
            return False

    async def broadcast_file(self, file_path: str) -> str:
        """
        Share a local file with known peers via SHARE_FILE_INFO gossip (F19).
        Advertises verified 4-tuple (file_name, file_size, merkle_root, total_chunks) (F14).
        """
        filename = os.path.basename(file_path)
        self.file_manager.validate_filename(filename)
        
        chunks, tree = self.file_manager.split_file(file_path)
        file_size = os.path.getsize(file_path)
        
        if not hasattr(self, 'files_by_root'):
            self.files_by_root = {}
        if not hasattr(self, 'file_trees'):
            self.file_trees = {}

        self.available_files[filename] = {
            'filename': filename,
            'file_size': file_size,
            'merkle_root': tree.root,
            'file_id': tree.root,
            'total_chunks': len(chunks)
        }
        self.files_by_root[tree.root] = filename
        self.file_trees[filename] = tree
        self.file_mtimes[filename] = os.path.getmtime(file_path)
        
        payload = {
            'type': 'SHARE_FILE_INFO',
            'sender_id': self.peer_id,
            'filename': filename,
            'file_size': file_size,
            'merkle_root': tree.root,
            'file_id': tree.root,
            'total_chunks': len(chunks),
            'host': self.host,
            'port': self.port
        }
        
        for (host, port), peer_entry in list(self.peers.items()):
            p_id = peer_entry[0] if isinstance(peer_entry, tuple) else peer_entry
            if self.reputation.is_blacklisted(p_id):
                continue
            await self._send_request(host, port, payload)
            
        return tree.root

    def broadcast_file_sync(self, file_path: str, timeout: float = 5.0) -> Optional[str]:
        """
        Synchronous, thread-safe wrapper to broadcast file to swarm from any thread (F19).
        Uses asyncio.run_coroutine_threadsafe to dispatch onto the node's background event loop.
        If called from a thread that already has an event loop or loop is not running, executes in a dedicated thread.
        """
        loop = getattr(self, 'loop', None)
        is_current_thread_loop = False
        try:
            current_loop = asyncio.get_running_loop()
            if current_loop is loop:
                is_current_thread_loop = True
        except RuntimeError:
            current_loop = None

        if loop is not None and loop.is_running() and not is_current_thread_loop:
            future = asyncio.run_coroutine_threadsafe(self.broadcast_file(file_path), loop)
            try:
                return future.result(timeout=timeout)
            except Exception as e:
                logger.error(f"Error in broadcast_file_sync for {file_path}: {e}")
                return None
        else:
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                def _runner():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(self.broadcast_file(file_path))
                    finally:
                        new_loop.close()
                future = executor.submit(_runner)
                try:
                    return future.result(timeout=timeout)
                except Exception as e:
                    logger.error(f"Fallback broadcast failed: {e}")
                    return None

    def get_network_files(self) -> Dict[str, Dict[str, Any]]:
        """
        Aggregate files discovered across the swarm, strictly binding providers to merkle_root (F14).
        Prevents filename collision and root spoofing by grouping providers strictly
        by identical (filename, merkle_root).
        Returns a dictionary keyed by compound key f"{filename}@{merkle_root[:8]}":
            {
                'filename': str,
                'file_size': int,
                'merkle_root': str,
                'file_id': str,
                'total_chunks': int,
                'providers': List[Tuple[str, int, str, str]] # (host, port, peer_id, peer_name)
            }
        """
        network_files = {}
        for (host, port), peer_val in list(self.peers.items()):
            p_id = peer_val[0] if isinstance(peer_val, tuple) else str(peer_val)
            p_name = peer_val[1] if isinstance(peer_val, tuple) and len(peer_val) > 1 else "Unknown"

            if self.reputation.is_blacklisted(p_id):
                continue

            files = self.peer_files.get(p_id, {})
            if not isinstance(files, dict):
                continue

            for fname, finfo in files.items():
                if not isinstance(finfo, dict):
                    continue
                mroot = finfo.get('merkle_root') or finfo.get('file_id')
                if not mroot:
                    continue
                tchunks = finfo.get('total_chunks', 0)
                fsize = finfo.get('file_size', 0)

                # Compound key partitions swarms by distinct Merkle roots
                swarm_key = f"{fname}@{mroot[:8]}"
                if swarm_key not in network_files:
                    network_files[swarm_key] = {
                        'filename': fname,
                        'merkle_root': mroot,
                        'file_id': mroot,
                        'total_chunks': tchunks,
                        'file_size': fsize,
                        'providers': []
                    }
                provider_tuple = (host, port, p_id, p_name)
                if provider_tuple not in network_files[swarm_key]['providers']:
                    network_files[swarm_key]['providers'].append(provider_tuple)
        return network_files

    async def download_file_from_swarm(
        self,
        filename: str,
        providers: list,
        expected_root: str,
        total_chunks: int,
        progress_callback=None,
        file_id: Optional[str] = None
    ) -> bool:
        """
        Downloads a file directly from a swarm of providers with zero-trust Merkle verification (F14, F15, F16, F17, F18).
        providers: list of (host, port, peer_id, peer_name)
        """
        # Strict path sanitization against directory traversal
        filename = self.file_manager.validate_filename(filename)
        logger.info(f"Requesting {filename} from swarm ({len(providers)} providers)")

        effective_file_id = file_id or expected_root
        self.downloading_files[filename] = {
            'expected_root': expected_root,
            'file_id': effective_file_id,
            'chunks': {},
            'started_at': time.time(),
            'total_chunks': total_chunks
        }
        if effective_file_id and effective_file_id != filename:
            self.downloading_files[effective_file_id] = self.downloading_files[filename]

        download_success = False
        try:
            for chunk_idx in range(total_chunks):
                chunk_received = False
                # Order providers starting from round-robin index
                ordered_providers = providers[chunk_idx % len(providers):] + providers[:chunk_idx % len(providers)]

                for provider_host, provider_port, provider_id, provider_name in ordered_providers:
                    if not provider_id or self.reputation.is_blacklisted(provider_id) or self.reputation.is_provider_quarantined(provider_id, filename):
                        continue

                    payload = {
                        'type': 'GET_CHUNK',
                        'sender_id': self.peer_id,
                        'filename': filename,
                        'file_id': expected_root,
                        'merkle_root': expected_root,
                        'chunk_index': chunk_idx
                    }

                    response = await self._send_request(provider_host, provider_port, payload)
                    if not response or 'data' not in response:
                        logger.warning(f"Could not get chunk {chunk_idx} from {provider_name} ({provider_host}:{provider_port}), trying next provider...")
                        continue

                    resp_idx = response.get('chunk_index')
                    if resp_idx is not None and resp_idx != chunk_idx:
                        logger.warning(f"Provider {provider_name} returned chunk {resp_idx} instead of requested {chunk_idx}")
                        continue

                    try:
                        chunk_data = base64.b64decode(response['data'])
                    except Exception as e:
                        logger.warning(f"Failed to decode base64 chunk {chunk_idx} from {provider_name}: {e}")
                        self.reputation.quarantine_provider_for_file(
                            provider_id, filename, reason=f"Malformed chunk payload #{chunk_idx}", reporter_id=self.peer_id
                        )
                        continue

                    # Extract sibling-hash Merkle proof (defaults to [] if not provided)
                    proof = response.get('proof', [])
                    if not isinstance(proof, list):
                        proof = []

                    # ZERO-TRUST: Genuine Cryptographic Merkle Proof Verification BEFORE saving to disk (F15)
                    is_valid = MerkleTree.verify_chunk_proof(chunk_data, chunk_idx, proof, expected_root)

                    if not is_valid:
                        logger.warning(
                            f"🚨 ZERO-TRUST DETECTED: Corrupted chunk {chunk_idx} received from {provider_name} ({provider_id[:8]})! "
                            f"Cryptographic Merkle verification failed."
                        )
                        # Ensure buffer is discarded and any accidental temp file removed
                        temp_dir = self.file_manager._resolve_safe_path(f"{filename}_temp")
                        stale_chunk_path = os.path.join(temp_dir, f"chunk_{chunk_idx}")
                        if os.path.exists(stale_chunk_path):
                            try:
                                os.remove(stale_chunk_path)
                            except OSError:
                                pass
                        chunk_data = None

                        # Targeted peer penalization: Strictly penalize the offending provider (F16)
                        self.reputation.quarantine_provider_for_file(
                            provider_id,
                            filename,
                            reason=f"Merkle proof verification failed for chunk {chunk_idx}",
                            reporter_id=self.peer_id
                        )
                        # Broadcast corruption alert with cryptographic proof across swarm (F17)
                        await self.broadcast_corruption_alert(
                            filename=filename,
                            bad_peer_id=provider_id,
                            bad_peer_name=provider_name,
                            chunk_index=chunk_idx,
                            chunk_data=response.get('data'),
                            expected_root=expected_root,
                            proof=proof,
                            signed_response=response.get('_envelope')
                        )
                        # Try next honest provider for this chunk
                        continue
                    else:
                        # Genuine proof passed: Reward honest provider
                        self.reputation.update_trust(provider_id, True)

                    if progress_callback:
                        try:
                            progress_callback(chunk_idx, total_chunks, provider_name)
                        except Exception as cb_err:
                            logger.debug(f"Progress callback ignored error: {cb_err}")

                    # Save verified chunk to temporary storage ONLY after passing verification
                    self.file_manager.save_chunk(filename, chunk_idx, chunk_data)
                    chunk_received = True
                    break

                if not chunk_received:
                    logger.error(f"Failed to obtain verified chunk {chunk_idx} from any provider!")
                    return False

            # Reassemble file after all chunks verified
            try:
                final_path = self.file_manager.reassemble_file(filename, total_chunks)
                _, tree = self.file_manager.split_file(final_path)
                if tree.root != expected_root:
                    logger.error(f"Final file Merkle Root mismatch for {filename}: computed {tree.root} != expected {expected_root}!")
                    if os.path.exists(final_path):
                        try:
                            os.remove(final_path)
                        except OSError:
                            pass
                    # ELIMINATED: line 419/720 scoping bug where provider_id of last iteration was arbitrarily penalized!
                    return False
                logger.info(f"File {filename} downloaded and verified successfully.")
                download_success = True
                return True
            except Exception as e:
                logger.error(f"Reassembly failed: {e}")
                return False
        finally:
            # F18: Guaranteed tracking cleanup across all outcomes (success, failure, cancellation)
            self.downloading_files.pop(filename, None)
            if effective_file_id and effective_file_id in self.downloading_files:
                self.downloading_files.pop(effective_file_id, None)
            if expected_root and expected_root in self.downloading_files:
                self.downloading_files.pop(expected_root, None)

            # Clean up partial temp chunks on non-success
            if not download_success:
                try:
                    temp_dir = self.file_manager._resolve_safe_path(f"{filename}_temp")
                    if os.path.exists(temp_dir):
                        for f in os.listdir(temp_dir):
                            os.remove(os.path.join(temp_dir, f))
                        os.rmdir(temp_dir)
                except Exception:
                    pass
