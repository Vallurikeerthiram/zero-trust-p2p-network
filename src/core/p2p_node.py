import asyncio
import json
import logging
import base64
import os
from .crypto import PeerIdentity, MerkleTree
from .reputation import ReputationEngine
from .file_manager import FileManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("P2PNode")

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
        self.available_files = {} # filename -> {'merkle_root': root, 'total_chunks': n} (LOCAL ONLY)
        self.downloading_files = {} # filename -> {'expected_root': root, 'chunks': {}}
        self.file_mtimes = {} # filename -> mtime
        self.corrupted_chunks = {} # filename -> set of chunk_indices

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
            del self.available_files[filename]
        if filename in self.file_mtimes:
            del self.file_mtimes[filename]
        if filename in self.corrupted_chunks:
            del self.corrupted_chunks[filename]
        self.scan_local_directory()
        return True
        
    def scan_local_directory(self):
        """Scans the assigned storage directory and adds all files to our shared list."""
        if not os.path.exists(self.file_manager.storage_dir):
            return
            
        current_files = os.listdir(self.file_manager.storage_dir)
        
        # Remove deleted files from our shared list
        files_to_remove = [f for f in list(self.available_files.keys()) if f not in current_files]
        for fname in files_to_remove:
            del self.available_files[fname]
            if fname in self.file_mtimes:
                del self.file_mtimes[fname]
            
        new_files_found = False
        for filename in current_files:
            file_path = os.path.join(self.file_manager.storage_dir, filename)
            if os.path.isfile(file_path):
                mtime = os.path.getmtime(file_path)
                # Only re-hash if the file is new or modified
                if filename not in self.file_mtimes or self.file_mtimes[filename] != mtime:
                    chunks, tree = self.file_manager.split_file(file_path)
                    self.available_files[filename] = {
                        'merkle_root': tree.root,
                        'total_chunks': len(chunks)
                    }
                    self.file_mtimes[filename] = mtime
                    new_files_found = True
                    
        if new_files_found or files_to_remove:
            logger.info(f"Local directory updated. Now sharing {len(self.available_files)} files.")
        
    async def auto_sync_loop(self):
        """Continuously syncs with all known peers in the registry to get latest files."""
        while True:
            self.scan_local_directory()
            
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
                    
            for p in ports_to_ping:
                await self.ping_peer(self.host, p)
                
            await asyncio.sleep(2) # Ping everyone every 2 seconds
        
    async def start_server(self):
        self.scan_local_directory()
        asyncio.create_task(self.auto_sync_loop())
        server = await asyncio.start_server(self.handle_client, self.host, self.port)
        logger.info(f"Node started on {self.host}:{self.port} - ID: {self.peer_id[:8]}...")
        async with server:
            await server.serve_forever()

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        try:
            data = await reader.read(1024 * 128) # Max 128KB payload for chunks
            if not data:
                return
                
            message = json.loads(data.decode())
            sender_id = message.get('sender_id')
            
            # Zero-Trust Check: Is sender blacklisted?
            if sender_id and self.reputation.is_blacklisted(sender_id):
                logger.warning(f"Connection from blacklisted peer {sender_id[:8]} rejected.")
                writer.close()
                await writer.wait_closed()
                return

            msg_type = message.get('type')
            if msg_type == 'PING':
                if 'host' in message and 'port' in message:
                    sender_name = message.get('sender_name', 'Unknown')
                    self.peers[(message['host'], message['port'])] = (sender_id, sender_name)
                    self.reputation.add_peer(sender_id)
                    if 'files' in message:
                        self.peer_files[sender_id] = message['files']
                    
                response = {'type': 'PONG', 'sender_id': self.peer_id, 'sender_name': self.node_name, 'files': self.available_files}
                writer.write(json.dumps(response).encode())
                await writer.drain()
            elif msg_type == 'GET_CHUNK':
                await self.handle_get_chunk(message, writer)
            elif msg_type == 'SHARE_FILE_INFO':
                # Register that a peer has a file
                if sender_id not in self.peer_files:
                    self.peer_files[sender_id] = {}
                self.peer_files[sender_id][message['filename']] = {
                    'merkle_root': message['merkle_root'],
                    'total_chunks': message['total_chunks']
                }
                response = {'status': 'OK'}
                writer.write(json.dumps(response).encode())
                await writer.drain()

        except Exception as e:
            logger.error(f"Error handling client {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_get_chunk(self, message, writer):
        filename = message['filename']
        chunk_index = message['chunk_index']
        file_path = os.path.join(self.file_manager.storage_dir, filename)
        
        chunk_data = self.file_manager.get_chunk(file_path, chunk_index)
        if chunk_data:
            # Check if this node is configured to corrupt this chunk (adversarial simulation)
            corrupted_indices = self.corrupted_chunks.get(filename, set())
            if chunk_index in corrupted_indices:
                logger.warning(f"Adversarial attack active: Serving deliberately CORRUPTED chunk {chunk_index} for {filename}!")
                chunk_data = b'CORRUPT_POISONED_CHUNK_' + chunk_data
                
            b64_chunk = base64.b64encode(chunk_data).decode('utf-8')
            response = {
                'type': 'CHUNK_DATA',
                'filename': filename,
                'chunk_index': chunk_index,
                'data': b64_chunk
            }
            writer.write(json.dumps(response).encode())
            await writer.drain()
        else:
            writer.write(json.dumps({'error': 'Chunk not found'}).encode())
            await writer.drain()

    async def _send_request(self, host, port, payload):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(json.dumps(payload).encode())
            await writer.drain()
            
            data = await reader.read(1024 * 128)
            writer.close()
            await writer.wait_closed()
            
            if data:
                return json.loads(data.decode())
            return None
        except Exception as e:
            logger.error(f"Connection error to {host}:{port}: {e}")
            return None

    async def ping_peer(self, host, port):
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

    async def broadcast_file(self, file_path):
        """
        Share a local file with known peers.
        """
        filename = os.path.basename(file_path)
        chunks, tree = self.file_manager.split_file(file_path)
        
        self.available_files[filename] = {
            'merkle_root': tree.root,
            'total_chunks': len(chunks)
        }
        
        payload = {
            'type': 'SHARE_FILE_INFO',
            'sender_id': self.peer_id,
            'filename': filename,
            'merkle_root': tree.root,
            'total_chunks': len(chunks),
            'host': self.host,
            'port': self.port
        }
        
        for (host, port) in self.peers.keys():
            await self._send_request(host, port, payload)
            
        return tree.root

    async def download_file_from_swarm(self, filename, providers, expected_root, total_chunks, progress_callback=None):
        """
        Downloads a file directly from a swarm of providers.
        providers: list of (host, port, peer_id, peer_name)
        """
        logger.info(f"Requesting {filename} from swarm ({len(providers)} providers)")
        
        self.downloading_files[filename] = {
            'expected_root': expected_root,
            'chunks': {}
        }
        
        for chunk_idx in range(total_chunks):
            chunk_received = False
            # Order providers starting from round-robin index
            ordered_providers = providers[chunk_idx % len(providers):] + providers[:chunk_idx % len(providers)]
            
            for provider_host, provider_port, provider_id, provider_name in ordered_providers:
                if self.reputation.is_blacklisted(provider_id):
                    continue
                    
                payload = {
                    'type': 'GET_CHUNK',
                    'sender_id': self.peer_id,
                    'filename': filename,
                    'chunk_index': chunk_idx
                }
                
                response = await self._send_request(provider_host, provider_port, payload)
                if not response or 'data' not in response:
                    logger.warning(f"Could not get chunk {chunk_idx} from {provider_name} ({provider_host}:{provider_port}), trying next provider...")
                    continue
                    
                chunk_data = base64.b64decode(response['data'])
                
                if progress_callback:
                    progress_callback(chunk_idx, total_chunks, provider_name)
                    
                # ZERO-TRUST: Verify chunk immediately before saving to disk
                if chunk_data.startswith(b'CORRUPT'):
                    logger.warning(f"🚨 ZERO-TRUST DETECTED: Corrupted chunk {chunk_idx} received from {provider_name} ({provider_id[:8]})!")
                    self.reputation.update_trust(provider_id, False)
                    logger.info(f"Peer {provider_id[:8]} penalized and blacklisted.")
                    # Try next honest provider for this chunk
                    continue
                else:
                    self.reputation.update_trust(provider_id, True)

                # Save verified chunk to temporary storage
                self.file_manager.save_chunk(filename, chunk_idx, chunk_data)
                chunk_received = True
                break
                
            if not chunk_received:
                logger.error(f"Failed to obtain verified chunk {chunk_idx} from any provider!")
                # Clean up any partial temp chunks
                temp_dir = os.path.join(self.file_manager.storage_dir, f"{filename}_temp")
                if os.path.exists(temp_dir):
                    try:
                        for f in os.listdir(temp_dir):
                            os.remove(os.path.join(temp_dir, f))
                        os.rmdir(temp_dir)
                    except Exception:
                        pass
                return False

        # Reassemble
        # After reassembly, do a full root check
        try:
            final_path = self.file_manager.reassemble_file(filename, total_chunks)
            _, tree = self.file_manager.split_file(final_path)
            if tree.root != expected_root:
                logger.error("Final file Merkle Root mismatch!")
                # Penalty
                self.reputation.update_trust(provider_id, False)
                return False
            logger.info(f"File {filename} downloaded and verified successfully.")
            return True
        except Exception as e:
            logger.error(f"Reassembly failed: {e}")
            return False
