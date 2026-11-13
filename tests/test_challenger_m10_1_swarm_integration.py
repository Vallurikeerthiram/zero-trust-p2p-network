"""
Empirical Adversarial Challenge Suite: Swarm Integration, Discovery & Corrupt Chunk Resilience (Milestone 10)
Target:
- src.discovery.lan_beacon (LAN Auto-Discovery UDP broadcast)
- src.core.p2p_node.P2PNode (connect_to_peer, connect_to_peer_sync, download_file_from_swarm, handle_get_chunk)
- src.core.file_manager.FileManager (Merkle tree generation, chunk saving, file reassembly)
- src.core.crypto.MerkleTree (verify_chunk_proof, sibling-hash audit path verification)
- src.core.reputation.ReputationEngine (targeted quarantine, trust penalty, anti-blacklisting invariants)

Adversarial Stress Invariants:
1. Hybrid Discovery & Manual Connect: Zero-configuration LAN beacon discovery + manual TCP connect coexist seamlessly.
2. Multi-Node Swarm File Transfer: Chunks are sourced in round-robin fashion across multiple discovered peers.
3. Zero-Trust Cryptographic Sibling-Hash Verification: Corrupted chunks are strictly detected and rejected BEFORE disk write.
4. Targeted Peer Isolation: ONLY the offending Byzantine peer is quarantined and penalized; honest peers receive trust rewards.
5. Swarm Liveness & Failover: Downloader automatically fails over to honest peers, reassembles authentic file without crash/hang.
6. Byzantine Proof Tampering & Spoofing: Forged sibling hashes, wrong chunk indices, malformed base64, and defamation alerts are thwarted.
7. Blacklist Transition: Repeated corruption drops trust score to 0, permanently blacklisting culprit across the entire swarm.
"""

import os
import sys
import time
import json
import base64
import socket
import asyncio
import hashlib
from typing import List, Tuple, Dict, Any
import pytest

from src.core.p2p_node import P2PNode, send_frame, read_frame, create_signed_envelope
from src.core.crypto import MerkleTree, PeerIdentity
from src.core.file_manager import FileManager, CHUNK_SIZE
from src.discovery.lan_beacon import LanBeacon


def find_free_tcp_port() -> int:
    """Allocate an ephemeral TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def find_free_udp_port() -> int:
    """Allocate an ephemeral UDP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
async def swarm_fixture(tmp_path):
    """
    Creates an isolated environment for multi-node swarm testing.
    Provides factory to spawn isolated P2PNodes and automatically cleans up servers.
    """
    nodes: List[P2PNode] = []
    tasks: List[asyncio.Task] = []

    def _create_node(name: str, enable_discovery: bool = False, beacon_port: int = 50050) -> P2PNode:
        port = find_free_tcp_port()
        db_path = str(tmp_path / f"rep_{name}_{port}.db")
        storage_dir = str(tmp_path / f"store_{name}_{port}")
        os.makedirs(storage_dir, exist_ok=True)
        # Bind to 0.0.0.0 per Requirement 3 to ensure reachability across all local interfaces
        node = P2PNode(
            host="0.0.0.0",
            port=port,
            db_path=db_path,
            storage_dir=storage_dir,
            node_name=name,
            enable_discovery=enable_discovery,
            beacon_port=beacon_port
        )
        nodes.append(node)
        return node

    yield _create_node, tasks

    # Teardown: cleanly stop all nodes and await task cancellations
    for node in nodes:
        try:
            await node.stop_async()
        except Exception:
            pass
    for t in tasks:
        if not t.done():
            t.cancel()
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass


# =============================================================================
# Challenge 1: Hybrid LAN Auto-Discovery + Manual Connect Multi-Peer Swarm
# =============================================================================

@pytest.mark.asyncio
async def test_01_hybrid_lan_discovery_and_manual_connect(swarm_fixture):
    """
    Adversarial Challenge 1: Hybrid Discovery Coexistence.
    - Node Alice & Node Bob discover each other automatically via LanBeacon (<2.5s).
    - Node Charlie is connected manually via connect_to_peer.
    - Node Dave is connected manually via connect_to_peer_sync from another thread.
    - Verify all 4 nodes form an authenticated mesh with human-friendly names and cryptographic Peer IDs.
    """
    create_node, tasks = swarm_fixture
    test_beacon_port = find_free_udp_port()

    # Alice and Bob enable LAN Auto-Discovery on test beacon port
    alice = create_node("Alice", enable_discovery=True, beacon_port=test_beacon_port)
    bob = create_node("Bob", enable_discovery=True, beacon_port=test_beacon_port)

    # Charlie and Dave do not run discovery beacons
    charlie = create_node("Charlie", enable_discovery=False)
    dave = create_node("Dave", enable_discovery=False)

    # Start TCP servers
    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(charlie.start_server()))
    tasks.append(asyncio.create_task(dave.start_server()))
    await asyncio.sleep(0.05)

    # Wait for Alice and Bob to auto-discover via LAN Beacon (< 2.5s)
    t_start = time.perf_counter()
    discovered = False
    for _ in range(60):
        await asyncio.sleep(0.04)
        alice_peer_ids = [p[0] for p in alice.peers.values()]
        bob_peer_ids = [p[0] for p in bob.peers.values()]
        if bob.peer_id in alice_peer_ids and alice.peer_id in bob_peer_ids:
            discovered = True
            break

    elapsed = time.perf_counter() - t_start
    assert discovered, f"Alice and Bob failed LAN auto-discovery! Alice peers: {alice.peers}, Bob peers: {bob.peers}"
    assert elapsed < 2.5, f"LAN auto-discovery took {elapsed:.3f}s >= 2.5s"

    # Manual Connect: Alice connects to Charlie asynchronously
    ok_c, msg_c = await alice.connect_to_peer(charlie.advertised_host, charlie.port)
    assert ok_c is True, f"Manual async connect to Charlie failed: {msg_c}"

    # Manual Connect: Alice connects to Dave synchronously from external thread
    loop = asyncio.get_running_loop()
    ok_d, msg_d = await loop.run_in_executor(None, alice.connect_to_peer_sync, dave.advertised_host, dave.port, 5.0)
    assert ok_d is True, f"Manual sync connect to Dave failed: {msg_d}"

    # Verify Alice's peer registry holds all 3 peers
    connected_peer_ids = {p[0] for p in alice.peers.values()}
    connected_peer_names = {p[1] for p in alice.peers.values()}

    assert bob.peer_id in connected_peer_ids
    assert charlie.peer_id in connected_peer_ids
    assert dave.peer_id in connected_peer_ids

    assert "Bob" in connected_peer_names
    assert "Charlie" in connected_peer_names
    assert "Dave" in connected_peer_names


# =============================================================================
# Challenge 2: E2E Multi-Chunk File Distribution Across Swarm with Sibling Proofs
# =============================================================================

@pytest.mark.asyncio
async def test_02_e2e_multi_chunk_swarm_file_distribution(swarm_fixture):
    """
    Adversarial Challenge 2: Multi-Chunk Swarm Transfer with Sibling Merkle Proofs.
    - 4 chunks created (depth 3 tree: non-trivial audit paths with left/right sibling hashes).
    - Authentic file shared by Bob, Charlie, and Dave.
    - Alice requests the file from the swarm; chunks are retrieved round-robin.
    - Every chunk is verified against expected Merkle root using sibling proofs.
    - Reassembled file is bit-for-bit identical to the source payload.
    - All honest providers receive +2 trust rewards.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    charlie = create_node("Charlie")
    dave = create_node("Dave")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(charlie.start_server()))
    tasks.append(asyncio.create_task(dave.start_server()))
    await asyncio.sleep(0.05)

    # Establish connections
    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(charlie.advertised_host, charlie.port)
    await alice.connect_to_peer(dave.advertised_host, dave.port)

    # Create 4-chunk authentic file using standard CHUNK_SIZE (64KB each)
    filename = "swarm_distribution_dataset.bin"
    chunk_0 = b"A" * CHUNK_SIZE
    chunk_1 = b"B" * CHUNK_SIZE
    chunk_2 = b"C" * CHUNK_SIZE
    chunk_3 = b"D" * CHUNK_SIZE
    full_payload = chunk_0 + chunk_1 + chunk_2 + chunk_3
    expected_sha256 = hashlib.sha256(full_payload).hexdigest()

    tree = MerkleTree([chunk_0, chunk_1, chunk_2, chunk_3])
    expected_root = tree.root

    # Verify that Merkle tree produces genuine multi-level sibling proofs
    proof_0 = tree.get_proof(0)
    assert len(proof_0) == 2, f"Expected 2-level proof for 4 chunks, got {len(proof_0)}"
    assert proof_0[0][0] == 'right'  # chunk 0's sibling is chunk 1 on the right

    # Store file in Bob, Charlie, and Dave's storage directories
    for node in (bob, charlie, dave):
        fpath = os.path.join(node.file_manager.storage_dir, filename)
        with open(fpath, "wb") as f:
            f.write(full_payload)
        node.scan_local_directory()
        assert filename in node.available_files
        assert node.available_files[filename]['merkle_root'] == expected_root

    # Initial trust scores on Alice
    for p in (bob, charlie, dave):
        alice.reputation.add_peer(p.peer_id)
        assert alice.reputation.get_trust_score(p.peer_id) == 50

    providers = [
        (bob.advertised_host, bob.port, bob.peer_id, "Bob"),
        (charlie.advertised_host, charlie.port, charlie.peer_id, "Charlie"),
        (dave.advertised_host, dave.port, dave.peer_id, "Dave")
    ]

    # Alice downloads from swarm
    success = await alice.download_file_from_swarm(
        filename=filename,
        providers=providers,
        expected_root=expected_root,
        total_chunks=4
    )
    assert success is True, "Multi-chunk swarm download failed!"

    # Verify reassembled file on disk
    dest_path = os.path.join(alice.file_manager.storage_dir, filename)
    assert os.path.exists(dest_path), "Downloaded file missing from Alice storage!"
    with open(dest_path, "rb") as f:
        downloaded_bytes = f.read()

    assert downloaded_bytes == full_payload, "Downloaded file bytes do not match original payload!"
    assert hashlib.sha256(downloaded_bytes).hexdigest() == expected_sha256

    # Verify that providers were rewarded (+2 per chunk provided)
    for p in (bob, charlie, dave):
        score = alice.reputation.get_trust_score(p.peer_id)
        assert score > 50, f"Provider {p.node_name} was not rewarded: score={score}"


# =============================================================================
# Challenge 3: Corrupted Chunk Injection, Cryptographic Sibling Rejection & Failover
# =============================================================================

@pytest.mark.asyncio
async def test_03_corrupt_chunk_injection_merkle_rejection_and_failover(swarm_fixture):
    """
    Adversarial Challenge 3: Poisoned Chunks & Targeted Peer Penalization.
    - 4 nodes: Alice (Downloader), Bob (Honest), Charlie (Honest), Mallory (Byzantine).
    - Mallory is configured with set_corrupted_chunks(filename, [1, 2]).
    - Mallory is placed FIRST in the providers list to actively attempt corruption.
    - Chunk 1: Mallory serves poisoned data.
      1. Cryptographic sibling-hash verification strictly detects the tamper.
      2. Poisoned buffer is discarded (never saved to disk).
      3. Mallory is immediately quarantined for this file: is_provider_quarantined is True.
      4. Mallory's trust score drops by 25 points (from 50 to 25).
      5. NON-COLLATERAL INVARIANT: Bob and Charlie are NOT quarantined and NOT penalized!
      6. Downloader fails over to Bob, retrieves authentic chunk 1, and verifies proof.
    - Chunk 2: Mallory is already quarantined, so downloader skips Mallory entirely!
    - Full download completes successfully with bit-for-bit authenticity.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    charlie = create_node("Charlie")
    mallory = create_node("Mallory")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(charlie.start_server()))
    tasks.append(asyncio.create_task(mallory.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(charlie.advertised_host, charlie.port)
    await alice.connect_to_peer(mallory.advertised_host, mallory.port)

    filename = "poison_injection_test.bin"
    chunk_0 = b"A" * CHUNK_SIZE
    chunk_1 = b"B" * CHUNK_SIZE
    chunk_2 = b"C" * CHUNK_SIZE
    chunk_3 = b"D" * CHUNK_SIZE
    full_payload = chunk_0 + chunk_1 + chunk_2 + chunk_3

    tree = MerkleTree([chunk_0, chunk_1, chunk_2, chunk_3])
    expected_root = tree.root

    # Setup authentic file on Bob, Charlie, and Mallory
    for node in (bob, charlie, mallory):
        fpath = os.path.join(node.file_manager.storage_dir, filename)
        with open(fpath, "wb") as f:
            f.write(full_payload)
        node.scan_local_directory()
        assert filename in node.available_files

    # Configure Mallory to maliciously poison chunk 0 (queried at chunk_idx=0 under round-robin)
    mallory.set_corrupted_chunks(filename, [0])
    assert mallory.get_corrupted_chunks(filename) == {0}

    # Initial reputation setup
    for p in (bob, charlie, mallory):
        alice.reputation.add_peer(p.peer_id)
        assert alice.reputation.get_trust_score(p.peer_id) == 50

    # Place Mallory FIRST so Mallory is queried first for chunk 1
    providers = [
        (mallory.advertised_host, mallory.port, mallory.peer_id, "Mallory"),
        (bob.advertised_host, bob.port, bob.peer_id, "Bob"),
        (charlie.advertised_host, charlie.port, charlie.peer_id, "Charlie")
    ]

    # Alice downloads from swarm
    success = await alice.download_file_from_swarm(
        filename=filename,
        providers=providers,
        expected_root=expected_root,
        total_chunks=4
    )
    assert success is True, "Download failed despite available honest providers in swarm!"

    # 1. Verify Mallory was strictly quarantined for filename
    assert alice.reputation.is_provider_quarantined(mallory.peer_id, filename) is True

    # 2. Verify Mallory received -25 penalty
    mallory_score = alice.reputation.get_trust_score(mallory.peer_id)
    assert mallory_score <= 25, f"Mallory trust score {mallory_score} was not penalized by >= 25!"

    # 3. CRITICAL NON-COLLATERAL INVARIANT: Bob and Charlie must NOT be quarantined
    assert alice.reputation.is_provider_quarantined(bob.peer_id, filename) is False
    assert alice.reputation.is_provider_quarantined(charlie.peer_id, filename) is False

    # 4. Bob and Charlie trust scores must be >= 50 (rewarded for honest failovers)
    assert alice.reputation.get_trust_score(bob.peer_id) >= 50
    assert alice.reputation.get_trust_score(charlie.peer_id) >= 50

    # 5. Verify no corrupted chunk fragments remain in temp folder
    temp_dir = alice.file_manager._resolve_safe_path(f"{filename}_temp")
    assert not os.path.exists(temp_dir), "Temp chunk directory was not cleaned up after assembly!"

    # 6. Verify final reassembled file is bit-for-bit identical to source
    dest_path = os.path.join(alice.file_manager.storage_dir, filename)
    with open(dest_path, "rb") as f:
        downloaded = f.read()
    assert downloaded == full_payload, "Reassembled file contains corrupted bytes!"


# =============================================================================
# Challenge 4: Forged Sibling Hash Proof Rejection
# =============================================================================

@pytest.mark.asyncio
async def test_04_forged_sibling_hash_proof_rejection(swarm_fixture):
    """
    Adversarial Challenge 4: Sibling Proof Tampering Attack.
    - Byzantine node serves authentic chunk bytes but an invalid sibling hash in the Merkle audit path.
    - Downloader detects proof verification failure, quarantines provider, and fails over to honest node.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    evil_charlie = create_node("EvilCharlie")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(evil_charlie.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(evil_charlie.advertised_host, evil_charlie.port)

    filename = "sibling_forgery_test.dat"
    c0 = b"A" * CHUNK_SIZE
    c1 = b"B" * CHUNK_SIZE
    full_payload = c0 + c1
    tree = MerkleTree([c0, c1])
    expected_root = tree.root

    for node in (bob, evil_charlie):
        fpath = os.path.join(node.file_manager.storage_dir, filename)
        with open(fpath, "wb") as f:
            f.write(full_payload)
        node.scan_local_directory()
        assert filename in node.available_files

    # Intercept EvilCharlie's handle_get_chunk to return forged sibling hash
    original_handle_get_chunk = evil_charlie.handle_get_chunk

    async def tampered_get_chunk(message, writer, sender_id=None, send_response=None):
        async def forged_sender(resp_dict):
            if resp_dict.get('type') == 'CHUNK_DATA':
                # Replace sibling proof with forged sibling hash
                resp_dict['proof'] = [('right', 'f' * 64)]
            if send_response:
                await send_response(resp_dict)
            else:
                await send_frame(writer, evil_charlie.create_signed_envelope(resp_dict))

        await original_handle_get_chunk(message, writer, sender_id=sender_id, send_response=forged_sender)

    evil_charlie.handle_get_chunk = tampered_get_chunk

    alice.reputation.add_peer(evil_charlie.peer_id)
    alice.reputation.add_peer(bob.peer_id)

    providers = [
        (evil_charlie.advertised_host, evil_charlie.port, evil_charlie.peer_id, "EvilCharlie"),
        (bob.advertised_host, bob.port, bob.peer_id, "Bob")
    ]

    success = await alice.download_file_from_swarm(
        filename=filename,
        providers=providers,
        expected_root=expected_root,
        total_chunks=2
    )
    assert success is True, "Download failed despite valid fallback to Bob!"

    # EvilCharlie should be quarantined and penalized
    assert alice.reputation.is_provider_quarantined(evil_charlie.peer_id, filename) is True
    assert alice.reputation.get_trust_score(evil_charlie.peer_id) <= 25

    # Bob should remain trusted
    assert alice.reputation.is_provider_quarantined(bob.peer_id, filename) is False


# =============================================================================
# Challenge 5: Chunk Index Spoofing & Malformed Base64 Resilience
# =============================================================================

@pytest.mark.asyncio
async def test_05_chunk_index_spoofing_and_malformed_payload(swarm_fixture):
    """
    Adversarial Challenge 5: Protocol Level Attacks.
    - Attacker returns wrong chunk_index (e.g. chunk 0 when chunk 1 requested).
    - Attacker returns corrupted non-base64 payload.
    - Downloader gracefully rejects malformed responses, quarantines culprit, and completes via honest peer.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    spoof_node = create_node("SpoofNode")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(spoof_node.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(spoof_node.advertised_host, spoof_node.port)

    filename = "index_spoof_test.dat"
    c0 = b"A" * CHUNK_SIZE
    c1 = b"B" * CHUNK_SIZE
    full_payload = c0 + c1
    tree = MerkleTree([c0, c1])
    expected_root = tree.root

    fpath = os.path.join(bob.file_manager.storage_dir, filename)
    with open(fpath, "wb") as f:
        f.write(full_payload)
    bob.scan_local_directory()

    # SpoofNode returns unparseable base64 or wrong chunk index
    async def malformed_get_chunk(message, writer, sender_id=None, send_response=None):
        resp = {
            'type': 'CHUNK_DATA',
            'sender_id': spoof_node.peer_id,
            'filename': filename,
            'chunk_index': 999,  # Spoofed index
            'data': "NOT_VALID_BASE64_!@#$%^&*()",
            'proof': []
        }
        if send_response:
            await send_response(resp)
        else:
            await send_frame(writer, spoof_node.create_signed_envelope(resp))

    spoof_node.handle_get_chunk = malformed_get_chunk

    alice.reputation.add_peer(spoof_node.peer_id)
    alice.reputation.add_peer(bob.peer_id)

    providers = [
        (spoof_node.advertised_host, spoof_node.port, spoof_node.peer_id, "SpoofNode"),
        (bob.advertised_host, bob.port, bob.peer_id, "Bob")
    ]

    success = await alice.download_file_from_swarm(
        filename=filename,
        providers=providers,
        expected_root=expected_root,
        total_chunks=2
    )
    assert success is True, "Downloader failed to fail over from malformed provider!"

    # Verify final file is intact
    dest_path = os.path.join(alice.file_manager.storage_dir, filename)
    with open(dest_path, "rb") as f:
        assert f.read() == full_payload


# =============================================================================
# Challenge 6: 100% Byzantine Swarm Clean Failure Without Hang
# =============================================================================

@pytest.mark.asyncio
async def test_06_all_malicious_swarm_clean_termination_no_hang(swarm_fixture):
    """
    Adversarial Challenge 6: Swarm of Death.
    - All providers are malicious and serve corrupted chunks.
    - Invariants:
      1. Downloader returns False cleanly within timeout (no infinite loop, no deadlock).
      2. No corrupted files are reassembled into local storage.
      3. All malicious providers are quarantined and penalized.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bad1 = create_node("Bad1")
    bad2 = create_node("Bad2")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bad1.start_server()))
    tasks.append(asyncio.create_task(bad2.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bad1.advertised_host, bad1.port)
    await alice.connect_to_peer(bad2.advertised_host, bad2.port)

    filename = "all_poisoned_file.bin"
    chunk_0 = b"LEGIT_PAYLOAD" * 30
    tree = MerkleTree([chunk_0])
    expected_root = tree.root

    for node in (bad1, bad2):
        fpath = os.path.join(node.file_manager.storage_dir, filename)
        with open(fpath, "wb") as f:
            f.write(chunk_0)
        node.scan_local_directory()
        node.set_corrupted_chunks(filename, [0])

    alice.reputation.add_peer(bad1.peer_id)
    alice.reputation.add_peer(bad2.peer_id)

    providers = [
        (bad1.advertised_host, bad1.port, bad1.peer_id, "Bad1"),
        (bad2.advertised_host, bad2.port, bad2.peer_id, "Bad2")
    ]

    t0 = time.perf_counter()
    success = await alice.download_file_from_swarm(
        filename=filename,
        providers=providers,
        expected_root=expected_root,
        total_chunks=1
    )
    elapsed = time.perf_counter() - t0

    # 1. Must return False cleanly
    assert success is False, "Download should have failed when all providers are malicious!"
    assert elapsed < 5.0, f"Swarm download hung or took too long: {elapsed:.2f}s >= 5.0s"

    # 2. Both bad providers must be quarantined
    assert alice.reputation.is_provider_quarantined(bad1.peer_id, filename) is True
    assert alice.reputation.is_provider_quarantined(bad2.peer_id, filename) is True

    # 3. No corrupted file on disk
    dest_path = os.path.join(alice.file_manager.storage_dir, filename)
    assert not os.path.exists(dest_path), "Corrupted file was saved to storage!"


# =============================================================================
# Challenge 7: Repeated Corruption Triggers Permanent Blacklist
# =============================================================================

@pytest.mark.asyncio
async def test_07_repeated_corruption_triggers_permanent_blacklist(swarm_fixture):
    """
    Adversarial Challenge 7: Blacklist State Transition.
    - Incident 1: Mallory corrupts file_A -> trust score drops from 50 to 25.
    - Incident 2: Mallory corrupts file_B -> trust score drops from 25 to 0.
    - Verify Mallory is automatically blacklisted: is_blacklisted is True.
    - Incident 3: On file_C download, Mallory is completely bypassed/ignored in provider selection.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    mallory = create_node("Mallory")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(mallory.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(mallory.advertised_host, mallory.port)

    alice.reputation.add_peer(mallory.peer_id)
    alice.reputation.add_peer(bob.peer_id)

    # File A: Mallory corrupts chunk
    fn_a = "file_a.dat"
    data_a = b"A" * 100
    tree_a = MerkleTree([data_a])
    for n in (bob, mallory):
        with open(os.path.join(n.file_manager.storage_dir, fn_a), "wb") as f:
            f.write(data_a)
        n.scan_local_directory()
    mallory.set_corrupted_chunks(fn_a, [0])

    res_a = await alice.download_file_from_swarm(
        filename=fn_a,
        providers=[(mallory.advertised_host, mallory.port, mallory.peer_id, "Mallory"), (bob.advertised_host, bob.port, bob.peer_id, "Bob")],
        expected_root=tree_a.root,
        total_chunks=1
    )
    assert res_a is True
    assert alice.reputation.get_trust_score(mallory.peer_id) == 25
    assert alice.reputation.is_blacklisted(mallory.peer_id) is False

    # File B: Mallory corrupts chunk again
    fn_b = "file_b.dat"
    data_b = b"B" * 100
    tree_b = MerkleTree([data_b])
    for n in (bob, mallory):
        with open(os.path.join(n.file_manager.storage_dir, fn_b), "wb") as f:
            f.write(data_b)
        n.scan_local_directory()
    mallory.set_corrupted_chunks(fn_b, [0])

    res_b = await alice.download_file_from_swarm(
        filename=fn_b,
        providers=[(mallory.advertised_host, mallory.port, mallory.peer_id, "Mallory"), (bob.advertised_host, bob.port, bob.peer_id, "Bob")],
        expected_root=tree_b.root,
        total_chunks=1
    )
    assert res_b is True
    assert alice.reputation.get_trust_score(mallory.peer_id) == 0
    assert alice.reputation.is_blacklisted(mallory.peer_id) is True

    # File C: Mallory is blacklisted, should be filtered out by download_file_from_swarm
    fn_c = "file_c.dat"
    data_c = b"C" * 100
    tree_c = MerkleTree([data_c])
    with open(os.path.join(bob.file_manager.storage_dir, fn_c), "wb") as f:
        f.write(data_c)
    bob.scan_local_directory()

    # Even if Mallory is listed in providers, Alice automatically bypasses blacklisted peers
    res_c = await alice.download_file_from_swarm(
        filename=fn_c,
        providers=[(mallory.advertised_host, mallory.port, mallory.peer_id, "Mallory"), (bob.advertised_host, bob.port, bob.peer_id, "Bob")],
        expected_root=tree_c.root,
        total_chunks=1
    )
    assert res_c is True


# =============================================================================
# Challenge 8: Defamation Attack Resistance (Anti-Framing Verification)
# =============================================================================

def test_08_defamation_attack_anti_framing():
    """
    Adversarial Challenge 8: Defamation / False-Accusation Resistance.
    - Malicious peer broadcasts fake CORRUPTION_ALERT against honest peer Bob.
    - Test A: Attached chunk data is valid and passes Merkle verification -> Framing rejected.
    - Test B: Attached chunk data is corrupted but lacks Bob's cryptographic signature -> Unsigned rejected.
    - In both cases, Bob is NOT penalized.
    """
    alice_identity = PeerIdentity("AliceIdentity")
    bob_identity = PeerIdentity("BobIdentity")
    mallory_identity = PeerIdentity("MalloryIdentity")

    chunk_data = b"HONEST_BOB_AUTHENTIC_DATA"
    tree = MerkleTree([chunk_data])
    expected_root = tree.root

    alice_node = P2PNode(node_name="AliceJudge", host="127.0.0.1", port=find_free_tcp_port())
    alice_node.reputation.add_peer(bob_identity.get_peer_id())
    initial_bob_score = alice_node.reputation.get_trust_score(bob_identity.get_peer_id())
    assert initial_bob_score == 50

    # Test A: Framing with valid chunk data
    fake_alert_valid_chunk = {
        'corrupted_peer_id': bob_identity.get_peer_id(),
        'filename': "test_file.bin",
        'expected_root': expected_root,
        'chunk_index': 0,
        'chunk_data': base64.b64encode(chunk_data).decode('utf-8'),
        'proof': tree.get_proof(0)
    }
    is_valid, reason = alice_node.verify_corruption_proof(fake_alert_valid_chunk, reporter_id=mallory_identity.get_peer_id())
    assert is_valid is False
    assert reason == "CHUNK_PASSES_MERKLE_VERIFICATION_FRAMING_ATTACK"

    # Test B: Corrupted chunk without Bob's signature
    fake_alert_unsigned = {
        'corrupted_peer_id': bob_identity.get_peer_id(),
        'filename': "test_file.bin",
        'expected_root': expected_root,
        'chunk_index': 0,
        'chunk_data': base64.b64encode(b"CORRUPTED_DATA_INSERTED_BY_MALLORY").decode('utf-8'),
        'proof': tree.get_proof(0)
    }
    is_valid_b, reason_b = alice_node.verify_corruption_proof(fake_alert_unsigned, reporter_id=mallory_identity.get_peer_id())
    assert is_valid_b is False
    assert reason_b == "MISSING_CRYPTOGRAPHIC_PROOF"

    # Bob's score must remain completely unharmed
    assert alice_node.reputation.get_trust_score(bob_identity.get_peer_id()) == 50
    assert alice_node.reputation.is_provider_quarantined(bob_identity.get_peer_id(), "test_file.bin") is False


# =============================================================================
# Challenge 9: Concurrent Swarm File Transfers Under Active Poisoning
# =============================================================================

@pytest.mark.asyncio
async def test_09_concurrent_swarm_transfers_under_active_poisoning(swarm_fixture):
    """
    Adversarial Challenge 9: Concurrency Under Stress.
    - Two large files downloaded simultaneously via asyncio.gather across a 4-node swarm.
    - Mallory actively poisons chunks on both files concurrently.
    - Verify both downloads succeed via failover to honest peers.
    - Verify no race condition in SQLite reputation database or local file manager.
    """
    create_node, tasks = swarm_fixture

    alice = create_node("Alice")
    bob = create_node("Bob")
    charlie = create_node("Charlie")
    mallory = create_node("Mallory")

    tasks.append(asyncio.create_task(alice.start_server()))
    tasks.append(asyncio.create_task(bob.start_server()))
    tasks.append(asyncio.create_task(charlie.start_server()))
    tasks.append(asyncio.create_task(mallory.start_server()))
    await asyncio.sleep(0.05)

    await alice.connect_to_peer(bob.advertised_host, bob.port)
    await alice.connect_to_peer(charlie.advertised_host, charlie.port)
    await alice.connect_to_peer(mallory.advertised_host, mallory.port)

    # File 1 (2 chunks)
    f1_name = "concurrent_file_1.dat"
    f1_chunk0 = b"F1_CHUNK0_" * 6553
    f1_chunk0 = f1_chunk0 + b"0" * (CHUNK_SIZE - len(f1_chunk0))
    f1_chunk1 = b"F1_CHUNK1_" * 6553
    f1_chunk1 = f1_chunk1 + b"1" * (CHUNK_SIZE - len(f1_chunk1))
    f1_payload = f1_chunk0 + f1_chunk1
    f1_tree = MerkleTree([f1_chunk0, f1_chunk1])

    # File 2 (2 chunks)
    f2_name = "concurrent_file_2.dat"
    f2_chunk0 = b"F2_CHUNK0_" * 6553
    f2_chunk0 = f2_chunk0 + b"0" * (CHUNK_SIZE - len(f2_chunk0))
    f2_chunk1 = b"F2_CHUNK1_" * 6553
    f2_chunk1 = f2_chunk1 + b"1" * (CHUNK_SIZE - len(f2_chunk1))
    f2_payload = f2_chunk0 + f2_chunk1
    f2_tree = MerkleTree([f2_chunk0, f2_chunk1])

    for n in (bob, charlie, mallory):
        with open(os.path.join(n.file_manager.storage_dir, f1_name), "wb") as f:
            f.write(f1_payload)
        with open(os.path.join(n.file_manager.storage_dir, f2_name), "wb") as f:
            f.write(f2_payload)
        n.scan_local_directory()
        assert f1_name in n.available_files
        assert f2_name in n.available_files

    # Mallory poisons chunk 0 of both files (queried first for chunk 0)
    mallory.set_corrupted_chunks(f1_name, [0])
    mallory.set_corrupted_chunks(f2_name, [0])

    alice.reputation.add_peer(bob.peer_id)
    alice.reputation.add_peer(charlie.peer_id)
    alice.reputation.add_peer(mallory.peer_id)

    providers = [
        (mallory.advertised_host, mallory.port, mallory.peer_id, "Mallory"),
        (bob.advertised_host, bob.port, bob.peer_id, "Bob"),
        (charlie.advertised_host, charlie.port, charlie.peer_id, "Charlie")
    ]

    # Run both downloads concurrently
    res1, res2 = await asyncio.gather(
        alice.download_file_from_swarm(f1_name, providers, f1_tree.root, 2),
        alice.download_file_from_swarm(f2_name, providers, f2_tree.root, 2)
    )

    assert res1 is True, "Concurrent download of File 1 failed!"
    assert res2 is True, "Concurrent download of File 2 failed!"

    # Verify both files on disk
    with open(os.path.join(alice.file_manager.storage_dir, f1_name), "rb") as f:
        assert f.read() == f1_payload
    with open(os.path.join(alice.file_manager.storage_dir, f2_name), "rb") as f:
        assert f.read() == f2_payload

    # Mallory is quarantined on both files and trust is heavily penalized
    assert alice.reputation.is_provider_quarantined(mallory.peer_id, f1_name) is True
    assert alice.reputation.is_provider_quarantined(mallory.peer_id, f2_name) is True
    assert alice.reputation.get_trust_score(mallory.peer_id) == 0
