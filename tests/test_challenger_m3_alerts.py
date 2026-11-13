"""
Empirical Challenger 2 Test Suite for Milestone 3:
Zero-Trust Swarm Verification, Adversarial Corruption Alerts, Anti-Framing Defenses,
Targeted Peer Penalization, and In-Flight State & Temp Cleanup.

Coverage:
1. Unauthenticated framing attack via CORRUPTION_ALERT:
   - Send unverified/spoofed alerts accusing innocent victim peer.
   - Assert alert rejected by receiver and victim's trust score/quarantine status unchanged.
   - Comprehensive checks for missing signed receipts, spoofed keys, and mismatched signatures.
2. False alert with authentic chunk:
   - Send alert where chunk actually verifies against Merkle root / local storage.
   - Assert alert actively rejected as framing attack; victim unharmed.
3. Proven corruption alert:
   - Send genuine alert with provider's signed envelope and invalid chunk / proof failure.
   - Assert provider is strictly quarantined and trust score is docked (-25).
4. Multi-provider swarm with 1 bad provider:
   - Swarm download where bad provider serves corrupt chunk and honest provider serves authentic chunk.
   - Assert strictly bad provider is quarantined and docked; honest provider is rewarded and unharmed.
   - Verifies absence of loop-variable scoping leaks.
5. In-flight cancellation of download task:
   - Cancel swarm download task in flight after partial chunk storage.
   - Assert downloading_files tracking state is cleared and temp directory is deleted.
"""

import asyncio
import base64
import hashlib
import json
import os
import time
import pytest
from unittest.mock import AsyncMock, patch

from src.core.p2p_node import (
    P2PNode,
    pack_tcp_frame,
    unpack_tcp_frame,
    read_frame,
    send_frame,
)
from src.core.crypto import PeerIdentity, MerkleTree
from tests.conftest import create_signed_envelope, find_free_port


@pytest.fixture
async def p2p_server_node(isolated_dir):
    """Start an active P2PNode TCP server for empirical socket-level adversarial tests."""
    port = find_free_port()
    db_path = f"challenger_m3_rep_{port}.db"
    storage_dir = f"challenger_m3_store_{port}"
    os.makedirs(storage_dir, exist_ok=True)

    node = P2PNode(
        host="127.0.0.1",
        port=port,
        db_path=db_path,
        storage_dir=storage_dir,
        node_name=f"target_node_{port}"
    )

    server = await asyncio.start_server(node.handle_client, node.host, node.port)
    server_task = asyncio.create_task(server.serve_forever())

    try:
        yield node, port
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


async def send_message_to_server(host: str, port: int, sender_id: PeerIdentity, payload: dict):
    """Helper to send a framed, signed message to a P2PNode TCP server and return the response payload."""
    reader, writer = await asyncio.open_connection(host, port)
    try:
        envelope = create_signed_envelope(sender_id, payload)
        await send_frame(writer, envelope)
        resp_env = await read_frame(reader)
        if resp_env and isinstance(resp_env, dict):
            return resp_env.get('payload', resp_env)
        return None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


class TestChallengerM3Alerts:
    """Adversarial stress harness for Milestone 3 Zero-Trust Swarm Verification & Corruption Alerts."""

    # =========================================================================
    # 1. Unauthenticated Framing Attacks via CORRUPTION_ALERT
    # =========================================================================

    @pytest.mark.asyncio
    async def test_framing_alert_without_signed_response_rejected(self, p2p_server_node, identity_factory):
        """
        Adversary sends a CORRUPTION_ALERT accusing an innocent victim peer
        without any signed response from the provider.
        Receiver MUST reject alert with ALERT_REJECTED and leave victim's score unchanged.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_node")
        victim_id = identity_factory("victim_node")

        # Initialize victim in reputation engine with default trust score (50)
        node.reputation.add_peer(victim_id.peer_id)
        assert node.reputation.get_trust_score(victim_id.peer_id) == 50
        assert not node.reputation.is_provider_quarantined(victim_id.peer_id, "secret.dat")

        # Craft malicious unverified alert
        corrupt_chunk_data = b"FAKE_CORRUPTED_CHUNK_DATA"
        alert_payload = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'sender_name': 'AttackerNode',
            'corrupted_peer_id': victim_id.peer_id,
            'corrupted_peer_name': 'VictimNode',
            'filename': 'secret.dat',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(corrupt_chunk_data).decode('utf-8'),
            'expected_root': 'a' * 64,
            'reason': 'Victim is totally corrupt!'
        }

        # 1. Direct unit verification
        is_valid, reason = node.verify_corruption_proof(alert_payload, attacker_id.peer_id)
        assert not is_valid
        assert reason == "MISSING_CRYPTOGRAPHIC_PROOF"

        # 2. Live TCP transmission
        response = await send_message_to_server("127.0.0.1", port, attacker_id, alert_payload)
        assert response is not None
        assert response.get('status') == 'ALERT_REJECTED'
        assert response.get('reason') == 'MISSING_CRYPTOGRAPHIC_PROOF'

        # 3. Assert victim peer reputation and quarantine remain completely unblemished
        assert node.reputation.get_trust_score(victim_id.peer_id) == 50
        assert not node.reputation.is_provider_quarantined(victim_id.peer_id, "secret.dat")
        assert not node.reputation.is_blacklisted(victim_id.peer_id)

    @pytest.mark.asyncio
    async def test_framing_alert_with_forged_or_mismatched_signature_rejected(self, p2p_server_node, identity_factory):
        """
        Adversary crafts a fake signed response signed by their OWN key but claims
        the signature belongs to the victim peer.
        Receiver MUST detect signature mismatch/spoofing, reject alert, and protect victim.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_forger")
        victim_id = identity_factory("victim_target")

        node.reputation.add_peer(victim_id.peer_id)

        corrupt_data = b"TAMPERED_CHUNK_PAYLOAD"
        b64_data = base64.b64encode(corrupt_data).decode('utf-8')

        # Attacker signs payload with attacker's key, but sets sender_id to victim's ID
        fake_payload = {'data': b64_data, 'chunk_index': 0}
        canonical = json.dumps(fake_payload, sort_keys=True).encode('utf-8')
        attacker_sig = attacker_id.sign_data(canonical)

        # Forgery Attempt A: Attacker's public key with victim's sender_id
        forged_signed_response_a = {
            'sender_id': victim_id.peer_id,  # Mismatch with attacker pubkey hash
            'public_key': attacker_id.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(attacker_sig).decode('utf-8'),
            'payload': fake_payload
        }

        alert_payload_a = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_id.peer_id,
            'filename': 'secure.bin',
            'chunk_index': 0,
            'chunk_data': b64_data,
            'expected_root': 'b' * 64,
            'signed_response': forged_signed_response_a
        }

        is_valid_a, reason_a = node.verify_corruption_proof(alert_payload_a, attacker_id.peer_id)
        assert not is_valid_a
        assert reason_a == "SPOOFED_PROVIDER_PUBLIC_KEY"

        # Forgery Attempt B: Victim's pubkey but invalid signature (attacker can't forge victim's sig)
        victim_pub_pem = victim_id.get_public_key_pem().decode('utf-8')
        forged_signed_response_b = {
            'sender_id': victim_id.peer_id,
            'public_key': victim_pub_pem,
            'signature': base64.b64encode(attacker_sig).decode('utf-8'),  # Invalid for victim pubkey
            'payload': fake_payload
        }

        alert_payload_b = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_id.peer_id,
            'filename': 'secure.bin',
            'chunk_index': 0,
            'chunk_data': b64_data,
            'expected_root': 'b' * 64,
            'signed_response': forged_signed_response_b
        }

        is_valid_b, reason_b = node.verify_corruption_proof(alert_payload_b, attacker_id.peer_id)
        assert not is_valid_b
        assert reason_b == "INVALID_PROVIDER_SIGNATURE"

        # Send Forgery B over network and verify rejection
        response = await send_message_to_server("127.0.0.1", port, attacker_id, alert_payload_b)
        assert response.get('status') == 'ALERT_REJECTED'
        assert response.get('reason') == 'INVALID_PROVIDER_SIGNATURE'

        # Victim trust score remains untouched
        assert node.reputation.get_trust_score(victim_id.peer_id) == 50
        assert not node.reputation.is_provider_quarantined(victim_id.peer_id, "secure.bin")

    @pytest.mark.asyncio
    async def test_framing_alert_edge_cases_rejected(self, p2p_server_node, identity_factory):
        """
        Adversarial edge cases:
        - Self-reporting (reporter_id == bad_peer_id)
        - Missing or malformed fields (bad_peer_id, expected_root, chunk_index)
        - Data mismatch between alert chunk_data and signed response chunk_data
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_edge")
        victim_id = identity_factory("victim_edge")

        # 1. Cannot report self
        self_report_payload = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': attacker_id.peer_id,
            'filename': 'test.bin',
            'chunk_index': 0,
            'chunk_data': 'AAAA',
            'expected_root': 'c' * 64
        }
        valid, reason = node.verify_corruption_proof(self_report_payload, attacker_id.peer_id)
        assert not valid
        assert reason == "CANNOT_REPORT_SELF"

        # 2. Invalid expected root (not 64 chars)
        invalid_root_payload = {
            'type': 'CORRUPTION_ALERT',
            'corrupted_peer_id': victim_id.peer_id,
            'filename': 'test.bin',
            'chunk_index': 0,
            'chunk_data': 'AAAA',
            'expected_root': 'short_root'
        }
        valid, reason = node.verify_corruption_proof(invalid_root_payload, attacker_id.peer_id)
        assert not valid
        assert reason == "MISSING_OR_INVALID_EXPECTED_ROOT"

        # 3. Signed response provider mismatch with corrupted_peer_id
        innocent_third_party = identity_factory("third_party")
        valid_third_party_resp = create_signed_envelope(innocent_third_party, {'data': 'AAAA'})
        mismatch_payload = {
            'type': 'CORRUPTION_ALERT',
            'corrupted_peer_id': victim_id.peer_id,
            'filename': 'test.bin',
            'chunk_index': 0,
            'chunk_data': 'AAAA',
            'expected_root': 'd' * 64,
            'signed_response': valid_third_party_resp
        }
        valid, reason = node.verify_corruption_proof(mismatch_payload, attacker_id.peer_id)
        assert not valid
        assert reason == "SIGNED_RESPONSE_PROVIDER_MISMATCH"

    # =========================================================================
    # 2. False Alert with Authentic Chunk (Framing Attempt)
    # =========================================================================

    @pytest.mark.asyncio
    async def test_false_alert_with_authentic_chunk_and_merkle_proof_rejected(self, p2p_server_node, identity_factory):
        """
        Adversary obtains an authentic chunk and valid Merkle proof, but submits a
        CORRUPTION_ALERT claiming the chunk is corrupt.
        Receiver verifies chunk against Merkle proof, detects it is completely valid,
        rejects alert with CHUNK_PASSES_MERKLE_VERIFICATION_FRAMING_ATTACK,
        and keeps victim trust score intact.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_merkle")
        victim_id = identity_factory("victim_honest")

        node.reputation.add_peer(victim_id.peer_id)

        # Generate genuine chunk and Merkle proof
        chunk_0 = b"AUTHENTIC_LEGITIMATE_CHUNK_DATA_ZERO"
        chunk_1 = b"AUTHENTIC_LEGITIMATE_CHUNK_DATA_ONE"
        tree = MerkleTree([chunk_0, chunk_1])
        valid_proof_0 = tree.get_proof(0)

        # Victim honestly signed the authentic response envelope
        victim_resp_payload = {
            'data': base64.b64encode(chunk_0).decode('utf-8'),
            'chunk_index': 0,
            'filename': 'authentic.bin',
            'proof': valid_proof_0
        }
        canonical = json.dumps(victim_resp_payload, sort_keys=True).encode('utf-8')
        victim_sig = victim_id.sign_data(canonical)

        signed_receipt = {
            'sender_id': victim_id.peer_id,
            'public_key': victim_id.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(victim_sig).decode('utf-8'),
            'payload': victim_resp_payload
        }

        # Attacker crafts false corruption alert attaching the valid chunk and proof
        framing_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_id.peer_id,
            'filename': 'authentic.bin',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(chunk_0).decode('utf-8'),
            'expected_root': tree.root,
            'proof': valid_proof_0,
            'signed_response': signed_receipt,
            'reason': 'I swear this chunk is corrupt!'
        }

        # 1. Direct verify
        is_valid, reason = node.verify_corruption_proof(framing_alert, attacker_id.peer_id)
        assert not is_valid
        assert reason == "CHUNK_PASSES_MERKLE_VERIFICATION_FRAMING_ATTACK"

        # 2. Over TCP socket
        response = await send_message_to_server("127.0.0.1", port, attacker_id, framing_alert)
        assert response.get('status') == 'ALERT_REJECTED'
        assert response.get('reason') == 'CHUNK_PASSES_MERKLE_VERIFICATION_FRAMING_ATTACK'

        # 3. Assert victim is totally unharmed
        assert node.reputation.get_trust_score(victim_id.peer_id) == 50
        assert not node.reputation.is_provider_quarantined(victim_id.peer_id, "authentic.bin")

    @pytest.mark.asyncio
    async def test_false_alert_with_locally_stored_identical_chunk_rejected(self, p2p_server_node, identity_factory):
        """
        Adversary sends an alert with a chunk for a file that the receiving node
        has stored locally. The chunk matches the local authentic chunk byte-for-byte.
        Receiver identifies chunk is authentic, rejects alert with CHUNK_IS_NOT_CORRUPT_FRAMING_ATTACK,
        and protects victim.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_local")
        victim_id = identity_factory("victim_local")

        node.reputation.add_peer(victim_id.peer_id)

        # Store authentic file locally in node's storage
        local_filename = "shared_dataset.txt"
        local_content = b"Local verified content that is 100% genuine and safe."
        local_file_path = os.path.join(node.file_manager.storage_dir, local_filename)
        with open(local_file_path, "wb") as f:
            f.write(local_content)

        node.scan_local_directory()
        assert local_filename in node.available_files
        local_root = node.available_files[local_filename]['merkle_root']

        # Attacker sends alert claiming local authentic chunk 0 is corrupt
        framing_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_id.peer_id,
            'filename': local_filename,
            'chunk_index': 0,
            'chunk_data': base64.b64encode(local_content).decode('utf-8'),
            'expected_root': local_root,
            'reason': 'False alarm attack'
        }

        is_valid, reason = node.verify_corruption_proof(framing_alert, attacker_id.peer_id)
        assert not is_valid
        assert reason == "CHUNK_IS_NOT_CORRUPT_FRAMING_ATTACK"

        # Over network
        response = await send_message_to_server("127.0.0.1", port, attacker_id, framing_alert)
        assert response.get('status') == 'ALERT_REJECTED'
        assert response.get('reason') == 'CHUNK_IS_NOT_CORRUPT_FRAMING_ATTACK'

        # Victim unharmed
        assert node.reputation.get_trust_score(victim_id.peer_id) == 50
        assert not node.reputation.is_provider_quarantined(victim_id.peer_id, local_filename)

    # =========================================================================
    # 3. Proven Corruption Alert
    # =========================================================================

    @pytest.mark.asyncio
    async def test_proven_corruption_alert_quarantines_and_penalizes_provider(self, p2p_server_node, identity_factory):
        """
        Downloader catches a rogue provider serving a corrupted chunk.
        Downloader broadcasts a CORRUPTION_ALERT containing:
        - The provider's authentic signed response envelope serving the bad chunk
        - The corrupted chunk bytes
        - The expected Merkle root and proof (which fails verification)
        Receiver verifies the provider signed the corrupted chunk and proof failed,
        quarantines the provider for this file, and docks trust score (-25).
        """
        node, port = p2p_server_node
        reporter_id = identity_factory("reporter_honest")
        bad_provider_id = identity_factory("malicious_provider_3")

        node.reputation.add_peer(bad_provider_id.peer_id)
        assert node.reputation.get_trust_score(bad_provider_id.peer_id) == 50

        # Authentic file expected root
        authentic_data = b"Authentic chunk that was supposed to be delivered"
        authentic_tree = MerkleTree([authentic_data])
        expected_root = authentic_tree.root

        # Bad provider delivered tampered chunk
        corrupted_data = b"CORRUPTED_AND_MUTATED_DATA_BYTES_FROM_ATTACKER"
        b64_corrupted = base64.b64encode(corrupted_data).decode('utf-8')

        # Authentic proof against expected_root fails for corrupted_data
        bogus_proof = authentic_tree.get_proof(0)
        assert not MerkleTree.verify_chunk_proof(corrupted_data, 0, bogus_proof, expected_root)

        # Bad provider signed their response envelope when serving the chunk
        # (models P2PNode.handle_get_chunk which includes proof, merkle_root, file_id)
        provider_resp_payload = {
            'data': b64_corrupted,
            'chunk_index': 0,
            'filename': 'database.db',
            'merkle_root': expected_root,
            'file_id': expected_root,
            'proof': bogus_proof
        }
        canonical = json.dumps(provider_resp_payload, sort_keys=True).encode('utf-8')
        prov_sig = bad_provider_id.sign_data(canonical)

        provider_signed_receipt = {
            'sender_id': bad_provider_id.peer_id,
            'public_key': bad_provider_id.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(prov_sig).decode('utf-8'),
            'payload': provider_resp_payload
        }

        alert_payload = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': reporter_id.peer_id,
            'sender_name': 'HonestReporter',
            'corrupted_peer_id': bad_provider_id.peer_id,
            'corrupted_peer_name': 'MaliciousProvider3',
            'filename': 'database.db',
            'chunk_index': 0,
            'chunk_data': b64_corrupted,
            'expected_root': expected_root,
            'proof': bogus_proof,
            'signed_response': provider_signed_receipt,
            'reason': 'Merkle proof verification failed for chunk 0'
        }

        # 1. Direct verification
        is_valid, reason = node.verify_corruption_proof(alert_payload, reporter_id.peer_id)
        assert is_valid
        assert reason == "PROVEN_CORRUPT_MERKLE_PROOF_FAILURE"

        # 2. Live network transmission
        response = await send_message_to_server("127.0.0.1", port, reporter_id, alert_payload)
        assert response.get('status') == 'ALERT_RECEIVED'

        # 3. Assert provider is quarantined and docked -25 points
        assert node.reputation.is_provider_quarantined(bad_provider_id.peer_id, "database.db")
        assert node.reputation.get_trust_score(bad_provider_id.peer_id) == 25  # 50 - 25

        # Alert recorded in security_alerts
        assert any(a['bad_peer_id'] == bad_provider_id.peer_id for a in node.security_alerts)

    # =========================================================================
    # 4. Multi-Provider Swarm with 1 Bad Provider
    # =========================================================================

    @pytest.mark.asyncio
    async def test_swarm_download_strictly_penalizes_bad_provider_and_rewards_honest_provider(self, node_factory, identity_factory):
        """
        Adversarial multi-provider swarm download:
        - 2 providers in swarm: BadProvider and HonestProvider.
        - 2-chunk file.
        - BadProvider serves corrupted chunk 0.
        - Downloader detects cryptographic Merkle failure:
          * Discards corrupted chunk immediately (no storage on disk).
          * Strictly penalizes and quarantines BadProvider.
          * Rotates to HonestProvider for chunk 0, which passes verification.
          * HonestProvider is rewarded (+2).
        - For chunk 1: BadProvider is quarantined and skipped; HonestProvider serves chunk 1.
        - Verification assertions:
          * Download completes successfully and file matches expected root.
          * BadProvider trust score is strictly docked (50 -> 25) and is quarantined.
          * HonestProvider trust score is strictly rewarded (50 -> 54) and NOT quarantined.
          * NO loop scoping leak!
        """
        node = node_factory("downloader_node")

        bad_identity = identity_factory("bad_provider_swarm")
        honest_identity = identity_factory("honest_provider_swarm")

        bad_id = bad_identity.peer_id
        honest_id = honest_identity.peer_id

        node.reputation.add_peer(bad_id)
        node.reputation.add_peer(honest_id)

        assert node.reputation.get_trust_score(bad_id) == 50
        assert node.reputation.get_trust_score(honest_id) == 50

        # Construct 2-chunk file and tree (chunk 0 must be CHUNK_SIZE = 64KB so split_file re-chunks identically)
        chunk_0_good = b"A" * (64 * 1024)
        chunk_1_good = b"B" * 1024
        tree = MerkleTree([chunk_0_good, chunk_1_good])
        expected_root = tree.root

        proof_0 = tree.get_proof(0)
        proof_1 = tree.get_proof(1)

        corrupt_chunk_0 = b"Z" * (64 * 1024)

        # Mock _send_request to dynamically simulate responses from bad vs honest provider
        async def mock_send_request(host, port, payload):
            chunk_idx = payload.get('chunk_index')

            # Identify if request went to bad or honest provider by port
            if port == 8001:  # Bad Provider
                corrupt_b64 = base64.b64encode(corrupt_chunk_0).decode('utf-8')
                resp_payload = {
                    'type': 'CHUNK_DATA',
                    'filename': 'multi_swarm.bin',
                    'chunk_index': chunk_idx,
                    'data': corrupt_b64,
                    'proof': proof_0  # Won't match corrupt chunk
                }
                canonical = json.dumps(resp_payload, sort_keys=True).encode('utf-8')
                sig = bad_identity.sign_data(canonical)
                resp_payload['_envelope'] = {
                    'sender_id': bad_id,
                    'public_key': bad_identity.get_public_key_pem().decode('utf-8'),
                    'signature': base64.b64encode(sig).decode('utf-8'),
                    'payload': resp_payload
                }
                return resp_payload

            elif port == 8002:  # Honest Provider
                chunk_data = chunk_0_good if chunk_idx == 0 else chunk_1_good
                proof = proof_0 if chunk_idx == 0 else proof_1
                good_b64 = base64.b64encode(chunk_data).decode('utf-8')
                resp_payload = {
                    'type': 'CHUNK_DATA',
                    'filename': 'multi_swarm.bin',
                    'chunk_index': chunk_idx,
                    'data': good_b64,
                    'proof': proof
                }
                canonical = json.dumps(resp_payload, sort_keys=True).encode('utf-8')
                sig = honest_identity.sign_data(canonical)
                resp_payload['_envelope'] = {
                    'sender_id': honest_id,
                    'public_key': honest_identity.get_public_key_pem().decode('utf-8'),
                    'signature': base64.b64encode(sig).decode('utf-8'),
                    'payload': resp_payload
                }
                return resp_payload

            return None

        node._send_request = AsyncMock(side_effect=mock_send_request)

        # Providers list with BadProvider first for chunk 0
        providers = [
            ("127.0.0.1", 8001, bad_id, "BadProvider"),
            ("127.0.0.1", 8002, honest_id, "HonestProvider")
        ]

        filename = "multi_swarm.bin"
        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=2
        )

        assert success is True, "Download must succeed by falling back to honest provider"

        # Verify final file integrity
        final_path = os.path.join(node.file_manager.storage_dir, filename)
        assert os.path.exists(final_path)
        with open(final_path, 'rb') as f:
            final_content = f.read()
        assert final_content == (chunk_0_good + chunk_1_good)

        # CRITICAL REPUTATION ASSERTIONS:
        # 1. Bad provider MUST be docked by 25 points and quarantined
        assert node.reputation.is_provider_quarantined(bad_id, filename) is True
        assert node.reputation.get_trust_score(bad_id) == 25

        # 2. Honest provider MUST NOT be quarantined and MUST be rewarded (+2 per valid chunk = 54)
        assert node.reputation.is_provider_quarantined(honest_id, filename) is False
        assert node.reputation.get_trust_score(honest_id) == 54

        # 3. No tracking leaks
        assert filename not in node.downloading_files

    # =========================================================================
    # 5. Cancel Download Task in Flight
    # =========================================================================

    @pytest.mark.asyncio
    async def test_cancel_download_task_in_flight_cleans_tracking_and_temp_dir(self, node_factory, identity_factory):
        """
        Adversarial test: Cancel a download task while it is mid-flight.
        - Chunk 0 is received and written to the temp directory.
        - While waiting for Chunk 1, the task is cancelled (asyncio.CancelledError).
        - Assert:
          1. downloading_files[filename] is purged.
          2. downloading_files[expected_root] is purged.
          3. The temporary storage directory (filename_temp) is completely deleted from disk.
          4. No residual chunk files remain on the filesystem.
        """
        node = node_factory("cancel_test_node")
        filename = "interrupted_file.dat"
        provider_id = identity_factory("provider_cancel").peer_id

        chunk_0_data = b"CHUNK_0_SAVED_BEFORE_CANCEL" * 50
        chunk_1_data = b"CHUNK_1_NEVER_SAVED" * 50
        tree = MerkleTree([chunk_0_data, chunk_1_data])
        expected_root = tree.root

        download_started_event = asyncio.Event()

        async def mock_slow_send_request(host, port, payload):
            idx = payload.get('chunk_index')
            if idx == 0:
                b64_data = base64.b64encode(chunk_0_data).decode('utf-8')
                return {
                    'type': 'CHUNK_DATA',
                    'filename': filename,
                    'chunk_index': 0,
                    'data': b64_data,
                    'proof': tree.get_proof(0)
                }
            elif idx == 1:
                # Signal that chunk 0 has been processed and chunk 1 is now in-flight
                download_started_event.set()
                # Hang to allow cancellation in flight
                await asyncio.sleep(10.0)
                return None

        node._send_request = AsyncMock(side_effect=mock_slow_send_request)
        providers = [("127.0.0.1", 9999, provider_id, "SlowProvider")]

        # Launch download in background task
        task = asyncio.create_task(
            node.download_file_from_swarm(
                filename=filename,
                providers=providers,
                expected_root=expected_root,
                total_chunks=2
            )
        )

        # Wait until chunk 0 is saved and chunk 1 is pending
        await asyncio.wait_for(download_started_event.wait(), timeout=3.0)

        temp_dir = os.path.join(node.file_manager.storage_dir, f"{filename}_temp")
        chunk_0_path = os.path.join(temp_dir, "chunk_0")

        # Verify intermediate in-flight state
        assert filename in node.downloading_files
        assert os.path.exists(temp_dir)
        assert os.path.exists(chunk_0_path)

        # CANCEL IN FLIGHT
        task.cancel()

        # Wait for task cancellation to complete
        with pytest.raises(asyncio.CancelledError):
            await task

        # VERIFY STATE CLEANUP GUARANTEES (F18):
        # 1. downloading_files is completely empty of this file
        assert filename not in node.downloading_files
        assert expected_root not in node.downloading_files

        # 2. Temp directory and all partial chunks are completely purged
        assert not os.path.exists(temp_dir), f"Temp dir {temp_dir} must be deleted upon cancellation"
        assert not os.path.exists(chunk_0_path)

    # =========================================================================
    # 6. Cumulative Corruption Blacklisting & Isolation
    # =========================================================================

    @pytest.mark.asyncio
    async def test_repeated_proven_corruption_blacklists_offending_peer(self, node_factory, identity_factory):
        """
        When a peer accumulates repeated proven corruption incidents:
        - 1st incident: trust score 50 -> 25 (quarantined)
        - 2nd incident: trust score 25 -> 0  (automatically blacklisted)
        Once blacklisted, all outbound requests and inbound interactions are blocked.
        """
        node = node_factory("blacklist_tester")
        bad_peer = identity_factory("repeat_offender")
        bad_id = bad_peer.peer_id

        node.reputation.add_peer(bad_id)
        assert node.reputation.get_trust_score(bad_id) == 50
        assert not node.reputation.is_blacklisted(bad_id)

        # First corruption incident
        score_1 = node.reputation.quarantine_provider_for_file(bad_id, "file1.bin", reason="First corruption")
        assert score_1 == 25
        assert node.reputation.get_trust_score(bad_id) == 25
        assert not node.reputation.is_blacklisted(bad_id)

        # Second corruption incident
        score_2 = node.reputation.quarantine_provider_for_file(bad_id, "file2.bin", reason="Second corruption")
        assert score_2 == 0
        assert node.reputation.get_trust_score(bad_id) == 0
        assert node.reputation.is_blacklisted(bad_id) is True

        # Inbound request from blacklisted peer is blocked
        mock_writer = AsyncMock()
        await node.handle_get_chunk(
            {'filename': 'file3.bin', 'chunk_index': 0},
            mock_writer,
            sender_id=bad_id
        )
        mock_writer.write.assert_not_called()

    # =========================================================================
    # 7. Advanced Adversarial Challenges: Anti-Framing Boundary Stress-Tests
    # =========================================================================

    @pytest.mark.asyncio
    async def test_adversarial_framing_by_substituting_bogus_proof(self, p2p_server_node, identity_factory):
        """
        Adversarial Challenge: Framing attack via Proof Substitution.
        Honest provider serves a valid chunk with a valid Merkle proof.
        Attacker replaces the proof with a bogus proof (not signed by provider)
        and submits a CORRUPTION_ALERT to a node that lacks the file locally.
        Zero-trust anti-framing MUST reject this alert and NOT dock the provider.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_proof_sub")
        victim_provider = identity_factory("victim_honest_provider")

        node.reputation.add_peer(victim_provider.peer_id)
        assert node.reputation.get_trust_score(victim_provider.peer_id) == 50

        # Authentic chunk and tree
        valid_chunk = b"VALID_AUTHENTIC_CHUNK_CONTENT_123" * 50
        tree = MerkleTree([valid_chunk])
        expected_root = tree.root
        valid_proof = tree.get_proof(0)

        # Provider honestly signed response with valid chunk and valid proof
        provider_resp = {
            'data': base64.b64encode(valid_chunk).decode('utf-8'),
            'chunk_index': 0,
            'filename': 'framing_target.bin',
            'proof': valid_proof
        }
        canonical = json.dumps(provider_resp, sort_keys=True).encode('utf-8')
        sig = victim_provider.sign_data(canonical)
        signed_receipt = {
            'sender_id': victim_provider.peer_id,
            'public_key': victim_provider.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(sig).decode('utf-8'),
            'payload': provider_resp
        }

        # Attacker substitutes a bogus proof
        bogus_proof = [["left", "00" * 32]]

        framing_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_provider.peer_id,
            'filename': 'framing_target.bin',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(valid_chunk).decode('utf-8'),
            'expected_root': expected_root,
            'proof': bogus_proof,
            'signed_response': signed_receipt,
            'reason': 'Attacker claiming chunk is corrupt with fake proof'
        }

        # System under review: MUST reject alert to prevent framing
        is_valid, reason = node.verify_corruption_proof(framing_alert, attacker_id.peer_id)
        assert not is_valid, (
            f"VULNERABILITY: Honest provider framed! Alert was accepted with reason '{reason}' "
            "because receiver failed to verify that proof came from provider's signed receipt."
        )

    @pytest.mark.asyncio
    async def test_adversarial_framing_by_omitting_proof_and_supplying_reason(self, p2p_server_node, identity_factory):
        """
        Adversarial Challenge: Framing attack via Omitted Proof & Reason Injection.
        Honest provider serves a valid chunk.
        Attacker submits CORRUPTION_ALERT with victim's signed receipt, sets proof=None,
        and provides an arbitrary reason string.
        Zero-trust anti-framing MUST reject this alert and NOT dock the provider.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_omitted_proof")
        victim_provider = identity_factory("victim_provider_reason")

        node.reputation.add_peer(victim_provider.peer_id)
        assert node.reputation.get_trust_score(victim_provider.peer_id) == 50

        valid_chunk = b"ANOTHER_AUTHENTIC_CHUNK_CONTENT_456" * 50
        tree = MerkleTree([valid_chunk])
        expected_root = tree.root

        provider_resp = {
            'data': base64.b64encode(valid_chunk).decode('utf-8'),
            'chunk_index': 0,
            'filename': 'target_reason.bin'
        }
        canonical = json.dumps(provider_resp, sort_keys=True).encode('utf-8')
        sig = victim_provider.sign_data(canonical)
        signed_receipt = {
            'sender_id': victim_provider.peer_id,
            'public_key': victim_provider.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(sig).decode('utf-8'),
            'payload': provider_resp
        }

        # Attacker omits proof and supplies reason
        framing_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_provider.peer_id,
            'filename': 'target_reason.bin',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(valid_chunk).decode('utf-8'),
            'expected_root': expected_root,
            'proof': None,
            'signed_response': signed_receipt,
            'reason': 'Arbitrary attacker reason string'
        }

        # System under review: MUST reject alert to prevent framing
        is_valid, reason = node.verify_corruption_proof(framing_alert, attacker_id.peer_id)
        assert not is_valid, (
            f"VULNERABILITY: Honest provider framed! Alert was accepted with reason '{reason}' "
            "because receiver accepted alert_payload.reason without cryptographic proof."
        )

    @pytest.mark.asyncio
    async def test_adversarial_framing_by_root_substitution(self, p2p_server_node, identity_factory):
        """
        Adversarial Challenge: Root Substitution Framing Exploit.
        Honest provider serves valid chunk with authentic Merkle root.
        Attacker crafts CORRUPTION_ALERT with victim's genuine signed response,
        but substitutes a bogus expected_root so Merkle verification fails.
        Receiver MUST reject alert with ROOT_MISMATCH_WITH_SIGNED_RESPONSE.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_root_sub")
        victim_provider = identity_factory("victim_root_sub")

        node.reputation.add_peer(victim_provider.peer_id)
        assert node.reputation.get_trust_score(victim_provider.peer_id) == 50

        valid_chunk = b"AUTHENTIC_DATA_ROOT_SUB_TEST" * 50
        tree = MerkleTree([valid_chunk])
        expected_root = tree.root
        valid_proof = tree.get_proof(0)

        provider_resp = {
            'type': 'CHUNK_DATA',
            'sender_id': victim_provider.peer_id,
            'filename': 'valid_file.bin',
            'file_id': expected_root,
            'merkle_root': expected_root,
            'chunk_index': 0,
            'data': base64.b64encode(valid_chunk).decode('utf-8'),
            'proof': valid_proof
        }
        canonical = json.dumps(provider_resp, sort_keys=True).encode('utf-8')
        sig = victim_provider.sign_data(canonical)
        signed_receipt = {
            'sender_id': victim_provider.peer_id,
            'public_key': victim_provider.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(sig).decode('utf-8'),
            'payload': provider_resp
        }

        # Attacker substitutes a bogus expected_root
        bogus_root = "0" * 64
        framing_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_provider.peer_id,
            'filename': 'valid_file.bin',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(valid_chunk).decode('utf-8'),
            'expected_root': bogus_root,
            'proof': valid_proof,
            'signed_response': signed_receipt,
            'reason': 'Framing honest provider with fake root'
        }

        is_valid, reason = node.verify_corruption_proof(framing_alert, attacker_id.peer_id)
        assert not is_valid
        assert reason == "ROOT_MISMATCH_WITH_SIGNED_RESPONSE"
        assert node.reputation.get_trust_score(victim_provider.peer_id) == 50

    @pytest.mark.asyncio
    async def test_adversarial_framing_by_chunk_index_or_filename_mismatch(self, p2p_server_node, identity_factory):
        """
        Adversarial Challenge: Chunk Index and Filename Context Mismatch.
        Attacker crafts CORRUPTION_ALERT with victim's signed response for chunk 0 / file A,
        but claims corruption for chunk 1 or file B.
        Receiver MUST reject with appropriate context mismatch reason.
        """
        node, port = p2p_server_node
        attacker_id = identity_factory("attacker_context_sub")
        victim_provider = identity_factory("victim_context_sub")

        valid_chunk = b"AUTHENTIC_DATA_CONTEXT_SUB_TEST" * 50
        tree = MerkleTree([valid_chunk])
        expected_root = tree.root

        provider_resp = {
            'type': 'CHUNK_DATA',
            'sender_id': victim_provider.peer_id,
            'filename': 'file_a.bin',
            'file_id': expected_root,
            'merkle_root': expected_root,
            'chunk_index': 0,
            'data': base64.b64encode(valid_chunk).decode('utf-8'),
            'proof': tree.get_proof(0)
        }
        canonical = json.dumps(provider_resp, sort_keys=True).encode('utf-8')
        sig = victim_provider.sign_data(canonical)
        signed_receipt = {
            'sender_id': victim_provider.peer_id,
            'public_key': victim_provider.get_public_key_pem().decode('utf-8'),
            'signature': base64.b64encode(sig).decode('utf-8'),
            'payload': provider_resp
        }

        # 1. Index mismatch test: signed index is 0, alert claims index 1
        index_mismatch_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_provider.peer_id,
            'filename': 'file_a.bin',
            'chunk_index': 1,
            'chunk_data': base64.b64encode(valid_chunk).decode('utf-8'),
            'expected_root': expected_root,
            'proof': tree.get_proof(0),
            'signed_response': signed_receipt
        }
        is_valid, reason = node.verify_corruption_proof(index_mismatch_alert, attacker_id.peer_id)
        assert not is_valid
        assert reason == "CHUNK_INDEX_MISMATCH_WITH_SIGNED_RESPONSE"

        # 2. Filename mismatch test: signed filename is file_a.bin, alert claims file_b.bin
        filename_mismatch_alert = {
            'type': 'CORRUPTION_ALERT',
            'sender_id': attacker_id.peer_id,
            'corrupted_peer_id': victim_provider.peer_id,
            'filename': 'file_b.bin',
            'chunk_index': 0,
            'chunk_data': base64.b64encode(valid_chunk).decode('utf-8'),
            'expected_root': expected_root,
            'proof': tree.get_proof(0),
            'signed_response': signed_receipt
        }
        is_valid, reason = node.verify_corruption_proof(filename_mismatch_alert, attacker_id.peer_id)
        assert not is_valid
        assert reason == "FILENAME_MISMATCH_WITH_SIGNED_RESPONSE"
