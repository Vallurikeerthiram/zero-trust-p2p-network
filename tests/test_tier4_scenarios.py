import os
import base64
import pytest
import asyncio
from unittest.mock import AsyncMock
from src.core.crypto import MerkleTree
from src.core.file_manager import FileManager


class TestTier4Scenarios:
    """Tier 4 - Real-World Scenarios: End-to-End File Sharing, Swarm Self-Healing, & Edge File Cycles."""

    @pytest.mark.asyncio
    async def test_scenario_full_file_sharing_lifecycle(self, node_factory, small_file):
        """Scenario 1: Full lifecycle — split file, advertise, download from peer, verify, and reassemble."""
        fpath, original_data = small_file
        filename = os.path.basename(fpath)

        # Provider node
        provider = node_factory("provider_node")
        provider_storage_file = os.path.join(provider.file_manager.storage_dir, filename)
        with open(provider_storage_file, "wb") as f:
            f.write(original_data)
        provider.scan_local_directory()

        file_meta = provider.available_files[filename]
        expected_root = file_meta["merkle_root"]
        total_chunks = file_meta["total_chunks"]

        # Downloader node
        downloader = node_factory("downloader_node")

        # Mock direct network request to provider's file manager
        async def mock_network_transfer(host, port, payload):
            if payload.get("type") == "GET_CHUNK":
                idx = payload["chunk_index"]
                target_path = os.path.join(provider.file_manager.storage_dir, payload["filename"])
                chunk = provider.file_manager.get_chunk(target_path, idx)
                if chunk:
                    return {
                        "type": "CHUNK_DATA",
                        "filename": payload["filename"],
                        "chunk_index": idx,
                        "data": base64.b64encode(chunk).decode("utf-8")
                    }
            return None

        downloader._send_request = mock_network_transfer

        providers = [(provider.host, provider.port, provider.peer_id, "ProviderNode")]
        download_success = await downloader.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=total_chunks
        )

        assert download_success is True

        # Verify reassembled file on downloader
        downloaded_file = os.path.join(downloader.file_manager.storage_dir, filename)
        assert os.path.exists(downloaded_file)
        with open(downloaded_file, "rb") as f:
            downloaded_bytes = f.read()

        assert downloaded_bytes == original_data
        # Verify provider gained reputation
        assert downloader.reputation.get_trust_score(provider.peer_id) >= 50

    @pytest.mark.asyncio
    async def test_scenario_corrupted_peer_detection_quarantine_and_failover(self, node_factory):
        """Scenario 2: Malicious peer serves tampered chunk; downloader quarantines it and fails over to honest peer."""
        filename = "contract.pdf"
        chunk_0_honest = b"Legitimate contract agreement signed by parties"
        tree = MerkleTree([chunk_0_honest])
        expected_root = tree.root

        honest_node = node_factory("honest_provider")
        malicious_node = node_factory("malicious_provider")
        downloader = node_factory("auditing_downloader")

        # Configure reputations
        downloader.reputation.add_peer(honest_node.peer_id)
        downloader.reputation.add_peer(malicious_node.peer_id)

        # Mock network responses: malicious serves corrupted, honest serves authentic
        async def mock_swarm_network(host, port, payload):
            p_id = None
            if port == malicious_node.port:
                # Malicious node sends corrupted chunk
                corrupted_data = b"CORRUPT_POISONED_PAYLOAD_" + chunk_0_honest
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": 0,
                    "data": base64.b64encode(corrupted_data).decode("utf-8")
                }
            elif port == honest_node.port:
                # Honest node sends valid chunk
                return {
                    "type": "CHUNK_DATA",
                    "filename": filename,
                    "chunk_index": 0,
                    "data": base64.b64encode(chunk_0_honest).decode("utf-8")
                }
            return None

        downloader._send_request = mock_swarm_network

        # Providers list with malicious first, honest second
        providers = [
            (malicious_node.host, malicious_node.port, malicious_node.peer_id, "MaliciousNode"),
            (honest_node.host, honest_node.port, honest_node.peer_id, "HonestNode")
        ]

        success = await downloader.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=1
        )

        assert success is True, "Downloader should have failed over and succeeded"

        # Check that malicious node was quarantined for this file
        assert downloader.reputation.is_provider_quarantined(malicious_node.peer_id, filename) is True

        # Check that malicious node was penalized (-25)
        assert downloader.reputation.get_trust_score(malicious_node.peer_id) <= 25

        # Check reassembled file matches authentic content
        out_file = os.path.join(downloader.file_manager.storage_dir, filename)
        assert os.path.exists(out_file)
        with open(out_file, "rb") as f:
            assert f.read() == chunk_0_honest

    @pytest.mark.asyncio
    async def test_scenario_zero_byte_file_sharing_lifecycle(self, node_factory, zero_byte_file):
        """Scenario 3: 0-byte file shared, advertised, downloaded, and reassembled without errors."""
        filename = os.path.basename(zero_byte_file)

        provider = node_factory("zero_byte_provider")
        prov_file = os.path.join(provider.file_manager.storage_dir, filename)
        with open(prov_file, "wb") as f:
            pass  # 0 bytes

        provider.scan_local_directory()
        assert filename in provider.available_files
        meta = provider.available_files[filename]
        assert meta["total_chunks"] == 0
        expected_root = meta["merkle_root"]

        downloader = node_factory("zero_byte_downloader")
        downloader._send_request = AsyncMock(return_value=None)

        providers = [(provider.host, provider.port, provider.peer_id, "ZeroProvider")]

        # Download 0-byte file (0 chunks)
        success = await downloader.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=expected_root,
            total_chunks=0
        )

        assert success is True

        # Check downloaded file
        down_file = os.path.join(downloader.file_manager.storage_dir, filename)
        assert os.path.exists(down_file)
        assert os.path.getsize(down_file) == 0
