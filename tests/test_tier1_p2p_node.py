import os
import pytest
import asyncio
from unittest.mock import AsyncMock, patch


class TestTier1P2PNode:
    """Tier 1 - Feature Coverage: P2P Node State, Tracking Cleanup, & Merkle Verification."""

    def test_node_initialization(self, node_factory):
        """Node initializes with correct peer_id, reputation engine, and clean tracking maps."""
        node = node_factory("node_init_test")
        assert len(node.peer_id) == 64
        assert node.peers == {}
        assert node.available_files == {}
        assert node.downloading_files == {}
        assert node.file_mtimes == {}

    def test_scan_local_directory_discovers_and_hashes_files(self, node_factory):
        """scan_local_directory discovers files and populates available_files with Merkle roots."""
        node = node_factory("node_scanner_test")
        sample_path = os.path.join(node.file_manager.storage_dir, "test_doc.txt")
        with open(sample_path, "wb") as f:
            f.write(b"Test content for directory scanner")

        node.scan_local_directory()
        assert "test_doc.txt" in node.available_files
        file_info = node.available_files["test_doc.txt"]
        assert "merkle_root" in file_info
        assert "total_chunks" in file_info
        assert file_info["total_chunks"] == 1
        assert file_info["merkle_root"] is not None

    def test_delete_local_file_cleans_all_state(self, node_factory):
        """delete_local_file removes file from storage and clears available_files and caches."""
        node = node_factory("node_delete_test")
        sample_path = os.path.join(node.file_manager.storage_dir, "to_delete.txt")
        with open(sample_path, "wb") as f:
            f.write(b"Disposable file")

        node.scan_local_directory()
        assert "to_delete.txt" in node.available_files

        node.delete_local_file("to_delete.txt")
        assert not os.path.exists(sample_path)
        assert "to_delete.txt" not in node.available_files
        assert "to_delete.txt" not in node.file_mtimes

    @pytest.mark.asyncio
    async def test_download_tracking_cleanup_on_success(self, node_factory):
        """downloading_files[filename] must be removed from tracking upon successful download."""
        node = node_factory("node_download_cleanup_ok")
        filename = "success_download.bin"
        chunk_data = b"Clean chunk payload"

        # Mock _send_request to return chunk data
        import base64
        b64_data = base64.b64encode(chunk_data).decode("utf-8")
        node._send_request = AsyncMock(return_value={
            "type": "CHUNK_DATA",
            "filename": filename,
            "chunk_index": 0,
            "data": b64_data
        })

        # Calculate authentic root
        from src.core.crypto import MerkleTree
        tree = MerkleTree([chunk_data])

        providers = [("127.0.0.1", 9999, "peer_mock_honest", "HonestNode")]

        # Run download
        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root=tree.root,
            total_chunks=1
        )

        assert success is True
        # CRITICAL: downloading_files entry must be cleaned up
        assert filename not in node.downloading_files, (
            "downloading_files[filename] must be cleared on download completion"
        )

    @pytest.mark.asyncio
    async def test_download_tracking_cleanup_on_failure(self, node_factory):
        """downloading_files[filename] must be cleared even if download fails or throws."""
        node = node_factory("node_download_cleanup_fail")
        filename = "failed_download.bin"

        # Mock _send_request to return None (simulating network failure)
        node._send_request = AsyncMock(return_value=None)

        providers = [("127.0.0.1", 9999, "peer_mock_down", "OfflineNode")]

        success = await node.download_file_from_swarm(
            filename=filename,
            providers=providers,
            expected_root="f" * 64,
            total_chunks=1
        )

        assert success is False
        # CRITICAL: downloading_files entry must be cleaned up in finally block
        assert filename not in node.downloading_files, (
            "downloading_files[filename] must be cleaned up in finally block upon failure"
        )
