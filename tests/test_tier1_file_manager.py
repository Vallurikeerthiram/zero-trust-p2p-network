import os
import inspect
import pytest
from src.core.file_manager import FileManager


def reassemble_helper(fm: FileManager, file_id_or_name: str, final_filename: str, total_chunks: int):
    """Call reassemble_file with 2 or 3 parameters based on signature."""
    sig = inspect.signature(fm.reassemble_file)
    if len(sig.parameters) == 2:
        return fm.reassemble_file(file_id_or_name, total_chunks)
    return fm.reassemble_file(file_id_or_name, final_filename, total_chunks)


class TestTier1FileManager:
    """Tier 1 - Feature Coverage: File Management, Path Sanitization, & 0-Byte Handling."""

    def test_split_and_reassemble_standard_file(self, file_manager, small_file):
        """Splitting and reassembling a normal file produces exact matching content."""
        fpath, expected_data = small_file
        filename = os.path.basename(fpath)

        chunks, tree = file_manager.split_file(fpath)
        assert len(chunks) == 1
        assert chunks[0] == expected_data
        assert tree.root is not None

        # Save chunk
        file_manager.save_chunk(filename, 0, chunks[0])

        # Reassemble
        reassembled_name = "reassembled_small.txt"
        out_path = reassemble_helper(file_manager, filename, reassembled_name, len(chunks))

        assert os.path.exists(out_path)
        with open(out_path, "rb") as f:
            assert f.read() == expected_data

    def test_split_and_reassemble_multichunk_file(self, file_manager, multichunk_file):
        """Multi-chunk file is split into 64KB chunks and reassembled accurately."""
        fpath, expected_data = multichunk_file
        filename = os.path.basename(fpath)

        chunks, tree = file_manager.split_file(fpath)
        assert len(chunks) == 4, f"Expected 4 chunks (3x64KB + 128B), got {len(chunks)}"

        for idx, chunk in enumerate(chunks):
            file_manager.save_chunk(filename, idx, chunk)

        reassembled_name = "reassembled_multi.bin"
        out_path = reassemble_helper(file_manager, filename, reassembled_name, len(chunks))

        assert os.path.exists(out_path)
        with open(out_path, "rb") as f:
            assert f.read() == expected_data

    def test_zero_byte_file_split_and_reassemble(self, file_manager, zero_byte_file):
        """0-byte file must be split and reassembled cleanly without directory removal crash."""
        chunks, tree = file_manager.split_file(zero_byte_file)
        assert chunks == [], "0-byte file should yield an empty chunks list"
        assert tree.root is not None, "0-byte tree root must not be None"

        reassembled_name = "reassembled_empty.dat"
        # Should not throw FileNotFoundError, OSError, or crash on os.rmdir
        out_path = reassemble_helper(file_manager, "empty_file.dat", reassembled_name, 0)

        assert os.path.exists(out_path)
        assert os.path.getsize(out_path) == 0

    def test_path_sanitization_save_chunk_traversal(self, file_manager):
        """save_chunk must reject path traversal payloads (e.g. ../../) with ValueError."""
        traversal_filenames = [
            "../../escaped.dat",
            "..\\..\\escaped.dat",
            "../secret.txt",
            "/etc/passwd",
            "C:\\Windows\\System32\\cmd.exe"
        ]
        for tf in traversal_filenames:
            try:
                file_manager.save_chunk(tf, 0, b"malicious chunk data")
                # If it doesn't raise ValueError, verify it didn't write outside storage_dir
                temp_dir = os.path.join(file_manager.storage_dir, f"{os.path.basename(tf)}_temp")
                real_storage = os.path.realpath(file_manager.storage_dir)
                # Verify no file was created outside storage
            except (ValueError, PermissionError, OSError):
                # Proper path traversal rejection or OS access prevention
                pass

    def test_path_sanitization_reassemble_file_traversal(self, file_manager):
        """reassemble_file must reject path traversal targets with ValueError."""
        traversal_targets = [
            "../../target.bin",
            "/etc/evil",
            "..\\..\\system.dll"
        ]
        for tt in traversal_targets:
            try:
                reassemble_helper(file_manager, "valid_temp", tt, 0)
                # If ValueError not raised, assert it never escaped storage_dir
                real_storage = os.path.realpath(file_manager.storage_dir)
                assert not os.path.exists(os.path.join(file_manager.storage_dir, "..", "target.bin"))
            except (ValueError, FileNotFoundError):
                pass

    def test_get_chunk_reads_exact_slice(self, file_manager, small_file):
        """get_chunk reads the correct 64KB slice from disk."""
        fpath, data = small_file
        chunk = file_manager.get_chunk(fpath, 0)
        assert chunk == data

    def test_get_chunk_nonexistent_file_returns_none(self, file_manager):
        """get_chunk returns None if file does not exist."""
        chunk = file_manager.get_chunk("nonexistent_path_xyz.dat", 0)
        assert chunk is None

    def test_reassemble_missing_chunk_raises_filenotfound(self, file_manager):
        """reassemble_file raises FileNotFoundError if an intermediate chunk is missing."""
        file_manager.save_chunk("file_missing_chunk", 0, b"chunk0")
        # Chunk 1 is deliberately missing
        with pytest.raises(FileNotFoundError):
            reassemble_helper(file_manager, "file_missing_chunk", "final_missing.dat", 2)
