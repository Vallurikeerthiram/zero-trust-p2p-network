import os
import shutil
from typing import List, Tuple, Optional
from .crypto import MerkleTree

CHUNK_SIZE = 1024 * 64  # 64 KB chunks

RESERVED_DEVICE_NAMES = {
    'CON', 'PRN', 'AUX', 'NUL',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
}

FORBIDDEN_FILENAME_CHARS = {'<', '>', ':', '"', '/', '\\', '|', '?', '*', '\0'}


class FileManager:
    """
    Secure zero-trust local file manager.
    Handles chunking, secure chunk storage, file reassembly, and chunk retrieval
    with strict path sanitization against directory traversal and support for 0-byte files.
    """

    def __init__(self, storage_dir: str = "storage"):
        self.storage_dir = os.path.abspath(storage_dir)
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir, exist_ok=True)

    @staticmethod
    def validate_filename(filename: str) -> str:
        """
        Validate and sanitize filename against directory traversal, control characters,
        null bytes, path separators, and reserved OS device names.
        Raises ValueError if invalid.
        """
        if not isinstance(filename, str):
            raise ValueError(f"Filename must be a string, got {type(filename).__name__}")
        if '\0' in filename:
            raise ValueError("Filename contains null byte")
        if not filename or not filename.strip():
            raise ValueError("Filename cannot be empty or whitespace only")
        if filename.strip() != filename:
            raise ValueError(f"Filename cannot have leading or trailing whitespace: {filename!r}")
        if '..' in filename:
            raise ValueError(f"Directory traversal detected ('..'): {filename!r}")
        if '/' in filename or '\\' in filename:
            raise ValueError(f"Directory separators not allowed in filename: {filename!r}")
        if os.path.basename(filename) != filename:
            raise ValueError(f"Filename cannot contain path components: {filename!r}")
        if os.path.isabs(filename) or (len(filename) >= 2 and filename[1] == ':'):
            raise ValueError(f"Absolute paths not allowed in filename: {filename!r}")
        if filename.startswith('//') or filename.startswith('\\\\'):
            raise ValueError(f"UNC paths not allowed: {filename!r}")
        if filename in ('.', '..'):
            raise ValueError(f"Invalid filename: {filename!r}")
        if filename.endswith('.'):
            raise ValueError(f"Filename cannot end with a period: {filename!r}")
        if any(c in FORBIDDEN_FILENAME_CHARS or ord(c) < 32 for c in filename):
            raise ValueError(f"Filename contains illegal or control characters: {filename!r}")

        # Check Windows reserved device names (e.g. CON.txt, NUL)
        stem = filename.split('.')[0].upper()
        if stem in RESERVED_DEVICE_NAMES:
            raise ValueError(f"Filename contains reserved system device name: {filename!r}")

        return filename

    def _resolve_safe_path(self, path_or_name: str) -> str:
        """
        Resolve path within self.storage_dir and verify sandbox containment via os.path.commonpath.
        Raises ValueError if path attempts directory traversal or escapes storage_dir.
        """
        if not isinstance(path_or_name, str):
            raise ValueError(f"Path must be a string, got {type(path_or_name).__name__}")
        if '\0' in path_or_name:
            raise ValueError("Path contains null byte")
        if '..' in path_or_name:
            raise ValueError(f"Directory traversal detected ('..'): {path_or_name!r}")

        base_abs = os.path.realpath(os.path.abspath(self.storage_dir))

        if os.path.isabs(path_or_name):
            target_abs = os.path.realpath(os.path.abspath(path_or_name))
        else:
            # If bare filename, validate syntax
            if '/' not in path_or_name and '\\' not in path_or_name:
                self.validate_filename(path_or_name)
            target_abs = os.path.realpath(os.path.abspath(os.path.join(base_abs, path_or_name)))

        try:
            common = os.path.commonpath([base_abs, target_abs])
        except ValueError as e:
            # On Windows, differing drive letters raise ValueError
            raise ValueError(f"Path outside storage directory (drive mismatch): {path_or_name!r}") from e

        if common != base_abs or target_abs == base_abs:
            raise ValueError(f"Path traversal detected: {path_or_name!r} is outside storage directory")

        return target_abs

    def split_file(self, file_path: str) -> Tuple[List[bytes], MerkleTree]:
        """
        Reads a file and splits it into chunks.
        Supports 0-byte files cleanly, returning ([], MerkleTree([])).
        Raises FileNotFoundError if file does not exist.
        """
        if not isinstance(file_path, str):
            raise ValueError(f"file_path must be a string, got {type(file_path).__name__}")
        if '\0' in file_path:
            raise ValueError("Path contains null byte")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")
        if os.path.isdir(file_path):
            raise ValueError(f"Path is a directory, not a regular file: {file_path}")

        chunks: List[bytes] = []
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)

        merkle_tree = MerkleTree(chunks)
        return chunks, merkle_tree

    def save_chunk(self, file_name: str, chunk_index: int, chunk_data: bytes) -> str:
        """
        Save an individual chunk to disk (temporary).
        Validates filename, chunk_index, and chunk_data.
        Raises ValueError on path traversal attempts or invalid types.
        """
        clean_name = self.validate_filename(file_name)
        if type(chunk_index) is not int or chunk_index < 0:
            raise ValueError(f"Invalid chunk_index: {chunk_index!r}. Must be non-negative integer.")
        if not isinstance(chunk_data, (bytes, bytearray)):
            raise ValueError(f"chunk_data must be bytes or bytearray, got {type(chunk_data).__name__}")

        temp_dir_name = f"{clean_name}_temp"
        temp_dir = self._resolve_safe_path(temp_dir_name)

        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, exist_ok=True)

        chunk_filename = f"chunk_{chunk_index}"
        chunk_path = os.path.abspath(os.path.join(temp_dir, chunk_filename))

        # Verify chunk_path is strictly inside temp_dir
        try:
            chunk_common = os.path.commonpath([temp_dir, chunk_path])
        except ValueError as e:
            raise ValueError(f"Path traversal detected in chunk path: {chunk_path}") from e
        if chunk_common != temp_dir or chunk_path == temp_dir:
            raise ValueError(f"Path traversal detected in chunk path: {chunk_path}")

        if os.path.exists(chunk_path):
            try:
                import stat
                os.chmod(chunk_path, stat.S_IWRITE | stat.S_IREAD)
            except Exception:
                pass

        with open(chunk_path, 'wb') as f:
            f.write(chunk_data)

        return chunk_path

    def reassemble_file(self, file_id: str, final_filename: str = None, total_chunks: int = None) -> str:
        """
        Reassemble chunks into final file.
        Supports:
          - reassemble_file(file_name, total_chunks)
          - reassemble_file(file_id, final_filename, total_chunks)
        Cleanly handles 0-byte files (total_chunks == 0) without directory cleanup crashes.
        """
        if isinstance(final_filename, int) and total_chunks is None:
            total_chunks = final_filename
            final_filename = file_id
        elif final_filename is None and isinstance(total_chunks, int):
            final_filename = file_id
        elif total_chunks is None:
            raise ValueError("total_chunks must be provided as a non-negative integer")

        clean_final_name = self.validate_filename(final_filename)
        clean_temp_name = self.validate_filename(file_id)

        if type(total_chunks) is not int or total_chunks < 0:
            raise ValueError(f"Invalid total_chunks: {total_chunks!r}. Must be non-negative integer.")

        final_path = self._resolve_safe_path(clean_final_name)
        temp_dir = self._resolve_safe_path(f"{clean_temp_name}_temp")

        # 0-byte file handling
        if total_chunks == 0:
            with open(final_path, 'wb'):
                pass  # create or truncate to empty file
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return final_path

        # total_chunks > 0 handling
        for i in range(total_chunks):
            chunk_path = os.path.join(temp_dir, f"chunk_{i}")
            if not os.path.exists(chunk_path):
                raise FileNotFoundError(f"Missing chunk {i} for {clean_final_name}")

        try:
            with open(final_path, 'wb') as f_out:
                for i in range(total_chunks):
                    chunk_path = os.path.join(temp_dir, f"chunk_{i}")
                    with open(chunk_path, 'rb') as f_in:
                        shutil.copyfileobj(f_in, f_out)
        except Exception:
            if os.path.exists(final_path):
                try:
                    os.remove(final_path)
                except OSError:
                    pass
            raise

        if os.path.exists(temp_dir):
            try:
                import stat
                for root, dirs, files in os.walk(temp_dir):
                    for fname in files:
                        p = os.path.join(root, fname)
                        try:
                            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
                        except Exception:
                            pass
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

        return final_path

    def get_chunk(self, file_path_or_name: str, chunk_index: int) -> Optional[bytes]:
        """
        Read a specific chunk from a local file.
        Validates target path is strictly within storage_dir.
        Raises ValueError on path traversal, null bytes, or invalid chunk_index.
        Returns chunk bytes, or None if file does not exist or chunk is past EOF.
        For 0-byte files, returns b'' for chunk 0, and None for chunk > 0.
        """
        if type(chunk_index) is not int or chunk_index < 0:
            raise ValueError(f"Invalid chunk_index: {chunk_index!r}. Must be non-negative integer.")

        target_path = self._resolve_safe_path(file_path_or_name)

        if not os.path.exists(target_path):
            return None
        if os.path.isdir(target_path):
            raise ValueError(f"Target path is a directory: {file_path_or_name!r}")

        file_size = os.path.getsize(target_path)
        if file_size == 0:
            if chunk_index == 0:
                return b""
            return None

        if chunk_index * CHUNK_SIZE >= file_size:
            return None

        with open(target_path, 'rb') as f:
            f.seek(chunk_index * CHUNK_SIZE)
            return f.read(CHUNK_SIZE)

    def delete_file(self, file_name: str) -> bool:
        """
        Safely delete a file from storage_dir with path traversal protection.
        """
        clean_name = self.validate_filename(file_name)
        target_path = self._resolve_safe_path(clean_name)
        if os.path.exists(target_path) and os.path.isfile(target_path):
            os.remove(target_path)
            return True
        return False
