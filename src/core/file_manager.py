import os
from .crypto import MerkleTree

CHUNK_SIZE = 1024 * 64  # 64 KB chunks

class FileManager:
    def __init__(self, storage_dir="storage"):
        self.storage_dir = storage_dir
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)

    def split_file(self, file_path):
        """
        Reads a file and splits it into chunks.
        Returns a list of chunks and the Merkle tree.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} not found.")

        chunks = []
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)

        # Generate Merkle Tree
        merkle_tree = MerkleTree(chunks)
        return chunks, merkle_tree

    def save_chunk(self, file_name, chunk_index, chunk_data):
        """
        Save an individual chunk to disk (temporary).
        """
        temp_dir = os.path.join(self.storage_dir, f"{file_name}_temp")
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            
        chunk_path = os.path.join(temp_dir, f"chunk_{chunk_index}")
        with open(chunk_path, 'wb') as f:
            f.write(chunk_data)

    def reassemble_file(self, file_name, total_chunks):
        """
        Reassemble chunks into the final file.
        """
        temp_dir = os.path.join(self.storage_dir, f"{file_name}_temp")
        final_path = os.path.join(self.storage_dir, file_name)
        
        with open(final_path, 'wb') as f_out:
            for i in range(total_chunks):
                chunk_path = os.path.join(temp_dir, f"chunk_{i}")
                if os.path.exists(chunk_path):
                    with open(chunk_path, 'rb') as f_in:
                        f_out.write(f_in.read())
                else:
                    raise FileNotFoundError(f"Missing chunk {i} for {file_name}")

        # Cleanup temp directory
        for i in range(total_chunks):
            os.remove(os.path.join(temp_dir, f"chunk_{i}"))
        os.rmdir(temp_dir)
        
        return final_path
        
    def get_chunk(self, file_path, chunk_index):
        """
        Read a specific chunk from a local file.
        """
        if not os.path.exists(file_path):
            return None
            
        with open(file_path, 'rb') as f:
            f.seek(chunk_index * CHUNK_SIZE)
            return f.read(CHUNK_SIZE)
