import os
import re
import pytest
from src.core.p2p_node import P2PNode


class TestMilestone4Hygiene:
    """Tests verifying Milestone 4: UI thread safety, packaging, and documentation alignment."""

    def test_dashboard_free_of_reload_and_monkey_patching(self):
        """Verify dashboard.py has eliminated all importlib.reload and runtime monkey patching."""
        dashboard_path = os.path.join("src", "app", "dashboard.py")
        assert os.path.exists(dashboard_path)
        with open(dashboard_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "importlib.reload" not in content, "Found importlib.reload in dashboard.py"
        assert "node.reputation.__class__" not in content, "Found monkey patching in dashboard.py"
        assert "P2PNode.handle_client.__get__" not in content, "Found method rebinding in dashboard.py"
        assert "time.sleep(0.2)" not in content, "Found artificial sleep delay in dashboard.py"

    def test_dashboard_uses_merkle_bound_network_files(self):
        """Verify dashboard.py uses get_network_files() to group files by Merkle root."""
        dashboard_path = os.path.join("src", "app", "dashboard.py")
        with open(dashboard_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "get_network_files" in content, "dashboard.py must use get_network_files()"
        assert "run_coroutine_threadsafe" in content, "dashboard.py must use thread-safe asyncio dispatch"
        assert "validate_filename" in content, "dashboard.py must validate uploaded filenames"

    def test_requirements_txt_completeness(self):
        """Verify requirements.txt declares all dependencies including reportlab and pytest."""
        req_path = "requirements.txt"
        assert os.path.exists(req_path)
        with open(req_path, "r", encoding="utf-8") as f:
            reqs = f.read().lower()

        required_packages = [
            "cryptography",
            "streamlit",
            "streamlit-autorefresh",
            "reportlab",
            "pytest",
            "pytest-asyncio"
        ]
        for pkg in required_packages:
            assert pkg in reqs, f"Missing {pkg} in requirements.txt"

    def test_readme_reputation_formula_alignment(self):
        """Verify README.md accurately reflects +2 reward, -25 penalty, and 0 blacklist threshold."""
        readme_path = "README.md"
        assert os.path.exists(readme_path)
        with open(readme_path, "r", encoding="utf-8") as f:
            readme = f.read()

        assert "+2" in readme, "README must document +2 reward"
        assert "-25" in readme, "README must document -25 penalty"
        assert "RFC 6962" in readme, "README must document RFC 6962 Merkle tree"
        assert "verify_chunk_proof" in readme, "README must document verify_chunk_proof"

    def test_broadcast_file_sync_callable(self, node_factory, small_file):
        """Verify broadcast_file_sync can be invoked cleanly from a synchronous caller."""
        fpath, _ = small_file
        node = node_factory("sync_broadcaster")
        # Copy file to node storage
        clean_name = os.path.basename(fpath)
        target = os.path.join(node.file_manager.storage_dir, clean_name)
        with open(target, "wb") as f_out, open(fpath, "rb") as f_in:
            f_out.write(f_in.read())

        root = node.broadcast_file_sync(target)
        assert root is not None
        assert len(root) == 64
        assert clean_name in node.available_files
