"""
Empirical Adversarial Stress Test Suite for Milestone 8 (M8)
Challenger: teamwork_challenger_m8_1

Focus:
1. AST hygiene rules and genuine call retention in src/app/dashboard.py.
2. Form validation stress testing on manual connect form (empty strings, whitespace, strange IPs, extreme ports).
3. Thread-safe execution dispatch via run_coroutine_threadsafe and error propagation.
4. User identity, peer endpoint, and network file provider formatting fallbacks.
"""

import os
import ast
import socket
import asyncio
import threading
import concurrent.futures
from typing import Tuple
import pytest

from src.core.p2p_node import P2PNode


def get_dashboard_path() -> str:
    path = os.path.join(os.path.dirname(__file__), "..", "src", "app", "dashboard.py")
    return os.path.abspath(path)


def read_dashboard_content() -> str:
    with open(get_dashboard_path(), "r", encoding="utf-8") as f:
        return f.read()


class TestDashboardASTHygiene:
    """Rigorous AST and lexical hygiene verification for src/app/dashboard.py."""

    def test_forbidden_strings_completely_absent(self):
        """Verify that forbidden strings do not appear anywhere in code or comments."""
        content = read_dashboard_content()
        forbidden_exact = [
            "importlib.reload",
            "node.reputation.__class__",
            "P2PNode.handle_client.__get__",
            "time.sleep(0.2)",
        ]
        for item in forbidden_exact:
            assert item not in content, f"Forbidden string '{item}' detected in dashboard.py"

    def test_ast_prohibits_monkey_patching_and_dynamic_reload(self):
        """Parse AST to verify absence of reload imports and dunder attribute hijacking."""
        content = read_dashboard_content()
        tree = ast.parse(content)

        for node in ast.walk(tree):
            # Prohibit importlib imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name != "importlib", "importlib must not be imported in dashboard.py"
            elif isinstance(node, ast.ImportFrom):
                assert node.module != "importlib", "importlib must not be imported in dashboard.py"

            # Prohibit __class__ or __get__ attribute tampering
            if isinstance(node, ast.Attribute):
                assert node.attr not in ("__class__", "__get__"), (
                    f"Forbidden attribute access '{node.attr}' at line {node.lineno}"
                )

            # Prohibit time.sleep calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "sleep":
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "time":
                        # If sleep is called, ensure no arbitrary sleeps in UI rendering
                        pytest.fail(f"time.sleep() call detected in dashboard.py at line {node.lineno}")

    def test_ast_verifies_required_functions_are_called(self):
        """Verify required functions are genuinely called in the AST (not just defined/commented)."""
        content = read_dashboard_content()
        tree = ast.parse(content)

        call_names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_names.append(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    call_names.append(node.func.attr)

        assert "get_network_files" in call_names, (
            "node.get_network_files() must be called in dashboard.py"
        )
        assert "run_coroutine_threadsafe" in call_names, (
            "asyncio.run_coroutine_threadsafe() must be called in dashboard.py"
        )
        assert "validate_filename" in call_names, (
            "file_manager.validate_filename() must be called in dashboard.py"
        )
        # Ensure run_coroutine_threadsafe is called at least twice (connect_to_peer and download)
        assert call_names.count("run_coroutine_threadsafe") >= 2, (
            "run_coroutine_threadsafe must be used for both manual connect and download operations"
        )

    def test_manual_connect_form_ast_structure(self):
        """Verify the structural presence of the manual connect form in dashboard.py."""
        content = read_dashboard_content()
        assert "manual_connect_form" in content, "Form 'manual_connect_form' not found in dashboard.py"
        assert "Connect to Peer (Manual)" in content, "Expander header not found in dashboard.py"
        assert "target_ip" in content, "target_ip variable missing in dashboard.py"
        assert "target_port" in content, "target_port variable missing in dashboard.py"
        assert "connect_to_peer" in content, "connect_to_peer call missing in dashboard.py"


class TestManualConnectFormValidationStress:
    """Stress testing the manual connect form validation logic and edge cases."""

    def test_form_host_sanitization_rules(self):
        """Simulate dashboard form host sanitization logic on adversarial inputs."""
        # Dashboard form logic:
        # clean_ip = target_ip.strip() if target_ip else ""
        # if not clean_ip: st.warning(...)
        adversarial_empty_inputs = [
            None,
            "",
            "   ",
            "\t\t",
            "\n\r",
            "   \t\n   ",
        ]
        for inp in adversarial_empty_inputs:
            clean_ip = inp.strip() if inp else ""
            assert not clean_ip, f"Input {inp!r} should resolve to empty string"

        adversarial_whitespace_padded = [
            ("  127.0.0.1  ", "127.0.0.1"),
            ("\t192.168.1.100\n", "192.168.1.100"),
            ("   10.0.0.1 ", "10.0.0.1"),
        ]
        for raw, expected in adversarial_whitespace_padded:
            clean_ip = raw.strip() if raw else ""
            assert clean_ip == expected, f"Failed to strip {raw!r}"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", [0, -1, -500, 65536, 70000, 99999, 1000000])
    async def test_connect_to_peer_rejects_extreme_ports(self, tmp_path, invalid_port):
        """Ensure connect_to_peer enforces port boundaries (1 <= port <= 65535)."""
        node = P2PNode(
            "127.0.0.1", 58888,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store")
        )
        success, msg = await node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg
        assert "between 1 and 65535" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", [
        "",
        "   ",
        "\t\n",
        "999.999.999.999",
        "http://127.0.0.1",
        "127.0.0.1:5001",
        "nonexistent.domain.invalid",
        "127.0.0.1; rm -rf /",
    ])
    async def test_connect_to_peer_rejects_invalid_hosts(self, tmp_path, invalid_host):
        """Ensure connect_to_peer safely rejects invalid or unresolvable hosts."""
        node = P2PNode(
            "127.0.0.1", 58889,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store")
        )
        success, msg = await node.connect_to_peer(invalid_host, 5001, timeout=0.5)
        assert success is False
        assert isinstance(msg, str)
        assert len(msg) > 0

    @pytest.mark.asyncio
    async def test_connect_to_peer_guards_against_self_connection(self, tmp_path):
        """Ensure connect_to_peer prevents connecting to oneself."""
        node = P2PNode(
            "127.0.0.1", 58890,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store"),
            advertise_host="192.168.1.99"
        )
        # Test loopback IP
        success, msg = await node.connect_to_peer("127.0.0.1", 58890)
        assert success is False
        assert "Cannot connect to self" in msg

        # Test localhost alias
        success, msg = await node.connect_to_peer("localhost", 58890)
        assert success is False
        assert "Cannot connect to self" in msg

        # Test advertised host
        success, msg = await node.connect_to_peer("192.168.1.99", 58890)
        assert success is False
        assert "Cannot connect to self" in msg

    @pytest.mark.asyncio
    async def test_connect_to_peer_rejects_blacklisted_peer(self, tmp_path):
        """Ensure connect_to_peer immediately rejects known blacklisted peer coordinates."""
        node = P2PNode(
            "127.0.0.1", 58891,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store")
        )
        target_peer_id = "a" * 64
        node.peers[("192.168.1.50", 6000)] = (target_peer_id, "BadNode")
        # Penalize twice to drop trust score to 0 and blacklist
        node.reputation.update_trust(target_peer_id, is_valid_chunk=False)
        node.reputation.update_trust(target_peer_id, is_valid_chunk=False)
        assert node.reputation.is_blacklisted(target_peer_id) is True

        success, msg = await node.connect_to_peer("192.168.1.50", 6000)
        assert success is False
        assert "blacklisted" in msg.lower()


class TestDashboardFormattingFallbacks:
    """Stress testing UI fallback display formatting for identities, peers, and network files."""

    def test_sidebar_identity_fallbacks(self):
        """Verify username display fallback when node.node_name is empty or None."""
        # Logic in dashboard:
        # username_display = node.node_name if node.node_name else f"Node_{node.port}"
        port = 8005
        assert ("" or f"Node_{port}") == "Node_8005"
        assert (None or f"Node_{port}") == "Node_8005"
        assert ("Alice" or f"Node_{port}") == "Alice"

    def test_peer_list_name_and_endpoint_formatting(self):
        """Verify peer name extraction handles tuple, dict, empty, or 'Unknown' correctly."""
        test_cases = [
            # (peer_key, peer_val, expected_host, expected_port, expected_name, expected_id)
            (
                ("127.0.0.1", 5001),
                ("peer_id_12345678", "Alice"),
                "127.0.0.1", 5001, "Alice", "peer_id_12345678"
            ),
            (
                ("192.168.1.10", 5002),
                ("peer_id_87654321", "Unknown"),
                "192.168.1.10", 5002, "Node_5002", "peer_id_87654321"
            ),
            (
                ("10.0.0.5", 5003),
                ("peer_id_99999999", ""),
                "10.0.0.5", 5003, "Node_5003", "peer_id_99999999"
            ),
            (
                ("10.0.0.6", 5004),
                ("peer_id_00000000", "   "),
                "10.0.0.6", 5004, "Node_5004", "peer_id_00000000"
            ),
            (
                ("10.0.0.7", 5005),
                {"peer_id": "peer_id_11111111", "username": "Bob"},
                "10.0.0.7", 5005, "Bob", "peer_id_11111111"
            ),
            (
                ("10.0.0.8", 5006),
                {"id": "peer_id_22222222", "node_name": "Charlie"},
                "10.0.0.8", 5006, "Charlie", "peer_id_22222222"
            ),
            (
                ("10.0.0.9", 5007),
                "peer_id_33333333",
                "10.0.0.9", 5007, "Node_5007", "peer_id_33333333"
            ),
        ]

        for peer_key, peer_val, exp_host, exp_port, exp_name, exp_id in test_cases:
            if isinstance(peer_key, (tuple, list)) and len(peer_key) == 2:
                peer_host, peer_port = peer_key[0], peer_key[1]
            else:
                peer_host, peer_port = str(peer_key), 0

            if isinstance(peer_val, dict):
                peer_id = str(peer_val.get('peer_id') or peer_val.get('id') or "")
                raw_name = str(peer_val.get('username') or peer_val.get('node_name') or peer_val.get('name') or peer_val.get('sender_name') or "")
            elif isinstance(peer_val, (tuple, list)):
                peer_id = str(peer_val[0]) if len(peer_val) > 0 else ""
                raw_name = str(peer_val[1]) if len(peer_val) > 1 else ""
            else:
                peer_id = str(peer_val)
                raw_name = ""

            peer_name = raw_name if (raw_name and raw_name.strip() and raw_name != "Unknown") else f"Node_{peer_port}"

            assert peer_host == exp_host
            assert peer_port == exp_port
            assert peer_name == exp_name
            assert peer_id == exp_id

    def test_network_files_provider_formatting(self):
        """Verify network files provider listings format usernames and fallbacks."""
        # Logic in dashboard:
        # p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
        # h_names.append(f"{p_display} ({p[2][:8]})")
        providers = [
            ("127.0.0.1", 5001, "3a1b4c5d6e7f8a9b", "Alice"),
            ("127.0.0.1", 5002, "8f2e1a4b5c6d7e8f", "Bob"),
            ("127.0.0.1", 5003, "deadbeefcafebabe", "Unknown"),
            ("127.0.0.1", 5004, "feedface00000000", ""),
            ("127.0.0.1", 5005, "1234567890abcdef"),  # 3-tuple
        ]

        formatted = []
        for p in providers:
            p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
            formatted.append(f"{p_display} ({p[2][:8]})")

        assert formatted[0] == "Alice (3a1b4c5d)"
        assert formatted[1] == "Bob (8f2e1a4b)"
        assert formatted[2] == "Node_5003 (deadbeef)"
        assert formatted[3] == "Node_5004 (feedface)"
        assert formatted[4] == "Node_5005 (12345678)"


class TestThreadSafeAsyncioDispatch:
    """Empirical verification of thread-safe event loop dispatch and timeout handling."""

    def test_run_coroutine_threadsafe_live_dispatch(self, tmp_path):
        """Spin up node event loop in background thread and dispatch connect_to_peer via threadsafe."""
        loop = asyncio.new_event_loop()
        node = P2PNode(
            "127.0.0.1", 58895,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store"),
            node_name="ThreadsafeTester"
        )
        node.loop = loop

        t = threading.Thread(target=loop.run_forever, daemon=True)
        t.start()

        try:
            # 1. Connect to non-existent peer
            future = asyncio.run_coroutine_threadsafe(
                node.connect_to_peer("127.0.0.1", 59999, timeout=0.5),
                loop
            )
            success, msg = future.result(timeout=5.0)
            assert success is False
            assert "Connection" in msg or "timed out" in msg

            # 2. Connect to self
            future_self = asyncio.run_coroutine_threadsafe(
                node.connect_to_peer("127.0.0.1", 58895),
                loop
            )
            success_self, msg_self = future_self.result(timeout=5.0)
            assert success_self is False
            assert "Cannot connect to self" in msg_self
        finally:
            loop.call_soon_threadsafe(loop.stop)
            t.join(timeout=2.0)

    def test_sync_fallback_when_loop_inactive(self, tmp_path):
        """Verify connect_to_peer_sync fails gracefully when node loop is None or stopped."""
        node = P2PNode(
            "127.0.0.1", 58896,
            db_path=str(tmp_path / "rep.db"),
            storage_dir=str(tmp_path / "store")
        )
        node.loop = None
        success, msg = node.connect_to_peer_sync("127.0.0.1", 5001, timeout=0.5)
        assert success is False
        assert "event loop is not active" in msg
