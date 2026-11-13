"""
Unit and Integration Tests for Manual Peer Connection (Feature F32)
Test Suite: tests/test_manual_connect.py
Target: src.core.p2p_node.P2PNode (connect_to_peer, connect_to_peer_sync)

Coverage:
1. Input validation for host (empty, whitespace, non-string) and port (<=0, >65535, non-numeric).
2. Self-connection defense (127.0.0.1, localhost, 0.0.0.0, advertised_host).
3. Zero-trust blacklist rejection (pre-check drop and live PONG rejection).
4. Connection idempotency ('Already connected' vs force=True).
5. Fast timeout and connection failure handling (closed port, non-routable IP, silent peer).
6. Authenticated handshake flow with mock signed PONG peer.
7. Synchronous bridge thread-safety (inactive loop, event loop thread guard, worker thread execution).
8. Dashboard UI integration AST verification.
"""

import os
import ast
import time
import socket
import asyncio
import threading
from typing import Tuple
from concurrent.futures import ThreadPoolExecutor
import pytest

from src.core.p2p_node import P2PNode, send_frame, read_frame, create_signed_envelope
from src.core.crypto import PeerIdentity


def find_free_tcp_port() -> int:
    """Allocate an available ephemeral TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def temp_node(tmp_path):
    """Fixture providing an isolated P2PNode with clean temp directory."""
    port = find_free_tcp_port()
    db = str(tmp_path / f"rep_{port}.db")
    storage = str(tmp_path / f"store_{port}")
    os.makedirs(storage, exist_ok=True)
    node = P2PNode(host="127.0.0.1", port=port, db_path=db, storage_dir=storage, node_name=f"Node_{port}")
    yield node
    node.stop()


# =============================================================================
# 1. Input Validation Tests
# =============================================================================

class TestInputValidation:
    """Verify robust validation of host and port parameters."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", ["", "   ", "\t\r\n", "  \n  "])
    async def test_connect_empty_and_whitespace_host_rejected(self, temp_node, invalid_host):
        success, msg = await temp_node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", [None, 127001, ["127.0.0.1"], {"ip": "127.0.0.1"}, b"127.0.0.1", object()])
    async def test_connect_non_string_host_types_rejected(self, temp_node, invalid_host):
        success, msg = await temp_node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    async def test_connect_host_surrounding_whitespace_stripped(self, temp_node):
        # When stripped, matches self endpoint and triggers self-connection guard
        success, msg = await temp_node.connect_to_peer("   127.0.0.1   ", temp_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", [0, -1, -500, 65536, 70000, 99999])
    async def test_connect_port_out_of_bounds_rejected(self, temp_node, invalid_port):
        success, msg = await temp_node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg
        assert "between 1 and 65535" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", ["abc", "port", "12a", None, [], {}, object(), float("nan")])
    async def test_connect_port_non_numeric_and_invalid_types(self, temp_node, invalid_port):
        success, msg = await temp_node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("float_port", [8000.5, 8000.1, 1.0, 65535.9])
    async def test_connect_port_float_coercion_rejected(self, temp_node, float_port):
        success, msg = await temp_node.connect_to_peer("127.0.0.1", float_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bool_port", [True, False])
    async def test_connect_port_bool_coercion_rejected(self, temp_node, bool_port):
        success, msg = await temp_node.connect_to_peer("127.0.0.1", bool_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    async def test_connect_port_numeric_string_coerced_successfully(self, temp_node):
        # A valid numeric string e.g. "8000" on self port should proceed to self-connect check
        success, msg = await temp_node.connect_to_peer("127.0.0.1", str(temp_node.port))
        assert success is False
        assert msg == "Cannot connect to self"


# =============================================================================
# 2. Self-Connection Guard Tests
# =============================================================================

class TestSelfConnectionGuards:
    """Verify rejection of self-connection attempts across all interfaces."""

    @pytest.mark.asyncio
    async def test_self_connection_127_0_0_1_rejected(self, temp_node):
        success, msg = await temp_node.connect_to_peer("127.0.0.1", temp_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("lh", ["localhost", "LOCALHOST", "LocalHost", "Localhost"])
    async def test_self_connection_localhost_case_insensitive_rejected(self, temp_node, lh):
        success, msg = await temp_node.connect_to_peer(lh, temp_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("loopback_ip", ["127.0.0.1", "127.0.0.2", "127.1.2.3", "::1"])
    async def test_self_connection_loopback_subnet_rejected(self, temp_node, loopback_ip):
        success, msg = await temp_node.connect_to_peer(loopback_ip, temp_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_self_connection_wildcard_bound_host_rejected(self, tmp_path):
        port = find_free_tcp_port()
        node = P2PNode(host="0.0.0.0", port=port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        try:
            for target in ["0.0.0.0", "127.0.0.1", "localhost", node.advertised_host]:
                success, msg = await node.connect_to_peer(target, port)
                assert success is False
                assert msg == "Cannot connect to self"
        finally:
            node.stop()

    @pytest.mark.asyncio
    async def test_self_connection_explicit_advertised_host_rejected(self, tmp_path):
        port = find_free_tcp_port()
        adv_ip = "192.168.1.188"
        node = P2PNode(host="0.0.0.0", port=port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host=adv_ip)
        try:
            success, msg = await node.connect_to_peer(adv_ip, port)
            assert success is False
            assert msg == "Cannot connect to self"
        finally:
            node.stop()

    @pytest.mark.asyncio
    async def test_self_connection_whitespace_host_stripped_and_rejected(self, temp_node):
        success, msg = await temp_node.connect_to_peer("   localhost   ", temp_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_different_port_on_localhost_not_rejected_as_self(self, temp_node):
        other_port = temp_node.port + 1
        success, msg = await temp_node.connect_to_peer("127.0.0.1", other_port, timeout=0.05)
        # Should fail with connection failure/timeout, NOT self-connection rejection
        assert msg != "Cannot connect to self"


# =============================================================================
# 3. Blacklist Defense & Connection Idempotency Tests
# =============================================================================

class TestBlacklistAndIdempotency:
    """Verify zero-trust blacklist rejection and connection idempotency."""

    @pytest.mark.asyncio
    async def test_blacklisted_peer_precheck_in_peers_immediate_drop(self, temp_node):
        bad_peer_id = "0" * 64
        temp_node.reputation.add_peer(bad_peer_id)
        temp_node.reputation.update_trust(bad_peer_id, False)
        temp_node.reputation.update_trust(bad_peer_id, False)
        assert temp_node.reputation.is_blacklisted(bad_peer_id)

        target_host = "192.168.1.55"
        target_port = 7777
        temp_node.peers[(target_host, target_port)] = (bad_peer_id, "BadPeer")

        success, msg = await temp_node.connect_to_peer(target_host, target_port)
        assert success is False
        assert msg == "Peer is blacklisted"

    @pytest.mark.asyncio
    async def test_blacklisted_peer_live_pong_rejected_and_pruned(self, temp_node):
        bad_ident = PeerIdentity("EvilPeer")
        bad_id = bad_ident.get_peer_id()

        temp_node.reputation.add_peer(bad_id)
        temp_node.reputation.update_trust(bad_id, False)
        temp_node.reputation.update_trust(bad_id, False)
        assert temp_node.reputation.is_blacklisted(bad_id)

        async def evil_handler(reader, writer):
            try:
                req = await read_frame(reader)
                resp = {'type': 'PONG', 'sender_id': bad_id, 'sender_name': 'EvilPeer', 'files': {}}
                await send_frame(writer, create_signed_envelope(bad_ident, resp))
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(evil_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=1.0)
            assert success is False
            assert "rejected handshake" in msg or "Connection failed" in msg
            assert ("127.0.0.1", port) not in temp_node.peers
            assert bad_id not in temp_node.peer_files
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_already_connected_idempotent_shortcut(self, temp_node):
        host, port = "192.168.1.99", 8888
        temp_node.peers[(host, port)] = ("peer_id_good_12345", "GoodNode")

        success, msg = await temp_node.connect_to_peer(host, port, force=False)
        assert success is True
        assert f"Already connected to {host}:{port}" in msg

    @pytest.mark.asyncio
    async def test_force_reconnect_bypasses_already_connected_guard(self, temp_node):
        host, port = "192.168.1.99", 8888
        temp_node.peers[(host, port)] = ("peer_id_good_12345", "GoodNode")

        # With force=True to non-existent endpoint, bypasses "Already connected" and attempts ping
        success, msg = await temp_node.connect_to_peer(host, port, timeout=0.05, force=True)
        assert success is False
        assert "Already connected" not in msg


# =============================================================================
# 4. Network Failures & Timeout Tests
# =============================================================================

class TestNetworkFailuresAndTimeouts:
    """Verify non-blocking error handling during connection and handshake drops."""

    @pytest.mark.asyncio
    async def test_connection_refused_closed_port_fails_cleanly(self, temp_node):
        # Use a closed local port
        closed_port = find_free_tcp_port()
        success, msg = await temp_node.connect_to_peer("127.0.0.1", closed_port, timeout=0.2)
        assert success is False
        assert "rejected handshake" in msg or "Connection failed" in msg or "timed out" in msg

    @pytest.mark.asyncio
    async def test_timeout_unreachable_endpoint_fast_abort(self, temp_node):
        # Non-routable IP (10.255.255.1) with 0.05s timeout
        start = time.time()
        success, msg = await temp_node.connect_to_peer("10.255.255.1", 54321, timeout=0.05)
        elapsed = time.time() - start

        assert success is False
        assert "timed out" in msg or "error" in msg
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_silent_hanging_peer_timeout_clean_abort(self, temp_node):
        stop_event = asyncio.Event()

        async def silent_handler(reader, writer):
            try:
                await reader.read(1024)
                await stop_event.wait()
            except asyncio.CancelledError:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(silent_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            start = time.time()
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=0.05)
            elapsed = time.time() - start

            assert success is False
            assert elapsed < 0.5
            assert ("127.0.0.1", port) not in temp_node.peers
        finally:
            stop_event.set()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_peer_immediate_tcp_disconnect_fails_cleanly(self, temp_node):
        async def drop_handler(reader, writer):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        server = await asyncio.start_server(drop_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=0.5)
            assert success is False
            assert ("127.0.0.1", port) not in temp_node.peers
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_peer_malformed_raw_bytes_fails_cleanly(self, temp_node):
        async def garbage_handler(reader, writer):
            try:
                await reader.read(1024)
                garbage = b"NON_JSON_CORRUPTED_BYTES"
                writer.write(len(garbage).to_bytes(4, "big") + garbage)
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(garbage_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=0.5)
            assert success is False
            assert "rejected handshake" in msg or "Connection failed" in msg
            assert ("127.0.0.1", port) not in temp_node.peers
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_peer_spoofed_sender_id_fails_cleanly(self, temp_node):
        ident = PeerIdentity("Spoofer")

        async def spoof_handler(reader, writer):
            try:
                req = await read_frame(reader)
                resp = {
                    'type': 'PONG',
                    'sender_id': '0' * 64,  # Mismatched spoofed sender ID
                    'sender_name': 'Spoofer',
                    'files': {}
                }
                # Wrap in envelope with mismatched sender_id
                env = create_signed_envelope(ident, resp)
                env['sender_id'] = '0' * 64
                await send_frame(writer, env)
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(spoof_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=0.5)
            assert success is False
            assert ("127.0.0.1", port) not in temp_node.peers
        finally:
            server.close()
            await server.wait_closed()


# =============================================================================
# 5. Successful Connection Flow Tests
# =============================================================================

class TestSuccessfulConnectionFlow:
    """Verify end-to-end authenticated handshake flow."""

    @pytest.mark.asyncio
    async def test_successful_connection_with_mock_pong_peer(self, temp_node):
        mock_ident = PeerIdentity("AliceResponder")
        mock_id = mock_ident.get_peer_id()
        mock_files = {
            "rfc6962.pdf": {"file_size": 1024, "merkle_root": "a" * 64, "total_chunks": 1}
        }

        async def valid_pong_handler(reader, writer):
            try:
                req = await read_frame(reader)
                assert req is not None
                resp_payload = {
                    'type': 'PONG',
                    'sender_id': mock_id,
                    'sender_name': 'AliceResponder',
                    'files': mock_files
                }
                await send_frame(writer, create_signed_envelope(mock_ident, resp_payload))
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(valid_pong_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            success, msg = await temp_node.connect_to_peer("127.0.0.1", port, timeout=1.0)
            assert success is True
            assert f"Connected to 127.0.0.1:{port}" in msg
            assert ("127.0.0.1", port) in temp_node.peers
            assert temp_node.peers[("127.0.0.1", port)] == (mock_id, "AliceResponder")
            assert temp_node.peer_files[mock_id] == mock_files
            assert temp_node.reputation.get_trust_score(mock_id) is not None
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_successful_connection_between_two_real_loopback_nodes(self, tmp_path):
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "rep1.db"), storage_dir=str(tmp_path / "s1"), node_name="Node1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "rep2.db"), storage_dir=str(tmp_path / "s2"), node_name="Node2")

        server2 = await asyncio.start_server(node2.handle_client, node2.host, node2.port)
        try:
            success, msg = await node1.connect_to_peer(node2.host, node2.port, timeout=1.0)
            assert success is True
            assert f"Connected to {node2.host}:{node2.port}" in msg
            assert (node2.host, node2.port) in node1.peers
            assert node1.peers[(node2.host, node2.port)][0] == node2.peer_id
            assert node1.peers[(node2.host, node2.port)][1] == "Node2"
        finally:
            server2.close()
            await server2.wait_closed()
            node1.stop()
            node2.stop()


# =============================================================================
# 6. Synchronous Bridge & Thread Safety Tests
# =============================================================================

class TestSyncBridgeAndThreading:
    """Verify thread-safety and deadlock prevention in connect_to_peer_sync."""

    def test_sync_inactive_loop_returns_error(self, temp_node):
        assert temp_node.loop is None
        success, msg = temp_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Node event loop is not active"

    @pytest.mark.asyncio
    async def test_sync_called_on_event_loop_thread_deadlock_guard(self, temp_node):
        temp_node.loop = asyncio.get_running_loop()
        success, msg = temp_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Cannot call connect_to_peer_sync from the event loop thread"

    @pytest.mark.asyncio
    async def test_sync_called_from_foreign_event_loop_thread_guard(self, temp_node):
        temp_node.loop = None
        success, msg = temp_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Cannot call connect_to_peer_sync from an event loop thread"

    def test_sync_called_from_worker_thread_success(self, tmp_path):
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "rep1.db"), storage_dir=str(tmp_path / "s1"), node_name="Node1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "rep2.db"), storage_dir=str(tmp_path / "s2"), node_name="Node2")

        loop1 = asyncio.new_event_loop()
        node1.loop = loop1
        t1 = threading.Thread(target=loop1.run_forever, daemon=True)
        t1.start()

        loop2 = asyncio.new_event_loop()
        node2.loop = loop2
        t2 = threading.Thread(target=loop2.run_forever, daemon=True)
        t2.start()

        async def start_server2():
            return await asyncio.start_server(node2.handle_client, node2.host, node2.port)

        server2 = asyncio.run_coroutine_threadsafe(start_server2(), loop2).result()

        try:
            success, msg = node1.connect_to_peer_sync(node2.host, node2.port, timeout=2.0)
            assert success is True
            assert f"Connected to {node2.host}:{node2.port}" in msg
            assert (node2.host, node2.port) in node1.peers
        finally:
            async def stop_server2():
                server2.close()
                await server2.wait_closed()
            asyncio.run_coroutine_threadsafe(stop_server2(), loop2).result()
            loop1.call_soon_threadsafe(loop1.stop)
            loop2.call_soon_threadsafe(loop2.stop)
            t1.join(timeout=1.0)
            t2.join(timeout=1.0)
            loop1.close()
            loop2.close()
            node1.stop()
            node2.stop()

    def test_sync_concurrent_workers_multithread_stress(self, tmp_path):
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "rep1.db"), storage_dir=str(tmp_path / "s1"), node_name="Node1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "rep2.db"), storage_dir=str(tmp_path / "s2"), node_name="Node2")

        loop1 = asyncio.new_event_loop()
        node1.loop = loop1
        t1 = threading.Thread(target=loop1.run_forever, daemon=True)
        t1.start()

        loop2 = asyncio.new_event_loop()
        node2.loop = loop2
        t2 = threading.Thread(target=loop2.run_forever, daemon=True)
        t2.start()

        async def start_server2():
            return await asyncio.start_server(node2.handle_client, node2.host, node2.port)

        server2 = asyncio.run_coroutine_threadsafe(start_server2(), loop2).result()

        try:
            def worker():
                return node1.connect_to_peer_sync(node2.host, node2.port, timeout=2.0)

            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(worker) for _ in range(8)]
                results = [f.result() for f in futures]

            for success, msg in results:
                assert success is True
                assert ("Connected to" in msg or "Already connected to" in msg)
        finally:
            async def stop_server2():
                server2.close()
                await server2.wait_closed()
            asyncio.run_coroutine_threadsafe(stop_server2(), loop2).result()
            loop1.call_soon_threadsafe(loop1.stop)
            loop2.call_soon_threadsafe(loop2.stop)
            t1.join(timeout=1.0)
            t2.join(timeout=1.0)
            loop1.close()
            loop2.close()
            node1.stop()
            node2.stop()


# =============================================================================
# 7. Dashboard UI Integration AST Verification
# =============================================================================

class TestDashboardIntegrationHygiene:
    """Verify that dashboard.py wires the manual connect form cleanly to P2PNode."""

    def test_dashboard_manual_connect_form_ast_wiring(self):
        dash_path = os.path.join(os.path.dirname(__file__), "..", "src", "app", "dashboard.py")
        assert os.path.exists(dash_path)
        with open(dash_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Static lexical checks
        assert "connect_to_peer" in content
        assert "connect_to_peer_sync" in content
        assert "run_coroutine_threadsafe" in content
        assert "Connect to Peer" in content

        # AST structural checks
        tree = ast.parse(content)
        call_names = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name):
                    call_names.append(n.func.id)
                elif isinstance(n.func, ast.Attribute):
                    call_names.append(n.func.attr)

        assert "connect_to_peer" in call_names or "connect_to_peer_sync" in call_names
        assert "run_coroutine_threadsafe" in call_names
