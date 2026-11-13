"""
Adversarial Empirical Challenge & Stress Test Suite for Milestone 6 (M6)
Challenger: teamwork_challenger_m6_1

Focus: Public Connect API (connect_to_peer and connect_to_peer_sync) in src.core.p2p_node.P2PNode

Verification Categories:
1. Port validation: 0, -1, 65536, 99999, non-numeric strings, None, objects, floats.
2. Host validation: empty string, whitespace, non-string objects, whitespace stripping.
3. Self-connection guard: 127.0.0.1, localhost, node.host, node.advertised_host with node.port across loopback and 0.0.0.0 nodes.
4. Timeout handling: non-routable IP (10.255.255.1) and silent peers with 0.5s timeout.
5. Blacklist rejection: known blacklisted peer pre-check and unseen live blacklisted peer handshake rejection.
6. Deadlock & Concurrency: event loop thread guard, inactive loop guard, external thread invocation, multi-threaded burst.
7. Hostile peer responses: garbage data, corrupted signatures, immediate disconnect, and idempotency.
"""

import os
import sys
import time
import socket
import asyncio
import threading
import pytest
from concurrent.futures import ThreadPoolExecutor

from src.core.p2p_node import P2PNode, pack_tcp_frame, send_frame
from src.core.crypto import PeerIdentity


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class TestAdversarialPortValidation:
    """Stress testing port parameter validation in connect_to_peer."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", [0, -1, -500, 65536, 70000, 99999])
    async def test_port_out_of_bounds_integers(self, tmp_path, invalid_port):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg
        assert "between 1 and 65535" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", ["abc", "port", "12a", "", "   ", "65536", "-1"])
    async def test_port_non_numeric_and_invalid_strings(self, tmp_path, invalid_port):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_port", [None, [], {}, object()])
    async def test_port_none_and_objects(self, tmp_path, invalid_port):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("127.0.0.1", invalid_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    async def test_port_nan_float(self, tmp_path):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("127.0.0.1", float("nan"))
        assert success is False
        assert "Invalid port" in msg


class TestAdversarialHostValidation:
    """Stress testing host parameter validation in connect_to_peer."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", ["", "   ", "\t\r\n", "    \n  "])
    async def test_host_empty_and_whitespace(self, tmp_path, invalid_host):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", [None, 127001, [], {}, object(), b"127.0.0.1"])
    async def test_host_non_string_types(self, tmp_path, invalid_host):
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    async def test_host_whitespace_stripping(self, tmp_path):
        """Host with surrounding whitespace should be stripped and trigger self-connection check."""
        port = find_free_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("   127.0.0.1   ", port)
        assert success is False
        assert msg == "Cannot connect to self"


class TestAdversarialSelfConnectionGuard:
    """Verifying strict self-connection defense across all node network configurations."""

    @pytest.mark.asyncio
    async def test_self_connection_loopback_node(self, tmp_path):
        port = find_free_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        targets = ["127.0.0.1", "localhost", node.host, node.advertised_host]
        for target in targets:
            success, msg = await node.connect_to_peer(target, port)
            assert success is False, f"Self-connection not blocked for {target}"
            assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_self_connection_wildcard_node(self, tmp_path):
        port = find_free_port()
        node = P2PNode("0.0.0.0", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        targets = ["127.0.0.1", "localhost", "0.0.0.0", node.host, node.advertised_host]
        for target in targets:
            success, msg = await node.connect_to_peer(target, port)
            assert success is False, f"Self-connection not blocked for {target}"
            assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_self_connection_explicit_advertise_host(self, tmp_path):
        port = find_free_port()
        node = P2PNode("0.0.0.0", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host="192.168.1.188")
        success, msg = await node.connect_to_peer("192.168.1.188", port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_different_port_not_blocked_as_self(self, tmp_path):
        """Connecting to localhost on a different port should NOT trigger self-connection error."""
        port = find_free_port()
        other_port = port + 1
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        success, msg = await node.connect_to_peer("127.0.0.1", other_port, timeout=0.1)
        assert msg != "Cannot connect to self"


class TestAdversarialTimeoutHandling:
    """Verifying non-blocking timeout handling during network failures."""

    @pytest.mark.asyncio
    async def test_connect_to_peer_timeout_non_routable_ip(self, tmp_path):
        """Simulate connecting to a non-routable / dropping IP (10.255.255.1) with 0.5s timeout."""
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        start = time.time()
        success, msg = await node.connect_to_peer("10.255.255.1", 54321, timeout=0.5)
        elapsed = time.time() - start

        assert success is False
        assert "timed out" in msg or "error" in msg
        assert elapsed < 2.0, f"Call hung for {elapsed:.2f}s exceeding timeout grace period"

    def test_connect_to_peer_sync_timeout_non_routable_ip(self, tmp_path):
        """Simulate synchronous connect to non-routable IP with 0.5s timeout from external thread."""
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        loop = asyncio.new_event_loop()
        node.loop = loop
        t = threading.Thread(target=loop.run_forever, daemon=True)
        t.start()

        try:
            start = time.time()
            success, msg = node.connect_to_peer_sync("10.255.255.1", 54321, timeout=0.5)
            elapsed = time.time() - start

            assert success is False
            assert "timed out" in msg or "error" in msg
            assert elapsed < 2.0, f"Sync call hung for {elapsed:.2f}s"
        finally:
            loop.call_soon_threadsafe(loop.stop)
            t.join(timeout=1.0)

    @pytest.mark.asyncio
    async def test_silent_hanging_peer_timeout(self, tmp_path):
        """Simulate a peer that accepts TCP connection but hangs indefinitely without sending response."""
        port = find_free_port()

        stop_event = asyncio.Event()

        async def silent_handler(reader, writer):
            try:
                await reader.read(4096)
                await stop_event.wait()
            except asyncio.CancelledError:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(silent_handler, "127.0.0.1", port)
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))

        try:
            start = time.time()
            success, msg = await node.connect_to_peer("127.0.0.1", port, timeout=0.5)
            elapsed = time.time() - start

            assert success is False
            assert elapsed < 2.0, f"Silent peer call hung for {elapsed:.2f}s"
            assert (node.host, port) not in node.peers
        finally:
            stop_event.set()
            server.close()
            await server.wait_closed()


class TestAdversarialBlacklistRejection:
    """Verifying strict blacklist isolation during connection initiation."""

    @pytest.mark.asyncio
    async def test_blacklist_precheck_in_peers_immediate_rejection(self, tmp_path):
        """A peer previously recorded in self.peers and subsequently blacklisted must be immediately rejected."""
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        bad_peer_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        
        node.reputation.add_peer(bad_peer_id)
        node.reputation.update_trust(bad_peer_id, False)
        node.reputation.update_trust(bad_peer_id, False)
        assert node.reputation.is_blacklisted(bad_peer_id)

        target_host = "192.168.1.99"
        target_port = 5002
        node.peers[(target_host, target_port)] = (bad_peer_id, "HostilePeer")

        success, msg = await node.connect_to_peer(target_host, target_port)
        assert success is False
        assert msg == "Peer is blacklisted"

    @pytest.mark.asyncio
    async def test_blacklist_postcheck_live_peer_rejected(self, tmp_path):
        """A live peer whose peer_id is blacklisted in reputation db must be rejected upon PONG response."""
        port_a = find_free_port()
        port_b = find_free_port()

        node_a = P2PNode("127.0.0.1", port_a, db_path=str(tmp_path / "rep_a.db"), storage_dir=str(tmp_path / "store_a"))
        node_b = P2PNode("127.0.0.1", port_b, db_path=str(tmp_path / "rep_b.db"), storage_dir=str(tmp_path / "store_b"))

        # Blacklist node_b in node_a's reputation database
        node_a.reputation.add_peer(node_b.peer_id)
        node_a.reputation.update_trust(node_b.peer_id, False)
        node_a.reputation.update_trust(node_b.peer_id, False)
        assert node_a.reputation.is_blacklisted(node_b.peer_id)

        server_b = await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)
        try:
            success, msg = await node_a.connect_to_peer(node_b.host, node_b.port, timeout=1.0)
            assert success is False
            assert (node_b.host, node_b.port) not in node_a.peers
            assert node_b.peer_id not in node_a.peer_files
        finally:
            server_b.close()
            await server_b.wait_closed()


class TestAdversarialConcurrencyAndDeadlock:
    """Verifying thread safety and deadlock prevention in connect_to_peer_sync."""

    @pytest.mark.asyncio
    async def test_sync_called_on_event_loop_thread_deadlock_guard(self, tmp_path):
        """Calling connect_to_peer_sync directly from the running event loop thread must return error immediately."""
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        node.loop = asyncio.get_running_loop()

        success, msg = node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Cannot call connect_to_peer_sync from the event loop thread"

    def test_sync_called_with_inactive_loop(self, tmp_path):
        """Calling connect_to_peer_sync when node loop is None or stopped must return error."""
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))
        assert node.loop is None

        success, msg = node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Node event loop is not active"

    def test_sync_called_from_external_thread(self, tmp_path):
        """Calling connect_to_peer_sync from an external thread connects successfully to an active peer."""
        port_a = find_free_port()
        port_b = find_free_port()

        node_a = P2PNode("127.0.0.1", port_a, db_path=str(tmp_path / "rep_a.db"), storage_dir=str(tmp_path / "store_a"), node_name="NodeA")
        node_b = P2PNode("127.0.0.1", port_b, db_path=str(tmp_path / "rep_b.db"), storage_dir=str(tmp_path / "store_b"), node_name="NodeB")

        loop_a = asyncio.new_event_loop()
        node_a.loop = loop_a
        t_a = threading.Thread(target=loop_a.run_forever, daemon=True)
        t_a.start()

        loop_b = asyncio.new_event_loop()
        node_b.loop = loop_b
        t_b = threading.Thread(target=loop_b.run_forever, daemon=True)
        t_b.start()

        async def start_b():
            return await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)

        server_b = asyncio.run_coroutine_threadsafe(start_b(), loop_b).result()

        try:
            success, msg = node_a.connect_to_peer_sync(node_b.host, node_b.port, timeout=3.0)
            assert success is True
            assert f"Connected to {node_b.host}:{node_b.port}" in msg
            assert (node_b.host, node_b.port) in node_a.peers
            assert node_a.peers[(node_b.host, node_b.port)][0] == node_b.peer_id
            assert node_a.peers[(node_b.host, node_b.port)][1] == "NodeB"
        finally:
            async def stop_b():
                server_b.close()
                await server_b.wait_closed()
            asyncio.run_coroutine_threadsafe(stop_b(), loop_b).result()
            loop_a.call_soon_threadsafe(loop_a.stop)
            loop_b.call_soon_threadsafe(loop_b.stop)
            t_a.join(timeout=1.0)
            t_b.join(timeout=1.0)

    def test_sync_concurrent_multi_thread(self, tmp_path):
        """Simulate concurrent threads calling connect_to_peer_sync simultaneously."""
        port_a = find_free_port()
        port_b = find_free_port()

        node_a = P2PNode("127.0.0.1", port_a, db_path=str(tmp_path / "rep_a.db"), storage_dir=str(tmp_path / "store_a"), node_name="NodeA")
        node_b = P2PNode("127.0.0.1", port_b, db_path=str(tmp_path / "rep_b.db"), storage_dir=str(tmp_path / "store_b"), node_name="NodeB")

        loop_a = asyncio.new_event_loop()
        node_a.loop = loop_a
        t_a = threading.Thread(target=loop_a.run_forever, daemon=True)
        t_a.start()

        loop_b = asyncio.new_event_loop()
        node_b.loop = loop_b
        t_b = threading.Thread(target=loop_b.run_forever, daemon=True)
        t_b.start()

        async def start_b():
            return await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)

        server_b = asyncio.run_coroutine_threadsafe(start_b(), loop_b).result()

        try:
            results = []
            def worker():
                return node_a.connect_to_peer_sync(node_b.host, node_b.port, timeout=3.0)

            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(worker) for _ in range(8)]
                for f in futures:
                    results.append(f.result())

            # All 8 threads must succeed (either "Connected to..." or "Already connected to...")
            for success, msg in results:
                assert success is True
                assert ("Connected to" in msg or "Already connected to" in msg)
        finally:
            async def stop_b():
                server_b.close()
                await server_b.wait_closed()
            asyncio.run_coroutine_threadsafe(stop_b(), loop_b).result()
            loop_a.call_soon_threadsafe(loop_a.stop)
            loop_b.call_soon_threadsafe(loop_b.stop)
            t_a.join(timeout=1.0)
            t_b.join(timeout=1.0)


class TestAdversarialHostilePeers:
    """Verifying defense against malformed or hostile remote peer servers."""

    @pytest.mark.asyncio
    async def test_peer_sends_garbage_bytes(self, tmp_path):
        """Peer accepts connection but responds with non-JSON random bytes."""
        port = find_free_port()

        async def garbage_handler(reader, writer):
            try:
                await reader.read(1024)
                # Send frame containing invalid JSON
                raw_payload = b"NOT_A_JSON_PAYLOAD_CORRUPT"
                frame = len(raw_payload).to_bytes(4, "big") + raw_payload
                writer.write(frame)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(garbage_handler, "127.0.0.1", port)
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))

        try:
            success, msg = await node.connect_to_peer("127.0.0.1", port, timeout=1.0)
            assert success is False
            assert "Connection failed or peer rejected handshake" in msg
            assert (node.host, port) not in node.peers
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_peer_disconnects_immediately(self, tmp_path):
        """Peer accepts connection and immediately closes socket (TCP FIN)."""
        port = find_free_port()

        async def drop_handler(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(drop_handler, "127.0.0.1", port)
        node = P2PNode("127.0.0.1", find_free_port(), db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))

        try:
            success, msg = await node.connect_to_peer("127.0.0.1", port, timeout=1.0)
            assert success is False
            assert (node.host, port) not in node.peers
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_idempotent_reconnection(self, tmp_path):
        """Re-connecting to an active peer with force=False returns 'Already connected' without pinging."""
        port_a = find_free_port()
        port_b = find_free_port()

        node_a = P2PNode("127.0.0.1", port_a, db_path=str(tmp_path / "rep_a.db"), storage_dir=str(tmp_path / "store_a"))
        node_b = P2PNode("127.0.0.1", port_b, db_path=str(tmp_path / "rep_b.db"), storage_dir=str(tmp_path / "store_b"))

        server_b = await asyncio.start_server(node_b.handle_client, node_b.host, node_b.port)
        try:
            # First connection
            s1, m1 = await node_a.connect_to_peer(node_b.host, node_b.port)
            assert s1 is True
            assert f"Connected to {node_b.host}:{node_b.port}" in m1

            # Second connection without force
            s2, m2 = await node_a.connect_to_peer(node_b.host, node_b.port, force=False)
            assert s2 is True
            assert f"Already connected to {node_b.host}:{node_b.port}" in m2

            # Third connection with force=True
            s3, m3 = await node_a.connect_to_peer(node_b.host, node_b.port, force=True)
            assert s3 is True
            assert f"Connected to {node_b.host}:{node_b.port}" in m3
        finally:
            server_b.close()
            await server_b.wait_closed()
