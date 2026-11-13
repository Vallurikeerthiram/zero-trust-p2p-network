"""
Adversarial Empirical Challenge & Concurrency Stress Test Suite for Milestone 9 (M9)
Challenger: challenger_m9_2 (EMPIRICAL CHALLENGER / critic / specialist)

Target:
- src.core.p2p_node.P2PNode (connect_to_peer, connect_to_peer_sync, ping_peer)
- tests.test_manual_connect

Verification Areas:
1. Concurrency and Race Conditions:
   - High concurrent connection attempts to the same host/port (idempotency under race conditions).
   - High concurrent multi-threaded calls to `connect_to_peer_sync` across 32 worker threads.
   - Deadlock rejection when `connect_to_peer_sync` is called on the active event loop thread.
   - Inactive or closed event loop safety in `connect_to_peer_sync`.
2. Boundary and Host Adversity:
   - Self-connection evasion attempts (case variations e.g. 'LOCALHOST', loopback subnet '127.0.0.2', '0.0.0.0', '::1', hex/int IP '2130706433').
   - Post-handshake PONG self-identity validation (peer returning node's own peer_id).
   - Port boundary values (0, 65535, 65536, -1, non-numeric strings, float coercion, boolean coercion).
   - In-flight blacklist mutation while PING is in transit.
   - Slow lorris partial framing and hanging TCP sockets with timeout enforcement.
"""

import os
import time
import socket
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest

from src.core.p2p_node import P2PNode, read_frame, send_frame, create_signed_envelope
from src.core.crypto import PeerIdentity


def find_free_tcp_port() -> int:
    """Allocate an ephemeral TCP port on loopback."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def isolated_node(tmp_path):
    """Fixture providing an isolated loopback P2PNode."""
    port = find_free_tcp_port()
    db = str(tmp_path / f"rep_{port}.db")
    storage = str(tmp_path / f"store_{port}")
    os.makedirs(storage, exist_ok=True)
    node = P2PNode(host="127.0.0.1", port=port, db_path=db, storage_dir=storage, node_name=f"Node_{port}")
    yield node
    node.stop()


# =============================================================================
# 1. Concurrency & Race Condition Stress Tests
# =============================================================================

class TestConcurrencyAndRaceConditions:
    """Stress-test concurrent connections, idempotency, and multi-threaded sync dispatch."""

    @pytest.mark.asyncio
    async def test_high_concurrency_simultaneous_connects_unconnected(self, tmp_path):
        """
        Stress test: 50 concurrent connect_to_peer calls hitting an unconnected peer simultaneously.
        Verifies race-free execution, 100% success rate, and exactly 1 registered peer entry.
        """
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "r1.db"), storage_dir=str(tmp_path / "s1"), node_name="N1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "r2.db"), storage_dir=str(tmp_path / "s2"), node_name="N2")
        server2 = await asyncio.start_server(node2.handle_client, node2.host, node2.port)

        try:
            tasks = [asyncio.create_task(node1.connect_to_peer(node2.host, node2.port, timeout=5.0)) for _ in range(50)]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successes = [r for r in results if isinstance(r, tuple) and r[0] is True]
            failures = [r for r in results if isinstance(r, tuple) and r[0] is False]
            exceptions = [r for r in results if isinstance(r, Exception)]

            assert len(exceptions) == 0, f"Encountered unexpected exceptions: {exceptions}"
            assert len(failures) == 0, f"Encountered failures: {failures}"
            assert len(successes) == 50, f"Expected 50 successes, got {len(successes)}"
            assert (node2.host, node2.port) in node1.peers
            assert len(node1.peers) == 1
        finally:
            server2.close()
            await server2.wait_closed()
            node1.stop()
            node2.stop()

    @pytest.mark.asyncio
    async def test_high_concurrency_already_connected_idempotency(self, isolated_node):
        """
        Stress test: 50 concurrent calls when the target peer is already active.
        Verifies fast idempotent path without redundant socket allocations.
        """
        target_host = "192.168.1.100"
        target_port = 8888
        fake_peer_id = "f" * 64
        isolated_node.peers[(target_host, target_port)] = (fake_peer_id, "FastPeer")

        tasks = [asyncio.create_task(isolated_node.connect_to_peer(target_host, target_port, force=False)) for _ in range(50)]
        results = await asyncio.gather(*tasks)

        for success, msg in results:
            assert success is True
            assert f"Already connected to {target_host}:{target_port}" in msg

    @pytest.mark.asyncio
    async def test_high_concurrency_mixed_force_and_no_force(self, tmp_path):
        """
        Stress test: 25 force=True and 25 force=False concurrent calls to an active peer.
        Verifies absence of state corruption or deadlocks under mixed flags.
        """
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "r1.db"), storage_dir=str(tmp_path / "s1"), node_name="N1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "r2.db"), storage_dir=str(tmp_path / "s2"), node_name="N2")
        server2 = await asyncio.start_server(node2.handle_client, node2.host, node2.port)

        try:
            # Connect once first
            await node1.connect_to_peer(node2.host, node2.port)

            tasks = []
            for i in range(50):
                force_flag = (i % 2 == 0)
                tasks.append(asyncio.create_task(node1.connect_to_peer(node2.host, node2.port, timeout=5.0, force=force_flag)))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = [r for r in results if isinstance(r, tuple) and r[0] is True]
            assert len(successes) == 50
        finally:
            server2.close()
            await server2.wait_closed()
            node1.stop()
            node2.stop()

    def test_multithreaded_connect_sync_heavy_burst(self, tmp_path):
        """
        Stress test: 32 concurrent OS worker threads calling connect_to_peer_sync.
        Verifies thread-safety across asyncio.run_coroutine_threadsafe dispatch.
        """
        port1 = find_free_tcp_port()
        port2 = find_free_tcp_port()

        node1 = P2PNode("127.0.0.1", port1, db_path=str(tmp_path / "r1.db"), storage_dir=str(tmp_path / "s1"), node_name="N1")
        node2 = P2PNode("127.0.0.1", port2, db_path=str(tmp_path / "r2.db"), storage_dir=str(tmp_path / "s2"), node_name="N2")

        loop1 = asyncio.new_event_loop()
        node1.loop = loop1
        t1 = threading.Thread(target=loop1.run_forever, daemon=True)
        t1.start()

        loop2 = asyncio.new_event_loop()
        node2.loop = loop2
        t2 = threading.Thread(target=loop2.run_forever, daemon=True)
        t2.start()

        async def start_server():
            return await asyncio.start_server(node2.handle_client, node2.host, node2.port)

        server = asyncio.run_coroutine_threadsafe(start_server(), loop2).result()

        try:
            def worker():
                return node1.connect_to_peer_sync(node2.host, node2.port, timeout=5.0)

            with ThreadPoolExecutor(max_workers=32) as pool:
                futures = [pool.submit(worker) for _ in range(32)]
                results = [f.result() for f in futures]

            successes = [r for r in results if r[0] is True]
            assert len(successes) == 32
            for s, msg in results:
                assert ("Connected to" in msg or "Already connected to" in msg)
        finally:
            async def stop_server():
                server.close()
                await server.wait_closed()
            asyncio.run_coroutine_threadsafe(stop_server(), loop2).result()
            loop1.call_soon_threadsafe(loop1.stop)
            loop2.call_soon_threadsafe(loop2.stop)
            t1.join(timeout=1.0)
            t2.join(timeout=1.0)
            loop1.close()
            loop2.close()
            node1.stop()
            node2.stop()

    @pytest.mark.asyncio
    async def test_sync_called_from_event_loop_thread_deadlock_guard(self, isolated_node):
        """
        Verify that invoking connect_to_peer_sync on the active event loop thread
        is immediately rejected to avoid recursive deadlock.
        """
        isolated_node.loop = asyncio.get_running_loop()
        success, msg = isolated_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert "Cannot call connect_to_peer_sync from" in msg and "event loop thread" in msg

    @pytest.mark.asyncio
    async def test_sync_called_from_foreign_event_loop_thread_deadlock_guard(self, isolated_node):
        """
        Verify that invoking connect_to_peer_sync from another running event loop thread
        is immediately rejected with 'Cannot call connect_to_peer_sync from an event loop thread'.
        """
        isolated_node.loop = None
        success, msg = isolated_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Cannot call connect_to_peer_sync from an event loop thread"

    def test_sync_called_with_inactive_or_closed_loop(self, isolated_node):
        """
        Verify that invoking connect_to_peer_sync with None or closed loop returns error cleanly.
        """
        assert isolated_node.loop is None
        success, msg = isolated_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success is False
        assert msg == "Node event loop is not active"

        closed_loop = asyncio.new_event_loop()
        closed_loop.close()
        isolated_node.loop = closed_loop
        success2, msg2 = isolated_node.connect_to_peer_sync("127.0.0.1", 9999)
        assert success2 is False
        assert msg2 == "Node event loop is not active"


# =============================================================================
# 2. Boundary & Host Adversity (Evasion Tests & Proofs)
# =============================================================================

class TestHostAdversityAndSelfConnectionEvasion:
    """Stress-test boundary addresses, evasive host representations, and self-connection defenses."""

    @pytest.mark.asyncio
    async def test_self_connection_case_insensitivity_evasion_vulnerability(self, tmp_path):
        """
        Adversarial Test & Empirical Proof (Finding 1):
        Investigates uppercase hostname evasion (e.g. 'LOCALHOST', 'LocalHost').
        In p2p_node.py line 1098:
          local_hosts = {"127.0.0.1", "localhost", self.host}
        Because host is not normalized with .lower(), 'LOCALHOST' evades local_hosts!
        When bound to 0.0.0.0, the node connects to itself and registers its own peer_id in self.peers.
        """
        port = find_free_tcp_port()
        node = P2PNode("0.0.0.0", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host="127.0.0.1")
        server = await asyncio.start_server(node.handle_client, node.host, node.port)

        try:
            success, msg = await node.connect_to_peer("LOCALHOST", port, timeout=1.0)
            assert success is False
            assert msg == "Cannot connect to self"
            assert (node.host, port) not in node.peers
            assert ("127.0.0.1", port) not in node.peers
            assert ("LOCALHOST", port) not in node.peers
        finally:
            server.close()
            await server.wait_closed()
            node.stop()

    @pytest.mark.asyncio
    async def test_self_connection_loopback_subnet_evasion_vulnerability(self, tmp_path):
        """
        Adversarial Test & Empirical Proof (Finding 1, Sub-case B):
        Investigates loopback subnet evasion (127.0.0.2).
        RFC 1122 defines 127.0.0.0/8 as the loopback block.
        When listening on 0.0.0.0, connecting to 127.0.0.2 routes to self.
        With hardened subnet loopback checking, it must be rejected immediately.
        """
        port = find_free_tcp_port()
        node = P2PNode("0.0.0.0", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host="127.0.0.1")
        server = await asyncio.start_server(node.handle_client, node.host, node.port)

        try:
            success, msg = await node.connect_to_peer("127.0.0.2", port, timeout=2.0)
            assert success is False
            assert msg == "Cannot connect to self"
            assert ("127.0.0.2", port) not in node.peers
        finally:
            server.close()
            await server.wait_closed()
            node.stop()

    @pytest.mark.asyncio
    async def test_pong_self_peer_id_check_vulnerability(self, tmp_path):
        """
        Adversarial Test & Empirical Proof (Finding 1, Sub-case C):
        Verifies whether ping_peer checks if returned peer_id == self.peer_id.
        If a remote endpoint responds with the caller node's own peer_id (reflection attack),
        ping_peer detects it and rejects registration in self.peers.
        """
        port = find_free_tcp_port()
        node = P2PNode("127.0.0.1", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"))

        # Reflector server responds with node's own peer identity
        async def reflector_handler(reader, writer):
            try:
                req = await read_frame(reader)
                # Reflection: use caller's peer_id and identity to forge PONG
                resp = {
                    'type': 'PONG',
                    'sender_id': node.peer_id,
                    'sender_name': 'ReflectedSelf',
                    'files': {}
                }
                await send_frame(writer, node.create_signed_envelope(resp))
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        reflector_server = await asyncio.start_server(reflector_handler, "127.0.0.1", 0)
        reflector_port = reflector_server.sockets[0].getsockname()[1]

        try:
            success, msg = await node.connect_to_peer("127.0.0.1", reflector_port, timeout=1.0)
            assert success is False
            assert "rejected handshake" in msg or "Connection failed" in msg
            assert ("127.0.0.1", reflector_port) not in node.peers
            assert node.peer_id not in [p[0] for p in node.peers.values()]
        finally:
            reflector_server.close()
            await reflector_server.wait_closed()
            node.stop()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", [None, 127001, ["127.0.0.1"], {"host": "127.0.0.1"}, b"127.0.0.1", object()])
    async def test_host_non_string_types_rejected(self, isolated_node, invalid_host):
        """Verify non-string host types are rejected cleanly with 'Invalid host'."""
        success, msg = await isolated_node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("invalid_host", ["", "   ", "\t\r\n", "  \n  "])
    async def test_host_empty_and_whitespace_rejected(self, isolated_node, invalid_host):
        """Verify empty and whitespace hosts are rejected cleanly with 'Invalid host'."""
        success, msg = await isolated_node.connect_to_peer(invalid_host, 8000)
        assert success is False
        assert msg == "Invalid host"

    @pytest.mark.asyncio
    async def test_host_surrounding_whitespace_stripped(self, isolated_node):
        """Verify leading and trailing whitespace is stripped before self-check."""
        success, msg = await isolated_node.connect_to_peer("   127.0.0.1   ", isolated_node.port)
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_self_connection_exact_matches(self, tmp_path):
        """Verify exact self-connection rejection on 127.0.0.1, localhost, and advertised_host."""
        port = find_free_tcp_port()
        node = P2PNode("0.0.0.0", port, db_path=str(tmp_path / "rep.db"), storage_dir=str(tmp_path / "store"), advertise_host="192.168.1.50")
        try:
            for h in ["127.0.0.1", "localhost", "0.0.0.0", "192.168.1.50"]:
                success, msg = await node.connect_to_peer(h, port)
                assert success is False
                assert msg == "Cannot connect to self"
        finally:
            node.stop()


# =============================================================================
# 3. Port Boundary & Type Safety Tests
# =============================================================================

class TestPortBoundaryAndTypeSafety:
    """Stress-test port validation, integer bounds, float truncation, and type coercion."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("out_of_bounds_port", [0, -1, -9999, 65536, 70000, 100000])
    async def test_port_out_of_bounds_rejected(self, isolated_node, out_of_bounds_port):
        """Verify ports outside 1..65535 are strictly rejected."""
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", out_of_bounds_port)
        assert success is False
        assert "Invalid port" in msg
        assert "between 1 and 65535" in msg

    @pytest.mark.asyncio
    @pytest.mark.parametrize("non_numeric_port", ["abc", "80a", "port", "", "  ", None, [], {}, float("nan")])
    async def test_port_non_numeric_and_nan_rejected(self, isolated_node, non_numeric_port):
        """Verify non-numeric strings, collections, and NaN floats are rejected."""
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", non_numeric_port)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    async def test_port_float_coercion_vulnerability(self, isolated_node):
        """
        Adversarial Test:
        Verify non-integer float ports (e.g. 8000.5) are strictly rejected upfront.
        """
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", 8000.5, timeout=0.1)
        assert success is False
        assert "Invalid port" in msg

    @pytest.mark.asyncio
    async def test_port_bool_coercion_vulnerability(self, isolated_node):
        """
        Adversarial Test:
        Verify boolean values (True, False) are strictly rejected and not coerced to 1/0.
        """
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", True, timeout=0.1)
        assert success is False
        assert "Invalid port" in msg

        success_f, msg_f = await isolated_node.connect_to_peer("127.0.0.1", False, timeout=0.1)
        assert success_f is False
        assert "Invalid port" in msg_f

    @pytest.mark.asyncio
    async def test_port_numeric_string_coercion_valid(self, isolated_node):
        """Verify valid numeric string (e.g. '8000') is coerced to int and proceeds."""
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", str(isolated_node.port))
        assert success is False
        assert msg == "Cannot connect to self"

    @pytest.mark.asyncio
    async def test_port_max_boundary_65535_accepted_for_validation(self, isolated_node):
        """Verify maximum valid TCP port (65535) passes port range check."""
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", 65535, timeout=0.05)
        assert "between 1 and 65535" not in msg


# =============================================================================
# 4. In-Flight Blacklist Mutation Tests
# =============================================================================

class TestInFlightBlacklistMutation:
    """Stress-test zero-trust enforcement when reputation is mutated during in-flight network ops."""

    @pytest.mark.asyncio
    async def test_blacklist_mutated_while_ping_in_flight(self, isolated_node):
        """
        Adversarial Test:
        1. Node initiates connect_to_peer to a remote peer.
        2. Remote peer receives PING.
        3. BEFORE remote peer responds with PONG, remote peer's ID is blacklisted in SQLite.
        4. Remote peer sends valid signed PONG envelope.
        5. Node's verify_envelope detects BLACKLISTED_PEER, drops connection, and cleans up.
        """
        remote_ident = PeerIdentity("RemotePeer")
        remote_id = remote_ident.get_peer_id()

        ping_received = asyncio.Event()
        unblock_pong = asyncio.Event()

        async def remote_handler(reader, writer):
            try:
                req = await read_frame(reader)
                ping_received.set()
                await unblock_pong.wait()
                resp = {'type': 'PONG', 'sender_id': remote_id, 'sender_name': 'RemotePeer', 'files': {}}
                await send_frame(writer, create_signed_envelope(remote_ident, resp))
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(remote_handler, "127.0.0.1", 0)
        remote_port = server.sockets[0].getsockname()[1]

        try:
            connect_task = asyncio.create_task(isolated_node.connect_to_peer("127.0.0.1", remote_port, timeout=3.0))
            await ping_received.wait()

            # In-flight reputation mutation: Blacklist the remote peer
            isolated_node.reputation.add_peer(remote_id)
            isolated_node.reputation.update_trust(remote_id, False)
            isolated_node.reputation.update_trust(remote_id, False)
            assert isolated_node.reputation.is_blacklisted(remote_id)

            # Unblock PONG delivery
            unblock_pong.set()
            success, msg = await connect_task

            assert success is False
            assert "rejected handshake" in msg or "Connection failed" in msg
            assert ("127.0.0.1", remote_port) not in isolated_node.peers
            assert remote_id not in isolated_node.peer_files
        finally:
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_blacklist_precheck_drops_without_network_io(self, isolated_node):
        """Verify pre-existing blacklisted peer entry in peers table drops without socket connect."""
        target_host = "10.0.0.5"
        target_port = 7777
        bad_peer_id = "0" * 64

        isolated_node.reputation.add_peer(bad_peer_id)
        isolated_node.reputation.update_trust(bad_peer_id, False)
        isolated_node.reputation.update_trust(bad_peer_id, False)
        assert isolated_node.reputation.is_blacklisted(bad_peer_id)

        isolated_node.peers[(target_host, target_port)] = (bad_peer_id, "BadNode")

        success, msg = await isolated_node.connect_to_peer(target_host, target_port)
        assert success is False
        assert msg == "Peer is blacklisted"


# =============================================================================
# 5. Slow Lorris & Hanging Socket Resilience Tests
# =============================================================================

class TestSlowLorrisAndHangingSockets:
    """Stress-test timeout enforcement and socket resource cleanup against slow/hanging peers."""

    @pytest.mark.asyncio
    async def test_slow_lorris_partial_frame_header_timeout(self, isolated_node):
        """
        Adversarial Test:
        Remote peer accepts connection, reads request, sends only 2 bytes of the 4-byte header,
        and then goes silent. Node must timeout cleanly within specified timeout.
        """
        stop_event = asyncio.Event()

        async def slow_lorris_handler(reader, writer):
            try:
                await reader.read(10)
                writer.write(b'\x00\x00')  # Partial 2-byte header
                await writer.drain()
                await stop_event.wait()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(slow_lorris_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            t0 = time.time()
            success, msg = await isolated_node.connect_to_peer("127.0.0.1", port, timeout=0.3)
            elapsed = time.time() - t0

            assert success is False
            assert elapsed < 1.0
            assert ("127.0.0.1", port) not in isolated_node.peers
        finally:
            stop_event.set()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_hanging_socket_zero_bytes_timeout(self, isolated_node):
        """
        Adversarial Test:
        Remote peer accepts connection and hangs without sending any response.
        Node must abort with timeout within specified deadline.
        """
        stop_event = asyncio.Event()

        async def silent_handler(reader, writer):
            try:
                await reader.read(1024)
                await stop_event.wait()
            except Exception:
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(silent_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        try:
            t0 = time.time()
            success, msg = await isolated_node.connect_to_peer("127.0.0.1", port, timeout=0.2)
            elapsed = time.time() - t0

            assert success is False
            assert elapsed < 0.8
            assert ("127.0.0.1", port) not in isolated_node.peers
        finally:
            stop_event.set()
            server.close()
            await server.wait_closed()

    @pytest.mark.asyncio
    async def test_immediate_connection_refused_clean_failure(self, isolated_node):
        """Verify connecting to a closed port fails immediately without hanging."""
        closed_port = find_free_tcp_port()
        t0 = time.time()
        success, msg = await isolated_node.connect_to_peer("127.0.0.1", closed_port, timeout=0.5)
        elapsed = time.time() - t0

        assert success is False
        assert elapsed < 1.0
        assert ("127.0.0.1", closed_port) not in isolated_node.peers
