"""
Empirical Challenger 1 Suite for Milestone 2:
Dynamic Stress Tests on TCP Framing, Coalesced JSON Frames, and Malformed Length Headers.

Tested against:
- `src.core.p2p_node` (pack_tcp_frame, unpack_tcp_frame, read_frame, send_frame, handle_client, P2PNode)
"""

import asyncio
import json
import os
import struct
import time
import pytest
from src.core.p2p_node import (
    P2PNode,
    pack_tcp_frame,
    unpack_tcp_frame,
    read_frame,
    send_frame,
    create_signed_envelope,
    HEADER_SIZE,
    MAX_MESSAGE_SIZE,
)
from src.core.crypto import PeerIdentity
from tests.conftest import find_free_port


@pytest.fixture
async def p2p_server(isolated_dir):
    """Start an active P2PNode TCP server for empirical socket-level testing."""
    port = find_free_port()
    db_path = f"test_challenger_rep_{port}.db"
    storage_dir = f"test_challenger_store_{port}"
    os.makedirs(storage_dir, exist_ok=True)

    node = P2PNode(
        host="127.0.0.1",
        port=port,
        db_path=db_path,
        storage_dir=storage_dir,
        node_name=f"server_node_{port}"
    )

    server = await asyncio.start_server(node.handle_client, node.host, node.port)
    server_task = asyncio.create_task(server.serve_forever())

    try:
        yield node, port
    finally:
        server.close()
        await server.wait_closed()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


class TestChallengerTCPFramingFragments:
    """1. Dynamic stress tests on TCP framing: split packets across 1B, 10B, 1024B fragments over real sockets."""

    async def test_tcp_framing_1b_fragments_real_socket(self, p2p_server, identity_factory):
        """Split a valid signed frame into 1-byte fragments sent over a real TCP socket."""
        node, port = p2p_server
        client_id = identity_factory("client_1b")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            payload = {
                "type": "PING",
                "sender_id": client_id.get_peer_id(),
                "sender_name": "client_1b",
                "host": "127.0.0.1",
                "port": 9991,
                "files": {}
            }
            envelope = create_signed_envelope(client_id, payload)
            raw_frame = pack_tcp_frame(envelope)

            # Send 1 byte at a time through writer.write and drain to stress TCP byte stream
            for b in raw_frame:
                writer.write(bytes([b]))
            await writer.drain()

            # Read response from server
            resp_frame = await read_frame(reader)
            assert resp_frame is not None, "Server must cleanly reassemble 1B fragments and return a response"
            assert resp_frame.get("sender_id") == node.peer_id
            assert resp_frame.get("payload", {}).get("type") == "PONG"
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tcp_framing_10b_fragments_real_socket(self, p2p_server, identity_factory):
        """Split a valid signed frame into 10-byte fragments over a real TCP socket."""
        node, port = p2p_server
        client_id = identity_factory("client_10b")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            payload = {
                "type": "PING",
                "sender_id": client_id.get_peer_id(),
                "sender_name": "client_10b",
                "host": "127.0.0.1",
                "port": 9992,
                "files": {}
            }
            envelope = create_signed_envelope(client_id, payload)
            raw_frame = pack_tcp_frame(envelope)

            # Send in 10-byte slices
            chunk_size = 10
            for i in range(0, len(raw_frame), chunk_size):
                writer.write(raw_frame[i:i + chunk_size])
                await writer.drain()
                await asyncio.sleep(0.001)

            resp_frame = await read_frame(reader)
            assert resp_frame is not None, "Server must cleanly reassemble 10B fragments"
            assert resp_frame.get("payload", {}).get("type") == "PONG"
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tcp_framing_1024b_fragments_large_payload_real_socket(self, p2p_server, identity_factory):
        """Split a 64KB+ payload into 1024-byte fragments over a real TCP socket."""
        node, port = p2p_server
        client_id = identity_factory("client_1024b")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            # Construct a large payload with a 60,000-char string
            large_data = "X" * 60000
            payload = {
                "type": "SHARE_FILE_INFO",
                "sender_id": client_id.get_peer_id(),
                "filename": "heavy_test.dat",
                "merkle_root": "0" * 64,
                "total_chunks": 10,
                "host": "127.0.0.1",
                "port": 9993,
                "extra_metadata": large_data
            }
            envelope = create_signed_envelope(client_id, payload)
            raw_frame = pack_tcp_frame(envelope)
            assert len(raw_frame) > 60000

            # Send in 1024-byte chunks
            chunk_size = 1024
            for i in range(0, len(raw_frame), chunk_size):
                writer.write(raw_frame[i:i + chunk_size])
                await writer.drain()

            resp_frame = await read_frame(reader)
            assert resp_frame is not None, "Server must cleanly receive and reassemble large 1024B-fragmented frame"
            assert resp_frame.get("payload", {}).get("status") == "OK"
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_tcp_framing_split_header_real_socket(self, p2p_server, identity_factory):
        """Empirically test fragmentation that slices directly across the 4-byte length header."""
        node, port = p2p_server
        client_id = identity_factory("client_header_split")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            payload = {
                "type": "PING",
                "sender_id": client_id.get_peer_id(),
                "sender_name": "client_header_split"
            }
            envelope = create_signed_envelope(client_id, payload)
            raw_frame = pack_tcp_frame(envelope)

            # Send 2 bytes of header, pause, send remaining 2 bytes of header + partial payload
            writer.write(raw_frame[:2])
            await writer.drain()
            await asyncio.sleep(0.01)

            writer.write(raw_frame[2:15])
            await writer.drain()
            await asyncio.sleep(0.01)

            writer.write(raw_frame[15:])
            await writer.drain()

            resp_frame = await read_frame(reader)
            assert resp_frame is not None
            assert resp_frame.get("payload", {}).get("type") == "PONG"
        finally:
            writer.close()
            await writer.wait_closed()


class TestChallengerCoalescedFrames:
    """2. Coalesced JSON frames arriving in single socket read; verify sequential unpacking."""

    async def test_coalesced_frames_single_socket_write(self, p2p_server, identity_factory):
        """Send 5 consecutive signed frames concatenated in a SINGLE socket write over real TCP."""
        node, port = p2p_server
        client_id = identity_factory("client_coalesced")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            num_frames = 5
            frames_bytes = b""
            for i in range(num_frames):
                payload = {
                    "type": "PING",
                    "sender_id": client_id.get_peer_id(),
                    "sender_name": f"client_burst_{i}",
                    "seq": i
                }
                envelope = create_signed_envelope(client_id, payload)
                frames_bytes += pack_tcp_frame(envelope)

            # Write all 5 frames in a SINGLE write call so they arrive coalesced in the socket buffer
            writer.write(frames_bytes)
            await writer.drain()

            # Read and verify 5 sequential responses
            for i in range(num_frames):
                resp = await read_frame(reader)
                assert resp is not None, f"Response #{i} must be unpacked cleanly from coalesced stream"
                assert resp.get("payload", {}).get("type") == "PONG"
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_coalesced_mixed_request_types(self, p2p_server, identity_factory):
        """Send mixed request types (PING, SHARE_FILE_INFO, PING) in a single coalesced buffer."""
        node, port = p2p_server
        client_id = identity_factory("client_mixed")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            p1 = {"type": "PING", "sender_id": client_id.get_peer_id(), "tag": "req_1"}
            p2 = {
                "type": "SHARE_FILE_INFO",
                "sender_id": client_id.get_peer_id(),
                "filename": "coalesced_file.txt",
                "merkle_root": "f" * 64,
                "total_chunks": 1,
                "tag": "req_2"
            }
            p3 = {"type": "PING", "sender_id": client_id.get_peer_id(), "tag": "req_3"}

            env1 = create_signed_envelope(client_id, p1)
            env2 = create_signed_envelope(client_id, p2)
            env3 = create_signed_envelope(client_id, p3)

            coalesced_stream = pack_tcp_frame(env1) + pack_tcp_frame(env2) + pack_tcp_frame(env3)

            writer.write(coalesced_stream)
            await writer.drain()

            resp1 = await read_frame(reader)
            assert resp1 is not None and resp1.get("payload", {}).get("type") == "PONG"

            resp2 = await read_frame(reader)
            assert resp2 is not None and resp2.get("payload", {}).get("status") == "OK"

            resp3 = await read_frame(reader)
            assert resp3 is not None and resp3.get("payload", {}).get("type") == "PONG"
        finally:
            writer.close()
            await writer.wait_closed()

    def test_unpack_tcp_frame_buffer_sequential_coalesced(self):
        """Empirically test unpack_tcp_frame on a raw bytes buffer holding 10 concatenated frames."""
        frames = []
        full_buffer = b""
        for i in range(10):
            msg = {"index": i, "payload": f"data_block_{i}"}
            frames.append(msg)
            full_buffer += pack_tcp_frame(msg)

        buffer = full_buffer
        unpacked_messages = []
        while buffer:
            msg, buffer = unpack_tcp_frame(buffer)
            if msg is None:
                break
            unpacked_messages.append(msg)

        assert len(unpacked_messages) == 10
        assert unpacked_messages == frames
        assert buffer == b""

    def test_unpack_tcp_frame_buffer_partial_frame_interleaving(self):
        """Test unpack_tcp_frame with incomplete boundaries: partial headers and payloads."""
        msg1 = {"step": 1}
        msg2 = {"step": 2}

        f1 = pack_tcp_frame(msg1)
        f2 = pack_tcp_frame(msg2)

        # Buffer contains full f1 + 2 bytes of f2 header
        buf = f1 + f2[:2]
        decoded1, rem = unpack_tcp_frame(buf)
        assert decoded1 == msg1
        assert rem == f2[:2]

        # Cannot unpack with partial header
        decoded_none, rem2 = unpack_tcp_frame(rem)
        assert decoded_none is None
        assert rem2 == f2[:2]

        # Add 2 more bytes (complete header) + 3 bytes of f2 payload
        rem3 = rem2 + f2[2:HEADER_SIZE + 3]
        decoded_none2, rem4 = unpack_tcp_frame(rem3)
        assert decoded_none2 is None
        assert rem4 == rem3

        # Add remainder of f2
        rem5 = rem4 + f2[HEADER_SIZE + 3:]
        decoded2, final_rem = unpack_tcp_frame(rem5)
        assert decoded2 == msg2
        assert final_rem == b""


class TestChallengerMalformedLengthHeaders:
    """3. Malformed length headers (0, negative, >16MB); verify clean rejection."""

    def test_unpack_tcp_frame_zero_length_raises_value_error(self):
        """Header with length=0 must raise ValueError."""
        header_zero = struct.pack(">I", 0)
        with pytest.raises(ValueError, match=r"Invalid frame length: 0"):
            unpack_tcp_frame(header_zero)

    def test_unpack_tcp_frame_negative_length_raises_value_error(self):
        """Header with signed negative length (packed as >i) must raise ValueError."""
        header_neg = struct.pack(">i", -1)  # 0xFFFFFFFF = 4294967295 as >I
        with pytest.raises(ValueError, match=r"Invalid frame length"):
            unpack_tcp_frame(header_neg)

        header_neg2 = struct.pack(">i", -500)
        with pytest.raises(ValueError, match=r"Invalid frame length"):
            unpack_tcp_frame(header_neg2)

    def test_unpack_tcp_frame_exceeds_16mb_raises_value_error(self):
        """Header exceeding MAX_MESSAGE_SIZE (16MB) must raise ValueError."""
        header_oversized = struct.pack(">I", MAX_MESSAGE_SIZE + 1)
        with pytest.raises(ValueError, match=r"Invalid frame length"):
            unpack_tcp_frame(header_oversized)

        header_huge = struct.pack(">I", 100 * 1024 * 1024)
        with pytest.raises(ValueError, match=r"Invalid frame length"):
            unpack_tcp_frame(header_huge)

    def test_pack_tcp_frame_oversized_payload_raises_value_error(self):
        """pack_tcp_frame with payload larger than 16MB must raise ValueError."""
        fake_dict = {"large": "A" * (MAX_MESSAGE_SIZE + 10)}
        with pytest.raises(ValueError, match=r"exceeds MAX_MESSAGE_SIZE"):
            pack_tcp_frame(fake_dict)

    async def test_malformed_header_zero_length_real_socket(self, p2p_server):
        """Send length header = 0 over real socket; server must cleanly disconnect without crashing."""
        node, port = p2p_server
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            # Send length = 0
            writer.write(struct.pack(">I", 0))
            await writer.drain()

            # Server must drop connection -> read returns EOF (b'')
            resp = await reader.read(1024)
            assert resp == b"", "Server must cleanly terminate connection on length=0 header"
        finally:
            writer.close()
            await writer.wait_closed()

        # Verify server remains operational for honest client
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        try:
            c_id = PeerIdentity("verify_liveness")
            env = create_signed_envelope(c_id, {"type": "PING", "sender_id": c_id.get_peer_id()})
            await send_frame(writer2, env)
            resp2 = await read_frame(reader2)
            assert resp2 is not None
            assert resp2.get("payload", {}).get("type") == "PONG"
        finally:
            writer2.close()
            await writer2.wait_closed()

    async def test_malformed_header_negative_length_real_socket(self, p2p_server):
        """Send negative length header (-1, -100) over real socket; server must drop cleanly."""
        node, port = p2p_server
        for neg_val in [-1, -42, -2147483648]:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(struct.pack(">i", neg_val))
                await writer.drain()

                resp = await reader.read(1024)
                assert resp == b"", f"Server must terminate connection on negative length ({neg_val})"
            finally:
                writer.close()
                await writer.wait_closed()

    async def test_malformed_header_exceeds_16mb_real_socket(self, p2p_server):
        """Send length header >16MB over real socket; server must drop without allocating memory."""
        node, port = p2p_server
        for oversized in [MAX_MESSAGE_SIZE + 1, 32 * 1024 * 1024, 0xFFFFFFFF]:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(struct.pack(">I", oversized))
                await writer.drain()

                resp = await reader.read(1024)
                assert resp == b"", f"Server must terminate connection on oversized length ({oversized})"
            finally:
                writer.close()
                await writer.wait_closed()

    async def test_malformed_header_truncated_connection_close_real_socket(self, p2p_server):
        """Client sends partial header (1..3 bytes) and immediately disconnects; server handles cleanly."""
        node, port = p2p_server
        for partial_len in [1, 2, 3]:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x00" * partial_len)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        # Verify server is still completely responsive
        reader_test, writer_test = await asyncio.open_connection("127.0.0.1", port)
        try:
            t_id = PeerIdentity("test_post_partial")
            env = create_signed_envelope(t_id, {"type": "PING", "sender_id": t_id.get_peer_id()})
            await send_frame(writer_test, env)
            resp = await read_frame(reader_test)
            assert resp is not None
        finally:
            writer_test.close()
            await writer_test.wait_closed()

    async def test_malformed_payload_truncated_body_real_socket(self, p2p_server):
        """Client claims 500-byte length header but only delivers 20 bytes before closing socket."""
        node, port = p2p_server
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(struct.pack(">I", 500) + b"A" * 20)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        # Verify server is still alive
        reader_test, writer_test = await asyncio.open_connection("127.0.0.1", port)
        try:
            t_id = PeerIdentity("test_post_trunc")
            env = create_signed_envelope(t_id, {"type": "PING", "sender_id": t_id.get_peer_id()})
            await send_frame(writer_test, env)
            resp = await read_frame(reader_test)
            assert resp is not None
        finally:
            writer_test.close()
            await writer_test.wait_closed()

    async def test_malformed_payload_corrupted_json_or_utf8_real_socket(self, p2p_server):
        """Payload declaring valid length but containing invalid UTF-8 or malformed JSON."""
        node, port = p2p_server

        # 1. Non-UTF8 payload
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            bad_bytes = b"\xff\xfe\xfd\xfc" * 8
            writer.write(struct.pack(">I", len(bad_bytes)) + bad_bytes)
            await writer.drain()
            resp = await reader.read(1024)
            assert resp == b"", "Server must drop connection on invalid UTF-8 payload"
        finally:
            writer.close()
            await writer.wait_closed()

        # 2. Valid UTF-8 but invalid JSON
        reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
        try:
            not_json = b"{'unclosed_json: true"
            writer2.write(struct.pack(">I", len(not_json)) + not_json)
            await writer2.drain()
            resp2 = await reader2.read(1024)
            assert resp2 == b"", "Server must drop connection on invalid JSON payload"
        finally:
            writer2.close()
            await writer2.wait_closed()


class TestChallengerFramingConcurrency:
    """Stress test: concurrent clients mixing 1B fragments, coalescing, and malformed frames."""

    async def test_concurrent_heterogeneous_traffic(self, p2p_server, identity_factory):
        """
        Concurrently run:
        - 4 clients sending 1B fragmented frames
        - 3 clients sending coalesced bursts
        - 3 adversarial clients sending malformed headers
        All honest clients must succeed, malformed clients must be dropped, and server must not crash.
        """
        node, port = p2p_server

        async def worker_fragmented_1b(worker_id):
            client_id = identity_factory(f"worker_1b_{worker_id}")
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                payload = {
                    "type": "PING",
                    "sender_id": client_id.get_peer_id(),
                    "sender_name": f"worker_1b_{worker_id}"
                }
                envelope = create_signed_envelope(client_id, payload)
                raw_frame = pack_tcp_frame(envelope)
                for b in raw_frame:
                    writer.write(bytes([b]))
                    await writer.drain()
                resp = await read_frame(reader)
                assert resp is not None
                assert resp.get("payload", {}).get("type") == "PONG"
                return True
            finally:
                writer.close()
                await writer.wait_closed()

        async def worker_coalesced(worker_id):
            client_id = identity_factory(f"worker_coal_{worker_id}")
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                stream = b""
                for i in range(3):
                    p = {"type": "PING", "sender_id": client_id.get_peer_id(), "seq": i}
                    stream += pack_tcp_frame(create_signed_envelope(client_id, p))
                writer.write(stream)
                await writer.drain()

                for i in range(3):
                    resp = await read_frame(reader)
                    assert resp is not None
                    assert resp.get("payload", {}).get("type") == "PONG"
                return True
            finally:
                writer.close()
                await writer.wait_closed()

        async def worker_malformed(worker_id):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                # Send invalid headers
                if worker_id % 3 == 0:
                    writer.write(struct.pack(">I", 0))
                elif worker_id % 3 == 1:
                    writer.write(struct.pack(">i", -10))
                else:
                    writer.write(struct.pack(">I", MAX_MESSAGE_SIZE + 500))
                await writer.drain()
                resp = await reader.read(1024)
                assert resp == b""
                return True
            finally:
                writer.close()
                await writer.wait_closed()

        tasks = []
        for i in range(4):
            tasks.append(worker_fragmented_1b(i))
        for i in range(3):
            tasks.append(worker_coalesced(i))
        for i in range(3):
            tasks.append(worker_malformed(i))

        results = await asyncio.gather(*tasks)
        assert all(results is True for results in results)


class TestChallengerAdversarialEdgeCases:
    """Adversarial challenge edge cases: middle-malformed coalesced frames, non-dict JSON, and raw BSD sockets."""

    async def test_coalesced_with_middle_malformed_frame(self, p2p_server, identity_factory):
        """
        Stream contains: Frame 1 (valid PING) + Frame 2 (malformed length=0) + Frame 3 (valid PING).
        Server should process Frame 1 and respond, then cleanly disconnect on Frame 2 without processing Frame 3.
        """
        node, port = p2p_server
        client_id = identity_factory("client_mid_bad")

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            f1 = pack_tcp_frame(create_signed_envelope(client_id, {"type": "PING", "seq": 1}))
            bad_f2 = struct.pack(">I", 0)  # length 0 header
            f3 = pack_tcp_frame(create_signed_envelope(client_id, {"type": "PING", "seq": 3}))

            writer.write(f1 + bad_f2 + f3)
            await writer.drain()

            # Read response 1
            resp1 = await read_frame(reader)
            assert resp1 is not None
            assert resp1.get("payload", {}).get("type") == "PONG"

            # Connection should now be closed by server on encountering length 0
            rest = await reader.read(1024)
            assert rest == b"", "Server must disconnect after encountering malformed frame in stream"
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_non_dict_json_payloads_real_socket(self, p2p_server):
        """
        Test non-dict JSON payloads: list, string, integer, boolean, null.
        Server must reject cleanly or terminate connection without crashing.
        """
        node, port = p2p_server
        test_payloads = [
            [1, 2, 3],
            "just_a_raw_string",
            98765,
            True,
            None
        ]

        for val in test_payloads:
            raw_bytes = json.dumps(val).encode('utf-8')
            frame = struct.pack(">I", len(raw_bytes)) + raw_bytes

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                writer.write(frame)
                await writer.drain()

                resp = await reader.read(1024)
                assert resp == b"", f"Server must terminate connection on non-dict payload {val}"
            finally:
                writer.close()
                await writer.wait_closed()

    async def test_raw_bsd_socket_streaming(self, p2p_server, identity_factory):
        """Verify TCP framing over a raw synchronous BSD socket with TCP_NODELAY."""
        import socket
        node, port = p2p_server
        client_id = identity_factory("raw_bsd_client")

        env = create_signed_envelope(client_id, {"type": "PING", "sender_id": client_id.get_peer_id()})
        frame = pack_tcp_frame(env)

        def sync_client_run():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.connect(("127.0.0.1", port))

                # Send byte-by-byte synchronously
                for b in frame:
                    s.sendall(bytes([b]))

                # Read 4-byte header
                header = s.recv(4)
                assert len(header) == 4
                resp_len = struct.unpack(">I", header)[0]
                assert 0 < resp_len <= MAX_MESSAGE_SIZE

                # Read payload
                payload_data = b""
                while len(payload_data) < resp_len:
                    chunk = s.recv(resp_len - len(payload_data))
                    assert len(chunk) > 0
                    payload_data += chunk

                resp_json = json.loads(payload_data.decode('utf-8'))
                assert resp_json.get("payload", {}).get("type") == "PONG"
                return True

        result = await asyncio.to_thread(sync_client_run)
        assert result is True

