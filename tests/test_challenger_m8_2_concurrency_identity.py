import pytest
import asyncio
import os
import shutil
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from src.core.p2p_node import P2PNode
from src.core.crypto import PeerIdentity, MerkleTree


@pytest.fixture
def temp_node_dir():
    temp_dir = tempfile.mkdtemp(prefix="p2p_test_m8_2_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


class TestPeerIdentityAndDisplayFormatting:
    """
    Stress-test peer identity formatting, multi-provider listing, and ID preservation.
    """

    def test_peer_name_fallback_empty_whitespace_unknown(self):
        """
        Adversarial test: verify that missing, empty, whitespace-only,
        and 'Unknown' usernames fallback strictly to Node_{port}.
        """
        cases = [
            # (raw_name, port, expected_fallback)
            ("", 5001, "Node_5001"),
            ("   ", 5002, "Node_5002"),
            ("\t\n  \r", 5003, "Node_5003"),
            ("Unknown", 5004, "Node_5004"),
            (None, 5005, "Node_5005"),
            ("UNKNOWN", 5006, "UNKNOWN"), # Case sensitive check
            ("Alice", 5007, "Alice"),
            ("Bob_P2P", 5008, "Bob_P2P"),
        ]

        for raw_name, peer_port, expected in cases:
            # col1 logic from dashboard.py line 189
            name_val = str(raw_name) if raw_name is not None else ""
            peer_name = name_val if (name_val and name_val.strip() and name_val != "Unknown") else f"Node_{peer_port}"
            assert peer_name == expected, f"Failed fallback for raw_name={raw_name!r}: got {peer_name}, expected {expected}"

    def test_multi_provider_formatting_spec(self):
        """
        Verify provider lists with multiple providers are formatted as:
        'Alice (3a1b4c5d), Bob (8f2e1a4b), Node_5003 (9c3d1e2f)'
        """
        providers = [
            ("127.0.0.1", 5001, "3a1b4c5d" + "0" * 56, "Alice"),
            ("127.0.0.1", 5002, "8f2e1a4b" + "1" * 56, "Bob"),
            ("127.0.0.1", 5003, "9c3d1e2f" + "2" * 56, "Unknown"), # should fallback
            ("127.0.0.1", 5004, "4e5f6a7b" + "3" * 56, "   "),     # whitespace fallback
            ("127.0.0.1", 5005, "5a6b7c8d" + "4" * 56, ""),        # empty fallback
        ]

        h_names = []
        for p in providers:
            p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
            h_names.append(f"{p_display} ({p[2][:8]})")

        caption_result = f"Available from: {', '.join(h_names)}"
        expected_caption = (
            "Available from: Alice (3a1b4c5d), Bob (8f2e1a4b), "
            "Node_5003 (9c3d1e2f), Node_5004 (4e5f6a7b), Node_5005 (5a6b7c8d)"
        )
        assert caption_result == expected_caption, f"Formatted caption mismatch:\nGot: {caption_result}\nExp: {expected_caption}"

    def test_network_files_preserves_crypto_identities(self, temp_node_dir):
        """
        Ensure node.get_network_files() preserves 64-char peer_id and merkle_root,
        and provider tuples contain genuine peer_ids.
        """
        db_path = os.path.join(temp_node_dir, "rep.db")
        node = P2PNode(host="127.0.0.1", port=9100, db_path=db_path, storage_dir=temp_node_dir, node_name="Tester")

        peer1_id = "a" * 64
        peer2_id = "b" * 64
        mroot = "c" * 64

        node.peers[("127.0.0.1", 9101)] = (peer1_id, "Alice")
        node.peers[("127.0.0.1", 9102)] = (peer2_id, "Unknown")

        node.peer_files[peer1_id] = {
            "dataset.csv": {
                "merkle_root": mroot,
                "file_id": mroot,
                "total_chunks": 4,
                "file_size": 1024
            }
        }
        node.peer_files[peer2_id] = {
            "dataset.csv": {
                "merkle_root": mroot,
                "file_id": mroot,
                "total_chunks": 4,
                "file_size": 1024
            }
        }

        net_files = node.get_network_files()
        swarm_key = f"dataset.csv@{mroot[:8]}"
        assert swarm_key in net_files, f"Expected compound key {swarm_key} in net_files"

        entry = net_files[swarm_key]
        assert entry["merkle_root"] == mroot
        assert entry["file_id"] == mroot
        assert len(entry["merkle_root"]) == 64
        assert len(entry["file_id"]) == 64
        assert entry["merkle_root"] != "Tester"
        assert entry["merkle_root"] != "Alice"

        # Check providers
        providers = entry["providers"]
        assert len(providers) == 2

        # Provider 1: Alice
        p1 = [p for p in providers if p[1] == 9101][0]
        assert p1[0] == "127.0.0.1"
        assert p1[1] == 9101
        assert p1[2] == peer1_id  # 64-char hex
        assert p1[3] == "Alice"

        # Provider 2: Unknown
        p2 = [p for p in providers if p[1] == 9102][0]
        assert p2[0] == "127.0.0.1"
        assert p2[1] == 9102
        assert p2[2] == peer2_id  # 64-char hex
        assert p2[3] == "Unknown"

    @pytest.mark.asyncio
    async def test_download_request_payload_invariants(self, temp_node_dir):
        """
        Adversarially verify that during download_file_from_swarm:
        1. 'sender_id' is node.peer_id (64-char hex), NEVER the username string.
        2. 'file_id' and 'merkle_root' are the 64-char Merkle root, NEVER username.
        3. Provider targets in the dispatch are strictly addressed by peer_id.
        """
        db_path = os.path.join(temp_node_dir, "rep.db")
        node = P2PNode(host="127.0.0.1", port=9200, db_path=db_path, storage_dir=temp_node_dir, node_name="Alice_Human")

        # Capture outbound payload sent by _send_request
        intercepted_requests = []

        async def mock_send_request(host, port, payload):
            intercepted_requests.append((host, port, dict(payload)))
            # Return empty response to simulate offline provider without raising
            return None

        node._send_request = mock_send_request

        expected_root = "f" * 64
        provider_id = "e" * 64
        providers = [("127.0.0.1", 9201, provider_id, "Bob_Provider")]

        # Attempt download
        result = await node.download_file_from_swarm(
            filename="secure_payload.bin",
            providers=providers,
            expected_root=expected_root,
            total_chunks=1,
            file_id=expected_root
        )

        assert len(intercepted_requests) > 0, "No requests intercepted"
        target_host, target_port, payload = intercepted_requests[0]

        assert target_host == "127.0.0.1"
        assert target_port == 9201
        assert payload["type"] == "GET_CHUNK"

        # Invariant 1: sender_id must be 64-char RSA key hash, not "Alice_Human"
        assert payload["sender_id"] == node.peer_id
        assert len(payload["sender_id"]) == 64
        assert payload["sender_id"] != "Alice_Human"

        # Invariant 2: file_id & merkle_root must be 64-char hash, not "Alice_Human" or "Bob_Provider"
        assert payload["file_id"] == expected_root
        assert payload["merkle_root"] == expected_root
        assert len(payload["file_id"]) == 64
        assert payload["file_id"] != "Alice_Human"
        assert payload["file_id"] != "Bob_Provider"

    def test_merkle_root_partitioning_under_filename_collision(self, temp_node_dir):
        """
        Adversarial collision test: 5 peers share a file named 'invoice.pdf'
        with 3 different Merkle roots.
        Ensure get_network_files partitions swarms strictly by (filename, merkle_root)
        and preserves provider lists without username collisions.
        """
        db_path = os.path.join(temp_node_dir, "rep_coll.db")
        node = P2PNode(host="127.0.0.1", port=9500, db_path=db_path, storage_dir=temp_node_dir, node_name="Auditor")

        root_A = "a" * 64
        root_B = "b" * 64
        root_C = "c" * 64

        peers_meta = [
            ("127.0.0.1", 9501, "1" * 64, "Alice", root_A),
            ("127.0.0.1", 9502, "2" * 64, "Bob", root_A),
            ("127.0.0.1", 9503, "3" * 64, "Charlie", root_B),
            ("127.0.0.1", 9504, "4" * 64, "Dave", root_C),
            ("127.0.0.1", 9505, "5" * 64, "Eve", root_C),
        ]

        for host, port, pid, name, root in peers_meta:
            node.peers[(host, port)] = (pid, name)
            node.peer_files[pid] = {
                "invoice.pdf": {
                    "merkle_root": root,
                    "file_id": root,
                    "total_chunks": 2,
                    "file_size": 2048
                }
            }

        net_files = node.get_network_files()
        assert len(net_files) == 3, f"Expected 3 distinct swarms, got {len(net_files)}"

        swarm_A = net_files[f"invoice.pdf@{root_A[:8]}"]
        swarm_B = net_files[f"invoice.pdf@{root_B[:8]}"]
        swarm_C = net_files[f"invoice.pdf@{root_C[:8]}"]

        assert len(swarm_A["providers"]) == 2
        assert len(swarm_B["providers"]) == 1
        assert len(swarm_C["providers"]) == 2

        # Verify provider identities in swarm A
        p_ids_A = {p[2] for p in swarm_A["providers"]}
        p_names_A = {p[3] for p in swarm_A["providers"]}
        assert p_ids_A == {"1" * 64, "2" * 64}
        assert p_names_A == {"Alice", "Bob"}

    def test_unicode_and_adversarial_usernames_formatting(self):
        """
        Adversarial test: verify that special characters, emojis, HTML tags,
        and quotes in usernames do not break provider formatting.
        """
        providers = [
            ("127.0.0.1", 6001, "1" * 64, "🚀 Rocket_Peer"),
            ("127.0.0.1", 6002, "2" * 64, "<script>alert(1)</script>"),
            ("127.0.0.1", 6003, "3" * 64, "Alice \"The Builder\""),
            ("127.0.0.1", 6004, "4" * 64, "日本語_Node"),
            ("127.0.0.1", 6005, "5" * 64, "Unknown"), # Must fallback
        ]

        h_names = []
        for p in providers:
            p_display = p[3] if (len(p) > 3 and p[3] and str(p[3]).strip() and p[3] != "Unknown") else f"Node_{p[1]}"
            h_names.append(f"{p_display} ({p[2][:8]})")

        formatted = ", ".join(h_names)
        assert "🚀 Rocket_Peer (11111111)" in formatted
        assert "<script>alert(1)</script> (22222222)" in formatted
        assert "Alice \"The Builder\" (33333333)" in formatted
        assert "日本語_Node (44444444)" in formatted
        assert "Node_6005 (55555555)" in formatted


class TestConcurrentConnectStress:
    """
    Stress-test concurrent calling of connect_to_peer and connect_to_peer_sync.
    Ensures no state corruption of node.peers, no unhandled exceptions, and no event loop deadlocks.
    """

    @pytest.mark.asyncio
    async def test_concurrent_connect_to_peer_async_stress(self, temp_node_dir):
        """
        Stress test: 30 concurrent calls to connect_to_peer against active peers,
        inactive ports, self-connection, and duplicate connections simultaneously.
        """
        db_main = os.path.join(temp_node_dir, "rep_main.db")
        db_target1 = os.path.join(temp_node_dir, "rep_t1.db")
        db_target2 = os.path.join(temp_node_dir, "rep_t2.db")

        # Create main node and 2 target nodes
        main_node = P2PNode(host="127.0.0.1", port=9300, db_path=db_main, storage_dir=temp_node_dir, node_name="MainNode")
        target1 = P2PNode(host="127.0.0.1", port=9301, db_path=db_target1, storage_dir=temp_node_dir, node_name="TargetOne")
        target2 = P2PNode(host="127.0.0.1", port=9302, db_path=db_target2, storage_dir=temp_node_dir, node_name="TargetTwo")

        server_tasks = [
            asyncio.create_task(main_node.start_server()),
            asyncio.create_task(target1.start_server()),
            asyncio.create_task(target2.start_server())
        ]
        # Allow servers to bind
        await asyncio.sleep(0.3)

        try:
            # Build list of 30 concurrent connection tasks
            coros = []
            # 10 calls to target1 (duplicate concurrent connections)
            for _ in range(10):
                coros.append(main_node.connect_to_peer("127.0.0.1", 9301))
            # 10 calls to target2
            for _ in range(10):
                coros.append(main_node.connect_to_peer("127.0.0.1", 9302))
            # 5 calls to self (self-connection guard)
            for _ in range(5):
                coros.append(main_node.connect_to_peer("127.0.0.1", 9300))
            # 5 calls to inactive ports
            for p in [9390, 9391, 9392, 9393, 9394]:
                coros.append(main_node.connect_to_peer("127.0.0.1", p, timeout=1.0))

            results = await asyncio.gather(*coros, return_exceptions=True)

            # Assert no unhandled Python exceptions occurred
            for r in results:
                assert not isinstance(r, Exception), f"Unexpected exception in connect_to_peer: {r}"
                assert isinstance(r, tuple)
                assert len(r) == 2
                assert isinstance(r[0], bool)
                assert isinstance(r[1], str)

            # Verify node.peers dictionary integrity
            assert isinstance(main_node.peers, dict)
            # Both target1 and target2 must be in peers
            assert ("127.0.0.1", 9301) in main_node.peers
            assert ("127.0.0.1", 9302) in main_node.peers

            # Verify peer tuple integrity
            p1_entry = main_node.peers[("127.0.0.1", 9301)]
            assert isinstance(p1_entry, tuple)
            assert p1_entry[0] == target1.peer_id
            assert p1_entry[1] == "TargetOne"

            p2_entry = main_node.peers[("127.0.0.1", 9302)]
            assert isinstance(p2_entry, tuple)
            assert p2_entry[0] == target2.peer_id
            assert p2_entry[1] == "TargetTwo"

            # Verify self is NOT in peers
            assert ("127.0.0.1", 9300) not in main_node.peers

            # Verify inactive ports are NOT in peers
            for p in [9390, 9391, 9392, 9393, 9394]:
                assert ("127.0.0.1", p) not in main_node.peers

        finally:
            await main_node.stop_async()
            await target1.stop_async()
            await target2.stop_async()
            for t in server_tasks:
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

    def test_concurrent_connect_to_peer_sync_multithread_stress(self, temp_node_dir):
        """
        Stress test: 20 concurrent OS threads calling connect_to_peer_sync
        dispatched across threads to node's background event loop.
        Verifies thread safety, absence of deadlocks, and node.peers consistency.
        """
        db_main = os.path.join(temp_node_dir, "rep_sync_main.db")
        db_target = os.path.join(temp_node_dir, "rep_sync_tgt.db")

        main_node = P2PNode(host="127.0.0.1", port=9400, db_path=db_main, storage_dir=temp_node_dir, node_name="SyncMain")
        target_node = P2PNode(host="127.0.0.1", port=9401, db_path=db_target, storage_dir=temp_node_dir, node_name="SyncTarget")

        # Start servers on background threads
        main_loop = asyncio.new_event_loop()
        target_loop = asyncio.new_event_loop()

        def run_loop(loop, node):
            asyncio.set_event_loop(loop)
            loop.run_until_complete(node.start_server())

        t_main = threading.Thread(target=run_loop, args=(main_loop, main_node), daemon=True)
        t_target = threading.Thread(target=run_loop, args=(target_loop, target_node), daemon=True)

        t_main.start()
        t_target.start()
        time.sleep(0.5)

        try:
            # 20 concurrent threads calling connect_to_peer_sync
            def worker_call(idx):
                if idx % 3 == 0:
                    return main_node.connect_to_peer_sync("127.0.0.1", 9401, timeout=3.0)
                elif idx % 3 == 1:
                    return main_node.connect_to_peer_sync("127.0.0.1", 9400, timeout=3.0) # Self
                else:
                    return main_node.connect_to_peer_sync("127.0.0.1", 9499, timeout=1.0) # Inactive

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(worker_call, i) for i in range(20)]
                results = [f.result(timeout=10.0) for f in futures]

            for success, msg in results:
                assert isinstance(success, bool)
                assert isinstance(msg, str)

            # Check that target_node was registered cleanly
            assert ("127.0.0.1", 9401) in main_node.peers
            peer_tuple = main_node.peers[("127.0.0.1", 9401)]
            assert peer_tuple[0] == target_node.peer_id
            assert peer_tuple[1] == "SyncTarget"

            # Check that self was rejected
            assert ("127.0.0.1", 9400) not in main_node.peers

        finally:
            main_loop.call_soon_threadsafe(lambda: asyncio.create_task(main_node.stop()))
            target_loop.call_soon_threadsafe(lambda: asyncio.create_task(target_node.stop()))
            time.sleep(0.3)
