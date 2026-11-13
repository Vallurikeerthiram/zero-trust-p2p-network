"""
Unit and Integration Tests for RFC 5389 STUN Client & Network Address Resolution (Feature F32)
Tests run 100% offline without contacting public STUN servers.
"""

import socket
import struct
import os
import threading
import ipaddress
import pytest
from unittest.mock import MagicMock, patch

from src.discovery.stun_client import (
    MAGIC_COOKIE,
    STUN_BINDING_REQUEST,
    STUN_BINDING_RESPONSE,
    ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    PUBLIC_STUN_SERVERS,
    get_lan_ip,
    query_stun_server,
    get_public_ip_and_port,
    resolve_network_addresses,
    _build_binding_request,
    _parse_stun_response,
)


@pytest.fixture(autouse=True)
def guard_offline_stun(monkeypatch):
    """Ensure NO test queries live Google STUN servers over the internet."""
    monkeypatch.setattr(
        "src.discovery.stun_client.PUBLIC_STUN_SERVERS",
        [("127.0.0.1", 19302), ("127.0.0.1", 19303)]
    )


# =============================================================================
# Helper Utilities & In-Process Mock STUN Server
# =============================================================================

def craft_stun_response(
    tx_id: bytes,
    xor_mapped: tuple = None,
    plain_mapped: tuple = None,
    msg_type: int = STUN_BINDING_RESPONSE,
    magic_cookie: int = MAGIC_COOKIE,
    extra_attrs: bytes = b""
) -> bytes:
    """Craft an RFC 5389 STUN response datagram for testing."""
    attrs = bytearray(extra_attrs)

    if xor_mapped:
        ip_str, port = xor_mapped
        x_port = port ^ (magic_cookie >> 16)
        ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
        x_ip = ip_int ^ magic_cookie
        val = struct.pack("!BBHI", 0, 0x01, x_port, x_ip)
        attrs.extend(struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(val)) + val)

    if plain_mapped:
        ip_str, port = plain_mapped
        val = struct.pack("!BBH4s", 0, 0x01, port, socket.inet_aton(ip_str))
        attrs.extend(struct.pack("!HH", ATTR_MAPPED_ADDRESS, len(val)) + val)

    header = struct.pack("!HHI12s", msg_type, len(attrs), magic_cookie, tx_id)
    return bytes(header + attrs)


class MockStunServer:
    """Lightweight in-process RFC 5389 STUN UDP server on loopback."""
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.host, self.port = self.sock.getsockname()
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if len(data) >= 20:
                    msg_type, msg_len, cookie, tx_id = struct.unpack("!HHI12s", data[:20])
                    if msg_type == STUN_BINDING_REQUEST and cookie == MAGIC_COOKIE:
                        # Echo back client's detected IP and port via XOR-MAPPED-ADDRESS
                        resp = craft_stun_response(tx_id, xor_mapped=(addr[0], addr[1]))
                        self.sock.sendto(resp, addr)
            except (socket.timeout, OSError):
                continue

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=1.0)


# =============================================================================
# 1. Constants & Packet Generation Tests
# =============================================================================

def test_stun_protocol_constants():
    assert MAGIC_COOKIE == 0x2112A442
    assert STUN_BINDING_REQUEST == 0x0001
    assert STUN_BINDING_RESPONSE == 0x0101
    assert ATTR_MAPPED_ADDRESS == 0x0001
    assert ATTR_XOR_MAPPED_ADDRESS == 0x0020
    assert len(PUBLIC_STUN_SERVERS) >= 2
    for host, port in PUBLIC_STUN_SERVERS:
        assert isinstance(host, str)
        assert isinstance(port, int)
        assert 1 <= port <= 65535


def test_build_binding_request_auto_tx_id():
    req_header, tx_id = _build_binding_request()
    assert len(req_header) == 20
    assert len(tx_id) == 12
    msg_type, msg_len, cookie, unpacked_tx = struct.unpack("!HHI12s", req_header)
    assert msg_type == STUN_BINDING_REQUEST
    assert msg_len == 0
    assert cookie == MAGIC_COOKIE
    assert unpacked_tx == tx_id


def test_build_binding_request_explicit_tx_id():
    explicit_tx = b"STUN_TX_1234"
    req_header, tx_id = _build_binding_request(transaction_id=explicit_tx)
    assert tx_id == explicit_tx
    msg_type, msg_len, cookie, unpacked_tx = struct.unpack("!HHI12s", req_header)
    assert unpacked_tx == explicit_tx


def test_build_binding_request_random_tx_ids():
    _, tx1 = _build_binding_request()
    _, tx2 = _build_binding_request()
    assert tx1 != tx2


# =============================================================================
# 2. Response Parsing & RFC 5389 XOR Unmasking Tests
# =============================================================================

def test_parse_stun_response_xor_mapped_ipv4_success():
    tx_id = b"TX_ID_VALID1"
    packet = craft_stun_response(tx_id, xor_mapped=("203.0.113.195", 54321))
    result = _parse_stun_response(packet, tx_id)
    assert result == ("203.0.113.195", 54321)


def test_parse_stun_response_mapped_address_fallback():
    tx_id = b"TX_ID_VALID2"
    packet = craft_stun_response(tx_id, plain_mapped=("198.51.100.77", 49152))
    result = _parse_stun_response(packet, tx_id)
    assert result == ("198.51.100.77", 49152)


def test_parse_stun_response_prefers_xor_over_plain():
    tx_id = b"TX_ID_VALID3"
    packet = craft_stun_response(
        tx_id,
        xor_mapped=("203.0.113.10", 10000),
        plain_mapped=("198.51.100.10", 20000)
    )
    result = _parse_stun_response(packet, tx_id)
    assert result == ("203.0.113.10", 10000)


def test_parse_stun_response_ignores_ipv6_family_xor():
    tx_id = b"TX_ID_VALID4"
    # Construct XOR attribute with family 0x02 (IPv6)
    ipv6_raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    val = struct.pack("!BBH16s", 0, 0x02, 54321 ^ 0x2112, ipv6_raw)
    extra = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(val)) + val
    packet = craft_stun_response(tx_id, extra_attrs=extra)
    result = _parse_stun_response(packet, tx_id)
    assert result is None


def test_parse_stun_response_ignores_ipv6_family_plain():
    tx_id = b"TX_ID_VALID5"
    ipv6_raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    val = struct.pack("!BBH16s", 0, 0x02, 54321, ipv6_raw)
    extra = struct.pack("!HH", ATTR_MAPPED_ADDRESS, len(val)) + val
    packet = craft_stun_response(tx_id, extra_attrs=extra)
    result = _parse_stun_response(packet, tx_id)
    assert result is None


def test_parse_stun_response_skips_unknown_attributes():
    tx_id = b"TX_ID_VALID6"
    # Prepend unknown attribute 0x8022 (SOFTWARE) with length 8
    software_val = b"P2P_NODE"
    unknown_attr = struct.pack("!HH", 0x8022, len(software_val)) + software_val
    packet = craft_stun_response(tx_id, xor_mapped=("192.0.2.1", 12345), extra_attrs=unknown_attr)
    result = _parse_stun_response(packet, tx_id)
    assert result == ("192.0.2.1", 12345)


def test_parse_stun_response_truncated_header():
    tx_id = b"TX_ID_VALID7"
    assert _parse_stun_response(b"", tx_id) is None
    assert _parse_stun_response(b"\x01\x01\x00\x00", tx_id) is None
    assert _parse_stun_response(os.urandom(19), tx_id) is None


def test_parse_stun_response_invalid_msg_type():
    tx_id = b"TX_ID_VALID8"
    packet = craft_stun_response(tx_id, xor_mapped=("203.0.113.1", 12345), msg_type=0x0111)
    assert _parse_stun_response(packet, tx_id) is None


def test_parse_stun_response_invalid_magic_cookie():
    tx_id = b"TX_ID_VALID9"
    packet = craft_stun_response(tx_id, xor_mapped=("203.0.113.1", 12345), magic_cookie=0x99999999)
    assert _parse_stun_response(packet, tx_id) is None


def test_parse_stun_response_mismatched_tx_id():
    tx_id = b"TX_ID_REQUST"
    other_tx = b"TX_ID_SPOOFD"
    packet = craft_stun_response(other_tx, xor_mapped=("203.0.113.1", 12345))
    assert _parse_stun_response(packet, tx_id) is None


def test_parse_stun_response_oversized_attr_len():
    tx_id = b"TX_ID_OVER10"
    # Attribute claims length 500 but datagram ends
    corrupt_attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, 500) + b"\x00\x01\x12\x34"
    header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(corrupt_attr), MAGIC_COOKIE, tx_id)
    packet = header + corrupt_attr
    assert _parse_stun_response(packet, tx_id) is None


def test_parse_stun_response_attribute_val_too_short():
    tx_id = b"TX_ID_SHORT1"
    # Attribute length 4 is less than minimum 8 bytes for IPv4 address
    short_val = b"\x00\x01\x12\x34"
    attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(short_val)) + short_val
    header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(attr), MAGIC_COOKIE, tx_id)
    packet = header + attr
    assert _parse_stun_response(packet, tx_id) is None


# =============================================================================
# 3. STUN Query Execution & Socket Handling Tests
# =============================================================================

def test_query_stun_server_mock_socket_success():
    expected_ip = "198.51.100.99"
    expected_port = 45000

    def fake_sendto(data, addr):
        fake_sendto.captured_req = data
        return len(data)

    def fake_recvfrom(bufsize):
        tx_id = struct.unpack("!12s", fake_sendto.captured_req[8:20])[0]
        return craft_stun_response(tx_id, xor_mapped=(expected_ip, expected_port)), ("127.0.0.1", 19302)

    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = fake_sendto
        mock_sock.recvfrom.side_effect = fake_recvfrom

        res = query_stun_server("127.0.0.1", 19302, timeout=1.0)
        assert res == (expected_ip, expected_port)
        mock_sock.settimeout.assert_called_with(1.0)
        mock_sock.close.assert_called_once()


def test_query_stun_server_bind_port_success():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.return_value = (b"", ("127.0.0.1", 19302))

        query_stun_server("127.0.0.1", 19302, bind_port=50001)
        mock_sock.bind.assert_called_with(("0.0.0.0", 50001))
        mock_sock.close.assert_called_once()


def test_query_stun_server_bind_port_collision_fallback():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.bind.side_effect = OSError(48, "Address already in use")

        def fake_recvfrom(bufsize):
            tx_id = struct.unpack("!12s", mock_sock.sendto.call_args[0][0][8:20])[0]
            return craft_stun_response(tx_id, xor_mapped=("1.2.3.4", 9999)), ("127.0.0.1", 19302)

        mock_sock.recvfrom.side_effect = fake_recvfrom

        res = query_stun_server("127.0.0.1", 19302, bind_port=50001)
        assert res == ("1.2.3.4", 9999)
        mock_sock.close.assert_called_once()


def test_query_stun_server_socket_timeout():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        res = query_stun_server("127.0.0.1", 19302, timeout=0.1)
        assert res is None
        mock_sock.close.assert_called_once()


def test_query_stun_server_socket_oserror():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        mock_sock.sendto.side_effect = OSError("Network is unreachable")

        res = query_stun_server("127.0.0.1", 19302)
        assert res is None
        mock_sock.close.assert_called_once()


def test_query_stun_server_loopback_integration():
    server = MockStunServer()
    server.start()
    try:
        res = query_stun_server(server.host, server.port, timeout=1.0)
        assert res is not None
        ip, port = res
        assert ip == "127.0.0.1"
        assert isinstance(port, int)
        assert 1 <= port <= 65535
    finally:
        server.stop()


# =============================================================================
# 4. Public IP Pool Resolution Tests
# =============================================================================

def test_get_public_ip_and_port_first_server_succeeds():
    with patch("src.discovery.stun_client.query_stun_server") as mock_query:
        mock_query.return_value = ("203.0.113.1", 10001)
        ip, port = get_public_ip_and_port()
        assert ip == "203.0.113.1"
        assert port == 10001
        assert mock_query.call_count == 1


def test_get_public_ip_and_port_failover_to_second_server():
    with patch("src.discovery.stun_client.query_stun_server") as mock_query:
        mock_query.side_effect = [None, ("203.0.113.2", 10002)]
        ip, port = get_public_ip_and_port()
        assert ip == "203.0.113.2"
        assert port == 10002
        assert mock_query.call_count == 2


def test_get_public_ip_and_port_all_servers_fail():
    with patch("src.discovery.stun_client.query_stun_server", return_value=None):
        ip, port = get_public_ip_and_port()
        assert ip is None
        assert port is None


def test_get_public_ip_and_port_custom_servers_list():
    custom = [("my.stun.custom", 3478)]
    with patch("src.discovery.stun_client.query_stun_server") as mock_query:
        mock_query.return_value = ("1.1.1.1", 5000)
        ip, port = get_public_ip_and_port(custom_servers=custom)
        assert (ip, port) == ("1.1.1.1", 5000)
        mock_query.assert_called_with("my.stun.custom", 3478, timeout=2.0, bind_port=None)


def test_get_public_ip_and_port_polymorphic_retries():
    with patch("src.discovery.stun_client.query_stun_server") as mock_query:
        mock_query.side_effect = [None, ("2.2.2.2", 6000)]
        res = get_public_ip_and_port(stun_host="test.stun", stun_port=19302, retries=2)
        assert res == ("2.2.2.2", 6000)
        assert mock_query.call_count == 2


# =============================================================================
# 5. LAN IP Resolution Tests
# =============================================================================

def test_get_lan_ip_primary_route_success():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.getsockname.return_value = ("192.168.1.155", 54321)

        lan_ip = get_lan_ip()
        assert lan_ip == "192.168.1.155"
        mock_sock.connect.assert_called_with(("8.8.8.8", 80))


def test_get_lan_ip_connect_fails_hostname_fallback():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("No route to host")

        with patch("socket.gethostname", return_value="my-workstation"), \
             patch("socket.gethostbyname", return_value="10.0.0.42"):
            lan_ip = get_lan_ip()
            assert lan_ip == "10.0.0.42"


def test_get_lan_ip_all_fail_returns_127_0_0_1():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = MagicMock()
        mock_sock_cls.return_value.__enter__.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("No route")

        with patch("socket.gethostname", return_value="my-workstation"), \
             patch("socket.gethostbyname", side_effect=OSError("DNS error")):
            lan_ip = get_lan_ip()
            assert lan_ip == "127.0.0.1"


def test_get_lan_ip_real_execution():
    lan_ip = get_lan_ip()
    assert isinstance(lan_ip, str)
    ip_obj = ipaddress.ip_address(lan_ip)
    assert ip_obj.version == 4


# =============================================================================
# 6. Full Network Address Resolution Tests
# =============================================================================

def test_resolve_network_addresses_with_public_wan():
    with patch("src.discovery.stun_client.get_lan_ip", return_value="192.168.1.100"), \
         patch("src.discovery.stun_client.get_public_ip_and_port", return_value=("203.0.113.88", 60000)):

        result = resolve_network_addresses(8001)

        assert result["lan_ip"] == "192.168.1.100"
        assert result["local_ip"] == "192.168.1.100"
        assert result["lan_port"] == 8001
        assert result["wan_ip"] == "203.0.113.88"
        assert result["public_ip"] == "203.0.113.88"
        assert result["wan_port"] == 60000
        assert result["public_port"] == 60000
        assert result["is_nat_traversed"] is True
        assert result["primary_reachable_address"] == "203.0.113.88:60000"


def test_resolve_network_addresses_offline_no_wan():
    with patch("src.discovery.stun_client.get_lan_ip", return_value="192.168.1.100"), \
         patch("src.discovery.stun_client.get_public_ip_and_port", return_value=(None, None)):

        result = resolve_network_addresses(8001)

        assert result["lan_ip"] == "192.168.1.100"
        assert result["local_ip"] == "192.168.1.100"
        assert result["lan_port"] == 8001
        assert result["wan_ip"] is None
        assert result["public_ip"] is None
        assert result["wan_port"] is None
        assert result["public_port"] is None
        assert result["is_nat_traversed"] is False
        assert result["primary_reachable_address"] == "192.168.1.100:8001"


def test_resolve_network_addresses_polymorphic_custom_host():
    with patch("src.discovery.stun_client.get_lan_ip", return_value="10.0.0.2"), \
         patch("src.discovery.stun_client.get_public_ip_and_port", return_value=("1.2.3.4", 9000)) as mock_pub:

        res = resolve_network_addresses(8001, stun_host="stun.test.org", stun_port=3478)
        assert res["wan_ip"] == "1.2.3.4"
        mock_pub.assert_called_with(custom_servers=[("stun.test.org", 3478)], timeout=1.5, bind_port=8001)


def test_resolve_network_addresses_string_host_invocation():
    with patch("src.discovery.stun_client.get_lan_ip", return_value="10.0.0.2"), \
         patch("src.discovery.stun_client.get_public_ip_and_port", return_value=("1.2.3.4", 9000)) as mock_pub:

        res = resolve_network_addresses("stun.test.org", 3478)
        assert res["wan_ip"] == "1.2.3.4"
        mock_pub.assert_called_with(custom_servers=[("stun.test.org", 3478)], timeout=1.5, bind_port=8000)


# =============================================================================
# 7. Adversarial Robustness & Fuzzing Tests
# =============================================================================

def test_fuzz_corrupted_stun_packets():
    tx_id = b"FUZZ_TEST_TX"
    for length in range(0, 50):
        garbage = os.urandom(length)
        assert _parse_stun_response(garbage, tx_id) is None


def test_dos_oversized_attribute_length():
    tx_id = b"DOS_TEST_TX1"
    # Declares 65535 byte attribute in small datagram
    corrupt = struct.pack("!HHI12sHH", STUN_BINDING_RESPONSE, 100, MAGIC_COOKIE, tx_id, ATTR_XOR_MAPPED_ADDRESS, 0xFFFF)
    assert _parse_stun_response(corrupt, tx_id) is None


def test_zero_length_attribute_handling():
    tx_id = b"ZERO_LEN_TX1"
    # Attribute length 0 should not loop forever or crash
    zero_attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, 0)
    packet = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(zero_attr), MAGIC_COOKIE, tx_id) + zero_attr
    assert _parse_stun_response(packet, tx_id) is None


def test_parse_stun_response_unaligned_attribute_padding():
    """
    RFC 5389 Section 15: Attributes must be padded to a multiple of 4 bytes.
    Verify that an unaligned attribute (e.g. 6-byte SOFTWARE with 2 bytes padding)
    preceding XOR-MAPPED-ADDRESS does not desynchronize attribute offset parsing.
    """
    tx_id = b"TX_ID_TEST12"
    software_val = b"Coturn"  # 6 bytes
    software_pad = b"\x00\x00"  # Padded to 8 bytes per RFC 5389
    attr1 = struct.pack("!HH", 0x8022, len(software_val)) + software_val + software_pad

    x_port = 54321 ^ (MAGIC_COOKIE >> 16)
    x_ip = struct.unpack("!I", socket.inet_aton("203.0.113.195"))[0] ^ MAGIC_COOKIE
    val2 = struct.pack("!BBHI", 0, 0x01, x_port, x_ip)
    attr2 = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(val2)) + val2

    payload = attr1 + attr2
    header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, len(payload), MAGIC_COOKIE, tx_id)
    packet = header + payload

    res = _parse_stun_response(packet, tx_id)
    assert res == ("203.0.113.195", 54321)


def test_parse_stun_response_attribute_exceeding_msg_len_boundary():
    """
    RFC 5389 Section 6: All valid attributes must fall within msg_len.
    Verify that an attribute extending past end_offset (20 + msg_len) is safely rejected.
    """
    tx_id = b"TX_ID_BOUND1"
    # Declares msg_len = 6 (end_offset = 26), but attribute value extends to offset 32
    x_port = 54321 ^ (MAGIC_COOKIE >> 16)
    x_ip = struct.unpack("!I", socket.inet_aton("203.0.113.195"))[0] ^ MAGIC_COOKIE
    val = struct.pack("!BBHI", 0, 0x01, x_port, x_ip)
    attr = struct.pack("!HH", ATTR_XOR_MAPPED_ADDRESS, len(val)) + val

    header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, 6, MAGIC_COOKIE, tx_id)
    packet = header + attr

    res = _parse_stun_response(packet, tx_id)
    assert res is None


def test_parse_stun_response_padded_len_exceeding_data_bounds():
    """
    Verify that when offset + padded_len > len(data), parsing safely terminates with None.
    """
    tx_id = b"TX_ID_BOUND2"
    software_val = b"Coturn"  # 6 bytes, declared attr_len = 6, but missing 2 padding bytes
    attr1 = struct.pack("!HH", 0x8022, len(software_val)) + software_val  # 4 + 6 = 10 bytes total (needs 12)
    header = struct.pack("!HHI12s", STUN_BINDING_RESPONSE, 12, MAGIC_COOKIE, tx_id)
    packet = header + attr1  # len(packet) = 30, but offset(24) + padded_len(8) = 32 > 30

    res = _parse_stun_response(packet, tx_id)
    assert res is None
