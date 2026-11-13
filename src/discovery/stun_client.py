import socket
import struct
import os
import logging
from typing import Optional, Tuple, Dict, Any, List, Union

logger = logging.getLogger("STUNClient")

PUBLIC_STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_RESPONSE = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_XOR_MAPPED_ADDRESS = 0x0020


def _build_binding_request(transaction_id: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Build an RFC 5389 compliant STUN Binding Request packet header.
    Returns (request_packet_bytes, 12_byte_transaction_id).
    """
    tx_id = transaction_id if transaction_id is not None else os.urandom(12)
    # STUN Header: [2 bytes: Type][2 bytes: Length][4 bytes: Magic Cookie][12 bytes: Tx ID]
    req_header = struct.pack("!HHI12s", STUN_BINDING_REQUEST, 0, MAGIC_COOKIE, tx_id)
    return req_header, tx_id


def _parse_stun_response(data: bytes, transaction_id: bytes) -> Optional[Tuple[str, int]]:
    """
    Parse an RFC 5389 STUN Binding Response datagram.
    Extracts XOR-MAPPED-ADDRESS (preferred) or MAPPED-ADDRESS (fallback).
    Returns (ip, port) tuple or None on invalid packet or missing attributes.
    """
    if len(data) < 20:
        return None

    msg_type, msg_len, cookie, resp_tx_id = struct.unpack("!HHI12s", data[:20])
    if msg_type != STUN_BINDING_RESPONSE or cookie != MAGIC_COOKIE or resp_tx_id != transaction_id:
        return None

    offset = 20
    end_offset = min(20 + msg_len, len(data))
    while offset + 4 <= end_offset:
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        padded_len = (attr_len + 3) & ~3
        if offset + attr_len > end_offset or offset + padded_len > len(data):
            break
        val = data[offset:offset + attr_len]
        offset += padded_len

        # Preferred: XOR-MAPPED-ADDRESS (0x0020)
        if attr_type == ATTR_XOR_MAPPED_ADDRESS and len(val) >= 8:
            family = val[1]
            if family == 0x01:  # IPv4
                x_port = struct.unpack("!H", val[2:4])[0]
                port = x_port ^ (MAGIC_COOKIE >> 16)
                x_ip = struct.unpack("!I", val[4:8])[0]
                ip_int = x_ip ^ MAGIC_COOKIE
                ip = socket.inet_ntoa(struct.pack("!I", ip_int))
                return ip, port

        # Fallback: MAPPED-ADDRESS (0x0001)
        elif attr_type == ATTR_MAPPED_ADDRESS and len(val) >= 8:
            family = val[1]
            if family == 0x01:  # IPv4
                port = struct.unpack("!H", val[2:4])[0]
                ip = socket.inet_ntoa(val[4:8])
                return ip, port

    return None


def get_lan_ip() -> str:
    """
    Determine the primary outbound LAN IPv4 address of this machine.
    Uses an ephemeral UDP connection without transmitting packets.
    Falls back to '127.0.0.1' if disconnected.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def query_stun_server(
    stun_host: str = "stun.l.google.com",
    stun_port: int = 19302,
    timeout: float = 2.0,
    bind_port: Optional[int] = None
) -> Optional[Tuple[str, int]]:
    """
    Query an RFC 5389 compliant STUN server to discover the external WAN IP and mapped port.
    Returns (wan_ip, mapped_port) or None on failure or timeout.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if bind_port:
            try:
                s.bind(("0.0.0.0", bind_port))
            except Exception:
                pass  # Fall back to ephemeral OS port if requested port is in use

        req_header, tx_id = _build_binding_request()
        s.sendto(req_header, (stun_host, stun_port))

        data, _ = s.recvfrom(2048)
        return _parse_stun_response(data, tx_id)
    except Exception as e:
        logger.debug(f"STUN query to {stun_host}:{stun_port} failed: {e}")
        return None
    finally:
        s.close()


def get_public_ip_and_port(
    custom_servers: Optional[Union[List[Tuple[str, int]], str]] = None,
    timeout: float = 2.0,
    bind_port: Optional[int] = None,
    stun_host: Optional[str] = None,
    stun_port: Optional[int] = None,
    retries: int = 1
) -> Tuple[Optional[str], Optional[int]]:
    """
    Attempt STUN resolution across a pool of public STUN servers with fallback.
    Supports:
      - get_public_ip_and_port(custom_servers=[...], timeout=..., bind_port=...)
      - get_public_ip_and_port("stun.host.com", 19302)
      - get_public_ip_and_port(stun_host="...", stun_port=..., timeout=..., retries=...)
    Returns (public_ip, public_port) or (None, None).
    """
    if isinstance(custom_servers, str):
        servers = [(custom_servers, stun_port or 19302)]
    elif stun_host:
        servers = [(stun_host, stun_port or 19302)]
    elif custom_servers:
        servers = custom_servers
    else:
        servers = PUBLIC_STUN_SERVERS

    for attempt in range(max(1, retries)):
        for host, port in servers:
            result = query_stun_server(host, port, timeout=timeout, bind_port=bind_port)
            if result:
                return result
    return None, None


def resolve_network_addresses(
    local_port: Union[int, str] = 8000,
    stun_host: Optional[Union[str, int]] = None,
    stun_port: Optional[int] = None
) -> Dict[str, Any]:
    """
    Resolve both LAN and WAN networking reachability for a local listening port.
    """
    if isinstance(local_port, str) and not local_port.isdigit():
        actual_host = local_port
        actual_stun_port = int(stun_host) if stun_host else 19302
        actual_local_port = 8000
    else:
        actual_local_port = int(local_port)
        actual_host = stun_host if isinstance(stun_host, str) else None
        actual_stun_port = int(stun_port) if stun_port else 19302

    lan_ip = get_lan_ip()
    servers = [(actual_host, actual_stun_port)] if actual_host else None
    wan_ip, wan_port = get_public_ip_and_port(custom_servers=servers, timeout=1.5, bind_port=actual_local_port)
    return {
        "lan_ip": lan_ip,
        "lan_port": actual_local_port,
        "local_ip": lan_ip,
        "wan_ip": wan_ip,
        "wan_port": wan_port,
        "public_ip": wan_ip,
        "public_port": wan_port,
        "is_nat_traversed": bool(wan_ip is not None),
        "primary_reachable_address": f"{wan_ip}:{wan_port}" if wan_ip else f"{lan_ip}:{actual_local_port}"
    }
