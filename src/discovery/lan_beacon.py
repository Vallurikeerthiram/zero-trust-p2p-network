"""
LAN Auto-Discovery UDP Broadcast Daemon (Feature F29)
Provides zero-configuration peer discovery across local area networks (Wi-Fi/Ethernet).
Transmits sub-second startup bursts and periodic beacons on UDP port 50050,
validates inbound beacons, filters self-reflections and blacklisted peers,
and dispatches authenticated TCP connections via P2PNode.connect_to_peer.
"""

import socket
import json
import time
import asyncio
import logging
from typing import Optional, Dict, List, Any, Tuple

logger = logging.getLogger("LanBeacon")


class LanBeacon:
    """
    UDP Broadcast discovery service for local peers.
    """

    def __init__(
        self,
        node: Any,
        broadcast_port: int = 50050,
        interval: float = 1.5,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ):
        """
        Initialize the LanBeacon daemon.

        :param node: The P2PNode instance hosting discovery.
        :param broadcast_port: UDP port used for subnet broadcast (default 50050).
        :param interval: Periodic broadcast interval in seconds (default 1.5s).
        :param loop: Optional asyncio event loop.
        """
        self.node = node
        self.broadcast_port = int(broadcast_port)
        self.interval = float(interval)
        self.loop = loop
        self.running: bool = False

        self._rx_sock: Optional[socket.socket] = None
        self._tx_sock: Optional[socket.socket] = None
        self._tasks: List[asyncio.Task] = []
        self._recent_attempts: Dict[Tuple[str, int], float] = {}

    def _create_sockets(self) -> None:
        """
        Initialize receiver and transmitter UDP sockets with appropriate broadcast options.
        """
        # Receiver Socket
        self._rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # SO_REUSEPORT if supported by platform (Linux/macOS)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                pass

        self._rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Windows / Linux: binding to '' binds to INADDR_ANY (0.0.0.0)
        self._rx_sock.bind(('', self.broadcast_port))
        self._rx_sock.setblocking(False)

        # Transmitter Socket
        self._tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def _build_payload(self) -> bytes:
        """
        Construct the standardized discovery beacon JSON payload.
        """
        adv_host = getattr(self.node, "advertised_host", "")
        payload = {
            "type": "DISCOVERY_BEACON",
            "peer_id": self.node.peer_id,
            "username": getattr(self.node, "node_name", ""),
            "tcp_port": self.node.port,
            "advertised_host": adv_host if adv_host else "",
            "timestamp": time.time()
        }
        return json.dumps(payload).encode('utf-8')

    def send_broadcast(self) -> None:
        """
        Transmit a single UDP broadcast beacon to the local network.
        """
        if not self._tx_sock or not self.running:
            return
        try:
            data = self._build_payload()
            self._tx_sock.sendto(data, ('<broadcast>', self.broadcast_port))
        except Exception as e:
            logger.debug(f"LAN Beacon broadcast send failed: {e}")

    async def _broadcast_loop(self) -> None:
        """
        Broadcast routine implementing sub-second discovery burst followed by periodic heartbeats.
        """
        try:
            # Sub-second discovery burst: 3 beacons at 0ms, 150ms, 300ms
            for _ in range(3):
                if not self.running:
                    return
                self.send_broadcast()
                await asyncio.sleep(0.15)

            # Periodic maintenance loop
            while self.running:
                await asyncio.sleep(self.interval)
                if not self.running:
                    break
                self.send_broadcast()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"LAN Beacon broadcast loop encountered error: {e}")

    async def _listen_loop(self) -> None:
        """
        Asynchronous UDP datagram receiver loop.
        Validates payloads, filters self and blacklisted beacons, and triggers connections.
        """
        loop = self.loop or asyncio.get_running_loop()
        while self.running:
            try:
                data, addr = await loop.sock_recvfrom(self._rx_sock, 4096)
            except (OSError, ConnectionResetError):
                # Socket closed during shutdown on Windows/Linux (e.g. WinError 995)
                if not self.running:
                    break
                await asyncio.sleep(0.02)
                continue
            except asyncio.CancelledError:
                break

            try:
                msg = json.loads(data.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue

            if not isinstance(msg, dict):
                continue

            beacon_type = msg.get("type")
            if beacon_type not in ("DISCOVERY_BEACON", "BEACON"):
                continue

            peer_id = msg.get("peer_id")
            if not peer_id or not isinstance(peer_id, str):
                continue

            # Step 1: Self-Beacon Filter
            if peer_id == self.node.peer_id:
                continue

            # Step 2: Reputation Blacklist Filter
            if hasattr(self.node, "reputation") and self.node.reputation.is_blacklisted(peer_id):
                logger.debug(f"Ignored beacon from blacklisted peer {peer_id[:8]}")
                continue

            # Step 3: TCP Port Validation
            tcp_port = msg.get("tcp_port") or msg.get("port")
            try:
                tcp_port = int(tcp_port)
                if not (1 <= tcp_port <= 65535):
                    continue
            except (ValueError, TypeError):
                continue

            # Step 4: Target Host Selection & Inbound Sanitization
            adv_host = msg.get("advertised_host") or msg.get("advertised_ip")
            if adv_host and isinstance(adv_host, str) and adv_host.strip() not in ("0.0.0.0", "::", "None", ""):
                target_host = adv_host.strip()
            else:
                target_host = addr[0]

            # Defense-in-depth: If peer announced 127.0.0.1 over a real LAN interface, use remote socket IP
            if target_host in ("127.0.0.1", "localhost") and addr[0] not in ("127.0.0.1", "::1"):
                target_host = addr[0]

            # Step 5: Deduplication Check
            active_peers = getattr(self.node, "peers", {})
            if (target_host, tcp_port) in active_peers:
                continue

            # Check if peer_id is already active under any address
            is_already_connected = False
            for p_entry in active_peers.values():
                p_id = p_entry[0] if isinstance(p_entry, tuple) else p_entry
                if p_id == peer_id:
                    is_already_connected = True
                    break
            if is_already_connected:
                continue

            # Step 6: In-Flight & Cooldown Deduplication
            now = time.time()
            # Prune stale records from recent attempts (> 30s)
            stale_keys = [k for k, ts in self._recent_attempts.items() if now - ts > 30.0]
            for k in stale_keys:
                del self._recent_attempts[k]

            last_attempt = self._recent_attempts.get((peer_id, tcp_port), 0.0)
            if now - last_attempt < 3.0:
                continue
            self._recent_attempts[(peer_id, tcp_port)] = now

            # Step 7: Dispatch Connection Task
            username = msg.get("username", "Unknown")
            logger.info(f"Discovered peer '{username}' ({peer_id[:8]}...) at {target_host}:{tcp_port} via LAN Beacon")
            if hasattr(self.node, "connect_to_peer"):
                asyncio.create_task(self.node.connect_to_peer(target_host, tcp_port))

    def start(self) -> None:
        """
        Start the LAN Beacon background listener and broadcast tasks.
        """
        if self.running:
            return
        self.running = True
        self.loop = self.loop or asyncio.get_running_loop()
        self._create_sockets()
        self._tasks.append(self.loop.create_task(self._listen_loop()))
        self._tasks.append(self.loop.create_task(self._broadcast_loop()))
        logger.info(f"LanBeacon started on UDP port {self.broadcast_port} (interval: {self.interval}s)")

    def stop(self) -> None:
        """
        Stop the LAN Beacon and cleanly close sockets without descriptor leaks.
        """
        if not self.running and not self._tasks and not self._rx_sock:
            return

        self.running = False

        for t in self._tasks:
            if not t.done():
                t.cancel()
        self._tasks.clear()

        if self._rx_sock:
            try:
                self._rx_sock.close()
            except Exception:
                pass
            self._rx_sock = None

        if self._tx_sock:
            try:
                self._tx_sock.close()
            except Exception:
                pass
            self._tx_sock = None

        logger.info("LanBeacon stopped cleanly.")
