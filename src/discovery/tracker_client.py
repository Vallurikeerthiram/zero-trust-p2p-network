"""
src/discovery/tracker_client.py
WAN Discovery Client integrating STUN resolution with Bootstrap Tracker registration & peer polling.
Zero external dependencies (uses standard library urllib.request and asyncio).
"""

import sys
import os
import json
import time
import asyncio
import logging
import ipaddress
import urllib.request
import urllib.error
from typing import Optional, Dict, Any, List, Tuple

logger = logging.getLogger("TrackerClient")


class TrackerClient:
    """
    Client daemon that discovers public WAN coordinates via STUN, registers with a
    centralized rendezvous Bootstrap Tracker, maintains periodic heartbeats, and polls
    active peers to initiate zero-trust P2P connections.
    """
    def __init__(
        self,
        node: Any,
        tracker_url: str = "http://127.0.0.1:9000",
        interval: float = 30.0,
        stun_host: Optional[str] = None,
        stun_port: Optional[int] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ):
        self.node = node
        self.tracker_url = tracker_url.rstrip('/')
        self.interval = float(interval)
        self.stun_host = stun_host
        self.stun_port = int(stun_port) if stun_port is not None else None
        self.loop = loop
        
        self.running = False
        self._task: Optional[asyncio.Task] = None
        self.is_registered = False

        # Discovered networking coordinates
        self.lan_ip: Optional[str] = None
        self.wan_ip: Optional[str] = None
        self.wan_port: Optional[int] = None
        self.registered_ip: Optional[str] = None

    # -------------------------------------------------------------------------
    # Network Resolution & STUN Fallback
    # -------------------------------------------------------------------------

    def _resolve_network_coordinates(self) -> Dict[str, Any]:
        """
        Synchronously discover LAN and STUN WAN coordinates.
        Runs inside an executor thread to prevent blocking the event loop.
        """
        from .stun_client import get_lan_ip, get_public_ip_and_port, query_stun_server

        lan_ip = get_lan_ip()
        wan_ip, wan_port = None, None

        try:
            if self.stun_host and self.stun_port:
                res = query_stun_server(self.stun_host, self.stun_port, timeout=2.0)
                if res:
                    wan_ip, wan_port = res
            else:
                wan_ip, wan_port = get_public_ip_and_port(timeout=2.0)
        except Exception as e:
            logger.debug(f"STUN query failed: {e}")

        # Check if wan_ip is a genuine public routable address
        is_public = False
        if wan_ip:
            try:
                ip_obj = ipaddress.ip_address(wan_ip)
                is_public = not (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_reserved
                    or ip_obj.is_link_local
                )
            except ValueError:
                is_public = False

        # Fallback hierarchy:
        # 1. Genuine public WAN IP from STUN
        # 2. node.advertised_host (if defined and non-wildcard)
        # 3. Local LAN IP
        if is_public and wan_ip:
            chosen_ip = wan_ip
        else:
            adv = getattr(self.node, "advertised_host", None)
            if adv and adv not in ("0.0.0.0", "", "::"):
                chosen_ip = adv
            else:
                chosen_ip = lan_ip

        return {
            "lan_ip": lan_ip,
            "wan_ip": wan_ip,
            "wan_port": wan_port,
            "chosen_ip": chosen_ip,
            "is_public": is_public
        }

    # -------------------------------------------------------------------------
    # Synchronous HTTP Helpers (Offloaded to Executor)
    # -------------------------------------------------------------------------

    def _sync_post(self, path: str, payload: Dict[str, Any], timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """Synchronous HTTP POST returning parsed JSON dict or None."""
        url = f"{self.tracker_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "ZeroTrustP2P-TrackerClient/1.0"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                err_raw = e.read()
                return json.loads(err_raw.decode("utf-8"))
            except Exception:
                return {"status": "error", "code": e.code, "message": str(e.reason)}
        except Exception as e:
            logger.debug(f"Tracker POST {url} failed: {e}")
            return None

    def _sync_get(self, path: str, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
        """Synchronous HTTP GET returning parsed JSON dict or None."""
        url = f"{self.tracker_url}{path}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ZeroTrustP2P-TrackerClient/1.0"
            },
            method="GET"
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                return json.loads(raw.decode("utf-8")) if raw else {}
        except urllib.error.HTTPError as e:
            logger.debug(f"Tracker GET {url} returned HTTP {e.code}: {e.reason}")
            return None
        except Exception as e:
            logger.debug(f"Tracker GET {url} failed: {e}")
            return None

    # -------------------------------------------------------------------------
    # Asynchronous REST Operations
    # -------------------------------------------------------------------------

    async def register(self) -> bool:
        """Discover network coordinates and register this node with the tracker."""
        loop = self.loop or asyncio.get_running_loop()
        net_info = await loop.run_in_executor(None, self._resolve_network_coordinates)

        self.lan_ip = net_info["lan_ip"]
        self.wan_ip = net_info["wan_ip"]
        self.wan_port = net_info["wan_port"]
        self.registered_ip = net_info["chosen_ip"]

        # If STUN resolved a public WAN IP, update node's advertised host
        if net_info["is_public"] and hasattr(self.node, "advertised_host"):
            self.node.advertised_host = self.registered_ip

        payload = {
            "peer_id": self.node.peer_id,
            "username": getattr(self.node, "node_name", ""),
            "ip": self.registered_ip,
            "port": self.node.port,
            "lan_ip": self.lan_ip,
            "wan_ip": self.wan_ip,
            "wan_port": self.wan_port
        }

        resp = await loop.run_in_executor(None, self._sync_post, "/register", payload)
        if resp and resp.get("status") == "ok":
            self.is_registered = True
            logger.info(
                f"Registered with bootstrap tracker at {self.tracker_url} "
                f"(Announced: {self.registered_ip}:{self.node.port})"
            )
            return True
        else:
            logger.warning(f"Registration at {self.tracker_url} failed: {resp}")
            return False

    async def heartbeat(self) -> bool:
        """Send keepalive heartbeat to tracker. Automatically re-registers if TTL expired."""
        loop = self.loop or asyncio.get_running_loop()
        payload = {"peer_id": self.node.peer_id}
        resp = await loop.run_in_executor(None, self._sync_post, "/heartbeat", payload)
        if resp and resp.get("status") == "ok":
            return True

        # If tracker returned 404 Not Found or peer expired, re-register immediately
        if resp and resp.get("status") == "error":
            logger.info("Tracker heartbeat rejected or record expired. Re-registering...")
            return await self.register()
        return False

    async def unregister(self) -> bool:
        """Deregister from tracker."""
        loop = self.loop or asyncio.get_running_loop()
        payload = {"peer_id": self.node.peer_id}
        resp = await loop.run_in_executor(None, self._sync_post, "/unregister", payload)
        self.is_registered = False
        return bool(resp and resp.get("status") == "ok")

    def unregister_sync(self) -> bool:
        """Synchronous unregister during node termination."""
        payload = {"peer_id": self.node.peer_id}
        resp = self._sync_post("/unregister", payload, timeout=2.0)
        self.is_registered = False
        return bool(resp and resp.get("status") == "ok")

    async def poll_peers(self) -> List[Dict[str, Any]]:
        """Fetch active peers from tracker and dispatch connections to new peers."""
        loop = self.loop or asyncio.get_running_loop()
        path = f"/peers?exclude={self.node.peer_id}"
        resp = await loop.run_in_executor(None, self._sync_get, path)
        if not resp or resp.get("status") != "ok" or "peers" not in resp:
            return []

        peers = resp["peers"]
        for peer in peers:
            peer_id = peer.get("peer_id")
            if not peer_id or peer_id == self.node.peer_id:
                continue

            # Zero-Trust Check: verify peer is not blacklisted
            if hasattr(self.node, "reputation") and self.node.reputation.is_blacklisted(peer_id):
                logger.debug(f"Skipping connection to blacklisted peer {peer_id[:8]}...")
                continue

            # NAT Hairpinning handling: if remote peer shares the same WAN IP as us, prefer its LAN IP
            target_ip = peer.get("ip")
            if (
                self.wan_ip
                and peer.get("wan_ip") == self.wan_ip
                and peer.get("lan_ip")
            ):
                target_ip = peer.get("lan_ip")

            target_port = peer.get("port")
            if not target_ip or not target_port:
                continue
            try:
                target_port = int(target_port)
            except (ValueError, TypeError):
                continue

            # Guard against connecting to self
            local_hosts = {"127.0.0.1", "localhost", getattr(self.node, "host", "")}
            adv = getattr(self.node, "advertised_host", None)
            if adv:
                local_hosts.add(adv)
            if target_ip in local_hosts and target_port == self.node.port:
                continue

            # Guard against connecting if already connected
            if hasattr(self.node, "peers") and (target_ip, target_port) in self.node.peers:
                continue

            logger.info(
                f"Tracker discovered new peer '{peer.get('username', '')}' "
                f"({peer_id[:8]}...) at {target_ip}:{target_port}. Initiating connection..."
            )

            # Asynchronously dispatch connection
            if hasattr(self.node, "connect_to_peer"):
                asyncio.create_task(self.node.connect_to_peer(target_ip, target_port))

        return peers

    # -------------------------------------------------------------------------
    # Lifecycle Management
    # -------------------------------------------------------------------------

    async def _loop(self):
        """Periodic heartbeat and peer polling loop."""
        # Initial registration and immediate peer polling
        await self.register()
        await self.poll_peers()

        while self.running:
            try:
                await asyncio.sleep(self.interval)
                if not self.running:
                    break
                await self.heartbeat()
                await self.poll_peers()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Tracker client loop exception: {e}")
                await asyncio.sleep(min(self.interval, 5.0))

    def start(self):
        """Start the tracker background task on the active asyncio event loop."""
        if self.running:
            return
        self.running = True
        if self.loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                self.loop = asyncio.new_event_loop()
        self._task = self.loop.create_task(self._loop())
        logger.info(f"TrackerClient started (Tracker: {self.tracker_url}, Interval: {self.interval}s)")

    def stop(self):
        """Cleanly stop tracker client background task and unregister."""
        if not self.running:
            return
        self.running = False
        if self._task and not self._task.done():
            self._task.cancel()
            self._task = None
        try:
            self.unregister_sync()
        except Exception as e:
            logger.debug(f"Tracker unregister error on stop: {e}")
        logger.info("TrackerClient stopped.")
