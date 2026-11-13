"""
Unit and Integration Tests for Zero-Trust Swarm Hub & Zero-Install Multi-Session Mode.
"""

import os
import socket
import pytest
from unittest.mock import patch, MagicMock

from src.core.swarm_hub import (
    safe_read_registry,
    safe_write_registry,
    register_node_port,
    unregister_node_port,
    get_free_port,
    REGISTRY_FILE,
)
from src.discovery.stun_client import get_lan_ip


class TestSwarmHubRegistry:
    """Validate thread-safe port registry operations."""

    def test_registry_read_write_cycle(self, tmp_path):
        test_file = str(tmp_path / "test_reg.json")
        with patch("src.core.swarm_hub.REGISTRY_FILE", test_file):
            assert safe_read_registry() == []
            success = safe_write_registry([8001, 8002, 8003])
            assert success is True
            assert safe_read_registry() == [8001, 8002, 8003]

    def test_register_and_unregister_port(self, tmp_path):
        test_file = str(tmp_path / "test_reg.json")
        with patch("src.core.swarm_hub.REGISTRY_FILE", test_file):
            register_node_port(8055)
            assert 8055 in safe_read_registry()
            # Idempotent addition
            register_node_port(8055)
            assert safe_read_registry().count(8055) == 1

            unregister_node_port(8055)
            assert 8055 not in safe_read_registry()
            # Idempotent removal
            unregister_node_port(8055)
            assert safe_read_registry() == []

    def test_get_free_port_allocates_clean_unbound_port(self, tmp_path):
        test_file = str(tmp_path / "test_reg.json")
        with patch("src.core.swarm_hub.REGISTRY_FILE", test_file):
            port = get_free_port(8100, 8150)
            assert 8100 <= port < 8150
            # Test that allocated port can actually be bound
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                assert s.getsockname()[1] == port

    def test_get_free_port_skips_registered_ports(self, tmp_path):
        test_file = str(tmp_path / "test_reg.json")
        with patch("src.core.swarm_hub.REGISTRY_FILE", test_file):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 8200))
                listener.listen(1)
                safe_write_registry([8200])
                port = get_free_port(8200, 8210)
                assert port != 8200
                assert port > 8200


class TestNetworkReachabilityHelper:
    """Validate LAN IP resolution."""

    def test_get_lan_ip_returns_valid_ipv4(self):
        lan_ip = get_lan_ip()
        assert isinstance(lan_ip, str)
        parts = lan_ip.split(".")
        assert len(parts) == 4
        for p in parts:
            val = int(p)
            assert 0 <= val <= 255
