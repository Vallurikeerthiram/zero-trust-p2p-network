import os
import json
import hashlib
import time
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("DeviceRegistry")
DEVICE_DB_FILE = "known_devices.json"


def get_device_fingerprint(client_ip: Optional[str], user_agent: Optional[str], token: Optional[str] = None) -> str:
    """Generate a stable device fingerprint from IP, User-Agent, and optional token."""
    if token and token.strip():
        return token.strip()
    raw = f"{client_ip or 'unknown'}_{user_agent or 'unknown'}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def parse_device_type(user_agent: Optional[str]) -> str:
    """Human-readable device description from User-Agent string."""
    if not user_agent:
        return "Unknown Device"
    ua = user_agent.lower()
    if "iphone" in ua:
        return "iPhone"
    if "ipad" in ua:
        return "iPad"
    if "android" in ua:
        if "nothing" in ua or "a063" in ua or "a065" in ua:
            return "Nothing Phone"
        if "pixel" in ua:
            return "Google Pixel"
        if "samsung" in ua or "sm-" in ua:
            return "Samsung Galaxy"
        return "Android Phone"
    if "macintosh" in ua or "mac os" in ua:
        return "Mac"
    if "windows" in ua:
        return "Windows PC"
    if "linux" in ua:
        return "Linux Device"
    return "Web Client"


def load_devices(db_file: Optional[str] = None) -> Dict[str, Any]:
    """Read known devices database."""
    target_file = db_file or DEVICE_DB_FILE
    if not os.path.exists(target_file):
        return {}
    try:
        with open(target_file, "r") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as e:
        logger.debug(f"Failed to load known devices: {e}")
        return {}


def save_devices(data: Dict[str, Any], db_file: Optional[str] = None) -> bool:
    """Write known devices database."""
    target_file = db_file or DEVICE_DB_FILE
    try:
        with open(target_file, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        logger.debug(f"Failed to save known devices: {e}")
        return False


def get_known_device(device_key: str, db_file: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Look up a device record by its fingerprint key."""
    devices = load_devices(db_file=db_file)
    return devices.get(device_key)


def register_device(
    device_key: str,
    username: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    peer_port: Optional[int] = None,
    peer_id: Optional[str] = None,
    db_file: Optional[str] = None
) -> Dict[str, Any]:
    """Register or update a known device profile."""
    devices = load_devices(db_file=db_file)
    device_type = parse_device_type(user_agent)
    record = {
        "username": username,
        "client_ip": client_ip or "127.0.0.1",
        "device_type": device_type,
        "last_seen": time.time(),
        "peer_port": peer_port,
        "peer_id": peer_id
    }
    devices[device_key] = record
    save_devices(devices, db_file=db_file)
    return record


def clear_device(device_key: str, db_file: Optional[str] = None) -> bool:
    """Remove a device profile so user can switch identity."""
    devices = load_devices(db_file=db_file)
    if device_key in devices:
        del devices[device_key]
        save_devices(devices, db_file=db_file)
        return True
    return False
