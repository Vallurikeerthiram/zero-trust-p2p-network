import unittest
import tempfile
from pathlib import Path
from src.core.device_registry import (
    get_device_fingerprint,
    parse_device_type,
    get_known_device,
    register_device,
    clear_device
)

class TestDeviceRegistry(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_file = str(Path(self.temp_dir.name) / "test_devices.json")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_parse_device_type(self):
        # iPhone
        iphone_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15"
        self.assertIn("iPhone", parse_device_type(iphone_ua))

        # Nothing Phone (user's specific device)
        nothing_ua = "Mozilla/5.0 (Linux; Android 14; A063 Build/UP1A.231005.007) Chrome/120.0.0.0 Mobile"
        self.assertIn("Nothing Phone", parse_device_type(nothing_ua))

        # Windows
        win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        self.assertIn("Windows PC", parse_device_type(win_ua))

        # Samsung Galaxy
        samsung_ua = "Mozilla/5.0 (Linux; Android 13; SM-S918B) Chrome/119.0.0.0 Mobile"
        self.assertIn("Samsung Galaxy", parse_device_type(samsung_ua))

        # Generic Android
        generic_android = "Mozilla/5.0 (Linux; U; Android 12; K) Mobile"
        self.assertIn("Android", parse_device_type(generic_android))

        # Empty / None
        self.assertIn("Device", parse_device_type(""))
        self.assertIn("Device", parse_device_type(None))

    def test_get_device_fingerprint_deterministic(self):
        fp1 = get_device_fingerprint("192.168.0.2", "Mozilla/5.0")
        fp2 = get_device_fingerprint("192.168.0.2", "Mozilla/5.0")
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 16)

        # Different IP produces different fingerprint
        fp3 = get_device_fingerprint("192.168.0.5", "Mozilla/5.0")
        self.assertNotEqual(fp1, fp3)

        # Query token overrides
        fp_token = get_device_fingerprint("192.168.0.2", "Mozilla/5.0", token="vkr_custom_token")
        self.assertEqual(fp_token, "vkr_custom_token")

    def test_register_and_get_known_device(self):
        fp = "test_fp_12345678"
        # Initially unknown
        self.assertIsNone(get_known_device(fp, db_file=self.storage_file))

        # Register device
        entry = register_device(
            device_key=fp,
            username="VKR Nothing",
            client_ip="192.168.0.2",
            user_agent="Mozilla/5.0 (Linux; Android 14; A063) Mobile",
            peer_port=8021,
            peer_id="peer_nothing_001",
            db_file=self.storage_file
        )
        self.assertEqual(entry["username"], "VKR Nothing")
        self.assertEqual(entry["device_type"], "Nothing Phone")
        self.assertEqual(entry["peer_port"], 8021)
        self.assertEqual(entry["peer_id"], "peer_nothing_001")

        # Retrieve known device
        retrieved = get_known_device(fp, db_file=self.storage_file)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["username"], "VKR Nothing")

        # Clear device
        cleared = clear_device(fp, db_file=self.storage_file)
        self.assertTrue(cleared)
        self.assertIsNone(get_known_device(fp, db_file=self.storage_file))

if __name__ == "__main__":
    unittest.main()
