from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch

from kvs.config import load_role_and_config
from kvs.tdx_runtime import enforce_tdx_requirement


class RequireTDXTest(unittest.TestCase):
    def test_enforce_skips_when_disabled(self) -> None:
        with patch("kvs.tdx_runtime.is_running_in_tdx_guest", return_value=False):
            enforce_tdx_requirement(False)

    def test_enforce_passes_when_detected(self) -> None:
        with patch("kvs.tdx_runtime.is_running_in_tdx_guest", return_value=True):
            enforce_tdx_requirement(True)

    def test_enforce_raises_when_missing(self) -> None:
        with patch("kvs.tdx_runtime.is_running_in_tdx_guest", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "require_tdx=true"):
                enforce_tdx_requirement(True)

    def test_root_require_tdx_applies_to_mn(self) -> None:
        payload = {
            "role": "mn",
            "require_tdx": True,
            "mn": {
                "node_id": "mn-1",
                "listen_host": "127.0.0.1",
                "listen_port": 7001,
                "cache_capacity": 32,
                "state_dir": "state/mn-1",
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/config.json"
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(payload, fp)
            _, config = load_role_and_config(path)
        self.assertTrue(config.require_tdx)

    def test_role_override_require_tdx(self) -> None:
        payload = {
            "role": "cn",
            "require_tdx": True,
            "cn": {
                "client_id": "cn-1",
                "encryption_key_hex": "00112233445566778899aabbccddeeff",
                "replication_factor": 1,
                "require_tdx": False,
                "mn_endpoints": [
                    {"node_id": "mn-1", "host": "127.0.0.1", "port": 7001},
                ],
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = f"{temp_dir}/config.json"
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(payload, fp)
            _, config = load_role_and_config(path)
        self.assertFalse(config.require_tdx)


if __name__ == "__main__":
    unittest.main()
