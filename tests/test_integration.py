from __future__ import annotations

import tempfile
import threading
import time
import unittest

from kvs.cn_node import CNConfig, CNNode
from kvs.mn_node import MNNode, MNNodeConfig
from kvs.rpc import Endpoint


class IntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        base = self.temp_dir.name

        self.mn1 = MNNode(
            MNNodeConfig(
                node_id="mn-1",
                listen_host="127.0.0.1",
                listen_port=0,
                cache_capacity=2,
                state_dir=f"{base}/mn1",
            )
        )
        self.mn2 = MNNode(
            MNNodeConfig(
                node_id="mn-2",
                listen_host="127.0.0.1",
                listen_port=0,
                cache_capacity=2,
                state_dir=f"{base}/mn2",
            )
        )

        self.server1 = self.mn1.build_server()
        self.server2 = self.mn2.build_server()
        self.thread1 = threading.Thread(target=self.server1.serve_forever, daemon=True)
        self.thread2 = threading.Thread(target=self.server2.serve_forever, daemon=True)
        self.thread1.start()
        self.thread2.start()
        time.sleep(0.05)

        endpoint1 = Endpoint(
            node_id="mn-1",
            host="127.0.0.1",
            port=int(self.server1.server_address[1]),
        )
        endpoint2 = Endpoint(
            node_id="mn-2",
            host="127.0.0.1",
            port=int(self.server2.server_address[1]),
        )

        self.client = CNNode(
            CNConfig(
                client_id="cn-1",
                encryption_key_hex="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                replication_factor=2,
                mn_endpoints=[endpoint1, endpoint2],
                populate_cache_on_read_miss=True,
                max_retries=16,
            )
        )

    def tearDown(self) -> None:
        self.server1.shutdown()
        self.server2.shutdown()
        self.server1.server_close()
        self.server2.server_close()
        self.thread1.join(timeout=1.0)
        self.thread2.join(timeout=1.0)
        self.temp_dir.cleanup()

    def test_write_read_update_delete(self) -> None:
        self.client.write("alpha", "v1")
        self.assertEqual("v1", self.client.read("alpha"))

        self.client.write("alpha", "v2")
        self.assertEqual("v2", self.client.read("alpha"))

        self.client.delete("alpha")
        self.assertIsNone(self.client.read("alpha"))

    def test_eviction_flush_and_private_miss_recovery(self) -> None:
        self.client.write("k1", "value-1")
        self.client.write("k2", "value-2")
        self.client.write("k3", "value-3")  # cache capacity=2 -> eviction happens

        states = self.client.debug_cluster_state()
        self.assertGreaterEqual(states["mn-1"]["private_entries"], 1)
        self.assertGreaterEqual(states["mn-2"]["private_entries"], 1)

        self.assertEqual("value-1", self.client.read("k1"))

    def test_replication_writes_prime_entries_on_all_replicas(self) -> None:
        self.client.write("hot-key", "hot-value")
        states = self.client.debug_cluster_state()
        self.assertIn("hot-key", states["mn-1"]["prime_keys"])
        self.assertIn("hot-key", states["mn-2"]["prime_keys"])


if __name__ == "__main__":
    unittest.main()
