from __future__ import annotations

import unittest
from unittest.mock import patch

from kvs.cn_node import CNConfig, CNNode
from kvs.rdma_rpc import RDMAError
from kvs.rpc import Endpoint


class CachePathTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.endpoint = Endpoint(node_id="mn-1", host="127.0.0.1", port=7001, rdma_port=7101)
        self.endpoint_no_rdma = Endpoint(node_id="mn-1", host="127.0.0.1", port=7001)
        self.base_key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

    def test_auto_prefers_rdma_when_available(self) -> None:
        client = CNNode(
            CNConfig(
                client_id="cn-1",
                encryption_key_hex=self.base_key,
                replication_factor=1,
                mn_endpoints=[self.endpoint],
                cache_path_transport="auto",
            )
        )

        with patch("kvs.cn_node.rdma_call", return_value={"ok": True, "result": {"x": 1}}) as rdma_mock:
            with patch("kvs.cn_node.rpc_call", return_value={"ok": True, "result": {"x": 2}}) as tcp_mock:
                out = client._cache_rpc_call(self.endpoint, "rdma_read_prime", {"key": "a"})
        self.assertEqual({"ok": True, "result": {"x": 1}}, out)
        rdma_mock.assert_called_once()
        tcp_mock.assert_not_called()

    def test_auto_falls_back_to_tcp_on_rdma_error(self) -> None:
        client = CNNode(
            CNConfig(
                client_id="cn-1",
                encryption_key_hex=self.base_key,
                replication_factor=1,
                mn_endpoints=[self.endpoint],
                cache_path_transport="auto",
            )
        )

        with patch("kvs.cn_node.rdma_call", side_effect=RDMAError("boom")):
            with patch("kvs.cn_node.rpc_call", return_value={"ok": True, "result": {"fallback": True}}) as tcp_mock:
                out = client._cache_rpc_call(self.endpoint, "rdma_read_prime", {"key": "a"})
        self.assertEqual({"ok": True, "result": {"fallback": True}}, out)
        tcp_mock.assert_called_once()

    def test_rdma_mode_raises_on_rdma_error(self) -> None:
        client = CNNode(
            CNConfig(
                client_id="cn-1",
                encryption_key_hex=self.base_key,
                replication_factor=1,
                mn_endpoints=[self.endpoint],
                cache_path_transport="rdma",
            )
        )

        with patch("kvs.cn_node.rdma_call", side_effect=RDMAError("boom")):
            with self.assertRaises(RDMAError):
                client._cache_rpc_call(self.endpoint, "rdma_read_prime", {"key": "a"})

    def test_rdma_mode_requires_rdma_port(self) -> None:
        client = CNNode(
            CNConfig(
                client_id="cn-1",
                encryption_key_hex=self.base_key,
                replication_factor=1,
                mn_endpoints=[self.endpoint_no_rdma],
                cache_path_transport="rdma",
            )
        )
        with self.assertRaisesRegex(RuntimeError, "no rdma_port"):
            client._cache_rpc_call(self.endpoint_no_rdma, "rdma_read_prime", {"key": "a"})


if __name__ == "__main__":
    unittest.main()
