from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from kvs.crypto import AEADCipher, key_from_hex
from kvs.models import CacheSlot, CipherRecord, PrimeEntry
from kvs.rdma_rpc import RDMAEndpoint, RDMAError, rdma_call
from kvs.rpc import Endpoint, rpc_call

TOMBSTONE_MARKER = b"__TDX_KVS_TOMBSTONE__"


@dataclass
class CNConfig:
    client_id: str
    encryption_key_hex: str
    replication_factor: int
    mn_endpoints: List[Endpoint]
    populate_cache_on_read_miss: bool = True
    max_retries: int = 8
    require_tdx: bool = False
    cache_path_transport: str = "auto"


class CNNode:
    def __init__(self, config: CNConfig):
        if not config.mn_endpoints:
            raise ValueError("cn config must include at least one MN endpoint")
        if config.replication_factor <= 0:
            raise ValueError("replication_factor must be > 0")

        self.config = config
        self._cipher = AEADCipher(key_from_hex(config.encryption_key_hex))

    def _cache_rpc_call(self, endpoint: Endpoint, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
        mode = self.config.cache_path_transport.lower()
        if mode not in {"auto", "tcp", "rdma"}:
            raise ValueError("cache_path_transport must be one of: auto, tcp, rdma")

        should_try_rdma = mode == "rdma" or (mode == "auto" and endpoint.rdma_port is not None)
        if should_try_rdma:
            if endpoint.rdma_port is None:
                raise RuntimeError(f"{endpoint.node_id} has no rdma_port configured")
            rdma_endpoint = RDMAEndpoint(
                node_id=endpoint.node_id,
                host=endpoint.host,
                port=endpoint.rdma_port,
            )
            try:
                return rdma_call(rdma_endpoint, action, params)
            except RDMAError:
                if mode == "rdma":
                    raise
                return rpc_call(endpoint, action, params)

        return rpc_call(endpoint, action, params)

    def _stable_hash(self, key: str) -> int:
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big")

    def _select_replicas(self, key: str) -> List[Endpoint]:
        endpoints = self.config.mn_endpoints
        replica_count = min(self.config.replication_factor, len(endpoints))
        start = self._stable_hash(key) % len(endpoints)
        return [endpoints[(start + i) % len(endpoints)] for i in range(replica_count)]

    def write(self, key: str, value: str) -> None:
        plaintext = value.encode("utf-8")
        record = self._cipher.encrypt(plaintext, aad=key.encode("utf-8"))
        record.tombstone = False
        self._replicate_record(key, record)

    def delete(self, key: str) -> None:
        record = self._cipher.encrypt(TOMBSTONE_MARKER, aad=key.encode("utf-8"))
        record.tombstone = True
        self._replicate_record(key, record)

    def _replicate_record(self, key: str, record: CipherRecord) -> None:
        replicas = self._select_replicas(key)
        errors: List[str] = []
        for endpoint in replicas:
            try:
                self._commit_to_replica(endpoint, key, record)
            except Exception as exc:
                errors.append(f"{endpoint.node_id}: {exc}")
        if errors:
            joined = "; ".join(errors)
            raise RuntimeError(f"replication failed on one or more replicas: {joined}")

    def _commit_to_replica(self, endpoint: Endpoint, key: str, record: CipherRecord) -> None:
        for _ in range(self.config.max_retries):
            prime_result = self._cache_rpc_call(endpoint, "rdma_read_prime", {"key": key})["result"]
            expected_addr: Optional[int] = None
            expected_epoch: Optional[int] = None
            private_addr: Optional[int] = None

            if prime_result.get("found"):
                current = PrimeEntry.from_dict(prime_result["entry"])
                expected_addr = current.addr
                expected_epoch = current.epoch
                private_addr = current.private_addr
            else:
                private_result = rpc_call(endpoint, "cpu_fetch_private", {"key": key})["result"]
                if private_result.get("found"):
                    private_addr = int(private_result["private_addr"])

            alloc_result = self._cache_rpc_call(endpoint, "rdma_alloc_slot", {})["result"]
            slot_id = int(alloc_result["slot_id"])
            slot_epoch = int(alloc_result["epoch"])

            write_result = self._cache_rpc_call(
                endpoint,
                "rdma_write_slot",
                {
                    "slot_id": slot_id,
                    "epoch": slot_epoch,
                    "record": record.to_dict(),
                },
            )["result"]
            if not write_result.get("write_ok", False):
                continue

            cas_result = self._cache_rpc_call(
                endpoint,
                "rdma_cas_prime",
                {
                    "key": key,
                    "expected_addr": expected_addr,
                    "expected_epoch": expected_epoch,
                    "new_addr": slot_id,
                    "new_epoch": slot_epoch,
                    "private_addr": private_addr,
                },
            )["result"]
            if cas_result.get("cas_ok", False):
                return
        raise RuntimeError("max retry exceeded for CAS commit")

    def read(self, key: str) -> Optional[str]:
        primary = self._select_replicas(key)[0]
        for _ in range(self.config.max_retries):
            prime1_result = self._cache_rpc_call(primary, "rdma_read_prime", {"key": key})["result"]

            if not prime1_result.get("found"):
                private_result = rpc_call(primary, "cpu_fetch_private", {"key": key})["result"]
                if not private_result.get("found"):
                    return None
                record = CipherRecord.from_dict(private_result["record"])
                private_addr = int(private_result["private_addr"])
                if self.config.populate_cache_on_read_miss:
                    self._promote_private_to_cache(primary, key, record, private_addr)
                if record.tombstone:
                    return None
                plaintext = self._cipher.decrypt(record, aad=key.encode("utf-8"))
                if plaintext == TOMBSTONE_MARKER:
                    return None
                return plaintext.decode("utf-8")

            prime1 = PrimeEntry.from_dict(prime1_result["entry"])
            slot_result = self._cache_rpc_call(primary, "rdma_read_slot", {"slot_id": prime1.addr})["result"]
            prime2_result = self._cache_rpc_call(primary, "rdma_read_prime", {"key": key})["result"]

            if not prime2_result.get("found"):
                continue
            prime2 = PrimeEntry.from_dict(prime2_result["entry"])
            if prime1.addr != prime2.addr or prime1.epoch != prime2.epoch:
                continue

            if not slot_result.get("found"):
                continue
            slot = CacheSlot.from_dict(slot_result["slot"])
            if slot.epoch != prime1.epoch:
                continue

            if slot.record.tombstone:
                return None
            plaintext = self._cipher.decrypt(slot.record, aad=key.encode("utf-8"))
            if plaintext == TOMBSTONE_MARKER:
                return None
            return plaintext.decode("utf-8")

        raise RuntimeError("snapshot read failed after max retries")

    def _promote_private_to_cache(
        self,
        endpoint: Endpoint,
        key: str,
        record: CipherRecord,
        private_addr: Optional[int],
    ) -> None:
        for _ in range(self.config.max_retries):
            alloc_result = self._cache_rpc_call(endpoint, "rdma_alloc_slot", {})["result"]
            slot_id = int(alloc_result["slot_id"])
            slot_epoch = int(alloc_result["epoch"])

            write_result = self._cache_rpc_call(
                endpoint,
                "rdma_write_slot",
                {
                    "slot_id": slot_id,
                    "epoch": slot_epoch,
                    "record": record.to_dict(),
                },
            )["result"]
            if not write_result.get("write_ok", False):
                continue

            cas_result = self._cache_rpc_call(
                endpoint,
                "rdma_cas_prime",
                {
                    "key": key,
                    "expected_addr": None,
                    "expected_epoch": None,
                    "new_addr": slot_id,
                    "new_epoch": slot_epoch,
                    "private_addr": private_addr,
                },
            )["result"]
            if cas_result.get("cas_ok", False):
                return
            current = cas_result.get("current")
            if current is not None:
                return

    def debug_cluster_state(self) -> Dict[str, Any]:
        states: Dict[str, Any] = {}
        for endpoint in self.config.mn_endpoints:
            states[endpoint.node_id] = rpc_call(endpoint, "debug_state")["result"]
        return states
