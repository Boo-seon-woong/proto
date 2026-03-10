from __future__ import annotations

import json
import os
import socketserver
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from kvs.models import CacheSlot, CipherRecord, PrimeEntry


@dataclass
class MNNodeConfig:
    node_id: str
    listen_host: str
    listen_port: int
    cache_capacity: int
    state_dir: str
    require_tdx: bool = False


class MNNode:
    def __init__(self, config: MNNodeConfig):
        if config.cache_capacity <= 0:
            raise ValueError("cache_capacity must be > 0")

        self.config = config
        self._lock = threading.RLock()

        self.cache_slots: Dict[int, CacheSlot] = {}
        self.prime_table: Dict[str, PrimeEntry] = {}
        self.slot_epochs: Dict[int, int] = {}
        self.free_slots: list[int] = []
        self.next_slot_id = 0
        self.lru_keys: "OrderedDict[str, None]" = OrderedDict()

        self.private_by_addr: Dict[int, Dict[str, Any]] = {}
        self.private_key_index: Dict[str, int] = {}
        self.next_private_addr = 1
        self._load_private_state()

    def _private_state_path(self) -> str:
        return os.path.join(self.config.state_dir, "private_store.json")

    def _load_private_state(self) -> None:
        os.makedirs(self.config.state_dir, exist_ok=True)
        path = self._private_state_path()
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        self.next_private_addr = int(data.get("next_private_addr", 1))
        raw_private_by_addr = data.get("private_by_addr", {})
        self.private_by_addr = {int(addr): value for addr, value in raw_private_by_addr.items()}
        self.private_key_index = {str(k): int(v) for k, v in data.get("private_key_index", {}).items()}

    def _persist_private_state_locked(self) -> None:
        path = self._private_state_path()
        data = {
            "next_private_addr": self.next_private_addr,
            "private_by_addr": {str(k): v for k, v in self.private_by_addr.items()},
            "private_key_index": self.private_key_index,
        }
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, sort_keys=True)

    def _touch_key_locked(self, key: str) -> None:
        if key in self.lru_keys:
            self.lru_keys.pop(key, None)
        self.lru_keys[key] = None

    def _release_slot_locked(self, slot_id: int) -> None:
        self.cache_slots.pop(slot_id, None)
        if slot_id not in self.free_slots:
            self.free_slots.append(slot_id)

    def _collect_orphan_slots_locked(self) -> None:
        referenced = {entry.addr for entry in self.prime_table.values()}
        orphan_ids = [slot_id for slot_id in self.cache_slots if slot_id not in referenced]
        for slot_id in orphan_ids:
            self._release_slot_locked(slot_id)

    def _write_private_locked(self, key: str, record: CipherRecord) -> int:
        addr = self.private_key_index.get(key)
        if addr is None:
            addr = self.next_private_addr
            self.next_private_addr += 1
            self.private_key_index[key] = addr
        self.private_by_addr[addr] = {"key": key, "record": record.to_dict()}
        self._persist_private_state_locked()
        return addr

    def _delete_private_locked(self, key: str) -> None:
        addr = self.private_key_index.pop(key, None)
        if addr is None:
            return
        self.private_by_addr.pop(addr, None)
        self._persist_private_state_locked()

    def _evict_one_locked(self) -> None:
        self._collect_orphan_slots_locked()
        if not self.prime_table:
            raise RuntimeError("cannot evict: no authoritative prime entries")

        victim_key = next(iter(self.lru_keys))
        victim_entry = self.prime_table.get(victim_key)
        if victim_entry is None:
            self.lru_keys.pop(victim_key, None)
            return

        slot = self.cache_slots.get(victim_entry.addr)
        if slot is None:
            self.prime_table.pop(victim_key, None)
            self.lru_keys.pop(victim_key, None)
            return

        if slot.record.tombstone:
            self._delete_private_locked(victim_key)
        else:
            self._write_private_locked(victim_key, slot.record)

        self.prime_table.pop(victim_key, None)
        self.lru_keys.pop(victim_key, None)
        self._release_slot_locked(victim_entry.addr)

    def _allocate_slot_locked(self) -> Tuple[int, int]:
        self._collect_orphan_slots_locked()
        if len(self.cache_slots) >= self.config.cache_capacity:
            self._evict_one_locked()
            self._collect_orphan_slots_locked()
            if len(self.cache_slots) >= self.config.cache_capacity:
                raise RuntimeError("cache remains full after eviction")

        if self.free_slots:
            slot_id = self.free_slots.pop()
            epoch = self.slot_epochs.get(slot_id, 0) + 1
        else:
            slot_id = self.next_slot_id
            self.next_slot_id += 1
            epoch = 1

        self.slot_epochs[slot_id] = epoch
        placeholder = CipherRecord(
            ciphertext_b64="",
            nonce_b64="",
            tag_b64="",
            algorithm="reserved",
            tombstone=False,
        )
        self.cache_slots[slot_id] = CacheSlot(slot_id=slot_id, epoch=epoch, record=placeholder)
        return slot_id, epoch

    def handle_rpc(self, request: Dict[str, Any]) -> Dict[str, Any]:
        action = request.get("action")
        params = request.get("params", {})
        if not isinstance(params, dict):
            return {"ok": False, "error": "params must be object"}

        try:
            if action == "rdma_alloc_slot":
                return {"ok": True, "result": self._rpc_rdma_alloc_slot()}
            if action == "rdma_write_slot":
                return {"ok": True, "result": self._rpc_rdma_write_slot(params)}
            if action == "rdma_read_slot":
                return {"ok": True, "result": self._rpc_rdma_read_slot(params)}
            if action == "rdma_read_prime":
                return {"ok": True, "result": self._rpc_rdma_read_prime(params)}
            if action == "rdma_cas_prime":
                return {"ok": True, "result": self._rpc_rdma_cas_prime(params)}
            if action == "cpu_fetch_private":
                return {"ok": True, "result": self._rpc_cpu_fetch_private(params)}
            if action == "cpu_delete_private":
                return {"ok": True, "result": self._rpc_cpu_delete_private(params)}
            if action == "debug_state":
                return {"ok": True, "result": self._rpc_debug_state()}
            return {"ok": False, "error": f"unknown action: {action}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _rpc_rdma_alloc_slot(self) -> Dict[str, Any]:
        with self._lock:
            slot_id, epoch = self._allocate_slot_locked()
            return {"slot_id": slot_id, "epoch": epoch}

    def _rpc_rdma_write_slot(self, params: Dict[str, Any]) -> Dict[str, Any]:
        slot_id = int(params["slot_id"])
        epoch = int(params["epoch"])
        record = CipherRecord.from_dict(params["record"])

        with self._lock:
            slot = self.cache_slots.get(slot_id)
            if slot is None:
                return {"write_ok": False, "reason": "slot_not_found"}
            if slot.epoch != epoch:
                return {"write_ok": False, "reason": "stale_epoch", "actual_epoch": slot.epoch}
            self.cache_slots[slot_id] = CacheSlot(slot_id=slot_id, epoch=epoch, record=record)
            return {"write_ok": True}

    def _rpc_rdma_read_slot(self, params: Dict[str, Any]) -> Dict[str, Any]:
        slot_id = int(params["slot_id"])
        with self._lock:
            slot = self.cache_slots.get(slot_id)
            if slot is None:
                return {"found": False}
            return {"found": True, "slot": slot.to_dict()}

    def _rpc_rdma_read_prime(self, params: Dict[str, Any]) -> Dict[str, Any]:
        key = str(params["key"])
        with self._lock:
            entry = self.prime_table.get(key)
            if entry is None:
                return {"found": False}
            self._touch_key_locked(key)
            return {"found": True, "entry": entry.to_dict()}

    def _rpc_rdma_cas_prime(self, params: Dict[str, Any]) -> Dict[str, Any]:
        key = str(params["key"])
        expected_addr = params.get("expected_addr")
        expected_epoch = params.get("expected_epoch")
        new_addr = int(params["new_addr"])
        new_epoch = int(params["new_epoch"])
        private_addr = params.get("private_addr")
        if private_addr is not None:
            private_addr = int(private_addr)

        with self._lock:
            current = self.prime_table.get(key)
            if expected_addr is None and expected_epoch is None:
                expected_match = current is None
            else:
                expected_match = (
                    current is not None
                    and current.addr == int(expected_addr)
                    and current.epoch == int(expected_epoch)
                )

            if not expected_match:
                return {
                    "cas_ok": False,
                    "current": current.to_dict() if current is not None else None,
                }

            slot = self.cache_slots.get(new_addr)
            if slot is None or slot.epoch != new_epoch:
                return {"cas_ok": False, "reason": "new_pointer_not_available"}

            next_private_addr = private_addr
            if next_private_addr is None and current is not None:
                next_private_addr = current.private_addr

            self.prime_table[key] = PrimeEntry(
                key=key,
                addr=new_addr,
                epoch=new_epoch,
                private_addr=next_private_addr,
                valid=True,
            )
            self._touch_key_locked(key)

            if current is not None and current.addr != new_addr:
                self._release_slot_locked(current.addr)

            return {"cas_ok": True, "entry": self.prime_table[key].to_dict()}

    def _rpc_cpu_fetch_private(self, params: Dict[str, Any]) -> Dict[str, Any]:
        key = str(params["key"])
        with self._lock:
            private_addr = self.private_key_index.get(key)
            if private_addr is None:
                return {"found": False}
            payload = self.private_by_addr.get(private_addr)
            if payload is None:
                self.private_key_index.pop(key, None)
                return {"found": False}
            return {
                "found": True,
                "private_addr": private_addr,
                "record": payload["record"],
            }

    def _rpc_cpu_delete_private(self, params: Dict[str, Any]) -> Dict[str, Any]:
        key = str(params["key"])
        with self._lock:
            self._delete_private_locked(key)
            return {"deleted": True}

    def _rpc_debug_state(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "node_id": self.config.node_id,
                "cache_slots": len(self.cache_slots),
                "prime_entries": len(self.prime_table),
                "private_entries": len(self.private_by_addr),
                "free_slots": sorted(self.free_slots),
                "prime_keys": sorted(self.prime_table.keys()),
            }

    def build_server(self) -> "ThreadedRPCServer":
        server = ThreadedRPCServer((self.config.listen_host, self.config.listen_port), RPCHandler)
        server.node = self
        return server

    def serve_forever(self) -> None:
        with self.build_server() as server:
            server.serve_forever()


class RPCHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline()
        if not line:
            return
        try:
            request = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError:
            response = {"ok": False, "error": "invalid json"}
        else:
            node = self.server.node  # type: ignore[attr-defined]
            response = node.handle_rpc(request)
        encoded = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
        self.wfile.write(encoded)


class ThreadedRPCServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
