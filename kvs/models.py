from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Pointer:
    addr: int
    epoch: int

    def to_dict(self) -> Dict[str, int]:
        return {"addr": self.addr, "epoch": self.epoch}

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Pointer":
        return cls(addr=int(raw["addr"]), epoch=int(raw["epoch"]))


@dataclass
class CipherRecord:
    ciphertext_b64: str
    nonce_b64: str
    tag_b64: str
    algorithm: str
    tombstone: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ciphertext_b64": self.ciphertext_b64,
            "nonce_b64": self.nonce_b64,
            "tag_b64": self.tag_b64,
            "algorithm": self.algorithm,
            "tombstone": self.tombstone,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "CipherRecord":
        return cls(
            ciphertext_b64=str(raw["ciphertext_b64"]),
            nonce_b64=str(raw["nonce_b64"]),
            tag_b64=str(raw["tag_b64"]),
            algorithm=str(raw["algorithm"]),
            tombstone=bool(raw.get("tombstone", False)),
        )


@dataclass
class CacheSlot:
    slot_id: int
    epoch: int
    record: CipherRecord

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "epoch": self.epoch,
            "record": self.record.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "CacheSlot":
        return cls(
            slot_id=int(raw["slot_id"]),
            epoch=int(raw["epoch"]),
            record=CipherRecord.from_dict(raw["record"]),
        )


@dataclass
class PrimeEntry:
    key: str
    addr: int
    epoch: int
    private_addr: Optional[int]
    valid: bool = True

    def pointer(self) -> Pointer:
        return Pointer(addr=self.addr, epoch=self.epoch)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "addr": self.addr,
            "epoch": self.epoch,
            "private_addr": self.private_addr,
            "valid": self.valid,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "PrimeEntry":
        private_addr = raw.get("private_addr")
        return cls(
            key=str(raw["key"]),
            addr=int(raw["addr"]),
            epoch=int(raw["epoch"]),
            private_addr=int(private_addr) if private_addr is not None else None,
            valid=bool(raw.get("valid", True)),
        )
