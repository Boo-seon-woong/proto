from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Optional

from kvs.models import CipherRecord

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    AESGCM = None  # type: ignore


def key_from_hex(key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    if len(key) not in (16, 24, 32):
        raise ValueError("encryption_key_hex must decode to 16/24/32 bytes")
    return key


class AEADCipher:
    def __init__(self, key: bytes):
        self._key = key
        self._aesgcm: Optional[AESGCM] = AESGCM(key) if AESGCM is not None else None  # type: ignore[arg-type]

    @property
    def preferred_algorithm(self) -> str:
        if self._aesgcm is not None:
            return "aes-gcm"
        return "hmac-stream-v1"

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> CipherRecord:
        if self._aesgcm is not None:
            nonce = os.urandom(12)
            encrypted = self._aesgcm.encrypt(nonce, plaintext, aad)
            ciphertext = encrypted[:-16]
            tag = encrypted[-16:]
            return CipherRecord(
                ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
                tag_b64=base64.b64encode(tag).decode("ascii"),
                algorithm="aes-gcm",
            )

        nonce = os.urandom(16)
        stream = self._stream_keystream(nonce, len(plaintext))
        ciphertext = bytes(p ^ s for p, s in zip(plaintext, stream))
        tag = hmac.new(self._key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        return CipherRecord(
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
            algorithm="hmac-stream-v1",
        )

    def decrypt(self, record: CipherRecord, aad: bytes = b"") -> bytes:
        ciphertext = base64.b64decode(record.ciphertext_b64.encode("ascii"))
        nonce = base64.b64decode(record.nonce_b64.encode("ascii"))
        tag = base64.b64decode(record.tag_b64.encode("ascii"))

        if record.algorithm == "aes-gcm":
            if self._aesgcm is None:
                raise RuntimeError("received aes-gcm record but cryptography AESGCM is unavailable")
            encrypted = ciphertext + tag
            return self._aesgcm.decrypt(nonce, encrypted, aad)

        if record.algorithm != "hmac-stream-v1":
            raise ValueError(f"unsupported algorithm: {record.algorithm}")

        expected_tag = hmac.new(self._key, nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(expected_tag, tag):
            raise ValueError("ciphertext authentication failed")

        stream = self._stream_keystream(nonce, len(ciphertext))
        return bytes(c ^ s for c, s in zip(ciphertext, stream))

    def _stream_keystream(self, nonce: bytes, length: int) -> bytes:
        out = bytearray()
        counter = 0
        while len(out) < length:
            block = hashlib.sha256(self._key + nonce + counter.to_bytes(4, "big")).digest()
            out.extend(block)
            counter += 1
        return bytes(out[:length])
