from __future__ import annotations

import ctypes
import errno
import json
import socket
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional


class RDMAError(RuntimeError):
    pass


class RDMAUnavailableError(RDMAError):
    pass


_socklen_t = ctypes.c_uint32
_size_t = ctypes.c_size_t
_ssize_t = ctypes.c_ssize_t


class _SockAddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("sin_port", ctypes.c_ushort),
        ("sin_addr", ctypes.c_ubyte * 4),
        ("sin_zero", ctypes.c_ubyte * 8),
    ]


def _load_rdmacm() -> ctypes.CDLL:
    try:
        lib = ctypes.CDLL("librdmacm.so.1", use_errno=True)
    except OSError as exc:
        raise RDMAUnavailableError(f"librdmacm unavailable: {exc}") from exc

    lib.rsocket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.rsocket.restype = ctypes.c_int
    lib.rbind.argtypes = [ctypes.c_int, ctypes.POINTER(_SockAddrIn), _socklen_t]
    lib.rbind.restype = ctypes.c_int
    lib.rlisten.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.rlisten.restype = ctypes.c_int
    lib.raccept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    lib.raccept.restype = ctypes.c_int
    lib.rconnect.argtypes = [ctypes.c_int, ctypes.POINTER(_SockAddrIn), _socklen_t]
    lib.rconnect.restype = ctypes.c_int
    lib.rsend.argtypes = [ctypes.c_int, ctypes.c_void_p, _size_t, ctypes.c_int]
    lib.rsend.restype = _ssize_t
    lib.rrecv.argtypes = [ctypes.c_int, ctypes.c_void_p, _size_t, ctypes.c_int]
    lib.rrecv.restype = _ssize_t
    lib.rclose.argtypes = [ctypes.c_int]
    lib.rclose.restype = ctypes.c_int
    return lib


_RDMACM = None
_RDMACM_ERR: Optional[Exception] = None
try:
    _RDMACM = _load_rdmacm()
except Exception as _exc:  # pragma: no cover - depends on system setup
    _RDMACM_ERR = _exc


def rdma_supported() -> bool:
    return _RDMACM is not None


def _ensure_rdma() -> ctypes.CDLL:
    if _RDMACM is None:
        raise RDMAUnavailableError(f"RDMA transport is unavailable: {_RDMACM_ERR}")
    return _RDMACM


def _sockaddr_in(host: str, port: int) -> _SockAddrIn:
    addr = _SockAddrIn()
    addr.sin_family = socket.AF_INET
    addr.sin_port = socket.htons(port)
    packed = socket.inet_aton(host)
    addr.sin_addr = (ctypes.c_ubyte * 4).from_buffer_copy(packed)
    addr.sin_zero = (ctypes.c_ubyte * 8)(*([0] * 8))
    return addr


def _raise_oserror(prefix: str) -> None:
    err_no = ctypes.get_errno()
    raise RDMAError(f"{prefix} failed: [{err_no}] {errno.errorcode.get(err_no, 'UNKNOWN')}")


def _sendall(fd: int, payload: bytes) -> None:
    lib = _ensure_rdma()
    view = memoryview(payload)
    sent = 0
    while sent < len(view):
        chunk = view[sent:]
        n = lib.rsend(fd, ctypes.c_char_p(chunk.tobytes()), len(chunk), 0)
        if n < 0:
            _raise_oserror("rsend")
        if n == 0:
            raise RDMAError("rsend returned 0 (peer closed)")
        sent += int(n)


def _recv_line(fd: int, max_bytes: int = 8 * 1024 * 1024) -> bytes:
    lib = _ensure_rdma()
    out = bytearray()
    buf = ctypes.create_string_buffer(4096)
    while len(out) < max_bytes:
        n = lib.rrecv(fd, buf, len(buf), 0)
        if n < 0:
            _raise_oserror("rrecv")
        if n == 0:
            break
        out.extend(buf.raw[:n])
        idx = out.find(b"\n")
        if idx >= 0:
            return bytes(out[: idx + 1])
    if len(out) >= max_bytes:
        raise RDMAError("RDMA message too large")
    return bytes(out)


def _close_fd(fd: int) -> None:
    if fd < 0:
        return
    lib = _ensure_rdma()
    rc = lib.rclose(fd)
    if rc < 0:
        _raise_oserror("rclose")


@dataclass(frozen=True)
class RDMAEndpoint:
    node_id: str
    host: str
    port: int


def rdma_call(
    endpoint: RDMAEndpoint,
    action: str,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    lib = _ensure_rdma()
    fd = lib.rsocket(socket.AF_INET, socket.SOCK_STREAM, 0)
    if fd < 0:
        _raise_oserror("rsocket")

    try:
        sockaddr = _sockaddr_in(endpoint.host, endpoint.port)
        rc = lib.rconnect(fd, ctypes.byref(sockaddr), ctypes.sizeof(sockaddr))
        if rc < 0:
            _raise_oserror("rconnect")

        payload = {"action": action, "params": params or {}}
        req = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        _sendall(fd, req)
        raw = _recv_line(fd)
        if not raw:
            raise RDMAError(f"{endpoint.node_id} closed connection without response")
        response = json.loads(raw.decode("utf-8"))
    finally:
        _close_fd(fd)

    if not isinstance(response, dict):
        raise RDMAError(f"{endpoint.node_id} returned non-dict response")
    if not response.get("ok", False):
        raise RDMAError(f"{endpoint.node_id} error: {response.get('error', 'unknown')}")
    return response


class RDMARPCServer:
    def __init__(
        self,
        host: str,
        port: int,
        handler: Callable[[Dict[str, Any]], Dict[str, Any]],
    ):
        self.host = host
        self.port = port
        self._handler = handler
        self._listener_fd = -1
        self._stop_event = threading.Event()

    def serve_forever(self) -> None:
        lib = _ensure_rdma()
        listener = lib.rsocket(socket.AF_INET, socket.SOCK_STREAM, 0)
        if listener < 0:
            _raise_oserror("rsocket(listener)")
        self._listener_fd = listener

        sockaddr = _sockaddr_in(self.host, self.port)
        if lib.rbind(listener, ctypes.byref(sockaddr), ctypes.sizeof(sockaddr)) < 0:
            _raise_oserror("rbind")
        if lib.rlisten(listener, 256) < 0:
            _raise_oserror("rlisten")

        try:
            while not self._stop_event.is_set():
                conn_fd = lib.raccept(listener, None, None)
                if conn_fd < 0:
                    if self._stop_event.is_set():
                        break
                    _raise_oserror("raccept")
                thread = threading.Thread(target=self._handle_conn, args=(conn_fd,), daemon=True)
                thread.start()
        finally:
            self.close()

    def _handle_conn(self, fd: int) -> None:
        try:
            line = _recv_line(fd)
            if not line:
                return
            try:
                request = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError:
                response = {"ok": False, "error": "invalid json"}
            else:
                response = self._handler(request)
            encoded = (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
            _sendall(fd, encoded)
        finally:
            try:
                _close_fd(fd)
            except Exception:
                pass

    def close(self) -> None:
        self._stop_event.set()
        if self._listener_fd >= 0:
            try:
                _close_fd(self._listener_fd)
            except Exception:
                pass
            self._listener_fd = -1
