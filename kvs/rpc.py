from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class Endpoint:
    node_id: str
    host: str
    port: int
    rdma_port: Optional[int] = None
    rdma_host: Optional[str] = None


class RPCError(RuntimeError):
    pass


def rpc_call(
    endpoint: Endpoint,
    action: str,
    params: Optional[Dict[str, Any]] = None,
    timeout_sec: float = 3.0,
) -> Dict[str, Any]:
    payload = {"action": action, "params": params or {}}
    request = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
    with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout_sec) as sock:
        sock.sendall(request)
        file_obj = sock.makefile("r", encoding="utf-8")
        line = file_obj.readline()
        if not line:
            raise RPCError(f"{endpoint.node_id} closed connection without response")
        response = json.loads(line)

    if not isinstance(response, dict):
        raise RPCError(f"{endpoint.node_id} returned non-dict response")
    if not response.get("ok", False):
        raise RPCError(f"{endpoint.node_id} error: {response.get('error', 'unknown')}")
    return response
