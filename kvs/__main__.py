from __future__ import annotations

import argparse
import json
import shlex
from typing import Sequence

from kvs.cn_node import CNNode
from kvs.config import load_role_and_config
from kvs.mn_node import MNNode
from kvs.tdx_runtime import enforce_tdx_requirement


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kvs",
        description="TDX-compatible client-centric KVS prototype",
    )
    parser.add_argument(
        "--config",
        default="build/config.json",
        help="path to node config file (default: build/config.json)",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("serve", help="run MN server loop (MN role only)")

    write_parser = subparsers.add_parser("write", help="write key/value (CN role only)")
    write_parser.add_argument("key")
    write_parser.add_argument("value")

    read_parser = subparsers.add_parser("read", help="read key (CN role only)")
    read_parser.add_argument("key")

    delete_parser = subparsers.add_parser("delete", help="delete key (CN role only)")
    delete_parser.add_argument("key")

    subparsers.add_parser("state", help="print MN state from all endpoints (CN role only)")
    subparsers.add_parser("repl", help="interactive CN shell")
    return parser


def run_repl(client: CNNode) -> None:
    print("CN REPL commands: write <k> <v>, read <k>, delete <k>, state, quit")
    while True:
        try:
            line = input("cn> ").strip()
        except EOFError:
            print()
            return
        if not line:
            continue
        if line in {"quit", "exit"}:
            return

        parts = shlex.split(line)
        cmd = parts[0]
        try:
            if cmd == "write" and len(parts) >= 3:
                key = parts[1]
                value = " ".join(parts[2:])
                client.write(key, value)
                print("OK")
                continue
            if cmd == "read" and len(parts) == 2:
                value = client.read(parts[1])
                print("NOT_FOUND" if value is None else value)
                continue
            if cmd == "delete" and len(parts) == 2:
                client.delete(parts[1])
                print("OK")
                continue
            if cmd == "state" and len(parts) == 1:
                print(json.dumps(client.debug_cluster_state(), indent=2, sort_keys=True))
                continue
        except Exception as exc:
            print(f"ERROR: {exc}")
            continue

        print("Invalid command")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    role, config = load_role_and_config(args.config)
    enforce_tdx_requirement(bool(getattr(config, "require_tdx", False)))

    if role == "mn":
        if args.command not in {None, "serve"}:
            raise SystemExit("MN role only supports: serve")
        node = MNNode(config)  # type: ignore[arg-type]
        print(f"MN node {node.config.node_id} control(TCP) listening on {node.config.listen_host}:{node.config.listen_port}")
        if node.config.enable_rdma_server:
            rdma_host = node.config.rdma_listen_host or node.config.listen_host
            rdma_port = node.config.rdma_listen_port or (node.config.listen_port + 100)
            print(f"MN node {node.config.node_id} cache-path(RDMA) listening on {rdma_host}:{rdma_port}")
        node.serve_forever()
        return 0

    client = CNNode(config)  # type: ignore[arg-type]
    command = args.command or "repl"
    if command == "write":
        client.write(args.key, args.value)
        print("OK")
        return 0
    if command == "read":
        value = client.read(args.key)
        print("NOT_FOUND" if value is None else value)
        return 0
    if command == "delete":
        client.delete(args.key)
        print("OK")
        return 0
    if command == "state":
        print(json.dumps(client.debug_cluster_state(), indent=2, sort_keys=True))
        return 0
    if command == "repl":
        run_repl(client)
        return 0

    raise SystemExit(f"unsupported command for CN role: {command}")


if __name__ == "__main__":
    raise SystemExit(main())
