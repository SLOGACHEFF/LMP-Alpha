"""Command-line entry point for the LMP Core alpha."""
from __future__ import annotations

import argparse
import asyncio
import logging
from getpass import getpass
from pathlib import Path

from .security.identity import IdentityKeyPair

from .node import LMPNode, NodeConfig, make_server_tls_context, send_message


def main() -> None:
    parser = argparse.ArgumentParser(prog="lmp-core")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run a local prototype node")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=7443)
    serve.add_argument("--cert", required=True)
    serve.add_argument("--key", required=True)
    serve.add_argument("--identity-file", required=True, help="encrypted LMP identity key file")
    serve.add_argument("--allow-principal", action="append", default=None, help="allowed client Principal ID; repeatable (default: any cryptographically authenticated identity)")
    serve.add_argument("--storage", default="lmp-messages.sqlite3", help="SQLite message database path (default: durable local file)")
    serve.add_argument("--log-level", default="INFO")

    send = sub.add_parser("send", help="send one test message")
    send.add_argument("--host", default="localhost")
    send.add_argument("--port", type=int, default=7443)
    send.add_argument("--ca", required=True)
    send.add_argument("--message", required=True)
    send.add_argument("--identity-file", required=True, help="encrypted local LMP identity key file")
    send.add_argument("--server-principal", required=True, help="pinned server Principal ID (lmp:p:...)")

    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, getattr(args, "log_level", "INFO").upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if args.command == "serve":
        asyncio.run(_serve(args))
    else:
        identity = _load_identity(args.identity_file, create=False)
        result = asyncio.run(send_message(args.host, args.port, args.ca, args.message,
                                          identity_keys=identity, expected_server_principal=args.server_principal))
        print(result)


async def _serve(args: argparse.Namespace) -> None:
    identity = _load_identity(args.identity_file, create=True)
    node = LMPNode(NodeConfig(node_label="lmp-alpha", identity_keys=identity,
                              allowed_principals=frozenset(args.allow_principal) if args.allow_principal else None,
                              storage_path=args.storage))
    tls = make_server_tls_context(args.cert, args.key)
    server = await node.serve(args.host, args.port, tls)
    print(f"LMP Principal ID: {identity.principal_id_text}")
    print(f"LMP Core alpha listening on {args.host}:{args.port}; SQLite storage: {args.storage}; Ctrl+C to stop")
    async with server:
        await server.serve_forever()


def _load_identity(path: str, *, create: bool) -> IdentityKeyPair:
    target = Path(path)
    if target.exists():
        password = getpass("Identity file password: ")
        return IdentityKeyPair.load_encrypted(target, password)
    if not create:
        raise SystemExit(f"identity file does not exist: {target}")
    password = getpass("Choose identity file password (8+ characters): ")
    confirm = getpass("Repeat password: ")
    if password != confirm or len(password) < 8:
        raise SystemExit("passwords do not match or are shorter than 8 characters")
    identity = IdentityKeyPair.generate()
    identity.save_encrypted(target, password)
    print(f"Created encrypted identity file: {target}")
    return identity
