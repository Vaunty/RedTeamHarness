from __future__ import annotations

import argparse
import asyncio
import os

from .crypto import KeyPair, keypair_from_files, keypair_to_files
from .hub import InformationHub
from .net import AsyncNodeServer
from .pool import AIPool

def ensure_keypair(sk_path: str, pk_path: str) -> KeyPair:
    if os.path.exists(sk_path) and os.path.exists(pk_path):
        return keypair_from_files(sk_path, pk_path)

    kp = KeyPair.generate()
    keypair_to_files(kp, sk_path, pk_path)
    return kp

async def main() -> None:
    ap = argparse.ArgumentParser(description="Run PoDL information hub")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--node-id", default="node-1")
    ap.add_argument("--sk", default="node_sk.bin")
    ap.add_argument("--pk", default="node_pk.bin")
    args = ap.parse_args()

    kp = ensure_keypair(args.sk, args.pk)
    pool = AIPool()
    hub = InformationHub(node_id=args.node_id, keypair=kp, pool=pool)

    server = AsyncNodeServer(args.host, args.port, hub.handle_packet)
    await server.start()

    print(f"[hub] listening on {args.host}:{args.port} as {args.node_id}")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())