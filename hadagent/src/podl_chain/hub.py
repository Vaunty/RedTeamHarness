from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional

from .crypto import KeyPair, sha256
from .packets import Packet, PacketType
from .pool import AIPool, PoolItem

from .records import (
    Record,
    Lane,
    DataType,
    ModelType,
    ProofType,
    make_ownership_commit,
    make_model_commit,
    make_podl_llm_eval,
    pack,
)

def _must_hex32(s: str) -> bytes:
    b = bytes.fromhex(s)
    if len(b) != 32:
        raise ValueError("Expected 32-byte hex value.")
    return b


class InformationHub:
    """
    Central async message router for:
    - receiving packets
    - validating packets
    - hashing + signing metadata
    - storing records in the local AI pool

    Raw data should stay off-chain.
    This hub stores only hashes and metadata in pool records.
    """

    def __init__(self, node_id: str, keypair: KeyPair, pool: Optional[AIPool] = None) -> None:
        self.node_id = node_id
        self.keypair = keypair
        self.pool = pool or AIPool()
        self.peers: List[tuple[str, int]] = []

    def add_peer(self, host: str, port: int) -> None:
        peer = (host, port)
        if peer not in self.peers:
            self.peers.append(peer)

    async def handle_packet(self, pkt: Packet, writer: asyncio.StreamWriter) -> None:
        try:
            if pkt.ptype == PacketType.PING:
                resp = Packet(
                    ptype=PacketType.PONG,
                    sender_id=self.node_id,
                    payload={"ok": True},
                    request_id=pkt.request_id,
                )
                writer.write(resp.to_bytes())
                await writer.drain()
                return

            if pkt.ptype == PacketType.NEW_DATA_RECORD:
                item_id = await self._handle_new_data_record(pkt.payload)
                resp = Packet(
                    ptype=PacketType.PONG,
                    sender_id=self.node_id,
                    payload={"ok": True, "item_id": item_id},
                    request_id=pkt.request_id,
                )
                writer.write(resp.to_bytes())
                await writer.drain()
                return

            if pkt.ptype == PacketType.NEW_MODEL_RECORD:
                item_id = await self._handle_new_model_record(pkt.payload)
                resp = Packet(
                    ptype=PacketType.PONG,
                    sender_id=self.node_id,
                    payload={"ok": True, "item_id": item_id},
                    request_id=pkt.request_id,
                )
                writer.write(resp.to_bytes())
                await writer.drain()
                return

            if pkt.ptype == PacketType.NEW_PROOF_RECORD:
                item_id = await self._handle_new_proof_record(pkt.payload)
                resp = Packet(
                    ptype=PacketType.PONG,
                    sender_id=self.node_id,
                    payload={"ok": True, "item_id": item_id},
                    request_id=pkt.request_id,
                )
                writer.write(resp.to_bytes())
                await writer.drain()
                return

            if pkt.ptype == PacketType.POOL_SYNC_REQUEST:
                items = await self.pool.list_all()
                payload = {
                    "items": [
                        {
                            "item_id": x.item_id,
                            "lane": x.lane,
                            "rtype": x.rtype,
                            "payload": x.payload,
                            "ts": x.ts,
                        }
                        for x in items
                    ]
                }
                resp = Packet(
                    ptype=PacketType.POOL_SYNC_RESPONSE,
                    sender_id=self.node_id,
                    payload=payload,
                    request_id=pkt.request_id,
                )
                writer.write(resp.to_bytes())
                await writer.drain()
                return

            resp = Packet(
                ptype=PacketType.ERROR,
                sender_id=self.node_id,
                payload={"ok": False, "error": f"Unhandled packet type: {pkt.ptype.value}"},
                request_id=pkt.request_id,
            )
            writer.write(resp.to_bytes())
            await writer.drain()

        except Exception as exc:
            resp = Packet(
                ptype=PacketType.ERROR,
                sender_id=self.node_id,
                payload={"ok": False, "error": str(exc)},
                request_id=pkt.request_id,
            )
            writer.write(resp.to_bytes())
            await writer.drain()

    async def _handle_new_data_record(self, payload: Dict[str, Any]) -> str:
        
        ts = int(time.time())

        data_id = _must_hex32(payload["data_id_hex"])
        content_hash = _must_hex32(payload["content_hash_hex"])
        policy_hash = _must_hex32(payload["policy_hash_hex"])
        storage_ref = str(payload["storage_ref"])

        # Sign only the metadata / hashes.
        msg = pack({
            "data_id": data_id,
            "owner_pk": self.keypair.pubkey_bytes(),
            "content_hash": content_hash,
            "policy_hash": policy_hash,
            "storage_ref": storage_ref,
            "ts": ts,
        })
        sig = self.keypair.sign(msg)

        record_payload = make_ownership_commit(
            data_id=data_id,
            owner_pk=self.keypair.pubkey_bytes(),
            content_hash=content_hash,
            policy_hash=policy_hash,
            storage_ref=storage_ref,
            ts=ts,
            sig=sig,
        )

        rec = Record(
            lane=Lane.DATA,
            rtype=DataType.OWNERSHIP_COMMIT,
            version=1,
            payload=record_payload,
        )

        item_id = rec.record_hash().hex()
        await self.pool.add(PoolItem(
            item_id=item_id,
            lane="DATA",
            rtype="OWNERSHIP_COMMIT",
            payload={"record_hex": rec.to_bytes().hex()},
            ts=ts,
        ))
        return item_id

    async def _handle_new_model_record(self, payload: Dict[str, Any]) -> str:
       
        ts = int(time.time())

        model_id = str(payload["model_id"])
        artifact_hash = _must_hex32(payload["artifact_hash_hex"])
        storage_ref = str(payload["storage_ref"])

        msg = pack({
            "model_id": model_id,
            "artifact_hash": artifact_hash,
            "owner_pk": self.keypair.pubkey_bytes(),
            "storage_ref": storage_ref,
            "ts": ts,
        })
        sig = self.keypair.sign(msg)

        record_payload = make_model_commit(
            model_id=model_id,
            artifact_hash=artifact_hash,
            owner_pk=self.keypair.pubkey_bytes(),
            storage_ref=storage_ref,
            ts=ts,
            sig=sig,
        )

        rec = Record(
            lane=Lane.MODEL,
            rtype=ModelType.MODEL_COMMIT,
            version=1,
            payload=record_payload,
        )

        item_id = rec.record_hash().hex()
        await self.pool.add(PoolItem(
            item_id=item_id,
            lane="MODEL",
            rtype="MODEL_COMMIT",
            payload={"record_hex": rec.to_bytes().hex()},
            ts=ts,
        ))
        return item_id

    async def _handle_new_proof_record(self, payload: Dict[str, Any]) -> str:
       
        ts = int(time.time())

        proof_id = _must_hex32(payload["proof_id_hex"])
        base_model_id = str(payload["base_model_id"])
        provider = str(payload["provider"])
        endpoint = str(payload["endpoint"])
        evalset_hash = _must_hex32(payload["evalset_hash_hex"])
        decode_cfg_hash = _must_hex32(payload["decode_cfg_hash_hex"])
        claimed_score_scaled = int(payload["claimed_score_scaled"])
        score_scale = int(payload["score_scale"])
        artifact_hash = _must_hex32(payload["artifact_hash_hex"])
        artifact_ref = str(payload.get("artifact_ref", ""))

        msg = pack({
            "proof_id": proof_id,
            "miner_pk": self.keypair.pubkey_bytes(),
            "base_model_id": base_model_id,
            "provider": provider,
            "endpoint": endpoint,
            "evalset_hash": evalset_hash,
            "decode_cfg_hash": decode_cfg_hash,
            "claimed_score_scaled": claimed_score_scaled,
            "score_scale": score_scale,
            "artifact_hash": artifact_hash,
            "artifact_ref": artifact_ref,
            "ts": ts,
        })
        sig = self.keypair.sign(msg)

        record_payload = make_podl_llm_eval(
            proof_id=proof_id,
            miner_pk=self.keypair.pubkey_bytes(),
            base_model_id=base_model_id,
            provider=provider,
            endpoint=endpoint,
            evalset_hash=evalset_hash,
            decode_cfg_hash=decode_cfg_hash,
            claimed_score_scaled=claimed_score_scaled,
            score_scale=score_scale,
            artifact_hash=artifact_hash,
            artifact_ref=artifact_ref,
            ts=ts,
            sig=sig,
        )

        rec = Record(
            lane=Lane.PROOF,
            rtype=ProofType.PODL_LLM_EVAL,
            version=1,
            payload=record_payload,
        )

        item_id = rec.record_hash().hex()
        await self.pool.add(PoolItem(
            item_id=item_id,
            lane="PROOF",
            rtype="PODL_LLM_EVAL",
            payload={"record_hex": rec.to_bytes().hex()},
            ts=ts,
        ))
        return item_id

    async def build_records_for_block(self, limit: int = 100) -> List[Record]:
        items = await self.pool.pop_for_block(limit=limit)
        records: List[Record] = []
        for item in items:
            record_hex = item.payload["record_hex"]
            records.append(Record.from_bytes(bytes.fromhex(record_hex)))
        return records