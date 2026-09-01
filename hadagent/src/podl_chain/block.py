from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
import os
from .crypto import sha256, verify
from .merkle import merkle_root
from .records import Record, Lane, ProofType, validate_record, pack, unpack
from .pdl import verify_podl_llm_eval

@dataclass(frozen=True)
class BlockHeader:
    version: int
    height: int
    prev_hash: bytes

    # Novel block body, separate roots per lane
    data_root: bytes
    model_root: bytes
    proof_root: bytes

    ts: int
    producer_pk: bytes
    sig: bytes

    def signing_bytes(self) -> bytes:
        return pack({
            "version": self.version,
            "height": self.height,
            "prev_hash": self.prev_hash,
            "data_root": self.data_root,
            "model_root": self.model_root,
            "proof_root": self.proof_root,
            "ts": self.ts,
            "producer_pk": self.producer_pk,
        })

@dataclass(frozen=True)
class Block:
    header: BlockHeader
    records: List[Record]

    def block_hash(self) -> bytes:
        return sha256(self.header.signing_bytes() + self.header.sig)

    @staticmethod
    def compute_lane_roots(records: List[Record]) -> Tuple[bytes, bytes, bytes]:
        data = sorted((r for r in records if r.lane == Lane.DATA), key=lambda r: r.record_hash())
        model = sorted((r for r in records if r.lane == Lane.MODEL), key=lambda r: r.record_hash())
        proof = sorted((r for r in records if r.lane == Lane.PROOF), key=lambda r: r.record_hash())

        data_root = merkle_root([r.record_hash() for r in data])
        model_root = merkle_root([r.record_hash() for r in model])
        proof_root = merkle_root([r.record_hash() for r in proof])
        return data_root, model_root, proof_root

    def to_bytes(self) -> bytes:
        return pack({
            "header": {
                "version": self.header.version,
                "height": self.header.height,
                "prev_hash": self.header.prev_hash,
                "data_root": self.header.data_root,
                "model_root": self.header.model_root,
                "proof_root": self.header.proof_root,
                "ts": self.header.ts,
                "producer_pk": self.header.producer_pk,
                "sig": self.header.sig,
            },
            "records": [r.to_bytes() for r in self.records],
        })

    @staticmethod
    def from_bytes(b: bytes) -> "Block":
        o = unpack(b)
        h = o["header"]
        header = BlockHeader(
            version=h["version"],
            height=h["height"],
            prev_hash=h["prev_hash"],
            data_root=h["data_root"],
            model_root=h["model_root"],
            proof_root=h["proof_root"],
            ts=h["ts"],
            producer_pk=h["producer_pk"],
            sig=h["sig"],
        )
        recs = [Record.from_bytes(x) for x in o["records"]]
        return Block(header=header, records=recs)

    def validate(self, expected_prev: bytes, expected_height: int) -> tuple[bool, str]:
        # Linkage checks
        if self.header.height != expected_height:
            return False, "height mismatch"
        if self.header.prev_hash != expected_prev:
            return False, "prev_hash mismatch"

        # Validate each record (signature + basic schema checks)
        for r in self.records:
            ok, reason = validate_record(r)
            if not ok:
                return False, f"invalid record lane={r.lane} type={r.rtype}: {reason}"

        # Recompute lane roots and compare
        data_root, model_root, proof_root = Block.compute_lane_roots(self.records)
        if data_root != self.header.data_root:
            return False, "data_root mismatch"
        if model_root != self.header.model_root:
            return False, "model_root mismatch"
        if proof_root != self.header.proof_root:
            return False, "proof_root mismatch"

        # Producer signature check
        if not verify(self.header.producer_pk, self.header.signing_bytes(), self.header.sig):
            return False, "bad producer signature"

        # PoDL checks 
        evalset_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "data", "evalset", "evalset.jsonl")
        )
        min_score_scaled = 8000  

        for r in self.records:
            if r.lane == Lane.PROOF and r.rtype == ProofType.PODL_LLM_EVAL:
                pobj = unpack(r.payload)
                ok, msg = verify_podl_llm_eval(
                    payload_obj=pobj,
                    evalset_path=evalset_path,
                    required_min_score_scaled=min_score_scaled,
                )
                if not ok:
                    return False, f"PoDL failed: {msg}"

        return True, "ok"