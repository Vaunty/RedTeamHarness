from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Dict, Tuple

import msgpack
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from .crypto import sha256

#  Canonical binary encoding for consensus objects
def pack(obj: Dict[str, Any]) -> bytes:
    
    return msgpack.packb(obj, use_bin_type=True, strict_types=True)

# Decode consensus object
def unpack(blob: bytes) -> Dict[str, Any]:
   
    return msgpack.unpackb(blob, raw=False)


class Lane(IntEnum):
    DATA = 1
    MODEL = 2
    PROOF = 3


class DataType(IntEnum):
    OWNERSHIP_COMMIT = 1


class ModelType(IntEnum):
    MODEL_COMMIT = 1


class ProofType(IntEnum):
    PODL_LLM_EVAL = 1


@dataclass(frozen=True)
class Record:
    lane: int
    rtype: int
    version: int
    payload: bytes

    def to_bytes(self) -> bytes:
        return pack(
            {
                "lane": int(self.lane),
                "rtype": int(self.rtype),
                "version": int(self.version),
                "payload": self.payload,
            }
        )

    @staticmethod
    def from_bytes(blob: bytes) -> "Record":
        obj = unpack(blob)
        return Record(
            lane=int(obj["lane"]),
            rtype=int(obj["rtype"]),
            version=int(obj["version"]),
            payload=obj["payload"],
        )

    # Hash the full record envelope, not just the payload 
    def record_hash(self) -> bytes:

        return sha256(self.to_bytes())

def _verify_sig(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        vk = VerifyKey(pubkey)
        vk.verify(msg, sig)
        return True
    except BadSignatureError:
        return False


def make_ownership_commit(
    data_id: bytes,
    owner_pk: bytes,
    content_hash: bytes,
    policy_hash: bytes,
    storage_ref: str,
    ts: int,
    sig: bytes,
) -> bytes:
    return pack(
        {
            "data_id": data_id,
            "owner_pk": owner_pk,
            "content_hash": content_hash,
            "policy_hash": policy_hash,
            "storage_ref": storage_ref,
            "ts": ts,
            "sig": sig,
        }
    )


def make_model_commit(
    model_id: str,
    artifact_hash: bytes,
    owner_pk: bytes,
    storage_ref: str,
    ts: int,
    sig: bytes,
) -> bytes:
    return pack(
        {
            "model_id": model_id,
            "artifact_hash": artifact_hash,
            "owner_pk": owner_pk,
            "storage_ref": storage_ref,
            "ts": ts,
            "sig": sig,
        }
    )


def make_podl_llm_eval(
    proof_id: bytes,
    miner_pk: bytes,
    base_model_id: str,
    provider: str,
    endpoint: str,
    evalset_hash: bytes,
    decode_cfg_hash: bytes,
    claimed_score_scaled: int,
    score_scale: int,
    artifact_hash: bytes,
    artifact_ref: str,
    ts: int,
    sig: bytes,
) -> bytes:
    return pack(
        {
            "proof_id": proof_id,
            "miner_pk": miner_pk,
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
            "sig": sig,
        }
    )


def _validate_ownership_commit(payload: bytes) -> Tuple[bool, str]:
    obj = unpack(payload)

    required = [
        "data_id",
        "owner_pk",
        "content_hash",
        "policy_hash",
        "storage_ref",
        "ts",
        "sig",
    ]
    for k in required:
        if k not in obj:
            return False, f"missing field: {k}"

    if len(obj["data_id"]) != 32:
        return False, "data_id must be 32 bytes"
    if len(obj["owner_pk"]) != 32:
        return False, "owner_pk must be 32 bytes"
    if len(obj["content_hash"]) != 32:
        return False, "content_hash must be 32 bytes"
    if len(obj["policy_hash"]) != 32:
        return False, "policy_hash must be 32 bytes"
    if not isinstance(obj["storage_ref"], str):
        return False, "storage_ref must be a string"
    if not isinstance(obj["ts"], int):
        return False, "ts must be an int"

    msg = pack(
        {
            "data_id": obj["data_id"],
            "owner_pk": obj["owner_pk"],
            "content_hash": obj["content_hash"],
            "policy_hash": obj["policy_hash"],
            "storage_ref": obj["storage_ref"],
            "ts": obj["ts"],
        }
    )

    if not _verify_sig(obj["owner_pk"], msg, obj["sig"]):
        return False, "invalid ownership signature"

    return True, "ok"


def _validate_model_commit(payload: bytes) -> Tuple[bool, str]:
    obj = unpack(payload)

    required = [
        "model_id",
        "artifact_hash",
        "owner_pk",
        "storage_ref",
        "ts",
        "sig",
    ]
    for k in required:
        if k not in obj:
            return False, f"missing field: {k}"

    if not isinstance(obj["model_id"], str):
        return False, "model_id must be a string"
    if len(obj["artifact_hash"]) != 32:
        return False, "artifact_hash must be 32 bytes"
    if len(obj["owner_pk"]) != 32:
        return False, "owner_pk must be 32 bytes"
    if not isinstance(obj["storage_ref"], str):
        return False, "storage_ref must be a string"
    if not isinstance(obj["ts"], int):
        return False, "ts must be an int"

    msg = pack(
        {
            "model_id": obj["model_id"],
            "artifact_hash": obj["artifact_hash"],
            "owner_pk": obj["owner_pk"],
            "storage_ref": obj["storage_ref"],
            "ts": obj["ts"],
        }
    )

    if not _verify_sig(obj["owner_pk"], msg, obj["sig"]):
        return False, "invalid model signature"

    return True, "ok"


def _validate_podl_llm_eval(payload: bytes) -> Tuple[bool, str]:
    obj = unpack(payload)

    required = [
        "proof_id",
        "miner_pk",
        "base_model_id",
        "provider",
        "endpoint",
        "evalset_hash",
        "decode_cfg_hash",
        "claimed_score_scaled",
        "score_scale",
        "artifact_hash",
        "artifact_ref",
        "ts",
        "sig",
    ]
    for k in required:
        if k not in obj:
            return False, f"missing field: {k}"

    if len(obj["proof_id"]) != 32:
        return False, "proof_id must be 32 bytes"
    if len(obj["miner_pk"]) != 32:
        return False, "miner_pk must be 32 bytes"
    if len(obj["evalset_hash"]) != 32:
        return False, "evalset_hash must be 32 bytes"
    if len(obj["decode_cfg_hash"]) != 32:
        return False, "decode_cfg_hash must be 32 bytes"
    if len(obj["artifact_hash"]) != 32:
        return False, "artifact_hash must be 32 bytes"
    if not isinstance(obj["base_model_id"], str):
        return False, "base_model_id must be a string"
    if not isinstance(obj["provider"], str):
        return False, "provider must be a string"
    if not isinstance(obj["endpoint"], str):
        return False, "endpoint must be a string"
    if not isinstance(obj["claimed_score_scaled"], int):
        return False, "claimed_score_scaled must be an int"
    if not isinstance(obj["score_scale"], int):
        return False, "score_scale must be an int"
    if not isinstance(obj["artifact_ref"], str):
        return False, "artifact_ref must be a string"
    if not isinstance(obj["ts"], int):
        return False, "ts must be an int"

    msg = pack(
        {
            "proof_id": obj["proof_id"],
            "miner_pk": obj["miner_pk"],
            "base_model_id": obj["base_model_id"],
            "provider": obj["provider"],
            "endpoint": obj["endpoint"],
            "evalset_hash": obj["evalset_hash"],
            "decode_cfg_hash": obj["decode_cfg_hash"],
            "claimed_score_scaled": obj["claimed_score_scaled"],
            "score_scale": obj["score_scale"],
            "artifact_hash": obj["artifact_hash"],
            "artifact_ref": obj["artifact_ref"],
            "ts": obj["ts"],
        }
    )

    if not _verify_sig(obj["miner_pk"], msg, obj["sig"]):
        return False, "invalid PoDL signature"

    return True, "ok"

#  Basic schema + signature validation 
def validate_record(rec: Record) -> Tuple[bool, str]:
   
    if rec.version != 1:
        return False, f"unsupported record version: {rec.version}"

    if rec.lane == Lane.DATA and rec.rtype == DataType.OWNERSHIP_COMMIT:
        return _validate_ownership_commit(rec.payload)

    if rec.lane == Lane.MODEL and rec.rtype == ModelType.MODEL_COMMIT:
        return _validate_model_commit(rec.payload)

    if rec.lane == Lane.PROOF and rec.rtype == ProofType.PODL_LLM_EVAL:
        return _validate_podl_llm_eval(rec.payload)

    return False, f"unknown record type: lane={rec.lane} rtype={rec.rtype}"