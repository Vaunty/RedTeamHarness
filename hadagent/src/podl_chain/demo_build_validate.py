from __future__ import annotations

import time

from .crypto import KeyPair, sha256
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
    unpack,
    validate_record,
)


def main() -> None:
    print("=== PoDL blockchain record demo ===")

    node_kp = KeyPair.generate()
    now_ts = int(time.time())

    # 1) DATA record
    raw_data = b"example off-chain dataset bytes"
    content_hash = sha256(raw_data)
    data_id = sha256(b"data-id:" + content_hash)
    policy_hash = sha256(b"owner-only-policy-v1")
    storage_ref = "blob:dataset-001"

    data_msg = pack(
        {
            "data_id": data_id,
            "owner_pk": node_kp.pubkey_bytes(),
            "content_hash": content_hash,
            "policy_hash": policy_hash,
            "storage_ref": storage_ref,
            "ts": now_ts,
        }
    )
    data_sig = node_kp.sign(data_msg)

    data_payload = make_ownership_commit(
        data_id=data_id,
        owner_pk=node_kp.pubkey_bytes(),
        content_hash=content_hash,
        policy_hash=policy_hash,
        storage_ref=storage_ref,
        ts=now_ts,
        sig=data_sig,
    )

    data_rec = Record(
        lane=Lane.DATA,
        rtype=DataType.OWNERSHIP_COMMIT,
        version=1,
        payload=data_payload,
    )

    # 2) MODEL record
    model_bytes = b"mistral-7b-instruct-artifact-placeholder"
    artifact_hash = sha256(model_bytes)
    model_id = "Mistral-7B-Instruct"
    model_storage_ref = "model:mistral-7b-instruct-v1"

    model_msg = pack(
        {
            "model_id": model_id,
            "artifact_hash": artifact_hash,
            "owner_pk": node_kp.pubkey_bytes(),
            "storage_ref": model_storage_ref,
            "ts": now_ts,
        }
    )
    model_sig = node_kp.sign(model_msg)

    model_payload = make_model_commit(
        model_id=model_id,
        artifact_hash=artifact_hash,
        owner_pk=node_kp.pubkey_bytes(),
        storage_ref=model_storage_ref,
        ts=now_ts,
        sig=model_sig,
    )

    model_rec = Record(
        lane=Lane.MODEL,
        rtype=ModelType.MODEL_COMMIT,
        version=1,
        payload=model_payload,
    )

    # 3) PROOF record
    proof_id = sha256(b"proof-001")
    evalset_hash = sha256(b"evalset-placeholder")
    decode_cfg_hash = sha256(b"decode-cfg-placeholder")
    claimed_score_scaled = 9100
    score_scale = 10000
    artifact_ref = ""

    proof_msg = pack(
        {
            "proof_id": proof_id,
            "miner_pk": node_kp.pubkey_bytes(),
            "base_model_id": model_id,
            "provider": "llama.cpp",
            "endpoint": "http://127.0.0.1:8080/completion",
            "evalset_hash": evalset_hash,
            "decode_cfg_hash": decode_cfg_hash,
            "claimed_score_scaled": claimed_score_scaled,
            "score_scale": score_scale,
            "artifact_hash": artifact_hash,
            "artifact_ref": artifact_ref,
            "ts": now_ts,
        }
    )
    proof_sig = node_kp.sign(proof_msg)

    proof_payload = make_podl_llm_eval(
        proof_id=proof_id,
        miner_pk=node_kp.pubkey_bytes(),
        base_model_id=model_id,
        provider="llama.cpp",
        endpoint="http://127.0.0.1:8080/completion",
        evalset_hash=evalset_hash,
        decode_cfg_hash=decode_cfg_hash,
        claimed_score_scaled=claimed_score_scaled,
        score_scale=score_scale,
        artifact_hash=artifact_hash,
        artifact_ref=artifact_ref,
        ts=now_ts,
        sig=proof_sig,
    )

    proof_rec = Record(
        lane=Lane.PROOF,
        rtype=ProofType.PODL_LLM_EVAL,
        version=1,
        payload=proof_payload,
    )

    # Validate all records
    records = [data_rec, model_rec, proof_rec]

    for i, rec in enumerate(records, start=1):
        ok, msg = validate_record(rec)
        print(f"\nRecord {i}: lane={rec.lane}, type={rec.rtype}")
        print("hash:", rec.record_hash().hex())
        print("valid:", ok, "-", msg)

    # Show what is actually stored
    print("\n=== Stored payload examples ===")
    print("DATA payload:")
    print(unpack(data_rec.payload))

    print("\nMODEL payload:")
    print(unpack(model_rec.payload))

    print("\nPROOF payload:")
    print(unpack(proof_rec.payload))

    print("\nDemo complete.")
    print("Raw data is not stored on-chain.")
    print("Only hashes, metadata, and signatures are stored.")


if __name__ == "__main__":
    main()