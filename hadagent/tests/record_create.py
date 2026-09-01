## this file creates the invalid and valid records for testing that way i do not have to create it in the main test file
#rather calling each variable that needs to be tested from this file 
#TEST STEPS 1 

from __future__ import annotations

import time
from typing import Iterable

from podl_chain.crypto import KeyPair, sha256
from podl_chain.records import (
    Record,
    Lane,
    DataType,
    ModelType,
    ProofType,
    pack,
    unpack,
    make_ownership_commit,
    make_model_commit,
    make_podl_llm_eval,
)
from podl_chain.block import Block, BlockHeader




def now() -> int:
    return int(time.time())

## creating fake signature 
def bad_sig() -> bytes:
    return b"\x00" * 64

## new key pair 
def kp() -> KeyPair:
    return KeyPair.generate()

## this willl test the missing feilds by unpacking the payload and repacking it 
def _edit_payload(payload: bytes, *, remove: str | None = None, **replace) -> bytes:
    obj = unpack(payload)
    if remove:
        obj.pop(remove, None)
    obj.update(replace)
    return pack(obj)


## these records are valid it helps me ensure that the functions are working as needed to be 
## testing its designs to do its actual function 


## valid record 
def valid_data_record(keypair: KeyPair | None = None) -> Record:
    keypair = keypair or kp()
    ts = now()
    data_id = sha256(b"data-1")
    content_hash = sha256(b"raw-data-off-chain")
    policy_hash = sha256(b"policy-1")
    storage_ref = "ipfs://data-1"

    msg = pack({
        "data_id": data_id,
        "owner_pk": keypair.pubkey_bytes(),
        "content_hash": content_hash,
        "policy_hash": policy_hash,
        "storage_ref": storage_ref,
        "ts": ts,
    })
    sig = keypair.sign(msg)

    return Record(
        lane=Lane.DATA,
        rtype=DataType.OWNERSHIP_COMMIT,
        version=1,
        payload=make_ownership_commit(
            data_id=data_id,
            owner_pk=keypair.pubkey_bytes(),
            content_hash=content_hash,
            policy_hash=policy_hash,
            storage_ref=storage_ref,
            ts=ts,
            sig=sig,
        ),
    )

## valid model
def valid_model_record(keypair: KeyPair | None = None) -> Record:
    keypair = keypair or kp()
    ts = now()
    model_id = "model-1"
    artifact_hash = sha256(b"model-bytes-off-chain")
    storage_ref = "s3://models/model-1"

    msg = pack({
        "model_id": model_id,
        "artifact_hash": artifact_hash,
        "owner_pk": keypair.pubkey_bytes(),
        "storage_ref": storage_ref,
        "ts": ts,
    })
    sig = keypair.sign(msg)

    return Record(
        lane=Lane.MODEL,
        rtype=ModelType.MODEL_COMMIT,
        version=1,
        payload=make_model_commit(
            model_id=model_id,
            artifact_hash=artifact_hash,
            owner_pk=keypair.pubkey_bytes(),
            storage_ref=storage_ref,
            ts=ts,
            sig=sig,
        ),
    )

## valid proof 
def valid_proof_record(keypair: KeyPair | None = None) -> Record:
    keypair = keypair or kp()
    ts = now()
    proof_id = sha256(b"proof-1")
    evalset_hash = sha256(b"evalset-1")
    decode_cfg_hash = sha256(b"decode-cfg-1")
    artifact_hash = sha256(b"proof-artifact-1")

    msg = pack({
        "proof_id": proof_id,
        "miner_pk": keypair.pubkey_bytes(),
        "base_model_id": "model-1",
        "provider": "openai",
        "endpoint": "https://example.test/eval",
        "evalset_hash": evalset_hash,
        "decode_cfg_hash": decode_cfg_hash,
        "claimed_score_scaled": 9500,
        "score_scale": 10000,
        "artifact_hash": artifact_hash,
        "artifact_ref": "ipfs://proof-1",
        "ts": ts,
    })
    sig = keypair.sign(msg)

    return Record(
        lane=Lane.PROOF,
        rtype=ProofType.PODL_LLM_EVAL,
        version=1,
        payload=make_podl_llm_eval(
            proof_id=proof_id,
            miner_pk=keypair.pubkey_bytes(),
            base_model_id="model-1",
            provider="openai",
            endpoint="https://example.test/eval",
            evalset_hash=evalset_hash,
            decode_cfg_hash=decode_cfg_hash,
            claimed_score_scaled=9500,
            score_scale=10000,
            artifact_hash=artifact_hash,
            artifact_ref="ipfs://proof-1",
            ts=ts,
            sig=sig,
        ),
    )


### these buildings create invalid functions to tes if program can catch mistakes 

## invalid missing feilds in record 
def invalid_data_missing_field() -> Record:
    rec = valid_data_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, remove="content_hash"))

## bad hash 
def invalid_data_bad_hash_len() -> Record:
    rec = valid_data_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, content_hash=b"x" * 16))

## bad signature 
def invalid_data_bad_sig() -> Record:
    rec = valid_data_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, sig=bad_sig()))

### missing feilds 
def invalid_model_missing_field() -> Record:
    rec = valid_model_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, remove="artifact_hash"))


def invalid_model_bad_sig() -> Record:
    rec = valid_model_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, sig=bad_sig()))


def invalid_proof_missing_field() -> Record:
    rec = valid_proof_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, remove="evalset_hash"))


def invalid_proof_bad_hash_len() -> Record:
    rec = valid_proof_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, proof_id=b"x" * 16))


def invalid_proof_bad_sig() -> Record:
    rec = valid_proof_record()
    return Record(rec.lane, rec.rtype, rec.version, _edit_payload(rec.payload, sig=bad_sig()))



## block building functions 
## building the blocks that hold the invalid and valid records to test 
def valid_records() -> list[Record]:
    keypair = kp()
    return [
        valid_data_record(keypair),
        valid_model_record(keypair),
        valid_proof_record(keypair),
    ]


def invalid_records() -> list[Record]:
    return [
        invalid_data_bad_sig(),
        invalid_model_missing_field(),
        invalid_proof_bad_hash_len(),
    ]


def build_block(records: Iterable[Record], *, height: int = 1, prev_hash: bytes = b"\x00" * 32,
                producer: KeyPair | None = None) -> Block:
    producer = producer or kp()
    records = list(records)
    data_root, model_root, proof_root = Block.compute_lane_roots(records)
    ts = now()

    header = BlockHeader(
        version=1,
        height=height,
        prev_hash=prev_hash,
        data_root=data_root,
        model_root=model_root,
        proof_root=proof_root,
        ts=ts,
        producer_pk=producer.pubkey_bytes(),
        sig=b"",
    )
    sig = producer.sign(header.signing_bytes())
    header = BlockHeader(
        version=header.version,
        height=header.height,
        prev_hash=header.prev_hash,
        data_root=header.data_root,
        model_root=header.model_root,
        proof_root=header.proof_root,
        ts=header.ts,
        producer_pk=header.producer_pk,
        sig=sig,
    )
    return Block(header=header, records=records)


def valid_block() -> Block:
    return build_block(valid_records())


def invalid_block() -> Block:
    return build_block(invalid_records())