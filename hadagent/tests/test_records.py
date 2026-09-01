
### this file test the following 
#loops through the records in each block 
##ensures valid record version pass or fail 
## sennds record payload to correct validator 
## validator checks the schema and signatrue 
## checks invalid records and blocks to ensure rejection , if any are invalid block creation stops immedately 
## if records pass block is created and added to chain

from __future__ import annotations

import time
from datetime import datetime, timezone

from record_create import (
    invalid_block,
    invalid_data_bad_hash_len,
    invalid_data_bad_sig,
    invalid_data_missing_field,
    invalid_model_bad_sig,
    invalid_model_missing_field,
    invalid_proof_bad_hash_len,
    invalid_proof_bad_sig,
    invalid_proof_missing_field,
    valid_block,
    valid_data_record,
    valid_model_record,
    valid_proof_record,
)
from podl_chain.block import Block, BlockHeader
from podl_chain.crypto import sha256
from podl_chain.records import validate_record


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def test_valid_records(case_tracker):
    valid_cases = [
        ("valid_data_record", valid_data_record),
        ("valid_model_record", valid_model_record),
        ("valid_proof_record", valid_proof_record),
    ]

    for name, factory in valid_cases:
        start_ts = utc_now_iso()
        start_perf = time.perf_counter()
        ok, msg = validate_record(factory())

        case_tracker(
            category="record",
            expected="valid",
            actual_passed=ok,
            start_perf=start_perf,
            start_ts=start_ts,
            notes=f"{name}: msg={msg}",
        )

        assert ok is True, f"{name} failed: {msg}"


def test_invalid_records(case_tracker):
    invalid_cases = [
        ("invalid_data_missing_field", invalid_data_missing_field),
        ("invalid_data_bad_hash_len", invalid_data_bad_hash_len),
        ("invalid_data_bad_sig", invalid_data_bad_sig),
        ("invalid_model_missing_field", invalid_model_missing_field),
        ("invalid_model_bad_sig", invalid_model_bad_sig),
        ("invalid_proof_missing_field", invalid_proof_missing_field),
        ("invalid_proof_bad_hash_len", invalid_proof_bad_hash_len),
        ("invalid_proof_bad_sig", invalid_proof_bad_sig),
    ]

    for name, factory in invalid_cases:
        start_ts = utc_now_iso()
        start_perf = time.perf_counter()
        ok, msg = validate_record(factory())

        case_tracker(
            category="record",
            expected="invalid",
            actual_passed=ok,
            start_perf=start_perf,
            start_ts=start_ts,
            notes=f"{name}: msg={msg}",
        )

        assert ok is False, f"{name} unexpectedly passed"


def test_valid_block(monkeypatch, case_tracker):
    import podl_chain.block as block_module

    monkeypatch.setattr(
        block_module,
        "verify_podl_llm_eval",
        lambda payload_obj, evalset_path, required_min_score_scaled: (True, "ok"),
    )

    blk = valid_block()

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = blk.validate(expected_prev=b"\x00" * 32, expected_height=1)

    case_tracker(
        category="block",
        expected="valid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"valid block: msg={msg}",
    )

    assert ok is True, msg


def test_invalid_block(monkeypatch, case_tracker):
    import podl_chain.block as block_module

    monkeypatch.setattr(
        block_module,
        "verify_podl_llm_eval",
        lambda payload_obj, evalset_path, required_min_score_scaled: (True, "ok"),
    )

    blk = invalid_block()

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = blk.validate(expected_prev=b"\x00" * 32, expected_height=1)

    case_tracker(
        category="block",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"invalid block with bad record: msg={msg}",
    )

    assert ok is False


def test_validate_wrong_height(case_tracker):
    empty_root = sha256(b"")

    header = BlockHeader(
        version=1,
        height=5,  # wrong on purpose
        prev_hash=b"abc",
        data_root=empty_root,
        model_root=empty_root,
        proof_root=empty_root,
        ts=0,
        producer_pk=b"",
        sig=b"",
    )
    block = Block(header=header, records=[])

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = block.validate(b"abc", 4)

    case_tracker(
        category="block",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"tampered field=height; msg={msg}",
    )

    assert ok is False
    assert msg == "height mismatch"


def test_validate_wrong_prev_hash(case_tracker):
    empty_root = sha256(b"")

    header = BlockHeader(
        version=1,
        height=4,
        prev_hash=b"bca",  # wrong on purpose
        data_root=empty_root,
        model_root=empty_root,
        proof_root=empty_root,
        ts=0,
        producer_pk=b"",
        sig=b"",
    )
    block = Block(header=header, records=[])

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = block.validate(b"abc", 4)

    case_tracker(
        category="block",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"tampered field=prev_hash; msg={msg}",
    )

    assert ok is False
    assert msg == "prev_hash mismatch"


def test_validate_wrong_data_root(case_tracker):
    empty_root = sha256(b"")

    header = BlockHeader(
        version=1,
        height=4,
        prev_hash=b"abc",
        data_root=b"wrong_data_root",  # wrong on purpose
        model_root=empty_root,
        proof_root=empty_root,
        ts=0,
        producer_pk=b"",
        sig=b"",
    )
    block = Block(header=header, records=[])

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = block.validate(b"abc", 4)

    case_tracker(
        category="block",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"tampered field=Merkle/data root; msg={msg}",
    )

    assert ok is False
    assert msg == "data_root mismatch"


def test_validate_wrong_signature(monkeypatch, case_tracker):
    import podl_chain.block as block_module

    monkeypatch.setattr(
        block_module,
        "verify_podl_llm_eval",
        lambda payload_obj, evalset_path, required_min_score_scaled: (True, "ok"),
    )

    blk = valid_block()

    tampered_header = BlockHeader(
        version=blk.header.version,
        height=blk.header.height,
        prev_hash=blk.header.prev_hash,
        data_root=blk.header.data_root,
        model_root=blk.header.model_root,
        proof_root=blk.header.proof_root,
        ts=blk.header.ts,
        producer_pk=blk.header.producer_pk,
        sig=b"\x00" * 64,  # invalid signature on purpose
    )
    tampered_block = Block(header=tampered_header, records=blk.records)

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = tampered_block.validate(expected_prev=b"\x00" * 32, expected_height=1)

    case_tracker(
        category="block",
        expected="invalid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"tampered field=signature; msg={msg}",
    )

    assert ok is False
    assert "signature" in msg.lower()


def test_two_block_linkage(case_tracker):
    from podl_chain.crypto import KeyPair

    producer = KeyPair.generate()
    empty_root = sha256(b"")

    header1 = BlockHeader(
        version=1,
        height=0,
        prev_hash=b"",
        data_root=empty_root,
        model_root=empty_root,
        proof_root=empty_root,
        ts=0,
        producer_pk=producer.pubkey_bytes(),
        sig=b"",
    )
    sig1 = producer.sign(header1.signing_bytes())
    header1 = BlockHeader(
        version=header1.version,
        height=header1.height,
        prev_hash=header1.prev_hash,
        data_root=header1.data_root,
        model_root=header1.model_root,
        proof_root=header1.proof_root,
        ts=header1.ts,
        producer_pk=header1.producer_pk,
        sig=sig1,
    )
    block1 = Block(header=header1, records=[])

    prev_hash = block1.block_hash()

    header2 = BlockHeader(
        version=1,
        height=1,
        prev_hash=prev_hash,
        data_root=empty_root,
        model_root=empty_root,
        proof_root=empty_root,
        ts=0,
        producer_pk=producer.pubkey_bytes(),
        sig=b"",
    )
    sig2 = producer.sign(header2.signing_bytes())
    header2 = BlockHeader(
        version=header2.version,
        height=header2.height,
        prev_hash=header2.prev_hash,
        data_root=header2.data_root,
        model_root=header2.model_root,
        proof_root=header2.proof_root,
        ts=header2.ts,
        producer_pk=header2.producer_pk,
        sig=sig2,
    )
    block2 = Block(header=header2, records=[])

    start_ts = utc_now_iso()
    start_perf = time.perf_counter()
    ok, msg = block2.validate(prev_hash, 1)

    case_tracker(
        category="block",
        expected="valid",
        actual_passed=ok,
        start_perf=start_perf,
        start_ts=start_ts,
        notes=f"correct block linkage; msg={msg}",
    )

    assert ok is True, msg


def test_scale_validate_1000_valid_records(case_tracker):
    total = 1000

    for i in range(total):
        start_ts = utc_now_iso()
        start_perf = time.perf_counter()

        ok, msg = validate_record(valid_data_record())

        case_tracker(
            category="record",
            expected="valid",
            actual_passed=ok,
            start_perf=start_perf,
            start_ts=start_ts,
            notes=f"scale_record_1000 idx={i} msg={msg}",
        )

        assert ok is True, f"record {i} failed: {msg}"