"""
tests/test_poi_record.py - Tests for PoIRecord, Ed25519 signing, and tuple-bug reproduction.
"""
import uuid
import hashlib
from nacl.signing import SigningKey

from core.poi.record import (
    Lane, PoIRecord, sign_record, verify_signature,
    validate_record, validate_record_schema, scale_score
)
import core.poi.record as record_mod


def test_record_signing_and_verification():
    sk = SigningKey.generate()
    vk = sk.verify_key

    rec = PoIRecord(
        record_id=uuid.uuid4(),
        node_id="node_1",
        lane=Lane.PROOF,
        model_hash=hashlib.sha256(b"mistral").hexdigest(),
        eval_task_id="task_mmlu_01",
        claimed_score=scale_score(0.85),
        raw_output_hash=hashlib.sha256(b"output").hexdigest()
    )
    
    assert rec.signature is None
    sign_record(rec, sk)
    assert rec.signature is not None
    assert verify_signature(rec, vk) is True


def test_signature_tampering_detected():
    sk = SigningKey.generate()
    vk = sk.verify_key

    rec = PoIRecord(
        record_id=uuid.uuid4(),
        node_id="node_1",
        lane=Lane.PROOF,
        model_hash=hashlib.sha256(b"mistral").hexdigest(),
        eval_task_id="task_mmlu_01",
        claimed_score=scale_score(0.85),
        raw_output_hash=hashlib.sha256(b"output").hexdigest()
    )
    sign_record(rec, sk)
    # Tamper with the claimed score
    rec.claimed_score = scale_score(0.99)
    assert verify_signature(rec, vk) is False


def test_tuple_bug_reproduction():
    """
    Verifies the historical HadAgent tuple bug:
    In legacy validation, returning (False, 'bad sig') was evaluated as truthy,
    causing invalid records to pass validation. In fixed mode, it properly returns False.
    """
    sk = SigningKey.generate()
    vk = sk.verify_key

    # Corrupt record with invalid signature
    bad_rec = PoIRecord(
        record_id=uuid.uuid4(),
        node_id="bad_node",
        lane=Lane.PROOF,
        model_hash=hashlib.sha256(b"mistral").hexdigest(),
        eval_task_id="task_mmlu_01",
        claimed_score=scale_score(0.85),
        raw_output_hash=hashlib.sha256(b"output").hexdigest(),
        signature=b"\x00" * 64
    )

    # 1. Under LEGACY_VALIDATION (tuple bug active)
    record_mod.LEGACY_VALIDATION = True
    assert validate_record(bad_rec, vk) is True, "Tuple bug should cause invalid record to evaluate as True"

    # 2. Under FIXED validation
    record_mod.LEGACY_VALIDATION = False
    assert validate_record(bad_rec, vk) is False, "Fixed validation must reject invalid signature"


if __name__ == "__main__":
    test_record_signing_and_verification()
    test_signature_tampering_detected()
    test_tuple_bug_reproduction()
    print("All test_poi_record tests passed!")
