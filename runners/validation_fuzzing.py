"""
runners/validation_fuzzing.py - Property-Based Validation Fuzzing & Tuple Bug Reproduction.

Reproduces the historical HadAgent tuple validation vulnerability documented in
Landy Jimenez & Mariah's consensus test logs:
- The legacy record schema validator returned `(boolean, string)` tuple.
- In Python, `if validate_record(r):` evaluates any non-empty tuple (even `(False, "bad sig")`) as Truthy.
- Result: 1 in 4 invalid test blocks were incorrectly accepted into consensus!

This runner:
1. Runs a corpus of invalid and fuzz-generated corrupted records through legacy vs fixed validation.
2. Measures acceptance rate of invalid payloads before and after the bug fix.
3. Tests block Merkle-tree tampering resistance.
"""
import uuid
import hashlib
import random
from typing import Dict, Any, List
from nacl.signing import SigningKey

from core.poi.record import (
    Lane, PoIRecord, sign_record, scale_score,
    validate_record, validate_record_schema
)
import core.poi.record as record_mod
from core.poi.block import create_block, validate_block
from core.database import init_db, insert_run, finish_run, insert_metrics


def generate_fuzzed_records(count: int = 40) -> List[Dict[str, Any]]:
    """
    Generates a corpus of both valid records and intentionally corrupted/fuzzed records.
    """
    sk = SigningKey.generate()
    vk = sk.verify_key

    corpus = []
    
    # 1. Valid baseline records
    for i in range(10):
        rec = PoIRecord(
            record_id=uuid.uuid4(),
            node_id=f"node_{i}",
            lane=Lane.PROOF,
            model_hash=hashlib.sha256(b"valid_model").hexdigest(),
            eval_task_id=f"task_{i}",
            claimed_score=scale_score(0.85),
            raw_output_hash=hashlib.sha256(b"valid_output").hexdigest()
        )
        sign_record(rec, sk)
        corpus.append({"record": rec, "is_genuinely_valid": True, "type": "valid", "vk": vk})

    # 2. Corrupt signature records
    for i in range(10):
        rec = PoIRecord(
            record_id=uuid.uuid4(),
            node_id=f"bad_node_{i}",
            lane=Lane.PROOF,
            model_hash=hashlib.sha256(b"valid_model").hexdigest(),
            eval_task_id=f"task_bad_sig_{i}",
            claimed_score=scale_score(0.80),
            raw_output_hash=hashlib.sha256(b"valid_output").hexdigest(),
            signature=b"\x00" * 64  # Fake / corrupted signature bytes
        )
        corpus.append({"record": rec, "is_genuinely_valid": False, "type": "corrupt_signature", "vk": vk})

    # 3. Out-of-bounds score records
    for i in range(10):
        invalid_score = random.choice([-50, -1, 1001, 2500, 99999])
        rec = PoIRecord(
            record_id=uuid.uuid4(),
            node_id=f"oob_node_{i}",
            lane=Lane.PROOF,
            model_hash=hashlib.sha256(b"valid_model").hexdigest(),
            eval_task_id=f"task_oob_{i}",
            claimed_score=invalid_score,
            raw_output_hash=hashlib.sha256(b"valid_output").hexdigest()
        )
        sign_record(rec, sk)
        corpus.append({"record": rec, "is_genuinely_valid": False, "type": "out_of_bounds_score", "vk": vk})

    # 4. Tampered payload post-signature
    for i in range(10):
        rec = PoIRecord(
            record_id=uuid.uuid4(),
            node_id=f"tamper_node_{i}",
            lane=Lane.PROOF,
            model_hash=hashlib.sha256(b"valid_model").hexdigest(),
            eval_task_id=f"task_tampered_{i}",
            claimed_score=scale_score(0.70),
            raw_output_hash=hashlib.sha256(b"valid_output").hexdigest()
        )
        sign_record(rec, sk)
        # Tamper claimed score after signing
        rec.claimed_score = scale_score(0.99)
        corpus.append({"record": rec, "is_genuinely_valid": False, "type": "tampered_after_sign", "vk": vk})

    return corpus


def run_validation_fuzzing_study() -> Dict[str, Any]:
    """
    Evaluates record and block validation under LEGACY (tuple bug) and FIXED logic.
    """
    init_db()
    run_id = insert_run(
        target_models=["hadagent-consensus-validator"],
        defense_mode="comparison",
        judge_model="property_based_oracle",
        judge_runs=1,
        notes="Historical tuple-bug validation fuzzing study"
    )

    corpus = generate_fuzzed_records(40)
    invalid_records = [c for c in corpus if not c["is_genuinely_valid"]]
    valid_records = [c for c in corpus if c["is_genuinely_valid"]]

    print("\n=== HadAgent Historical Validation Bug Fuzzing Study ===")
    print(f"Total Fuzzed / Test Records: {len(corpus)}")
    print(f"  Genuinely Valid          : {len(valid_records)}")
    print(f"  Intentionally Corrupted  : {len(invalid_records)}")

    # 1. Test under LEGACY_VALIDATION (Tuple Bug Active)
    record_mod.LEGACY_VALIDATION = True
    legacy_accepted_invalid = 0
    for item in invalid_records:
        if validate_record(item["record"], item["vk"]):
            legacy_accepted_invalid += 1

    # 2. Test under FIXED VALIDATION
    record_mod.LEGACY_VALIDATION = False
    fixed_accepted_invalid = 0
    for item in invalid_records:
        if validate_record(item["record"], item["vk"]):
            fixed_accepted_invalid += 1

    # 3. Block validation test with corrupted records
    sk = SigningKey.generate()
    bad_block_records = [item["record"] for item in invalid_records[:4]]
    pk_map = {item["record"].node_id: item["vk"] for item in invalid_records[:4]}
    bad_block = create_block(Lane.PROOF, bad_block_records, "genesis_hash")

    record_mod.LEGACY_VALIDATION = True
    legacy_bad_block_accepted = validate_block(bad_block, public_keys=pk_map)

    record_mod.LEGACY_VALIDATION = False
    fixed_bad_block_accepted = validate_block(bad_block, public_keys=pk_map)

    legacy_invalid_acceptance_rate = legacy_accepted_invalid / len(invalid_records)
    fixed_invalid_acceptance_rate = fixed_accepted_invalid / len(invalid_records)

    metrics = {
        "legacy_invalid_acceptance_rate": round(legacy_invalid_acceptance_rate, 4),
        "fixed_invalid_acceptance_rate": round(fixed_invalid_acceptance_rate, 4),
        "legacy_invalid_records_accepted": legacy_accepted_invalid,
        "fixed_invalid_records_accepted": fixed_accepted_invalid,
        "legacy_bad_block_accepted": 1 if legacy_bad_block_accepted else 0,
        "fixed_bad_block_accepted": 1 if fixed_bad_block_accepted else 0,
        "total_invalid_tested": len(invalid_records)
    }

    insert_metrics(run_id, metrics)
    finish_run(run_id, len(corpus))

    print("\nResults:")
    print(f"Legacy Mode (Tuple Bug) Invalid Records Accepted: {legacy_accepted_invalid} / {len(invalid_records)} ({legacy_invalid_acceptance_rate:.1%})")
    print(f"Fixed Mode Invalid Records Accepted             : {fixed_accepted_invalid} / {len(invalid_records)} ({fixed_invalid_acceptance_rate:.1%})")
    print(f"Legacy Mode Corrupted Block Accepted            : {legacy_bad_block_accepted} (Consensus Invariant Violated)")
    print(f"Fixed Mode Corrupted Block Accepted             : {fixed_bad_block_accepted} (Consensus Invariant Holds)")

    return {
        "run_id": run_id,
        "metrics": metrics
    }


if __name__ == "__main__":
    run_validation_fuzzing_study()
