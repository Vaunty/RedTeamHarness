"""
PoI Consensus Simulation - Records.

This module implements the base Proof-of-Inference (PoI) record structure,
including the three-lane design (DATA, MODEL, PROOF) and Ed25519 signing.
Includes the historical 'tuple bug' in validation.
"""
import hashlib
import json
import uuid
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

class Lane(Enum):
    DATA = "DATA"
    MODEL = "MODEL"
    PROOF = "PROOF"

@dataclass
class PoIRecord:
    record_id: uuid.UUID
    node_id: str
    lane: Lane
    model_hash: str
    eval_task_id: str
    claimed_score: int
    raw_output_hash: str
    signature: Optional[bytes] = None
    timestamp: float = field(default_factory=time.time)

    def payload_for_signing(self) -> bytes:
        payload = {
            "record_id": str(self.record_id),
            "node_id": self.node_id,
            "lane": self.lane.value,
            "model_hash": self.model_hash,
            "eval_task_id": self.eval_task_id,
            "claimed_score": self.claimed_score,
            "raw_output_hash": self.raw_output_hash,
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

def sign_record(record: PoIRecord, private_key: SigningKey) -> PoIRecord:
    payload = record.payload_for_signing()
    signed = private_key.sign(payload)
    record.signature = signed.signature
    return record

def verify_signature(record: PoIRecord, public_key: VerifyKey) -> bool:
    if not record.signature:
        return False
    try:
        payload = record.payload_for_signing()
        public_key.verify(payload, record.signature)
        return True
    except BadSignatureError:
        return False

# Module-level flag to toggle the historical HadAgent tuple bug
LEGACY_VALIDATION = False

def validate_record_schema(record: PoIRecord, public_key: Optional[VerifyKey] = None) -> tuple[bool, str]:
    """
    Checks record schema, signature, and score bounds.
    Returns (is_valid, reason).
    """
    if public_key is not None and record.signature is not None:
        if not verify_signature(record, public_key):
            return False, "bad signature"
    elif record.signature is None and public_key is not None:
        return False, "missing signature"
        
    if not (0 <= record.claimed_score <= 1000):
        return False, "claimed_score out of bounds [0, 1000]"
        
    return True, "valid"

def validate_record(record: PoIRecord, public_key: Optional[VerifyKey] = None) -> bool:
    """
    Validates a PoIRecord.
    In LEGACY_VALIDATION mode, this reproduces the tuple bug from HadAgent
    where the caller evaluated `if validate_record_schema(r):`, which in Python
    treats any non-empty tuple like `(False, 'bad signature')` as Truthy!
    """
    schema_res = validate_record_schema(record, public_key)
    if LEGACY_VALIDATION:
        # Tuple bug: (False, "bad signature") evaluated directly as a condition in `if validate_record_schema(...)`
        return bool(schema_res)
    else:
        return schema_res[0]

def scale_score(accuracy: float) -> int:
    return int(accuracy * 1000)

if __name__ == '__main__':
    # Self-test
    sk = SigningKey.generate()
    vk = sk.verify_key
    
    rec = PoIRecord(
        record_id=uuid.uuid4(),
        node_id="node_1",
        lane=Lane.PROOF,
        model_hash=hashlib.sha256(b"model").hexdigest(),
        eval_task_id="task_1",
        claimed_score=scale_score(0.85),
        raw_output_hash=hashlib.sha256(b"output").hexdigest()
    )
    sign_record(rec, sk)
    assert validate_record(rec, vk), "Validation failed"
    print("record.py self-test passed")
