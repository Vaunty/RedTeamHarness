"""
tests/test_poi_block.py - Tests for PoIBlock and Merkle root calculation.
"""
import uuid
import hashlib
from nacl.signing import SigningKey

from core.poi.record import Lane, PoIRecord, sign_record, scale_score
from core.poi.block import create_block, validate_block, merkle_root


def test_merkle_root_integrity():
    h1 = hashlib.sha256(b"rec1").digest()
    h2 = hashlib.sha256(b"rec2").digest()
    root1 = merkle_root([h1, h2])
    root2 = merkle_root([h1, h2])
    assert root1 == root2, "Merkle root calculation must be deterministic"


def test_block_creation_and_validation():
    sk = SigningKey.generate()
    rec1 = PoIRecord(uuid.uuid4(), "node_1", Lane.DATA, "m1", "t1", scale_score(0.8), "o1")
    rec2 = PoIRecord(uuid.uuid4(), "node_2", Lane.DATA, "m2", "t2", scale_score(0.9), "o2")
    sign_record(rec1, sk)
    sign_record(rec2, sk)

    block = create_block(Lane.DATA, [rec1, rec2], "prev_hash_genesis")
    assert validate_block(block) is True

    # Tampering with record in block must invalidate block
    rec1.claimed_score = scale_score(0.99)
    assert validate_block(block) is False


if __name__ == "__main__":
    test_merkle_root_integrity()
    test_block_creation_and_validation()
    print("All test_poi_block tests passed!")
