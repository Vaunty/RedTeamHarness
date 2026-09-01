"""
PoI Consensus Simulation - Blocks.

This module implements Merkle-rooted blocks per lane.
"""
import hashlib
import uuid
import time
from dataclasses import dataclass, field
from typing import List, Optional
from core.poi.record import Lane, PoIRecord, validate_record

def merkle_root(hashes: List[bytes]) -> bytes:
    if not hashes:
        return hashlib.sha256(b"").digest()
    
    current_level = hashes
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = left + right
            next_level.append(hashlib.sha256(combined).digest())
        current_level = next_level
        
    return current_level[0]

@dataclass
class PoIBlock:
    block_id: str
    lane: Lane
    records: List[PoIRecord]
    merkle_root: bytes
    previous_block_hash: str
    timestamp: float = field(default_factory=time.time)

def create_block(lane: Lane, records: List[PoIRecord], previous_hash: str) -> PoIBlock:
    hashes = []
    for r in records:
        h = hashlib.sha256(r.payload_for_signing()).digest()
        hashes.append(h)
        
    root = merkle_root(hashes)
    return PoIBlock(
        block_id=str(uuid.uuid4()),
        lane=lane,
        records=records,
        merkle_root=root,
        previous_block_hash=previous_hash
    )

def validate_block(block: PoIBlock, public_keys: Optional[dict] = None) -> bool:
    hashes = []
    for r in block.records:
        pk = public_keys.get(r.node_id) if isinstance(public_keys, dict) else public_keys
        if not validate_record(r, public_key=pk):
            return False
        h = hashlib.sha256(r.payload_for_signing()).digest()
        hashes.append(h)
        
    expected_root = merkle_root(hashes)
    return block.merkle_root == expected_root

if __name__ == '__main__':
    from core.poi.record import scale_score
    rec1 = PoIRecord(uuid.uuid4(), "node_1", Lane.DATA, "mhash", "eval", scale_score(0.9), "ohash")
    rec2 = PoIRecord(uuid.uuid4(), "node_2", Lane.DATA, "mhash", "eval", scale_score(0.8), "ohash")
    blk = create_block(Lane.DATA, [rec1, rec2], "genesis")
    assert validate_block(blk), "Block validation failed"
    print("block.py self-test passed")
