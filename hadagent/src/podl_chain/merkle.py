from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
from .crypto import sha256

def _parent(left: bytes, right: bytes) -> bytes:
    return sha256(left + right)

# Merkle root
# empty list => sha256(b"")
# if odd count, duplicate the last leaf
# parents are sha256(left || right)
def merkle_root(leaves: List[bytes]) -> bytes:
 
    if not leaves:
        return sha256(b"")

    # Normalize: if someone passes raw data, hash it once into 32 bytes
    level = [x if len(x) == 32 else sha256(x) for x in leaves]

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_parent(level[i], level[i + 1]))
        level = nxt

    return level[0]

@dataclass(frozen=True)
class MerkleProof:
    # sibling hashes going up the tree
    siblings: List[bytes]
    # True means current node was on the left at that level
    left_flags: List[bool]

# Builds a proof for one leaf
def merkle_proof(leaves: List[bytes], index: int) -> MerkleProof:
  
    if index < 0 or index >= len(leaves):
        raise IndexError("leaf index out of range")
    if not leaves:
        raise ValueError("no leaves")

    level = [x if len(x) == 32 else sha256(x) for x in leaves]
    idx = index
    siblings: List[bytes] = []
    left_flags: List[bool] = []

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        is_left = (idx % 2 == 0)
        sib_idx = idx + 1 if is_left else idx - 1

        siblings.append(level[sib_idx])
        left_flags.append(is_left)

        # move up
        idx = idx // 2

        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_parent(level[i], level[i + 1]))
        level = nxt

    return MerkleProof(siblings=siblings, left_flags=left_flags)

def verify_merkle_proof(leaf: bytes, root: bytes, proof: MerkleProof) -> bool:
    cur = leaf if len(leaf) == 32 else sha256(leaf)

    for sib, is_left in zip(proof.siblings, proof.left_flags):
        if is_left:
            cur = _parent(cur, sib)
        else:
            cur = _parent(sib, cur)

    return cur == root