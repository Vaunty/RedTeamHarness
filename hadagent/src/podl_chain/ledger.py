from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Optional
from .block import Block

GENESIS_PREV = b"\x00" * 32

@dataclass
class Ledger:
    chain_dir: str

    def __post_init__(self) -> None:
        os.makedirs(self.chain_dir, exist_ok=True)

    def _path(self, height: int) -> str:
        return os.path.join(self.chain_dir, f"{height:016d}.block")

    def height(self) -> int:
        files = sorted(f for f in os.listdir(self.chain_dir) if f.endswith(".block"))
        if not files:
            return -1
        return int(files[-1].split(".")[0])

    def last_block(self) -> Optional[Block]:
        h = self.height()
        if h < 0:
            return None
        with open(self._path(h), "rb") as f:
            return Block.from_bytes(f.read())

    def last_hash(self) -> bytes:
        b = self.last_block()
        return GENESIS_PREV if b is None else b.block_hash()

    def append(self, block: Block) -> tuple[bool, str]:
        expected_height = self.height() + 1
        expected_prev = self.last_hash()

        ok, msg = block.validate(expected_prev, expected_height)
        if not ok:
            return False, msg

        with open(self._path(block.header.height), "wb") as f:
            f.write(block.to_bytes())
        return True, "appended"