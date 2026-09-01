from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional

@dataclass
class PoolItem:
    item_id: str
    lane: str
    rtype: str
    payload: dict
    ts: int

# in-memory pool for pending AI-related records
# This pool stores only metadata / hashes / signed records
# Raw datasets or raw model artifacts should remain off-chain 
class AIPool:
   
    def __init__(self, max_items: int = 10000) -> None:
        self.max_items = max_items
        self._items: Dict[str, PoolItem] = {}
        self._lock = asyncio.Lock()

    async def add(self, item: PoolItem) -> bool:
        async with self._lock:
            if item.item_id in self._items:
                return False

            if len(self._items) >= self.max_items:
                # Drop the oldest item if the pool is full.
                oldest_key = min(self._items, key=lambda k: self._items[k].ts)
                self._items.pop(oldest_key, None)

            self._items[item.item_id] = item
            return True

    async def get(self, item_id: str) -> Optional[PoolItem]:
        async with self._lock:
            return self._items.get(item_id)

    async def remove(self, item_id: str) -> None:
        async with self._lock:
            self._items.pop(item_id, None)

    async def list_all(self) -> List[PoolItem]:
        async with self._lock:
            return list(self._items.values())

    async def list_by_lane(self, lane: str) -> List[PoolItem]:
        async with self._lock:
            return [x for x in self._items.values() if x.lane == lane]

    async def pop_for_block(self, limit: int = 100) -> List[PoolItem]:
        """
        This takes the oldest records first.
        We can maybe replace this with score-based or priority-based selection.
        """
        async with self._lock:
            ordered = sorted(self._items.values(), key=lambda x: x.ts)
            selected = ordered[:limit]
            for item in selected:
                self._items.pop(item.item_id, None)
            return selected

    async def cleanup_expired(self, max_age_seconds: int, now_ts: int) -> int:
        async with self._lock:
            expired = [k for k, v in self._items.items() if now_ts - v.ts > max_age_seconds]
            for k in expired:
                self._items.pop(k, None)
            return len(expired)