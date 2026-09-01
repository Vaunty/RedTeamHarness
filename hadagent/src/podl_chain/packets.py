from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class PacketType(str, Enum):
    NEW_DATA_RECORD = "NEW_DATA_RECORD"
    NEW_MODEL_RECORD = "NEW_MODEL_RECORD"
    NEW_PROOF_RECORD = "NEW_PROOF_RECORD"
    POOL_SYNC_REQUEST = "POOL_SYNC_REQUEST"
    POOL_SYNC_RESPONSE = "POOL_SYNC_RESPONSE"
    BLOCK_ANNOUNCE = "BLOCK_ANNOUNCE"
    PING = "PING"
    PONG = "PONG"
    ERROR = "ERROR"


@dataclass
class Packet:
    ptype: PacketType
    sender_id: str
    payload: Dict[str, Any]
    ts: int = field(default_factory=lambda: int(time.time()))
    request_id: Optional[str] = None

    # Serialize packet to JSON bytes with a newline terminator 
    #  Newline-delimited JSON makes socket streaming easier 
    def to_bytes(self) -> bytes:
        
        obj = {
            "ptype": self.ptype.value,
            "sender_id": self.sender_id,
            "payload": self.payload,
            "ts": self.ts,
            "request_id": self.request_id,
        }
        return (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

    @staticmethod
    def from_bytes(raw: bytes) -> "Packet":
        obj = json.loads(raw.decode("utf-8"))
        return Packet(
            ptype=PacketType(obj["ptype"]),
            sender_id=obj["sender_id"],
            payload=obj["payload"],
            ts=int(obj["ts"]),
            request_id=obj.get("request_id"),
        )