from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hex32(b: bytes) -> str:
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b.hex()

def b32_from_hex(h: str) -> bytes:
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError(f"expected 32-byte hex, got {len(b)} bytes")
    return b

@dataclass(frozen=True)
class KeyPair:
    sk: SigningKey
    vk: VerifyKey

    @staticmethod
    def generate() -> "KeyPair":
        sk = SigningKey.generate()
        return KeyPair(sk=sk, vk=sk.verify_key)

    @staticmethod
    def from_seed(seed32: bytes) -> "KeyPair":
       
        if len(seed32) != 32:
            raise ValueError("seed must be exactly 32 bytes")
        sk = SigningKey(seed32)
        return KeyPair(sk=sk, vk=sk.verify_key)

    def pubkey_bytes(self) -> bytes:
        return bytes(self.vk)

    def sign(self, msg: bytes) -> bytes:
        # Returns the raw 64-byte signature.
        return self.sk.sign(msg).signature

def verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    # Returns True/False 
    try:
        VerifyKey(pubkey).verify(msg, sig)
        return True
    except BadSignatureError:
        return False

def save_sk(path: str, kp: KeyPair) -> None:
    with open(path, "wb") as f:
        f.write(bytes(kp.sk))

def load_kp(sk_path: str) -> KeyPair:
    with open(sk_path, "rb") as f:
        sk_bytes = f.read()
    sk = SigningKey(sk_bytes)
    return KeyPair(sk=sk, vk=sk.verify_key)