#!/usr/bin/env python3
"""Generate the Crypto challenge artifacts deterministically.

The teaching mistake is password-based stream encryption with a fixed nonce.
Both messages share the same keystream, so C1 xor C2 = P1 xor P2.  The leaked
memo is long enough to expose the flag plaintext.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC = HERE.parent / "public"
FLAG = (HERE / "flag.txt").read_text(encoding="utf-8").strip()
PASSWORD = "Tr0ub4dor&3"
NONCE = b"fixed-nonce-001!"
MEMO = b"MEETING AT DAWN. BRING THE MANUAL AND DESTROY THIS NOTE."


def keystream(password: str, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(password.encode() + nonce + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(out[:length])


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key))


def encrypt(plaintext: bytes) -> bytes:
    return xor(plaintext, keystream(PASSWORD, NONCE, len(plaintext)))


def main() -> None:
    assert len(MEMO) >= len(FLAG), "memo must expose enough keystream"
    payload = {
        "scheme": "sha256-password-stream-v1",
        "nonce": base64.b64encode(NONCE).decode(),
        "ciphertext_flag": base64.b64encode(encrypt(FLAG.encode())).decode(),
        "ciphertext_memo": base64.b64encode(encrypt(MEMO)).decode(),
    }
    PUBLIC.mkdir(parents=True, exist_ok=True)
    (PUBLIC / "ciphertexts.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (PUBLIC / "leaked_memo.txt").write_text(MEMO.decode() + "\n", encoding="utf-8")
    print("wrote", PUBLIC / "ciphertexts.json")
    print("wrote", PUBLIC / "leaked_memo.txt")


if __name__ == "__main__":
    main()
