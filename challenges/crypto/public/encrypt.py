#!/usr/bin/env python3
"""The (flawed) stream-cipher construction used for the challenge.

This file is handed to students so they can reason about the construction.
The password is NOT included.  The important property is that the keystream
depends only on (password, nonce, counter): reusing a nonce reuses the stream.
"""
from __future__ import annotations

import hashlib


def keystream(password: str, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(password.encode() + nonce + counter.to_bytes(4, "big")).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt(password: str, nonce: bytes, plaintext: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(plaintext, keystream(password, nonce, len(plaintext))))


def decrypt(password: str, nonce: bytes, ciphertext: bytes) -> bytes:
    return encrypt(password, nonce, ciphertext)


if __name__ == "__main__":
    # Demonstration bytes only; not the challenge messages.
    nonce = b"demo-nonce-0000!"
    ct = encrypt("demo-password", nonce, b"hello stream cipher")
    print(ct.hex())
