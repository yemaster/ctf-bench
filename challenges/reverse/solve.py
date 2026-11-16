#!/usr/bin/env python3
"""Reference solver for the stripped Reverse challenge.

The public checker is stripped, so there is no target_table symbol to read.
The checker's constants are still in .rodata as a tagged license blob:

    uint32 magic;       // 0x5256334c
    uint32 key_len;
    uint32 flag_len;
    uint8  perm[key_len];     // layer 1: byte permutation
    uint8  target[key_len];   // layer 2: chained-XOR target
    uint8  flag_enc[flag_len];

This script locates that blob in the public ELF, inverts both layers to
recover the key, then lets the unmodified binary decode and print the flag.
It does not read instructor/secret.h or instructor/flag.txt.
"""
from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE / "public" / "checker"

MAGIC = 0x5256334C  # blob tag only; the key and flag are not hard-coded
CHAIN_SEED = 0x5A
CHAIN_MUL = 0x1D
CHAIN_ADD = 0x33


def rodata_span(binary: Path) -> tuple[int, int]:
    """Return (file_offset, size) of .rodata."""
    out = subprocess.run(
        ["readelf", "-SW", str(binary)],
        check=True, capture_output=True, text=True,
    ).stdout
    pattern = re.compile(
        r"^\s*\[\s*\d+\]\s+\.rodata\s+\S+\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    for line in out.splitlines():
        m = pattern.match(line)
        if m:
            return int(m.group(2), 16), int(m.group(3), 16)
    raise SystemExit(".rodata section not found")


def find_blob(binary: Path) -> tuple[bytes, bytes, bytes, int, int, int]:
    """Locate and parse the tagged blob; return perm, target, flag_enc, offset, lengths."""
    raw = binary.read_bytes()
    sec_off, sec_size = rodata_span(binary)
    section = raw[sec_off:sec_off + sec_size]
    tag = struct.pack("<I", MAGIC)

    pos = section.find(tag)
    while pos != -1:
        if pos + 12 <= len(section):
            key_len, flag_len = struct.unpack_from("<II", section, pos + 4)
            if 8 <= key_len <= 64 and 8 <= flag_len <= 1024:
                perm_off = pos + 12
                target_off = perm_off + key_len
                flag_off = target_off + key_len
                end = flag_off + flag_len
                if end <= len(section):
                    perm = section[perm_off:target_off]
                    target = section[target_off:flag_off]
                    flag_enc = section[flag_off:end]
                    if sorted(perm) == list(range(key_len)):
                        return perm, target, flag_enc, sec_off + pos, key_len, flag_len
        pos = section.find(tag, pos + 1)
    raise SystemExit("tagged license blob not found in .rodata")


def recover_key(perm: bytes, target: bytes) -> bytes:
    """Invert the adjacent-byte chain, then invert the permutation."""
    key_len = len(target)

    # Layer 2 inverse: p[i] = target[i] ^ prev ^ f(i), prev = p[i-1].
    p = bytearray()
    prev = CHAIN_SEED
    for i, t in enumerate(target):
        v = (t ^ prev ^ ((i * CHAIN_MUL + CHAIN_ADD) & 0xFF)) & 0xFF
        p.append(v)
        prev = v

    # Layer 1 inverse: key[perm[i]] = p[i].
    key = bytearray(key_len)
    seen = [False] * key_len
    for i, target_index in enumerate(perm):
        if target_index >= key_len or seen[target_index]:
            raise SystemExit("invalid permutation in license blob")
        key[target_index] = p[i]
        seen[target_index] = True
    if not all(seen):
        raise SystemExit("permutation does not cover every key byte")
    return bytes(key)


def main() -> None:
    perm, target, flag_enc, blob_file_off, key_len, flag_len = find_blob(BIN)
    print(f"[1] found license blob at file offset 0x{blob_file_off:x} "
          f"(key_len={key_len}, flag_len={flag_len})")
    print(f"    perm:   {perm.hex()}")
    print(f"    target: {target.hex()}")

    key = recover_key(perm, target)
    print(f"[2] recovered key: {key.decode('ascii', errors='replace')!r}")

    # Decode the extracted flag_enc independently of the binary, as a check.
    decoded = bytearray()
    for i, b in enumerate(flag_enc):
        k = (key[i % key_len] * 7 + i * 13 + 0x5A
             + key[(i + 1) % key_len]) & 0xFF
        decoded.append(b ^ k)
    print(f"[3] flag decoded from blob: {decoded.decode('ascii', errors='replace')!r}")

    proc = subprocess.run(
        [str(BIN)], input=key + b"\n", capture_output=True, timeout=10,
    )
    print(f"[4] checker output:\n{proc.stdout.decode(errors='replace').rstrip()}")
    match = re.search(r"flag\{[^}]+\}", proc.stdout.decode(errors="replace"))
    if not match:
        raise SystemExit("checker did not print a flag; recovered key is wrong")
    if match.group().encode() != bytes(decoded):
        raise SystemExit("blob decode and checker output disagree")
    print(f"[+] FLAG: {match.group()}")


if __name__ == "__main__":
    main()
