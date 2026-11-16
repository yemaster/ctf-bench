#!/usr/bin/env python3
"""Reference solver for the Crypto challenge.

1. The JSON shows both messages were encrypted with the same nonce under a
   password-derived stream cipher.  Therefore:
       C_flag xor C_memo = P_flag xor P_memo
2. The leaked memo is known plaintext, so:
       P_flag = C_flag xor C_memo xor P_memo
No password is required.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLAG_RE = re.compile(rb"flag\{[^}]+\}")


def main() -> None:
    payload = json.loads((HERE / "public" / "ciphertexts.json").read_text(encoding="utf-8"))
    memo = (HERE / "public" / "leaked_memo.txt").read_text(encoding="utf-8").encode()
    ct_flag = base64.b64decode(payload["ciphertext_flag"])
    ct_memo = base64.b64decode(payload["ciphertext_memo"])

    print(f"[1] ciphertext lengths: flag={len(ct_flag)}, memo={len(ct_memo)}, nonce reused={payload['nonce']}")
    xored = bytes(a ^ b for a, b in zip(ct_flag, ct_memo))
    recovered = bytes(a ^ b for a, b in zip(xored, memo))

    print(f"[2] C_flag xor C_memo = {xored.hex()}")
    print(f"    recovered plaintext: {recovered!r}")

    match = FLAG_RE.search(recovered)
    if not match:
        raise SystemExit("flag not recovered; check the leaked memo")
    print(f"[+] FLAG: {match.group().decode()}")


if __name__ == "__main__":
    main()
