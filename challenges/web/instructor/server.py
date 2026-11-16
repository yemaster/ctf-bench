#!/usr/bin/env python3
"""Toy storefront for the Web challenge.

Intentionally vulnerable business logic:
  * a staff promo code is hidden (base64) in the public JavaScript;
  * the promo unlocks a hidden VIP SKU;
  * the order total is computed as price * qty without rejecting negative qty,
    and the only balance check is "total > balance".

The flag is read from instructor/flag.txt at startup. It is never placed in
public/ and never served to users who have not completed the order.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent.parent
PUBLIC = BASE / "public"
FLAG_FILE = Path(__file__).resolve().parent / "flag.txt"

STAFF_CODE = "STAFF-2024"
FLAG = FLAG_FILE.read_text(encoding="utf-8").strip()

PUBLIC_PRODUCTS = [
    {"id": 1, "name": "Sticker Pack", "price": 800, "kind": "merch"},
    {"id": 2, "name": "CTF Handbook", "price": 2500, "kind": "book"},
    {"id": 3, "name": "Coffee Mug", "price": 1500, "kind": "merch"},
]
VIP_PRODUCT = {"id": 99, "name": "Flag License", "price": 99900, "kind": "vip"}

USERS: dict[str, dict] = {}
ORDERS: list[dict] = []


class Handler(BaseHTTPRequestHandler):
    server_version = "TrainingShop/1.0"
    protocol_version = "HTTP/1.1"

    # ---------- helpers ----------
    def _send(self, status: int, payload: dict | bytes, content_type: str = "application/json") -> None:
        if isinstance(payload, dict):
            body = json.dumps(payload, separators=(",", ":")).encode()
        else:
            body = payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > 4096:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def _user(self) -> dict | None:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        return USERS.get(auth[7:].strip())

    def _require_user(self) -> dict | None:
        user = self._user()
        if user is None:
            self._send(401, {"ok": False, "error": "login required"})
        return user

    # ---------- static files ----------
    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/":
            path = "/index.html"
        if path.startswith("/static/"):
            rel = path[len("/static/"):]
            candidate = (PUBLIC / rel).resolve()
            try:
                candidate.relative_to(PUBLIC.resolve())
            except ValueError:
                self._send(404, {"ok": False, "error": "not found"})
                return
            if candidate.is_file():
                ctype = {
                    ".html": "text/html; charset=utf-8",
                    ".js": "text/javascript; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                }.get(candidate.suffix, "application/octet-stream")
                self._send(200, candidate.read_bytes(), ctype)
            else:
                self._send(404, {"ok": False, "error": "not found"})
            return
        if path == "/index.html":
            index = PUBLIC / "index.html"
            if index.is_file():
                self._send(200, index.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, {"ok": False, "error": "not found"})
            return
        if path == "/api/products":
            user = self._require_user()
            if user is None:
                return
            items = list(PUBLIC_PRODUCTS)
            if user["vip"]:
                items.append(VIP_PRODUCT)
            self._send(200, {"ok": True, "balance": user["balance"], "products": items})
            return
        self._send(404, {"ok": False, "error": "not found"})

    # ---------- API ----------
    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        try:
            data = self._json_body()
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"ok": False, "error": "invalid JSON body"})
            return

        if path == "/api/login":
            name = str(data.get("name", "guest"))[:32] or "guest"
            token = secrets.token_urlsafe(24)
            USERS[token] = {"name": name, "vip": False, "balance": 5000}
            self._send(200, {"ok": True, "token": token, "balance": 5000})
            return

        if path == "/api/redeem":
            user = self._require_user()
            if user is None:
                return
            code = str(data.get("code", ""))
            if code != STAFF_CODE:
                self._send(403, {"ok": False, "error": "invalid promo code"})
                return
            user["vip"] = True
            self._send(200, {"ok": True, "vip": True, "message": "staff pricing enabled"})
            return

        if path == "/api/order":
            user = self._require_user()
            if user is None:
                return
            try:
                product_id = int(data["product_id"])
                qty = int(data["qty"])
            except (KeyError, TypeError, ValueError):
                self._send(400, {"ok": False, "error": "product_id and qty are required integers"})
                return
            if isinstance(data.get("qty"), bool) or qty == 0:
                self._send(400, {"ok": False, "error": "qty must be a non-zero integer"})
                return
            catalog = {p["id"]: p for p in PUBLIC_PRODUCTS}
            product = catalog.get(product_id)
            if product is None and product_id == VIP_PRODUCT["id"]:
                if not user["vip"]:
                    self._send(403, {"ok": False, "error": "VIP product is not available"})
                    return
                product = VIP_PRODUCT
            if product is None:
                self._send(404, {"ok": False, "error": "unknown product"})
                return

            # Deliberate logic flaw: no qty > 0 validation, and a negative total
            # always satisfies "total <= balance".
            total = product["price"] * qty
            if total > user["balance"]:
                self._send(402, {"ok": False, "error": "insufficient balance", "total": total})
                return
            user["balance"] -= total
            order = {
                "order_id": len(ORDERS) + 1,
                "product": product["name"],
                "qty": qty,
                "total": total,
            }
            ORDERS.append(order)
            response = {"ok": True, **order, "balance": user["balance"]}
            if product_id == VIP_PRODUCT["id"]:
                response["flag"] = FLAG
            self._send(200, response)
            return

        self._send(404, {"ok": False, "error": "not found"})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[web] %s - %s\n" % (self.address_string(), fmt % args))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = Server((args.host, args.port), Handler)
    print(f"LISTENING {srv.server_address[1]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
