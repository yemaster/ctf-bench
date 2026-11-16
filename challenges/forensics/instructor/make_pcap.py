#!/usr/bin/env python3
"""Synthesize a small, self-contained DNS exfiltration PCAP.

Captured traffic (all synthetic):
  * a TXT lookup/answer for key.exfil.training.test carries the XOR key;
  * A queries cNN-<hex>.exfil.training.test carry shuffled flag chunks;
  * a few ordinary DNS lookups are mixed in as noise.

The resulting capture is consumed by ../solve.py using only the standard
library (no scapy/dpkt required).
"""
from __future__ import annotations

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC = HERE.parent / "public"
FLAG = (HERE / "flag.txt").read_text(encoding="utf-8").strip().encode()
KEY = b"s3cr3tK3y!"
DOMAIN = "exfil.training.test"
SENSOR = "10.10.4.5"
RESOLVER = "10.10.4.53"
SRC_MAC = bytes.fromhex("020000000005")
DST_MAC = bytes.fromhex("020000000053")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        raw = label.encode()
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def dns_query(txid: int, name: str, qtype: int) -> bytes:
    return (
        struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        + dns_name(name)
        + struct.pack(">HH", qtype, 1)
    )


def dns_txt_response(txid: int, name: str, text: bytes) -> bytes:
    question = dns_name(name) + struct.pack(">HH", 16, 1)
    rdata = bytes([len(text)]) + text
    answer = (
        b"\xc0\x0c"  # pointer to question name at offset 12
        + struct.pack(">HHIH", 16, 1, 60, len(rdata))
        + rdata
    )
    return struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def udp_ip_eth(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    src_b = bytes(map(int, src.split(".")))
    dst_b = bytes(map(int, dst.split(".")))
    total_len = 20 + len(udp)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0x4000, 64, 17, 0, src_b, dst_b,
    )
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    eth = DST_MAC + SRC_MAC + struct.pack(">H", 0x0800)
    return eth + ip + udp


def main() -> None:
    # XOR the flag byte-by-byte with the repeating key, then hex-encode it and
    # split the hex stream into 12-character (6-byte) labels.
    stream = bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(FLAG)).hex()
    encoded = [
        (idx + 1, stream[i:i + 12])
        for idx, i in enumerate(range(0, len(stream), 12))
    ]
    # Shuffle transmission order to force sequence-number reassembly.
    order = sorted(range(len(encoded)), key=lambda i: (i * 3 + 1) % len(encoded))

    packets: list[bytes] = []
    txid = 0x4100
    ts = 1_700_000_000

    # Noise: ordinary lookups.
    for name, qtype in [("www.training.test", 1), ("mail.training.test", 1), ("vpn.training.test", 1)]:
        txid += 1
        packets.append(udp_ip_eth(SENSOR, RESOLVER, 40000 + txid % 1000, 53, dns_query(txid, name, qtype), txid))
        ts += 1

    # The key is delivered in a TXT answer.
    txid += 1
    key_name = "key." + DOMAIN
    packets.append(udp_ip_eth(SENSOR, RESOLVER, 41001, 53, dns_query(txid, key_name, 16), txid))
    ts += 1
    packets.append(udp_ip_eth(RESOLVER, SENSOR, 53, 41001, dns_txt_response(txid, key_name, KEY), txid))
    ts += 1

    # A harmless TXT lookup as a decoy.
    txid += 1
    packets.append(udp_ip_eth(SENSOR, RESOLVER, 41002, 53, dns_query(txid, "notes.training.test", 16), txid))
    ts += 1
    packets.append(udp_ip_eth(RESOLVER, SENSOR, 53, 41002, dns_txt_response(txid, "notes.training.test", b"maintenance window"), txid))
    ts += 1

    # Flag chunks leave in A-query labels, out of order.
    for pos in order:
        seq, hex_chunk = encoded[pos]
        name = f"c{seq:02d}-{hex_chunk}.{DOMAIN}"
        txid += 1
        packets.append(udp_ip_eth(SENSOR, RESOLVER, 42000 + seq, 53, dns_query(txid, name, 1), txid))
        ts += 1

    pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, pkt in enumerate(packets):
        pcap.extend(struct.pack("<IIII", ts + i, i * 1000, len(pkt), len(pkt)))
        pcap.extend(pkt)

    PUBLIC.mkdir(parents=True, exist_ok=True)
    out = PUBLIC / "capture.pcap"
    out.write_bytes(pcap)
    print(f"wrote {out} ({len(pcap)} bytes, {len(packets)} packets)")
    print(f"key={KEY.decode()} chunks={[e[0] for e in encoded]}")


if __name__ == "__main__":
    main()
