#!/usr/bin/env python3
"""Reference solver for the Forensics challenge.

1. Walk the synthesized PCAP (Ethernet / IPv4 / UDP) and select DNS packets.
2. Read the TXT answer for key.exfil.training.test to recover the XOR key.
3. Collect the cNN-<hex> query labels, sort by NN, hex-decode, and XOR with
   the key to recover the flag.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PCAP = HERE / "public" / "capture.pcap"
CHUNK_RE = re.compile(r"^c(\d+)-([0-9a-fA-F]+)\.exfil\.training\.test$")
FLAG_RE = re.compile(rb"flag\{[^}]+\}")


def parse_name(msg: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(msg):
            raise ValueError("truncated DNS name")
        length = msg[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | msg[offset + 1]
            suffix, _ = parse_name(msg, ptr)
            if suffix:
                labels.append(suffix)
            offset += 2
            break
        labels.append(msg[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    return ".".join(labels), offset


def parse_dns(msg: bytes) -> tuple[bool, list[tuple[str, int]], list[tuple[str, bytes]]]:
    if len(msg) < 12:
        return False, [], []
    _txid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
    off = 12
    questions: list[tuple[str, int]] = []
    for _ in range(qd):
        name, off = parse_name(msg, off)
        qtype, _qclass = struct.unpack(">HH", msg[off:off + 4])
        off += 4
        questions.append((name, qtype))
    txts: list[tuple[str, bytes]] = []
    for _ in range(an):
        name, off = parse_name(msg, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        off += rdlen
        if rtype == 16:
            strings = []
            p = 0
            while p < len(rdata):
                n = rdata[p]
                strings.append(rdata[p + 1:p + 1 + n])
                p += 1 + n
            txts.append((name, b"".join(strings)))
    return bool(flags & 0x8000), questions, txts


def dns_payloads(pcap: bytes):
    magic = struct.unpack_from("<I", pcap, 0)[0]
    if magic != 0xA1B2C3D4:
        raise SystemExit("unexpected pcap magic (expected little-endian classic pcap)")
    off = 24
    while off + 16 <= len(pcap):
        _ts, _usec, incl, _orig = struct.unpack_from("<IIII", pcap, off)
        frame = pcap[off + 16:off + 16 + incl]
        off += 16 + incl
        if len(frame) < 14:
            continue
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype != 0x0800:
            continue
        ip_off = 14
        ihl = (frame[ip_off] & 0x0F) * 4
        if len(frame) < ip_off + ihl + 8 or frame[ip_off + 9] != 17:
            continue
        udp_off = ip_off + ihl
        sport, dport, ulen, _ucsum = struct.unpack_from(">HHHH", frame, udp_off)
        if 53 not in (sport, dport):
            continue
        dns = frame[udp_off + 8:udp_off + ulen]
        yield sport, dport, dns


def main() -> None:
    pcap = PCAP.read_bytes()
    queries: list[str] = []
    txts: dict[str, bytes] = {}
    packet_count = 0

    for sport, dport, dns in dns_payloads(pcap):
        packet_count += 1
        is_response, questions, answers = parse_dns(dns)
        if is_response:
            for name, text in answers:
                txts[name] = text
        else:
            for name, _qtype in questions:
                queries.append(name)

    print(f"[1] parsed {packet_count} DNS packets; TXT names: {sorted(txts)}")
    key = b""
    for name, text in txts.items():
        if name.startswith("key."):
            key = text
            break
    if not key:
        raise SystemExit("key TXT record not found")
    print(f"[2] XOR key from TXT record: {key!r}")

    chunks: dict[int, bytes] = {}
    for name in queries:
        m = CHUNK_RE.match(name)
        if m:
            chunks[int(m.group(1))] = bytes.fromhex(m.group(2))
    if not chunks:
        raise SystemExit("no exfil chunks found")
    ordered = b"".join(chunks[k] for k in sorted(chunks))
    plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(ordered))
    print(f"[3] reassembled {len(chunks)} chunks ({len(ordered)} bytes)")
    print(f"    plaintext: {plain!r}")

    match = FLAG_RE.search(plain)
    if not match:
        raise SystemExit("flag not recovered")
    print(f"[+] FLAG: {match.group().decode()}")


if __name__ == "__main__":
    main()
