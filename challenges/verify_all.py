#!/usr/bin/env python3
"""One-click verification for all five local CTF challenges.

For each challenge this script:
  * starts a real service when needed (Web),
  * runs the reference solve.py against the shipped artifacts,
  * compares the recovered flag with instructor/flag.txt,
  * checks that the plaintext flag is not present in public/ student files.

Exit code is 0 only if every challenge passes.
"""
from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FLAG_RE = re.compile(r"flag\{[^}]+\}")


@dataclass
class Result:
    name: str
    ok: bool
    detail: str
    elapsed: float
    stdout: str = ""
    stderr: str = ""


def expected_flag(name: str) -> str:
    return (ROOT / name / "instructor" / "flag.txt").read_text(encoding="utf-8").strip()


def run_solve(name: str, *extra: str, timeout: float = 30.0) -> tuple[int, str, str]:
    cmd = [sys.executable, "solve.py", *extra]
    proc = subprocess.run(
        cmd, cwd=ROOT / name, capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)


def read_line_with_timeout(stream, timeout: float) -> str | None:
    ready, _, _ = select.select([stream.fileno()], [], [], timeout)
    if not ready:
        return None
    line = stream.readline()
    return line.strip() if line else None


def web_solve() -> tuple[int, str, str]:
    server = subprocess.Popen(
        [sys.executable, "instructor/server.py", "--host", "127.0.0.1", "--port", "0"],
        cwd=ROOT / "web",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        line = read_line_with_timeout(server.stdout, 10.0)
        if not line or not line.startswith("LISTENING "):
            err = ""
            if server.poll() is not None:
                err = server.stderr.read()
            raise RuntimeError(f"web server did not announce a port: {line!r} {err}")
        port = line.split()[1]
        return run_solve("web", "--url", f"http://127.0.0.1:{port}")
    finally:
        stop_process(server)


def check_public_leak(name: str, flag: str) -> str:
    public = ROOT / name / "public"
    if not public.is_dir():
        return "public/ missing"
    needle = flag.encode()
    for path in public.rglob("*"):
        if not path.is_file():
            continue
        if needle in path.read_bytes():
            return f"plaintext flag leaked in {path.relative_to(ROOT)}"
    return ""


def verify_one(name: str) -> Result:
    start = time.monotonic()
    try:
        flag = expected_flag(name)
        if name == "web":
            rc, out, err = web_solve()
        else:
            rc, out, err = run_solve(name)
        elapsed = time.monotonic() - start

        leak = check_public_leak(name, flag)
        if leak:
            return Result(name, False, leak, elapsed, out, err)
        if rc != 0:
            return Result(name, False, f"solve.py exited {rc}", elapsed, out, err)
        found = FLAG_RE.findall(out)
        if not found:
            return Result(name, False, "no flag in solver output", elapsed, out, err)
        if found[-1] != flag:
            return Result(name, False, f"flag mismatch: {found[-1]!r} != {flag!r}", elapsed, out, err)
        return Result(name, True, "solver recovered the expected flag", elapsed, out, err)
    except subprocess.TimeoutExpired:
        return Result(name, False, "timeout", time.monotonic() - start)
    except Exception as exc:  # noqa: BLE001 - report any harness failure
        return Result(name, False, f"{type(exc).__name__}: {exc}", time.monotonic() - start)


def main() -> int:
    names = ["web", "crypto", "reverse", "pwn", "forensics"]
    print("=" * 74)
    print("CTF Training Package -- one-click verification")
    print(f"workspace: {ROOT}")
    print(f"python:    {sys.version.split()[0]}")
    print("=" * 74)

    results = [verify_one(name) for name in names]

    print("\n{:<12} {:<6} {:>7}  {}".format("CHALLENGE", "RESULT", "TIME", "DETAIL"))
    print("-" * 74)
    for r in results:
        print("{:<12} {:<6} {:>6.1f}s  {}".format(
            r.name, "PASS" if r.ok else "FAIL", r.elapsed, r.detail,
        ))

    failed = [r for r in results if not r.ok]
    if failed:
        print("\n" + "=" * 74)
        print("FAILURE DETAILS")
        for r in failed:
            print(f"\n--- {r.name} ---")
            if r.stdout:
                print("[stdout]\n" + r.stdout[-4000:])
            if r.stderr:
                print("[stderr]\n" + r.stderr[-4000:])
    print("\n" + "=" * 74)
    print(f"summary: {len(results) - len(failed)}/{len(results)} passed, {len(failed)} failed")
    print("=" * 74)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
