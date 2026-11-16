#!/usr/bin/env python3
"""End-to-end test for the local CTF benchmark judge.

Runs the judge on 127.0.0.1 only, drives the full TSec-compatible API,
checks flag grading, hint deduction, duplicate handling, artifact isolation
(no instructor files / plaintext flags), the active-instance limit, the
scoreboard and state persistence across a restart.

    python3 test_api.py
"""

from __future__ import annotations

import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import server

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
CHALLENGES = HERE / "challenges"
TOKEN = "test-token-1234567890"

CODES = ("web-01", "crypto-01", "reverse-01", "pwn-01", "forensics-01")
DIRS = {
    "web-01": "web",
    "crypto-01": "crypto",
    "reverse-01": "reverse",
    "pwn-01": "pwn",
    "forensics-01": "forensics",
}
# forensics-01 is solved after reading one hint (0.7 multiplier).
EXPECTED_AWARD = {
    "web-01": 100,
    "crypto-01": 120,
    "reverse-01": 160,
    "pwn-01": 140,
    "forensics-01": 84,
}
EXPECTED_TOTAL = sum(EXPECTED_AWARD.values())  # 604


class Client:
    def __init__(self, base: str, token: str = TOKEN):
        self.base = base.rstrip("/")
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, path: str, body: dict | None = None, token: bool = True):
        request = urllib.request.Request(self.base + path, method=method)
        if body is not None:
            request.data = json.dumps(body).encode("utf-8")
            request.add_header("Content-Type", "application/json")
        if token:
            request.add_header("BENCHMARK_TOKEN", self.token)
        try:
            with self.opener.open(request, timeout=20) as response:
                raw = response.read()
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                data = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                data = {"raw": raw.decode("utf-8", errors="replace")}
            return exc.code, data
        except urllib.error.URLError as exc:
            raise RuntimeError(f"cannot reach judge: {exc}") from None

    def raw(self, url: str) -> tuple[int, bytes]:
        with self.opener.open(url, timeout=20) as response:
            return response.status, response.read()


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(self, condition: bool, name: str, detail: str = "") -> None:
        if condition:
            self.passed += 1
            print(f"[PASS] {name}")
        else:
            self.failed.append(f"{name}: {detail}")
            print(f"[FAIL] {name}  {detail}")

    def summary(self) -> int:
        print("-" * 70)
        if self.failed:
            print(f"summary: {self.passed} passed, {len(self.failed)} failed")
            for item in self.failed:
                print(f"  - {item}")
            return 1
        print(f"summary: {self.passed} passed, 0 failed")
        return 0


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def start_server(port: int, state_file: Path, log_path: Path) -> subprocess.Popen:
    command = [
        sys.executable,
        str(SERVER),
        "--bind",
        "127.0.0.1",
        "--port",
        str(port),
        "--web-bind",
        "127.0.0.1",
        "--web-advertise",
        "127.0.0.1",
        "--challenges-dir",
        str(CHALLENGES),
        "--state-file",
        str(state_file),
        "--token",
        TOKEN,
    ]
    log = open(log_path, "ab")
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )
    log.close()
    return proc


def wait_healthy(base: str, proc: subprocess.Popen, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    client = Client(base)
    last: str = ""
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"judge exited with {proc.returncode}")
        try:
            status, _ = client.call("GET", "/health", token=False)
            if status == 200:
                return
            last = f"status {status}"
        except Exception as exc:  # noqa: BLE001 - retry until healthy
            last = str(exc)
        time.sleep(0.15)
    raise RuntimeError(f"judge did not become healthy ({last})")


def stop_server(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def read_flags() -> dict[str, str]:
    return {
        code: (CHALLENGES / directory / "instructor" / "flag.txt")
        .read_text(encoding="utf-8")
        .strip()
        for code, directory in DIRS.items()
    }


def inspect_artifact(
    checks: Checks, code: str, payload: bytes, flag: str
) -> None:
    checks.check(payload[:2] == b"\x1f\x8b", f"{code}: artifact is gzip", repr(payload[:40]))
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            checks.check(
                any(name.endswith("/challenge.md") for name in names),
                f"{code}: artifact contains challenge.md",
                str(names[:10]),
            )
            checks.check(
                any("/public/" in name for name in names),
                f"{code}: artifact contains public/",
                str(names[:10]),
            )
            forbidden = [
                name
                for name in names
                if "instructor" in name
                or name.endswith("solve.py")
                or "walkthrough" in name
            ]
            checks.check(
                not forbidden,
                f"{code}: no instructor/solver files",
                str(forbidden),
            )
            leaked = []
            for member in members:
                if not member.isfile():
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                if flag.encode() in handle.read():
                    leaked.append(member.name)
            checks.check(
                not leaked,
                f"{code}: no plaintext flag in artifact",
                str(leaked),
            )
    except tarfile.TarError as exc:
        checks.check(False, f"{code}: artifact is a valid tarball", str(exc))


def check_config_extension(checks: Checks) -> None:
    """Validate the manifest and the auto-discovery extension point."""
    try:
        entries = server.load_challenge_config(HERE / "challenges.json", CHALLENGES)
        checks.check(
            len(entries) == 5 and {entry["code"] for entry in entries} == set(CODES),
            "challenges.json loads the five explicit challenges",
            str([entry["code"] for entry in entries]),
        )
    except SystemExit as exc:
        checks.check(False, "challenges.json loads", str(exc))

    ext_dir = Path(tempfile.mkdtemp(prefix="ctf-bench-ext-"))
    try:
        root = ext_dir / "newchal"
        (root / "public").mkdir(parents=True)
        (root / "instructor").mkdir()
        (root / "challenge.md").write_text(
            "# 新题\n\n- **方向**：Web\n- **难度**：难\n- **分值**：250\n",
            encoding="utf-8",
        )
        (root / "public" / "a.txt").write_text("x", encoding="utf-8")
        (root / "instructor" / "flag.txt").write_text("flag{new}", encoding="utf-8")
        (ext_dir / "cfg.json").write_text(
            json.dumps({"auto_discover": True, "challenges": []}), encoding="utf-8"
        )
        discovered = server.load_challenge_config(ext_dir / "cfg.json", ext_dir)
        item = discovered[0] if len(discovered) == 1 else {}
        checks.check(
            len(discovered) == 1
            and item.get("code") == "newchal"
            and item.get("title") == "新题"
            and item.get("category") == "Web"
            and item.get("total_score") == 250
            and item.get("difficulty") == 5
            and item.get("kind") == "artifact",
            "auto-discovery registers a new dir and infers metadata",
            str(
                [
                    (
                        entry.get("code"),
                        entry.get("title"),
                        entry.get("category"),
                        entry.get("total_score"),
                        entry.get("difficulty"),
                        entry.get("kind"),
                    )
                    for entry in discovered
                ]
            ),
        )
        leak_root = ext_dir / "leakchal"
        (leak_root / "instructor").mkdir(parents=True)
        (leak_root / "challenge.md").write_text("# leak\n", encoding="utf-8")
        (leak_root / "instructor" / "flag.txt").write_text(
            "flag{leak}", encoding="utf-8"
        )
        (ext_dir / "cfg2.json").write_text(
            json.dumps(
                {
                    "auto_discover": False,
                    "challenges": [{"dir": "leakchal", "public_dir": "."}],
                }
            ),
            encoding="utf-8",
        )
        try:
            server.load_challenge_config(ext_dir / "cfg2.json", ext_dir)
            checks.check(
                False, "public_dir cannot be the challenge root", "no error raised"
            )
        except SystemExit:
            checks.check(True, "public_dir cannot be the challenge root")
    except Exception as exc:  # noqa: BLE001 - surface as a failed check
        checks.check(False, "auto-discovery", f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(ext_dir, ignore_errors=True)


def check_multi_flag(checks: Checks) -> None:
    """A new challenge may carry several flags (one per line in flag.txt)."""
    workdir = Path(tempfile.mkdtemp(prefix="ctf-bench-multi-"))
    try:
        root = workdir / "multi"
        (root / "public").mkdir(parents=True)
        (root / "instructor").mkdir()
        (root / "challenge.md").write_text(
            "# 多 flag 测试\n\n## 提示\n\n1. 提示一\n", encoding="utf-8"
        )
        (root / "public" / "a.txt").write_text("x", encoding="utf-8")
        (root / "instructor" / "flag.txt").write_text(
            "flag{multi-a}\nflag{multi-b}\n", encoding="utf-8"
        )
        config = workdir / "cfg.json"
        config.write_text(
            json.dumps(
                {
                    "auto_discover": False,
                    "challenges": [
                        {
                            "dir": "multi",
                            "code": "multi-01",
                            "total_score": 100,
                            "kind": "artifact",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        judge = server.Judge(
            challenges_dir=workdir,
            config_path=config,
            state_file=workdir / "state.json",
            base_url="http://127.0.0.1:1",
            bind_host="127.0.0.1",
            web_bind="127.0.0.1",
            web_advertise="127.0.0.1",
            token_arg="multi-test",
            max_active=3,
            hint_ratio=0.7,
            time_limit_minutes=0,
            reset=False,
        )
        try:
            item = judge.list_challenges()[0]
            checks.check(
                item["flag_count"] == 2 and item["is_completed"] is False,
                "multi-flag: flag.txt lines become flag_count",
                str(item["flag_count"]),
            )
            judge.start("multi-01")
            first = judge.submit("multi-01", "flag{multi-a}")
            checks.check(
                first["correct"] is True
                and first["awarded"] == 50
                and first["matched_flag_index"] == 1
                and first["correct_flag_count"] == 1,
                "multi-flag: first flag awards half",
                str(first),
            )
            second = judge.submit("multi-01", "flag{multi-b}")
            checks.check(
                second["correct"] is True
                and second["awarded"] == 100
                and second["matched_flag_index"] == 2
                and second["correct_flag_count"] == 2,
                "multi-flag: second flag completes the score",
                str(second),
            )
            try:
                judge.submit("multi-01", "flag{multi-a}")
                checks.check(False, "multi-flag: duplicate is rejected", "no error")
            except server.ApiError as exc:
                checks.check(
                    exc.status == 409 and exc.code == "duplicate",
                    "multi-flag: duplicate is rejected",
                    f"{exc.status} {exc.code}",
                )
            board = judge.scoreboard()
            checks.check(
                board["total_score"] == 100 and board["completed"] == 1,
                "multi-flag: scoreboard completes",
                str(board["total_score"]),
            )

            # A hint taken between flags retroactively applies the ratio.
            judge.reset()
            judge.hint("multi-01")
            judge.submit("multi-01", "flag{multi-a}")
            final = judge.submit("multi-01", "flag{multi-b}")
            checks.check(
                final["awarded"] == 70 and final["correct_flag_count"] == 2,
                "multi-flag: hint ratio applies to the whole challenge",
                str(final),
            )
        finally:
            judge.shutdown()
    except Exception as exc:  # noqa: BLE001 - surface as a failed check
        checks.check(False, "multi-flag", f"{type(exc).__name__}: {exc}")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    checks = Checks()
    flags = read_flags()
    check_config_extension(checks)
    check_multi_flag(checks)
    workdir = Path(tempfile.mkdtemp(prefix="ctf-bench-test-"))
    state_file = workdir / "state.json"
    log_path = workdir / "judge.log"
    servers: list[subprocess.Popen] = []

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    client = Client(base)

    try:
        proc = start_server(port, state_file, log_path)
        servers.append(proc)
        wait_healthy(base, proc)
        checks.check(True, "judge: health")

        status, data = client.call("GET", "/vpn-check", token=False)
        checks.check(
            status == 200 and data.get("status") == "ok",
            "vpn-check returns status ok",
            f"{status} {data}",
        )

        status, data = client.call("GET", "/openapi/v1/challenges", token=False)
        checks.check(
            status == 404 and data.get("code") == "task_not_found",
            "missing token is rejected with task_not_found",
            f"{status} {data}",
        )

        status, data = client.call("GET", "/openapi/v1/challenges", token=True)
        checks.check(
            status == 200 and isinstance(data, list) and len(data) == 5,
            "challenge list returns 5 items",
            f"{status} {type(data).__name__}",
        )
        by_code = {item["unique_code"]: item for item in data} if isinstance(data, list) else {}
        checks.check(
            set(by_code) == set(CODES),
            "challenge codes are stable",
            str(sorted(by_code)),
        )
        checks.check(
            all("container_addr" not in item for item in by_code.values()),
            "container_addr hidden before start",
            str([item for item in by_code.values() if "container_addr" in item]),
        )
        checks.check(
            all(item["flag_count"] == 1 for item in by_code.values()),
            "each challenge has one flag",
        )
        checks.check(
            all(item["hint_cost_radio"] == 0.7 for item in by_code.values()),
            "hint_cost_radio is 0.7",
        )

        status, web = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=web-01"
        )
        checks.check(
            status == 200 and web.get("container_addr", "").startswith("http://127.0.0.1:"),
            "start web-01 returns a service address",
            f"{status} {web}",
        )
        web_addr = web.get("container_addr", "")
        status, page = client.raw(web_addr + "/") if web_addr else (0, b"")
        checks.check(
            status == 200 and b"<html" in page.lower(),
            "web-01 service is reachable",
            f"{status} {page[:80]!r}",
        )

        status, crypto = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=crypto-01"
        )
        checks.check(
            status == 200 and crypto.get("container_addr", "").endswith(".tar.gz"),
            "start crypto-01 returns an artifact address",
            f"{status} {crypto}",
        )

        status, reverse = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=reverse-01"
        )
        checks.check(status == 200, "start reverse-01", f"{status} {reverse}")

        status, data = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=pwn-01"
        )
        checks.check(
            status == 409
            and data.get("code") == "invalid_state"
            and "max active" in data.get("message", ""),
            "active-instance limit is enforced",
            f"{status} {data}",
        )

        status, _ = client.call(
            "POST", "/openapi/v1/challenges/close?unique_code=crypto-01"
        )
        checks.check(status == 200, "close crypto-01", f"{status}")

        status, pwn = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=pwn-01"
        )
        checks.check(status == 200, "start pwn-01 after a close", f"{status} {pwn}")

        status, _ = client.call(
            "POST", "/openapi/v1/challenges/close?unique_code=reverse-01"
        )
        checks.check(status == 200, "close reverse-01", f"{status}")

        status, forensics = client.call(
            "POST", "/openapi/v1/challenges/start?unique_code=forensics-01"
        )
        checks.check(status == 200, "start forensics-01", f"{status} {forensics}")

        artifact_addrs = {
            "crypto-01": crypto.get("container_addr", ""),
            "reverse-01": reverse.get("container_addr", ""),
            "pwn-01": pwn.get("container_addr", ""),
            "forensics-01": forensics.get("container_addr", ""),
        }
        for code, address in artifact_addrs.items():
            status, payload = client.raw(address)
            checks.check(status == 200, f"{code}: artifact download", f"{status}")
            inspect_artifact(checks, code, payload, flags[code])

        status, hint = client.call(
            "GET", "/openapi/v1/challenges/hint?unique_code=forensics-01"
        )
        checks.check(
            status == 200 and hint.get("hint") and hint.get("hint_cost_radio") == 0.7,
            "hint endpoint returns text and cost ratio",
            f"{status} {hint}",
        )

        status, wrong = client.call(
            "POST",
            "/openapi/v1/challenges/submit",
            {"unique_code": "pwn-01", "flag": "flag{definitely-not-the-flag}"},
        )
        checks.check(
            status == 200 and wrong.get("correct") is False and wrong.get("awarded") == 0,
            "wrong flag is graded as incorrect",
            f"{status} {wrong}",
        )

        status, unicode_wrong = client.call(
            "POST",
            "/openapi/v1/challenges/submit",
            {"unique_code": "web-01", "flag": "flag{这不是flag}"},
        )
        checks.check(
            status == 200 and unicode_wrong.get("correct") is False,
            "non-ASCII flag is graded as incorrect, not a 500",
            f"{status} {unicode_wrong}",
        )

        for code in CODES:
            status, result = client.call(
                "POST",
                "/openapi/v1/challenges/submit",
                {"unique_code": code, "flag": flags[code]},
            )
            checks.check(
                status == 200
                and result.get("correct") is True
                and result.get("awarded") == EXPECTED_AWARD[code],
                f"{code}: correct flag and score",
                f"{status} {result}",
            )

        status, duplicate = client.call(
            "POST",
            "/openapi/v1/challenges/submit",
            {"unique_code": "forensics-01", "flag": flags["forensics-01"]},
        )
        checks.check(
            status == 409 and duplicate.get("code") == "duplicate",
            "duplicate correct submit returns 409 duplicate",
            f"{status} {duplicate}",
        )

        status, data = client.call(
            "GET", "/openapi/v1/challenges/hint?unique_code=forensics-01"
        )
        checks.check(
            status == 409 and data.get("code") == "invalid_state",
            "hint after completion returns 409 invalid_state",
            f"{status} {data}",
        )

        status, board = client.call("GET", "/scoreboard", token=False)
        checks.check(
            status == 200
            and board.get("total_score") == EXPECTED_TOTAL
            and board.get("max_score") == 640
            and board.get("completed") == 5,
            "scoreboard totals are correct",
            f"{status} {board.get('total_score')} {board.get('completed')}",
        )
        serialized = json.dumps(board, ensure_ascii=False)
        checks.check(
            not any(flag in serialized for flag in flags.values()),
            "scoreboard does not leak flags",
        )

        status, items = client.call("GET", "/openapi/v1/challenges")
        checks.check(
            status == 200 and all(item["is_completed"] for item in items),
            "all challenges report completed",
            f"{status}",
        )

        for code in CODES:
            client.call("POST", f"/openapi/v1/challenges/close?unique_code={code}")
        status, items = client.call("GET", "/openapi/v1/challenges")
        checks.check(
            status == 200
            and all(item["container_status"] == "stopped" for item in items),
            "close releases every instance",
            str([item["container_status"] for item in items]),
        )

        # --- persistence across restart ---
        stop_server(proc)
        servers.remove(proc)
        port2 = free_port()
        base2 = f"http://127.0.0.1:{port2}"
        client2 = Client(base2)
        proc2 = start_server(port2, state_file, log_path)
        servers.append(proc2)
        wait_healthy(base2, proc2)
        status, board2 = client2.call("GET", "/scoreboard", token=False)
        checks.check(
            status == 200
            and board2.get("total_score") == EXPECTED_TOTAL
            and board2.get("completed") == 5
            and board2.get("task_id") == board.get("task_id"),
            "state and token persist across restart",
            f"{status} {board2.get('total_score')} {board2.get('task_id')}",
        )
        status, items2 = client2.call("GET", "/openapi/v1/challenges")
        checks.check(
            status == 200
            and all(item["container_status"] == "stopped" for item in items2),
            "restart does not restore dead instances",
            str([item["container_status"] for item in items2]),
        )

        status, reset = client2.call("POST", "/openapi/v1/admin/reset")
        status2, board3 = client2.call("GET", "/scoreboard", token=False)
        checks.check(
            status == 200
            and reset.get("reset") is True
            and status2 == 200
            and board3.get("total_score") == 0
            and board3.get("completed") == 0,
            "admin reset clears scores",
            f"{status} {status2} {board3.get('total_score')}",
        )

    except Exception as exc:  # noqa: BLE001 - report and show the log
        checks.check(False, "test harness", f"{type(exc).__name__}: {exc}")
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = ""
        if tail:
            print("\n--- judge log (tail) ---")
            print(tail)
    finally:
        for proc in servers:
            stop_server(proc)

    result = checks.summary()
    if result == 0:
        for path in workdir.iterdir():
            try:
                path.unlink()
            except OSError:
                pass
        try:
            workdir.rmdir()
        except OSError:
            pass
    else:
        print(f"artifacts kept at: {workdir}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
