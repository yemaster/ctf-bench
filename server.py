#!/usr/bin/env python3
"""Local CTF benchmark judge for an in-repo challenge package.

This service exposes the subset of the TSec benchmark API that Qiming's
``tsec-benchmark`` skill drives, backed by the challenges in ``challenges/``:

    GET  /openapi/v1/challenges
    POST /openapi/v1/challenges/start?unique_code=<code>
    GET  /openapi/v1/challenges/hint?unique_code=<code>
    POST /openapi/v1/challenges/submit      {"unique_code": ..., "flag": ...}
    POST /openapi/v1/challenges/close?unique_code=<code>

Extra local endpoints:

    GET  /vpn-check           VPN pre-flight probe used by the skill
    GET  /scoreboard          JSON scoreboard
    GET  /                    small HTML scoreboard
    GET  /artifact/<code>.tar.gz
    GET  /health
    POST /openapi/v1/admin/reset

All ``/openapi/v1/*`` calls require ``BENCHMARK_TOKEN: <token>``.  The
artifact tarballs are deliberately token-free because the master agent must
not pass the token to its sub-agents.

Only ``challenge.md`` and ``public/**`` are ever served; ``instructor/``
(flags, walkthroughs) and ``solve.py`` never leave the host.
"""

from __future__ import annotations

import argparse
import html
import io
import json
import os
import re
import secrets
import select
import signal
import subprocess
import sys
import tarfile
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
DEFAULT_CHALLENGES_DIR = HERE / "challenges"
DEFAULT_NETWORK = "qiming_default"
DEFAULT_FALLBACK_GATEWAY = "172.18.0.1"
VERSION = "1.0.0"

DEFAULT_CONFIG_FILE = HERE / "challenges.json"

DEFAULT_PLATFORM_NOTES = {
    "service": (
        "本实例是一个独立的服务。目标地址以 start 接口返回的 "
        "container_addr 为准；不要访问题面里示例的 127.0.0.1:8080。"
    ),
    "artifact": (
        "本实例没有网络服务。start 返回的 container_addr 是附件包 "
        "tar.gz 的下载地址；下载解压后，题面中的 public/ 就是解压目录下的 public/。"
    ),
}

# Defaults for a "service" challenge.  A new service challenge normally only
# needs ``instructor/server.py`` accepting --host/--port and printing
# ``LISTENING <port>``; anything else can be overridden in challenges.json.
DEFAULT_SERVICE = {
    "script": "instructor/server.py",
    "host_arg": "--host",
    "port_arg": "--port",
    "port": 0,
    "ready_regex": r"^LISTENING\s+(\d+)\s*$",
    "timeout": 12.0,
}

DIFFICULTY_LABELS = {
    "简单": 1,
    "入门": 1,
    "easy": 1,
    "中等": 2,
    "medium": 2,
    "中等偏难": 3,
    "较难": 4,
    "困难": 5,
    "难": 5,
    "hard": 5,
}

MAX_ACTIVE_DEFAULT = 3
HINT_RATIO_DEFAULT = 0.7
MAX_BODY_BYTES = 64 * 1024
MAX_FLAG_LEN = 4096


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_hints(markdown: str) -> list[str]:
    """Extract the numbered items under the ``## 提示`` section."""
    lines = markdown.splitlines()
    start = None
    for index, line in enumerate(lines):
        stripped = line.strip().lower()
        if stripped.startswith("## 提示") or stripped.startswith("## hint"):
            start = index + 1
            break
    if start is None:
        return []

    hints: list[str] = []
    current: str | None = None
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("## "):
            break
        match = re.match(r"^\d+[.)]\s+(.*)$", stripped)
        if match:
            if current is not None:
                hints.append(" ".join(current.split()))
            current = match.group(1)
        elif current is not None and line[:1] in (" ", "\t") and stripped:
            current += " " + stripped
    if current is not None:
        hints.append(" ".join(current.split()))
    return hints


def detect_docker_gateway(network: str) -> str | None:
    try:
        result = subprocess.run(
            [
                "docker",
                "network",
                "inspect",
                network,
                "--format",
                "{{(index .IPAM.Config 0).Gateway}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


# ---------------------------------------------------------------------------
# challenge configuration
# ---------------------------------------------------------------------------


def _as_index_list(value: object) -> list[int]:
    result: set[int] = set()
    if isinstance(value, (list, tuple)):
        for item in value:
            try:
                number = int(item)
            except (TypeError, ValueError):
                continue
            if number >= 1:
                result.add(number)
    return sorted(result)


def _read_json_file(path: Path, what: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SystemExit(f"cannot read {what} {path}: {exc}") from None
    except ValueError as exc:
        raise SystemExit(f"invalid JSON in {what} {path}: {exc}") from None
    if not isinstance(data, dict):
        raise SystemExit(f"{what} {path} must contain a JSON object")
    return data


def _difficulty_value(label: str) -> int:
    lowered = label.strip().lower()
    for key in sorted(DIFFICULTY_LABELS, key=len, reverse=True):
        if key in lowered:
            return DIFFICULTY_LABELS[key]
    return 3


def infer_metadata(challenge_root: Path) -> dict:
    """Best-effort metadata from challenge.md for auto-discovered challenges."""
    markdown = ""
    try:
        markdown = (challenge_root / "challenge.md").read_text(encoding="utf-8")
    except OSError:
        pass

    title = challenge_root.name
    for line in markdown.splitlines():
        if line.startswith("# "):
            title = line[2:].strip() or title
            break

    category = "Misc"
    match = re.search(r"方向\**\s*[:：]\s*([A-Za-z][A-Za-z0-9+ /_-]*)", markdown)
    if match:
        category = match.group(1).strip()

    total_score = 100
    match = re.search(r"分值\**\s*[:：]\s*(\d+)", markdown)
    if match:
        total_score = int(match.group(1))

    difficulty = 3
    match = re.search(r"难度\**\s*[:：]\s*([^\n]+)", markdown)
    if match:
        difficulty = _difficulty_value(match.group(1))

    return {
        "title": title,
        "category": category,
        "difficulty": difficulty,
        "level": difficulty,
        "total_score": total_score,
    }


def _resolve_root(raw: dict, challenges_dir: Path) -> Path:
    value = raw.get("dir") or raw.get("path") or raw.get("code")
    if not value:
        raise SystemExit("challenge entry needs at least a 'dir' or 'code'")
    root = Path(str(value)).expanduser()
    if not root.is_absolute():
        root = challenges_dir / root
    return root.resolve()


def _under(root: Path, value: str | None, default: str, label: str) -> Path:
    path = Path(str(value or default)).expanduser()
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    root = root.resolve()
    if path != root and root not in path.parents:
        raise SystemExit(f"{label} must stay inside {root}: {path}")
    if not path.is_file():
        raise SystemExit(f"{label} does not exist or is not a file: {path}")
    return path


def normalise_entry(merged: dict, root: Path) -> dict:
    inferred = infer_metadata(root)
    code = str(merged.get("code") or root.name)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", code):
        raise SystemExit(
            f"invalid challenge code {code!r}: use letters, digits, dot, dash, underscore"
        )
    if not root.is_dir():
        raise SystemExit(f"challenge directory does not exist: {root}")

    kind = str(merged.get("kind") or ("service" if (root / "instructor" / "server.py").is_file() else "artifact")).lower()
    if kind not in ("service", "artifact"):
        raise SystemExit(f"{code}: kind must be 'service' or 'artifact', got {kind!r}")

    challenge_path = _under(root, merged.get("challenge_file"), "challenge.md", f"{code}: challenge_file")
    flag_path = _under(root, merged.get("flag_file"), "instructor/flag.txt", f"{code}: flag_file")

    public_value = merged.get("public_dir", "public")
    public_path: Path | None = None
    if public_value:
        candidate = Path(str(public_value)).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        candidate = candidate.resolve()
        if candidate.is_dir():
            if root not in candidate.parents and candidate != root:
                raise SystemExit(f"{code}: public_dir must stay inside {root}: {candidate}")
            if candidate == root:
                raise SystemExit(
                    f"{code}: public_dir must be a subdirectory, not the challenge root"
                )
            public_path = candidate
        elif "public_dir" in merged:
            raise SystemExit(f"{code}: public_dir does not exist: {candidate}")

    try:
        total_score = int(merged.get("total_score", inferred["total_score"]))
        difficulty = int(merged.get("difficulty", inferred["difficulty"]))
        level = int(merged.get("level", inferred["level"]))
    except (TypeError, ValueError):
        raise SystemExit(
            f"{code}: total_score/difficulty/level must be integers"
        ) from None
    if total_score <= 0:
        raise SystemExit(f"{code}: total_score must be positive")

    flag_count_raw = merged.get("flag_count")
    if flag_count_raw is None:
        flag_count: int | None = None  # derived from the non-empty lines in flag_file
    else:
        try:
            flag_count = int(flag_count_raw)
        except (TypeError, ValueError):
            raise SystemExit(f"{code}: flag_count must be an integer") from None
        if flag_count < 1:
            raise SystemExit(f"{code}: flag_count must be >= 1")

    ratio_value = merged.get("hint_ratio")
    if ratio_value is None:
        hint_ratio: float | None = None
    else:
        try:
            hint_ratio = float(ratio_value)
        except (TypeError, ValueError):
            raise SystemExit(f"{code}: hint_ratio must be a number") from None
        hint_ratio = min(1.0, max(0.0, hint_ratio))

    service = None
    if kind == "service":
        service = dict(DEFAULT_SERVICE)
        raw_service = merged.get("service")
        if raw_service is not None:
            if not isinstance(raw_service, dict):
                raise SystemExit(f"{code}: service must be a JSON object")
            service.update(raw_service)
        script = Path(str(service["script"])).expanduser()
        if not script.is_absolute():
            script = root / script
        script = script.resolve()
        if root not in script.parents and script != root:
            raise SystemExit(f"{code}: service.script must stay inside {root}: {script}")
        if not script.is_file():
            raise SystemExit(f"{code}: service script does not exist: {script}")
        service["script_path"] = str(script)
        try:
            service["port"] = int(service.get("port", 0))
            service["timeout"] = float(service.get("timeout", 12.0))
        except (TypeError, ValueError):
            raise SystemExit(f"{code}: service.port/timeout must be numeric") from None
        try:
            pattern = re.compile(str(service.get("ready_regex") or DEFAULT_SERVICE["ready_regex"]))
        except re.error as exc:
            raise SystemExit(f"{code}: invalid service.ready_regex: {exc}") from None
        if pattern.groups < 1:
            raise SystemExit(f"{code}: service.ready_regex needs a capture group for the port")
        service["ready_regex_compiled"] = pattern

    return {
        "code": code,
        "dir": root.name,
        "root": root,
        "title": str(merged.get("title") or inferred["title"]),
        "category": str(merged.get("category") or inferred["category"]),
        "difficulty": difficulty,
        "level": level,
        "total_score": total_score,
        "kind": kind,
        "flag_count": flag_count,
        "hint_ratio": hint_ratio,
        "platform_note": str(merged.get("platform_note") or DEFAULT_PLATFORM_NOTES[kind]),
        "challenge_path": challenge_path,
        "flag_path": flag_path,
        "public_path": public_path,
        "service": service,
    }


def load_challenge_config(config_path: Path, challenges_dir: Path) -> list[dict]:
    """Load challenges from a JSON manifest, optionally auto-discovering dirs.

    Adding a challenge:
      1. create ``<challenges-dir>/<newdir>/challenge.md``,
         ``<newdir>/public/`` and ``<newdir>/instructor/flag.txt``;
      2. with ``"auto_discover": true`` (the shipped default) it is picked up
         automatically, with title/category/score/difficulty inferred from
         challenge.md;
      3. or add an explicit entry to ``challenges.json`` for full control.
    """
    challenges_dir = challenges_dir.expanduser().resolve()
    if not challenges_dir.is_dir():
        raise SystemExit(f"challenges directory does not exist: {challenges_dir}")

    raw_entries: list[dict] = []
    auto_discover = True
    if config_path.exists():
        data = _read_json_file(config_path, "challenge config")
        listed = data.get("challenges", [])
        if not isinstance(listed, list):
            raise SystemExit(f"{config_path}: 'challenges' must be a JSON array")
        for entry in listed:
            if not isinstance(entry, dict):
                raise SystemExit(f"{config_path}: each challenge entry must be a JSON object")
            raw_entries.append(dict(entry))
        auto_discover = bool(data.get("auto_discover", False))

    listed_roots = {_resolve_root(raw, challenges_dir) for raw in raw_entries}
    if auto_discover:
        for child in sorted(challenges_dir.iterdir()):
            if not child.is_dir():
                continue
            if not (child / "challenge.md").is_file():
                continue
            if not (child / "instructor" / "flag.txt").is_file():
                continue
            if child.resolve() in listed_roots:
                continue
            raw_entries.append({"dir": child.name})

    entries: list[dict] = []
    seen_codes: set[str] = set()
    for raw in raw_entries:
        root = _resolve_root(raw, challenges_dir)
        if not root.is_dir():
            raise SystemExit(f"challenge directory does not exist: {root}")
        merged: dict = {}
        benchmark_file = root / "benchmark.json"
        if benchmark_file.is_file():
            merged.update(_read_json_file(benchmark_file, f"benchmark metadata for {root.name}"))
        merged.update(raw)
        if merged.get("enabled") is False:
            continue
        entry = normalise_entry(merged, root)
        if entry["code"] in seen_codes:
            raise SystemExit(f"duplicate challenge code: {entry['code']}")
        seen_codes.add(entry["code"])
        entries.append(entry)

    if not entries:
        raise SystemExit(
            f"no challenges found under {challenges_dir}; create a directory with "
            "challenge.md, public/ and instructor/flag.txt, or list it in the config"
        )
    return entries


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, detail: dict | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.detail = detail or {}


@dataclass
class ChallengeState:
    correct_flag_count: int = 0
    matched_indices: list[int] = field(default_factory=list)
    hints_used: int = 0
    awarded: int = 0
    attempts: int = 0
    status: str = "stopped"  # stopped | available
    container_addr: str | None = None
    started_at: str | None = None
    completed_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "correct_flag_count": self.correct_flag_count,
            "matched_indices": sorted(self.matched_indices),
            "hints_used": self.hints_used,
            "awarded": self.awarded,
            "attempts": self.attempts,
            "completed_at": self.completed_at,
        }


# ---------------------------------------------------------------------------
# judge core
# ---------------------------------------------------------------------------


class Judge:
    def __init__(
        self,
        challenges_dir: Path,
        config_path: Path,
        state_file: Path,
        base_url: str,
        bind_host: str,
        web_bind: str,
        web_advertise: str,
        token_arg: str | None,
        max_active: int,
        hint_ratio: float,
        time_limit_minutes: float,
        reset: bool,
    ) -> None:
        self.challenges_dir = challenges_dir
        self.config_path = config_path
        self.state_file = state_file
        self.base_url = base_url.rstrip("/")
        self.bind_host = bind_host
        self.web_bind = web_bind
        self.web_advertise = web_advertise
        self.max_active = max_active
        self.hint_ratio = hint_ratio
        self.time_limit_minutes = time_limit_minutes
        self.lock = threading.RLock()
        self.web_procs: dict[str, subprocess.Popen] = {}
        self.specs: dict[str, dict] = {}
        self.descriptions: dict[str, str] = {}
        self.hints: dict[str, list[str]] = {}
        self.truth: dict[str, list[str]] = {}
        self.states: dict[str, ChallengeState] = {}
        self.token_arg = token_arg

        self._load_challenges()
        self._load_state()

        self.deadline: float | None = None
        if self.time_limit_minutes and self.time_limit_minutes > 0:
            self.deadline = time.monotonic() + self.time_limit_minutes * 60

        if reset:
            self.reset()

    # -- loading -----------------------------------------------------------

    def _load_challenges(self) -> None:
        entries = load_challenge_config(self.config_path, self.challenges_dir)
        for spec in entries:
            code = spec["code"]
            try:
                description = spec["challenge_path"].read_text(encoding="utf-8")
                flag_lines = spec["flag_path"].read_text(encoding="utf-8").splitlines()
            except OSError as exc:
                raise SystemExit(f"{code}: cannot read challenge files: {exc}") from None
            flags = [line.strip() for line in flag_lines if line.strip()]
            if not flags:
                raise SystemExit(f"{code}: empty flag file: {spec['flag_path']}")
            if spec["flag_count"] is not None and spec["flag_count"] != len(flags):
                raise SystemExit(
                    f"{code}: flag_count={spec['flag_count']} but "
                    f"{spec['flag_path'].name} has {len(flags)} non-empty lines"
                )
            spec["flag_count"] = len(flags)
            self.specs[code] = spec
            self.descriptions[code] = description
            self.hints[code] = parse_hints(description)
            self.truth[code] = flags
            self.states[code] = ChallengeState()

    def _load_state(self) -> None:
        self.task_id = f"local-{datetime.now(timezone.utc):%Y%m%d}-{secrets.token_hex(3)}"
        self.created_at = utc_now()
        persisted_token: str | None = None

        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001 - keep running with a fresh state
                backup = self.state_file.with_name(
                    self.state_file.name + f".corrupt-{int(time.time())}"
                )
                try:
                    self.state_file.replace(backup)
                except OSError:
                    pass
                print(
                    f"[judge] warning: cannot read state ({exc}); backed up to {backup}",
                    file=sys.stderr,
                )
                data = {}
            self.task_id = data.get("task_id") or self.task_id
            self.created_at = data.get("created_at") or self.created_at
            persisted_token = data.get("token")
            for code, saved in (data.get("challenges") or {}).items():
                if code not in self.states or not isinstance(saved, dict):
                    continue
                state = self.states[code]
                spec = self.specs[code]
                indices = _as_index_list(saved.get("matched_indices"))
                if not indices:
                    legacy_count = int(saved.get("correct_flag_count", 0) or 0)
                    indices = list(range(1, max(0, legacy_count) + 1))
                if not indices and bool(saved.get("correct_submitted")):
                    # state written before multi-flag support
                    indices = [1]
                # Drop indices that no longer exist after editing flag.txt.
                state.matched_indices = sorted(
                    {index for index in indices if 1 <= index <= spec["flag_count"]}
                )
                state.correct_flag_count = len(state.matched_indices)
                state.hints_used = int(saved.get("hints_used", 0) or 0)
                state.attempts = int(saved.get("attempts", 0) or 0)
                # Recompute the awarded score from the current config so that
                # score/flag edits stay consistent across restarts.
                if state.correct_flag_count:
                    ratio = (
                        spec["hint_ratio"]
                        if spec["hint_ratio"] is not None
                        else self.hint_ratio
                    ) if state.hints_used else 1.0
                    target = int(round(spec["total_score"] * ratio))
                    state.awarded = int(
                        round(
                            target
                            * state.correct_flag_count
                            / spec["flag_count"]
                        )
                    )
                else:
                    state.awarded = 0
                state.completed_at = (
                    saved.get("completed_at")
                    if state.correct_flag_count >= spec["flag_count"]
                    else None
                )
                # Processes never survive a restart.
                state.status = "stopped"
                state.container_addr = None
                state.started_at = None

        self.token = self.token_arg or persisted_token or secrets.token_urlsafe(24)
        self._save_state()

    # -- persistence -------------------------------------------------------

    def _save_state(self) -> None:
        payload = {
            "version": 2,
            "task_id": self.task_id,
            "created_at": self.created_at,
            "updated_at": utc_now(),
            "token": self.token,
            "challenges": {code: state.to_dict() for code, state in self.states.items()},
        }
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_name(self.state_file.name + ".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.state_file)

    # -- helpers -----------------------------------------------------------

    def _spec(self, code: str) -> dict:
        spec = self.specs.get(code)
        if spec is None:
            raise ApiError(
                404, "challenge_not_found", f"unknown unique_code: {code}", {"unique_code": code}
            )
        return spec

    def _check_deadline(self) -> None:
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ApiError(409, "invalid_state", "task time limit reached", {})

    def _active_count(self) -> int:
        return sum(1 for state in self.states.values() if state.status == "available")

    def _web_alive(self, code: str) -> bool:
        proc = self.web_procs.get(code)
        if proc is None:
            return False
        if proc.poll() is None:
            return True
        self.web_procs.pop(code, None)
        return False

    def _reap_dead_web(self) -> None:
        """Mark service instances that died on their own as stopped."""
        changed = False
        for code, spec in self.specs.items():
            state = self.states[code]
            if (
                state.status == "available"
                and spec["kind"] == "service"
                and not self._web_alive(code)
            ):
                state.status = "stopped"
                state.container_addr = None
                state.started_at = None
                changed = True
        if changed:
            self._save_state()

    def _public_item(self, code: str) -> dict:
        spec = self.specs[code]
        state = self.states[code]
        item = {
            "unique_code": code,
            "title": spec["title"],
            "category": spec["category"],
            "description": self.descriptions[code]
            + "\n\n---\n平台说明（本地比赛）："
            + spec["platform_note"],
            "difficulty": spec["difficulty"],
            "level": spec["level"],
            "total_score": spec["total_score"],
            "flag_count": spec["flag_count"],
            "correct_flag_count": state.correct_flag_count,
            "is_completed": state.correct_flag_count >= spec["flag_count"],
            "container_status": state.status,
            "cumulative_score": state.awarded,
            "awarded_score": state.awarded,
            "hints_used": state.hints_used,
            "attempts": state.attempts,
            "hint_cost_radio": spec["hint_ratio"]
            if spec["hint_ratio"] is not None
            else self.hint_ratio,
        }
        if state.status == "available" and state.container_addr:
            item["container_addr"] = state.container_addr
        return item

    def _start_payload(self, code: str) -> dict:
        spec = self.specs[code]
        state = self.states[code]
        payload = {
            "unique_code": code,
            "title": spec["title"],
            "kind": spec["kind"],
            "container_status": state.status,
            "container_addr": state.container_addr,
        }
        if spec["kind"] == "artifact":
            payload["artifacts"] = [state.container_addr] if state.container_addr else []
            payload["usage"] = "下载 container_addr 指向的 tar.gz 并解压后分析"
        else:
            payload["usage"] = "直接访问 container_addr 指向的 Web 服务"
        return payload

    # -- web instances -----------------------------------------------------

    def _spawn_web(self, code: str) -> str:
        spec = self.specs[code]
        root = spec["root"]
        service = spec.get("service") or {}
        if not service:
            raise ApiError(
                503, "resource_unavailable", f"no service config for {code}", {}
            )

        command = [sys.executable, str(service["script_path"])]
        if service.get("host_arg"):
            command += [str(service["host_arg"]), self.web_bind]
        if service.get("port_arg"):
            command += [str(service["port_arg"]), str(service.get("port", 0))]

        log_dir = self.state_file.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{code}-{int(time.time())}-{secrets.token_hex(2)}.log"
        log_file = open(log_path, "ab")
        try:
            proc = subprocess.Popen(
                command,
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=log_file,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            log_file.close()
            raise ApiError(
                503, "resource_unavailable", f"cannot start web instance: {exc}", {}
            ) from None
        log_file.close()

        try:
            ready, _, _ = select.select(
                [proc.stdout], [], [], float(service.get("timeout", 12.0))
            )
            line = proc.stdout.readline().strip() if ready else ""
            match = service["ready_regex_compiled"].search(line)
            if not match:
                raise RuntimeError(line or "no ready line")
            port = int(match.group(1))
        except Exception as exc:  # noqa: BLE001 - convert to API error
            self._stop_proc(proc)
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
            except OSError:
                pass
            raise ApiError(
                503,
                "resource_unavailable",
                f"web instance for {code} failed to start: {exc}",
                {"log_tail": tail},
            ) from None

        self.web_procs[code] = proc
        return f"http://{self.web_advertise}:{port}"

    @staticmethod
    def _stop_proc(proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass

    def _kill_web(self, code: str) -> None:
        proc = self.web_procs.pop(code, None)
        if proc is not None:
            self._stop_proc(proc)

    # -- public operations -------------------------------------------------

    def list_challenges(self) -> list[dict]:
        with self.lock:
            self._reap_dead_web()
            return [self._public_item(code) for code in self.specs]

    def start(self, code: str) -> dict:
        with self.lock:
            self._check_deadline()
            self._reap_dead_web()
            spec = self._spec(code)
            state = self.states[code]

            if state.status == "available":
                if spec["kind"] == "service" and not self._web_alive(code):
                    state.status = "stopped"
                    state.container_addr = None
                else:
                    return self._start_payload(code)

            if self._active_count() >= self.max_active:
                raise ApiError(
                    409,
                    "invalid_state",
                    f"max active challenges reached ({self.max_active}); close one first",
                    {"max_active": self.max_active},
                )

            if spec["kind"] == "service":
                address = self._spawn_web(code)
            else:
                address = f"{self.base_url}/artifact/{code}.tar.gz"

            state.status = "available"
            state.container_addr = address
            state.started_at = utc_now()
            self._save_state()
            return self._start_payload(code)

    def close(self, code: str) -> dict:
        with self.lock:
            self._spec(code)
            state = self.states[code]
            if state.status != "available":
                return {
                    "unique_code": code,
                    "container_status": state.status,
                    "closed": False,
                }
            self._kill_web(code)
            state.status = "stopped"
            state.container_addr = None
            state.started_at = None
            self._save_state()
            return {"unique_code": code, "container_status": "stopped", "closed": True}

    def hint(self, code: str) -> dict:
        with self.lock:
            self._check_deadline()
            spec = self._spec(code)
            state = self.states[code]
            if state.correct_flag_count >= spec["flag_count"]:
                raise ApiError(
                    409,
                    "invalid_state",
                    "challenge already completed; hint unavailable",
                    {"unique_code": code},
                )
            hints = self.hints.get(code) or []
            if not hints:
                raise ApiError(
                    404, "challenge_not_found", f"no hints configured for {code}", {}
                )
            index = min(state.hints_used, len(hints) - 1)
            text = hints[index]
            state.hints_used += 1
            self._save_state()
            ratio = (
                spec["hint_ratio"]
                if spec["hint_ratio"] is not None
                else self.hint_ratio
            )
            return {
                "unique_code": code,
                "hint": text,
                "hints_used": state.hints_used,
                "hint_cost_radio": ratio,
                "hint_cost_ratio": ratio,
            }

    def submit(self, code: str, flag: object) -> dict:
        with self.lock:
            self._check_deadline()
            spec = self._spec(code)
            state = self.states[code]
            if not isinstance(flag, str) or not (1 <= len(flag) <= MAX_FLAG_LEN):
                raise ApiError(
                    422,
                    "invalid_params",
                    f"flag must be a string of 1..{MAX_FLAG_LEN} characters",
                    {},
                )
            state.attempts += 1
            supplied = flag.strip()
            encoded = supplied.encode("utf-8")

            matched_index = 0
            for index, expected in enumerate(self.truth[code], 1):
                if secrets.compare_digest(encoded, expected.encode("utf-8")):
                    matched_index = index
                    break

            if not matched_index:
                self._save_state()
                return {
                    "correct": False,
                    "awarded": 0,
                    "cumulative_score": self._total_score(),
                    "correct_flag_count": state.correct_flag_count,
                    "total_flag_count": spec["flag_count"],
                    "matched_flag_index": 0,
                }

            if matched_index in state.matched_indices:
                raise ApiError(
                    409, "duplicate", "this flag was already submitted correctly", {}
                )

            state.matched_indices.append(matched_index)
            state.matched_indices.sort()
            state.correct_flag_count = len(state.matched_indices)
            hint_ratio = (
                spec["hint_ratio"]
                if spec["hint_ratio"] is not None
                else self.hint_ratio
            )
            ratio = hint_ratio if state.hints_used else 1.0
            target_total = int(round(spec["total_score"] * ratio))
            state.awarded = int(
                round(target_total * state.correct_flag_count / spec["flag_count"])
            )
            state.completed_at = (
                utc_now()
                if state.correct_flag_count >= spec["flag_count"]
                else state.completed_at
            )
            self._save_state()
            return {
                "correct": True,
                "awarded": state.awarded,
                "cumulative_score": self._total_score(),
                "correct_flag_count": state.correct_flag_count,
                "total_flag_count": spec["flag_count"],
                "matched_flag_index": matched_index,
            }

    def _total_score(self) -> int:
        return sum(state.awarded for state in self.states.values())

    def scoreboard(self) -> dict:
        with self.lock:
            items = []
            for code, spec in self.specs.items():
                state = self.states[code]
                items.append(
                    {
                        "unique_code": code,
                        "title": spec["title"],
                        "category": spec["category"],
                        "difficulty": spec["difficulty"],
                        "level": spec["level"],
                        "total_score": spec["total_score"],
                        "awarded_score": state.awarded,
                        "correct_flag_count": state.correct_flag_count,
                        "flag_count": spec["flag_count"],
                        "is_completed": state.correct_flag_count >= spec["flag_count"],
                        "container_status": state.status,
                        "hints_used": state.hints_used,
                        "attempts": state.attempts,
                        "completed_at": state.completed_at,
                    }
                )
            return {
                "task_id": self.task_id,
                "created_at": self.created_at,
                "updated_at": utc_now(),
                "max_score": sum(spec["total_score"] for spec in self.specs.values()),
                "total_score": self._total_score(),
                "completed": sum(
                    1
                    for code, spec in self.specs.items()
                    if self.states[code].correct_flag_count >= spec["flag_count"]
                ),
                "challenges": items,
            }

    def build_artifact(self, code: str) -> bytes:
        with self.lock:
            spec = self._spec(code)
            root = spec["root"]
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                md_path = spec["challenge_path"]
                archive.add(
                    str(md_path),
                    arcname=f"{code}/{md_path.relative_to(root).as_posix()}",
                )
                public = spec.get("public_path")
                if public is not None:
                    flag_path = spec["flag_path"].resolve()
                    instructor = (root / "instructor").resolve()
                    md_resolved = md_path.resolve()
                    for path in sorted(public.rglob("*")):
                        if path.is_symlink() or not path.is_file():
                            continue
                        resolved = path.resolve()
                        if public not in resolved.parents:
                            continue
                        # Defence in depth: never ship the flag, instructor
                        # material, or a duplicate of the challenge text.
                        if resolved in (flag_path, md_resolved):
                            continue
                        if instructor == resolved or instructor in resolved.parents:
                            continue
                        arcname = f"{code}/{path.relative_to(root).as_posix()}"
                        archive.add(str(path), arcname=arcname)
            return buffer.getvalue()

    def reset(self) -> None:
        with self.lock:
            for code in self.specs:
                self._kill_web(code)
                self.states[code] = ChallengeState()
            self._save_state()
            print("[judge] state reset (token and task id kept)", flush=True)

    def shutdown(self) -> None:
        with self.lock:
            for code in list(self.web_procs):
                self._kill_web(code)


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    server_version = f"CTFBench/{VERSION}"
    protocol_version = "HTTP/1.1"

    @property
    def judge(self) -> Judge:
        return self.server.judge  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("[judge] %s - %s\n" % (self.address_string(), fmt % args))

    # -- response helpers --------------------------------------------------

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _html(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _error(self, exc: ApiError) -> None:
        # An error response may follow an unread request body; do not reuse
        # the connection after it.
        self.close_connection = True
        self._json(
            exc.status,
            {"code": exc.code, "message": exc.message, "detail": exc.detail},
        )

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ApiError(422, "invalid_params", "invalid Content-Length", {}) from None
        if length <= 0:
            raise ApiError(422, "invalid_params", "JSON body required", {})
        if length > MAX_BODY_BYTES:
            raise ApiError(422, "invalid_params", "JSON body too large", {})
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ApiError(422, "invalid_params", "malformed JSON body", {}) from None
        if not isinstance(value, dict):
            raise ApiError(422, "invalid_params", "JSON object required", {})
        return value

    def _require_token(self) -> None:
        supplied = self.headers.get("BENCHMARK_TOKEN") or ""
        if not supplied:
            authorization = self.headers.get("Authorization") or ""
            if authorization.lower().startswith("bearer "):
                supplied = authorization[7:].strip()
        if not supplied or not secrets.compare_digest(
            supplied.encode("utf-8"), self.judge.token.encode("utf-8")
        ):
            raise ApiError(
                404, "task_not_found", "invalid or missing BENCHMARK_TOKEN", {}
            )

    @staticmethod
    def _code_from(query: dict, body: dict | None = None) -> str:
        if body:
            value = body.get("unique_code")
            if isinstance(value, str) and value:
                return value
        values = query.get("unique_code") or []
        if values and values[0]:
            return values[0]
        raise ApiError(422, "invalid_params", "unique_code is required", {})

    # -- routing -----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)

            if method == "GET" and path == "/health":
                self._json(200, {"status": "ok", "service": "ctf-bench", "version": VERSION})
                return

            if method == "GET" and path == "/vpn-check":
                self._json(
                    200,
                    {
                        "client_ip": self.client_address[0],
                        "status": "ok",
                        "time": utc_now(),
                    },
                )
                return

            if method == "GET" and path == "/scoreboard":
                self._json(200, self.judge.scoreboard())
                return

            if method == "GET" and path == "/":
                self._html(200, self._scoreboard_html())
                return

            if method == "GET" and path.startswith("/artifact/"):
                name = path[len("/artifact/") :]
                if not name.endswith(".tar.gz"):
                    raise ApiError(404, "challenge_not_found", "artifact not found", {})
                code = name[: -len(".tar.gz")]
                payload = self.judge.build_artifact(code)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/gzip")
                    self.send_header("Content-Length", str(len(payload)))
                    self.send_header(
                        "Content-Disposition", f'attachment; filename="{code}.tar.gz"'
                    )
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return

            if path.startswith("/openapi/v1/"):
                self._require_token()
                self._api(method, path, query)
                return

            raise ApiError(404, "not_found", f"no route for {method} {path}", {})

        except ApiError as exc:
            self._error(exc)
        except Exception as exc:  # noqa: BLE001 - never leak a traceback to clients
            traceback.print_exc()
            self.close_connection = True
            self._json(
                500,
                {
                    "code": "internal_error",
                    "message": "internal error",
                    "detail": {"error": str(exc)},
                },
            )

    def _api(self, method: str, path: str, query: dict) -> None:
        if method == "GET" and path == "/openapi/v1/challenges":
            self._json(200, self.judge.list_challenges())
            return

        if method == "POST" and path == "/openapi/v1/challenges/start":
            code = self._code_from(query)
            self._json(200, self.judge.start(code))
            return

        if method == "POST" and path == "/openapi/v1/challenges/close":
            code = self._code_from(query)
            self._json(200, self.judge.close(code))
            return

        if method == "GET" and path == "/openapi/v1/challenges/hint":
            code = self._code_from(query)
            self._json(200, self.judge.hint(code))
            return

        if method == "POST" and path == "/openapi/v1/challenges/submit":
            body = self._read_json()
            code = self._code_from(query, body)
            self._json(200, self.judge.submit(code, body.get("flag")))
            return

        if method == "POST" and path == "/openapi/v1/admin/reset":
            self.judge.reset()
            self._json(200, {"ok": True, "reset": True})
            return

        raise ApiError(404, "not_found", f"no route for {method} {path}", {})

    # -- HTML scoreboard ---------------------------------------------------

    def _scoreboard_html(self) -> str:
        board = self.judge.scoreboard()
        rows = []
        for item in board["challenges"]:
            done = "✅" if item["is_completed"] else "—"
            rows.append(
                "<tr>"
                f"<td>{html.escape(item['unique_code'])}</td>"
                f"<td>{html.escape(item['title'])}</td>"
                f"<td>{html.escape(item['category'])}</td>"
                f"<td>{item['difficulty']}</td>"
                f"<td>{item['awarded_score']} / {item['total_score']}</td>"
                f"<td>{html.escape(item['container_status'])}</td>"
                f"<td>{item['hints_used']}</td>"
                f"<td>{item['attempts']}</td>"
                f"<td>{done}</td>"
                "</tr>"
            )
        return (
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"refresh\" content=\"5\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>CTF 本地比赛计分板</title>"
            "<style>"
            ":root{color-scheme:light dark}"
            "body{font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif;margin:0;padding:24px;"
            "background:#0f1117;color:#e6e8ee}"
            "h1{font-size:22px;margin:0 0 4px}"
            ".meta{color:#9aa3b2;margin-bottom:18px}"
            ".big{font-size:34px;font-weight:650;color:#7ee787}"
            "table{border-collapse:collapse;width:100%;margin-top:18px}"
            "th,td{padding:9px 10px;border-bottom:1px solid #262b36;text-align:left;white-space:nowrap}"
            "th{color:#9aa3b2;font-weight:500;font-size:13px}"
            "tr:hover td{background:#151923}"
            "code{color:#a5d6ff}"
            "</style></head><body>"
            f"<h1>CTF 本地比赛计分板</h1>"
            f"<div class=\"meta\">task <code>{html.escape(board['task_id'])}</code> · "
            f"更新于 {html.escape(board['updated_at'])} · 5 秒自动刷新</div>"
            f"<div class=\"big\">{board['total_score']} / {board['max_score']}</div>"
            f"<div class=\"meta\">已完成 {board['completed']} / {len(board['challenges'])} 题</div>"
            "<table><thead><tr>"
            "<th>题号</th><th>题目</th><th>方向</th><th>难度</th>"
            "<th>得分</th><th>实例</th><th>提示</th><th>提交</th><th>通关</th>"
            "</tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></body></html>"
        )


class BenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], judge: Judge):
        self.judge = judge
        super().__init__(address, Handler)


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local CTF benchmark judge compatible with Qiming's tsec-benchmark skill.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--challenges-dir",
        default=str(DEFAULT_CHALLENGES_DIR),
        help="path to the challenge package (default: ./challenges)",
    )
    parser.add_argument(
        "--challenges-config",
        default=str(DEFAULT_CONFIG_FILE),
        help=(
            "JSON manifest for challenge metadata; if the file is missing, "
            "all valid challenge directories are auto-discovered"
        ),
    )
    parser.add_argument(
        "--list-challenges",
        action="store_true",
        help="validate the config, print the resolved challenge list, then exit",
    )
    parser.add_argument(
        "--state-file",
        default=str(HERE / "data" / "state.json"),
        help="score/state file (contains the API token, mode 600)",
    )
    parser.add_argument(
        "--bind",
        default=None,
        help="API listen address; default: Docker bridge gateway (auto-detected)",
    )
    parser.add_argument(
        "--advertise-host",
        default=None,
        help="host placed in agent-facing URLs; default: bind address",
    )
    parser.add_argument("--port", type=int, default=9000, help="API listen port")
    parser.add_argument(
        "--web-bind",
        default=None,
        help="bind address for spawned Web challenge instances; default: --bind",
    )
    parser.add_argument(
        "--web-advertise",
        default=None,
        help="host placed in container_addr for Web instances; default: advertise host",
    )
    parser.add_argument(
        "--network",
        default=DEFAULT_NETWORK,
        help="Docker network whose gateway is the default listen address",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="BENCHMARK_TOKEN; default: $BENCHMARK_TOKEN, persisted token, or random",
    )
    parser.add_argument(
        "--max-active",
        type=int,
        default=MAX_ACTIVE_DEFAULT,
        help="maximum simultaneously started challenges",
    )
    parser.add_argument(
        "--hint-ratio",
        type=float,
        default=HINT_RATIO_DEFAULT,
        help="score multiplier after viewing a hint",
    )
    parser.add_argument(
        "--time-limit-minutes",
        type=float,
        default=0,
        help="disable challenge operations after N minutes; 0 = no limit",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="clear scores/hints/instances before serving (token is kept)",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    challenges_dir = Path(args.challenges_dir).expanduser().resolve()
    config_path = Path(args.challenges_config).expanduser().resolve()
    hint_ratio = min(1.0, max(0.0, args.hint_ratio))

    if args.list_challenges:
        try:
            entries = load_challenge_config(config_path, challenges_dir)
        except SystemExit as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"{'code':<16}{'kind':<10}{'diff':<5}{'level':<6}{'score':<6}title")
        print("-" * 78)
        for entry in entries:
            print(
                f"{entry['code']:<16}{entry['kind']:<10}{entry['difficulty']:<5}"
                f"{entry['level']:<6}{entry['total_score']:<6}{entry['title']}"
            )
        print(
            f"\n{len(entries)} challenges, max score "
            f"{sum(entry['total_score'] for entry in entries)}; "
            f"config: {config_path}"
        )
        return 0

    gateway = detect_docker_gateway(args.network)
    bind_host = args.bind or gateway or DEFAULT_FALLBACK_GATEWAY
    if bind_host == "0.0.0.0":
        advertise_host = args.advertise_host or gateway or DEFAULT_FALLBACK_GATEWAY
    else:
        advertise_host = args.advertise_host or bind_host
    web_bind = args.web_bind or bind_host
    web_advertise = args.web_advertise or advertise_host

    if bind_host in ("127.0.0.1", "::1") and advertise_host in ("127.0.0.1", "::1"):
        print(
            "warning: the API only listens on loopback; a Docker-hosted agent cannot reach it. "
            "Use --bind <docker gateway> or --bind 0.0.0.0.",
            file=sys.stderr,
        )

    state_file = Path(args.state_file).expanduser().resolve()
    token_arg = args.token or os.environ.get("BENCHMARK_TOKEN") or None
    base_url = f"http://{advertise_host}:{args.port}"

    try:
        judge = Judge(
            challenges_dir=challenges_dir,
            config_path=config_path,
            state_file=state_file,
            base_url=base_url,
            bind_host=bind_host,
            web_bind=web_bind,
            web_advertise=web_advertise,
            token_arg=token_arg,
            max_active=max(1, args.max_active),
            hint_ratio=hint_ratio,
            time_limit_minutes=args.time_limit_minutes,
            reset=args.reset,
        )
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        server = BenchServer((bind_host, args.port), judge)
    except OSError as exc:
        print(
            f"error: cannot bind {bind_host}:{args.port} ({exc}).\n"
            f"  - is the Docker network {args.network!r} up? "
            f"Try: docker network inspect {args.network}\n"
            f"  - or pass --bind 0.0.0.0 (LAN-visible) / --bind 127.0.0.1 (local only)",
            file=sys.stderr,
        )
        judge.shutdown()
        return 2

    def stop(_signum, _frame) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    vpn_url = f"{base_url}/vpn-check"
    print("=" * 70)
    print(f" CTF local benchmark judge v{VERSION}")
    print("=" * 70)
    print(f" challenges : {len(judge.specs)}  (max {sum(s['total_score'] for s in judge.specs.values())} points)")
    print(
        f" config     : {config_path}"
        + ("" if config_path.exists() else "  (missing; auto-discovery)")
    )
    print(f" state      : {state_file}")
    print(f" listen     : http://{bind_host}:{args.port}")
    print(f" web bind   : {web_bind}  (instances advertise {web_advertise})")
    print(f" max active : {judge.max_active}")
    print(f" hint ratio : {judge.hint_ratio}")
    if judge.deadline is not None:
        print(f" time limit : {args.time_limit_minutes:g} minutes")
    print("-" * 70)
    print(f" BENCHMARK_BASE_URL={base_url}")
    print(f" BENCHMARK_TOKEN={judge.token}")
    print(f" BENCHMARK_VPN_CHECK_URL={vpn_url}")
    print(f" scoreboard: {base_url}/scoreboard")
    print("-" * 70)
    print(" Qiming prompt (paste into the workbench / CLI):")
    print(
        "   请调用 tsec-benchmark Skill 跑本次本地比赛。\n"
        f"   BENCHMARK_TOKEN={judge.token}\n"
        f"   BENCHMARK_BASE_URL={base_url}\n"
        f"   BENCHMARK_VPN_CHECK_URL={vpn_url}\n"
        "   先检查连接并执行 VPN 预检，然后按平台流程 start → 解题 → submit → close，"
        "最后汇报总进度和总分。只测试本平台提供的靶场。"
    )
    print("=" * 70, flush=True)

    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        judge.shutdown()
        server.server_close()
        print("[judge] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
