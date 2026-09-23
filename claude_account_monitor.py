#!/usr/bin/env python3
"""Claude Account Monitor.

Watches which Claude (Anthropic) account is signed in on this machine and records
login / logout / switch events to a local report and, optionally, a central sink.

Reads only account *identity* fields (email, org name). It never reads or logs
auth tokens or credential files.

Usage:
    claude_account_monitor.py            # run as a daemon (poll loop)
    claude_account_monitor.py --once     # write a single snapshot and exit
    claude_account_monitor.py --print    # print current detection, no writes
    claude_account_monitor.py --config /path/config.json
    claude_account_monitor.py --interval 5
"""

from __future__ import annotations

import argparse
import csv
import getpass
import glob
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Defaults / config
# --------------------------------------------------------------------------- #

DEFAULT_CONFIG = {
    "poll_interval_seconds": 15,
    "heartbeat_seconds": 3600,
    "local_report_dir": "~/claude-monitor",
    "state_file": "~/.local/state/claude-monitor/state.json",
    # Override for testing; defaults to the real Claude Code config.
    "claude_code_config": "~/.claude.json",
    # Root of Claude Code session transcripts (override honours CLAUDE_CONFIG_DIR).
    "projects_dir": "~/.claude/projects",
    "sources": ["claude-code", "desktop", "browser"],
    # A session whose newest transcript was touched within this window is "active".
    "active_window_seconds": 300,
    # Sum token usage from the current transcript as a fallback to native OTEL.
    "transcript_usage": True,
    # Report each session's auto-generated title (from Claude Code's own "ai-title"
    # entries). Content-derived, so it can be switched off fleet-wide. Prompts
    # themselves are never read.
    "capture_session_titles": True,
    # Fleet reporting: POST a per-machine snapshot to a central collector.
    # url may be https:// when the collector is behind Cloudflare Tunnel / a proxy.
    # token is this machine's OWN per-agent token; headers carries any extra edge
    # headers (e.g. Cloudflare Access service-token pair).
    # e.g. {"url": "https://collector.example.com", "token": "<AGENT_TOKEN>",
    #        "headers": {"CF-Access-Client-Id": "...", "CF-Access-Client-Secret": "..."}}
    # events: also send login/logout/switch events to <url>/events (default on).
    "central_fleet": {"url": None, "token": None, "headers": {}, "events": True},
    # Legacy sink for raw event rows (unrelated to the fleet dashboard).
    "central": {"type": "none"},
}

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if path:
        with open(expand(path), "r", encoding="utf-8") as fh:
            user_cfg = json.load(fh)
        cfg.update(user_cfg)
        # Merge nested dicts so a partial override doesn't drop sibling keys.
        for key in ("central", "central_fleet"):
            if key in user_cfg:
                merged = dict(DEFAULT_CONFIG[key])
                merged.update(user_cfg[key])
                cfg[key] = merged
    return cfg


# --------------------------------------------------------------------------- #
# System identity
# --------------------------------------------------------------------------- #

def primary_ip() -> str | None:
    """Best-effort primary LAN IP (the source address used to reach the network).

    Opens a UDP socket to a routable address; no packets are actually sent, so this
    works offline and just reveals which local interface would be used.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        s.close()


def _run(cmd: list[str]) -> str | None:
    """Run a short command, return stdout stripped, or None on any failure."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return (out.stdout or "").strip() or None


def _fallback_machine_id() -> str:
    """A generated UUID persisted under the config dir, so a machine that exposes
    no hardware GUID still gets a stable key (never falls back to hostname)."""
    path = expand("~/.config/claude-monitor/machine-id")
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as fh:
                mid = fh.read().strip()
            if mid:
                return mid
    except OSError:
        pass
    mid = str(uuid.uuid4())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(mid + "\n")
    except OSError:
        pass
    return mid


def machine_id() -> str | None:
    """Stable per-machine ID that survives hostname/IP changes, cross-OS."""
    system = platform.system()

    if system == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    mid = fh.read().strip()
                if mid:
                    return mid
            except OSError:
                continue

    elif system == "Darwin":  # macOS: IOPlatformUUID from ioreg
        out = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        if out:
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
            if m:
                return m.group(1)

    elif system == "Windows":  # MachineGuid, then csproduct UUID
        out = _run(["reg", "query",
                    r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        if out:
            m = re.search(r"MachineGuid\s+REG_SZ\s+([A-Fa-f0-9\-]+)", out)
            if m:
                return m.group(1)
        out = _run(["wmic", "csproduct", "get", "uuid"])
        if out:
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            if len(lines) >= 2 and lines[1].lower() != "uuid":
                return lines[1]

    return _fallback_machine_id()


def system_identity() -> dict:
    try:
        os_user = getpass.getuser()
    except Exception:
        os_user = os.environ.get("USER", "unknown")
    hostname = socket.gethostname()
    return {
        "machine_id": machine_id(),
        "os_user": os_user,
        "hostname": hostname,
        "terminal": f"{os_user}@{hostname}",
        "ip": primary_ip(),
        "platform": platform.platform(),
    }


# --------------------------------------------------------------------------- #
# Account detection
# --------------------------------------------------------------------------- #

def detect_claude_code(cfg: dict) -> list[dict]:
    """Read the signed-in identity from the Claude Code CLI config."""
    path = expand(cfg.get("claude_code_config", "~/.claude.json"))
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    acct = data.get("oauthAccount") or {}
    email = acct.get("emailAddress")
    if not email:
        return []
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat()
    except OSError:
        mtime = None
    return [{
        "source": "claude-code",
        "email": email.strip().lower(),
        "org": acct.get("organizationName"),
        "detail": f"config_mtime={mtime}",
        "plan": account_plan(acct),
        "limits": account_limits(data, acct),
    }]


def plan_name(org_type: str | None, tier: str | None) -> str | None:
    """Human name for the subscription: claude_max + default_claude_max_20x -> 'Max 20x'."""
    if not org_type and not tier:
        return None
    base = {"claude_max": "Max", "claude_pro": "Pro", "claude_team": "Team", "team": "Team",
            "claude_enterprise": "Enterprise", "enterprise": "Enterprise", "api": "API", "console": "API",
            "free": "Free"}.get((org_type or "").lower(), (org_type or "").replace("claude_", "").title() or None)
    mult = re.search(r"_(\d+x)$", tier or "")
    return f"{base} {mult.group(1)}" if base and mult else base


def account_plan(acct: dict) -> dict:
    """Subscription metadata only (no secrets): plan/tier/billing/role/since."""
    org_type = acct.get("organizationType")
    tier = acct.get("organizationRateLimitTier") or acct.get("userRateLimitTier")
    return {
        "name": plan_name(org_type, tier),
        "type": org_type,
        "tier": tier,
        "seat_tier": acct.get("seatTier"),
        "billing": acct.get("billingType"),
        "role": acct.get("organizationRole"),
        "subscription_since": acct.get("subscriptionCreatedAt"),
        "extra_usage": bool(acct.get("hasExtraUsageEnabled")),
        "trial_ends_at": acct.get("claudeCodeTrialEndsAt"),
    }


def account_limits(data: dict, acct: dict) -> dict | None:
    """Claude Code's cached /usage answer: percent of the 5-hour and 7-day limits
    used, when they reset, and when Claude Code last fetched it."""
    cache = data.get("cachedUsageUtilization") or {}
    util = cache.get("utilization") or {}
    if not util:
        return None
    if cache.get("accountUuid") and acct.get("accountUuid") and cache["accountUuid"] != acct["accountUuid"]:
        return None  # stale cache from a different account

    def window(name: str) -> dict | None:
        w = util.get(name)
        if not isinstance(w, dict):
            return None
        return {"pct": w.get("utilization"), "resets_at": w.get("resets_at"),
                "locked_reason": w.get("locked_reason")}

    fetched = cache.get("fetchedAtMs")
    extra = util.get("extra_usage") if isinstance(util.get("extra_usage"), dict) else {}
    return {
        "five_hour": window("five_hour"),
        "seven_day": window("seven_day"),
        "seven_day_opus": window("seven_day_opus"),
        "seven_day_sonnet": window("seven_day_sonnet"),
        "extra_usage": {"enabled": bool(extra.get("is_enabled")), "pct": extra.get("utilization"),
                        "monthly_limit": extra.get("monthly_limit"), "used": extra.get("used_credits"),
                        "currency": extra.get("currency")} if extra else None,
        "fetched_at": datetime.fromtimestamp(fetched / 1000, timezone.utc).isoformat() if fetched else None,
    }


def detect_desktop() -> list[dict]:
    """Best-effort scan of the Claude Desktop app config for an account email."""
    results: list[dict] = []
    seen: set[str] = set()
    candidates: list[str] = []
    for base in glob.glob(expand("~/.config/Claude*")):
        candidates += glob.glob(os.path.join(base, "**", "*.json"), recursive=True)
    for path in candidates:
        # Skip anything that looks like a credential/token store.
        low = os.path.basename(path).lower()
        if "credential" in low or "token" in low or "cookie" in low:
            continue
        try:
            if os.path.getsize(path) > 2_000_000:  # skip huge caches
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        # Only trust an email that sits next to an "email"-ish key.
        for m in re.finditer(r'"[^"]*email[^"]*"\s*:\s*"([^"]+)"', text, re.I):
            email = m.group(1).strip().lower()
            if EMAIL_RE.fullmatch(email) and email not in seen:
                seen.add(email)
                results.append({
                    "source": "desktop",
                    "email": email,
                    "org": None,
                    "detail": f"file={os.path.basename(path)}",
                })
    return results


def _browser_profile_roots() -> list[str]:
    roots = []
    for pat in (
        "~/.config/google-chrome",
        "~/.config/chromium",
        "~/.config/microsoft-edge",
        "~/.config/BraveSoftware/Brave-Browser",
    ):
        p = expand(pat)
        if os.path.isdir(p):
            roots.append(p)
    return roots


def detect_browser() -> list[dict]:
    """Best-effort: report whether a claude.ai browser session appears active.

    Chrome encrypts cookies and claude.ai does not store the account email in
    plaintext, so this reports presence only ("session active: yes/no"), not the
    email. Detection is done by looking for a claude.ai host key in the Cookies
    SQLite file's raw bytes (no decryption, no value read).
    """
    active = False
    where = None
    for root in _browser_profile_roots():
        for cookies in glob.glob(os.path.join(root, "*", "Cookies")) + \
                glob.glob(os.path.join(root, "*", "Network", "Cookies")):
            try:
                with open(cookies, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            if b"claude.ai" in blob:
                active = True
                where = os.path.relpath(cookies, root)
                break
        if active:
            break
    if not active:
        return []
    return [{
        "source": "browser",
        "email": None,  # not reliably extractable
        "org": None,
        "detail": f"claude.ai session active (email not extractable); at {where}",
    }]


def detect_accounts(cfg: dict) -> list[dict]:
    sources = cfg.get("sources", DEFAULT_CONFIG["sources"])
    found: list[dict] = []
    if "claude-code" in sources:
        found += detect_claude_code(cfg)
    if "desktop" in sources:
        found += detect_desktop()
    if "browser" in sources:
        found += detect_browser()
    return found


def state_key(acct: dict) -> str:
    return f"{acct['source']}:{acct.get('email') or '(no-email)'}"


# --------------------------------------------------------------------------- #
# Claude Code activity + token usage (from session transcripts)
# --------------------------------------------------------------------------- #

def newest_transcript(projects_dir: str) -> str | None:
    """Most recently modified session transcript across all project folders."""
    root = expand(projects_dir)
    if not os.path.isdir(root):
        return None
    files = glob.glob(os.path.join(root, "*", "*.jsonl"))
    if not files:
        return None
    try:
        return max(files, key=os.path.getmtime)
    except OSError:
        return None


def scan_active_session(cfg: dict) -> dict:
    """Detect whether Claude Code is actively in use and which session/model.

    Uses the newest transcript's mtime as the activity signal.
    """
    window = int(cfg.get("active_window_seconds", 300))
    path = newest_transcript(cfg.get("projects_dir", "~/.claude/projects"))
    if not path:
        return {"claude_code_active": False, "session_active": False,
                "session_id": None, "current_model": None, "last_updated": None}
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0
    active = (time.time() - mtime) <= window
    last_updated = datetime.fromtimestamp(mtime, timezone.utc).isoformat() if mtime else None
    session_id = os.path.splitext(os.path.basename(path))[0]
    return {
        "claude_code_active": True,        # Claude Code has been used on this machine
        "session_active": active,          # a session is live right now
        "session_id": session_id,
        "current_model": None,             # filled in by transcript_usage()
        "last_updated": last_updated,
        "_transcript_path": path,
    }


def _usage_tokens(usage: dict) -> dict:
    return {
        "input": int(usage.get("input_tokens", 0) or 0),
        "output": int(usage.get("output_tokens", 0) or 0),
        "cache_read": int(usage.get("cache_read_input_tokens", 0) or 0),
        "cache_creation": int(usage.get("cache_creation_input_tokens", 0) or 0),
    }


def _assistant_entry(line: str) -> tuple[dict, dict] | None:
    """Parse one transcript line; return (entry, message) for assistant turns."""
    line = line.strip()
    if not line:
        return None
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    msg = entry.get("message") if isinstance(entry, dict) else None
    if not isinstance(msg, dict) or msg.get("role") != "assistant":
        return None
    return entry, msg


def transcript_usage(session_file: str | None) -> dict:
    """Sum token usage for one session transcript. FALLBACK to native OTEL.

    The transcript format is internal to Claude Code and can change between
    releases, so this is guarded and clearly labelled as the fallback source.

    Claude Code writes one line per content block of an assistant turn and each
    line repeats the same message.id + usage, so usage is de-duplicated per
    message id (last write wins) before summing.
    """
    totals = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0}
    by_model: dict[str, dict] = {}
    model = None
    if not session_file or not os.path.isfile(session_file):
        return {"tokens": totals, "model": None, "tokens_source": "transcript",
                "tokens_by_model": by_model, "ok": False}
    per_message: dict[str, tuple[str | None, dict]] = {}
    try:
        with open(session_file, "r", encoding="utf-8", errors="ignore") as fh:
            for i, line in enumerate(fh):
                parsed = _assistant_entry(line)
                if not parsed:
                    continue
                entry, msg = parsed
                if msg.get("model"):
                    model = msg["model"]
                mid = msg.get("id") or f"line-{i}"
                per_message[mid] = (msg.get("model"), _usage_tokens(msg.get("usage") or {}))
    except OSError:
        return {"tokens": totals, "model": model, "tokens_source": "transcript",
                "tokens_by_model": by_model, "ok": False}
    for m, tok in per_message.values():
        bucket = by_model.setdefault(m or "?", {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0})
        for k in totals:
            totals[k] += tok[k]
            bucket[k] += tok[k]
    return {"tokens": totals, "model": model, "tokens_source": "transcript",
            "tokens_by_model": by_model, "ok": True}


def transcript_deltas(cfg: dict, state: dict, now: float | None = None) -> list[dict]:
    """New assistant turns since the last poll, as timestamped usage deltas.

    Tails every transcript modified recently (or previously tailed) from the
    byte offset stored in `state`, de-duplicates by message.id, and returns
    {"ts", "session_id", "model", input, output, cache_read, cache_creation}
    rows the collector rolls up per day. Because the transcript's own
    timestamp is used, usage lands on the right day even after an outage.
    """
    now = now or time.time()
    root = expand(cfg.get("projects_dir", "~/.claude/projects"))
    if not os.path.isdir(root):
        return []
    # Tail every transcript touched in the last 24 h so the session list covers
    # a whole working day; each file is parsed once, then only appended bytes.
    window = 86400
    offsets: dict[str, int] = state.setdefault("transcript_offsets", {})
    seen: dict[str, list] = state.setdefault("seen_msg_ids", {})
    # Per-session running stats, built from the same incremental tail (never
    # re-parses a whole transcript): session_id -> {path, cwd, started_at, ...}
    stats: dict[str, dict] = state.setdefault("session_stats", {})
    candidates = set(offsets)
    for path in glob.glob(os.path.join(root, "*", "*.jsonl")):
        try:
            if now - os.path.getmtime(path) <= window:
                candidates.add(path)
        except OSError:
            continue

    capture_titles = bool(cfg.get("capture_session_titles", True))

    def _stat(sid: str, path: str, mtime: float) -> dict:
        st = stats.setdefault(sid, {"cwd": None, "started_at": None, "last_ts": None, "model": None,
                                    "turns": 0, "tokens": {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0},
                                    "title": None, "plan_mode": False, "tool_counts": {},
                                    "lines_added": 0, "lines_removed": 0, "local_cost_usd": None})
        st["path"] = path
        st["mtime"] = mtime
        return st

    deltas: list[dict] = []
    for path in sorted(candidates):
        try:
            size = os.path.getsize(path)
            mtime = os.path.getmtime(path)
        except OSError:
            offsets.pop(path, None)
            continue
        session_default = os.path.splitext(os.path.basename(path))[0]
        if now - mtime > 7 * 86400:      # forget files idle for a week
            offsets.pop(path, None)
            seen.pop(session_default, None)
            stats.pop(session_default, None)
            continue
        off = int(offsets.get(path, 0))
        if off > size:                   # truncated/rewritten: start over
            off = 0
        _stat(session_default, path, mtime)   # keep mtime fresh even with nothing new to read
        if off == size:
            continue
        try:
            with open(path, "rb") as fh:
                fh.seek(off)
                chunk = fh.read()
        except OSError:
            continue
        if not chunk.endswith(b"\n"):    # keep a partially written last line for next time
            cut = chunk.rfind(b"\n")
            chunk = chunk[:cut + 1] if cut >= 0 else b""
        consumed = len(chunk)
        lines = chunk.decode("utf-8", errors="ignore").splitlines()
        if off == 0 and lines:           # first sight of this transcript: where and when it started
            for raw in lines[:8]:        # the first entries carry cwd + timestamp (any role)
                try:
                    first = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(first, dict):
                    continue
                st = _stat(first.get("sessionId") or session_default, path, mtime)
                st["cwd"] = st["cwd"] or first.get("cwd")
                st["started_at"] = st["started_at"] or first.get("timestamp")
                if st["cwd"] and st["started_at"]:
                    break
        for line in lines:
            # Session-level signals Claude Code writes alongside the messages. Only
            # metadata is read here: titles it generated itself, the permission
            # mode, and its own cost/lines summary. Prompt text is never read.
            if line.startswith('{"type":"ai-title"') or line.startswith('{"type":"permission-mode"') \
                    or line.startswith('{"type":"cost-state"') or line.startswith('{"type": "ai-title"') \
                    or line.startswith('{"type": "permission-mode"') or line.startswith('{"type": "cost-state"'):
                try:
                    meta_entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(meta_entry, dict):
                    st = _stat(meta_entry.get("sessionId") or session_default, path, mtime)
                    kind = meta_entry.get("type")
                    if kind == "ai-title" and capture_titles and meta_entry.get("aiTitle"):
                        st["title"] = str(meta_entry["aiTitle"])[:120]
                    elif kind == "permission-mode" and meta_entry.get("permissionMode") == "plan":
                        st["plan_mode"] = True
                    elif kind == "cost-state":
                        st["lines_added"] = int(meta_entry.get("totalLinesAdded") or 0)
                        st["lines_removed"] = int(meta_entry.get("totalLinesRemoved") or 0)
                        if meta_entry.get("totalCostUSD") is not None:
                            st["local_cost_usd"] = round(float(meta_entry["totalCostUSD"]), 4)
                continue
            parsed = _assistant_entry(line)
            if not parsed:
                continue
            entry, msg = parsed
            sid = entry.get("sessionId") or entry.get("session_id") or session_default
            # Tool use (one content block per line) tells what the session is for.
            content = msg.get("content")
            if isinstance(content, list):
                st = _stat(sid, path, mtime)
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name"):
                        name = str(block["name"])[:40]
                        tc = st["tool_counts"]
                        if name in tc or len(tc) < 40:
                            tc[name] = int(tc.get(name, 0)) + 1
                        if name in ("EnterPlanMode", "ExitPlanMode"):
                            st["plan_mode"] = True
            msg_id = msg.get("id")
            if msg_id:
                ids = seen.setdefault(sid, [])
                if msg_id in ids:
                    continue
                ids.append(msg_id)
                if len(ids) > 500:
                    del ids[:-500]
            tok = _usage_tokens(msg.get("usage") or {})
            st = _stat(sid, path, mtime)
            st["cwd"] = st["cwd"] or entry.get("cwd")
            st["started_at"] = st["started_at"] or entry.get("timestamp")
            st["last_ts"] = entry.get("timestamp") or st["last_ts"]
            if msg.get("model"):
                st["model"] = msg["model"]
            st["turns"] = int(st.get("turns", 0)) + 1
            for k in tok:
                st["tokens"][k] = int(st["tokens"].get(k, 0)) + tok[k]
            if not any(tok.values()):
                continue
            deltas.append({"ts": entry.get("timestamp") or datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
                           "session_id": sid, "model": msg.get("model") or "?", **tok})
        offsets[path] = off + consumed
    return deltas


EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
SHELL_TOOLS = {"Bash"}
RESEARCH_TOOLS = {"Read", "Grep", "Glob", "WebFetch", "WebSearch", "ToolSearch", "Agent", "LS"}


def classify_session(st: dict) -> str:
    """What a session is used for, from counts only: coding / planning / shell /
    research / conversation."""
    tc = st.get("tool_counts") or {}
    edits = sum(v for k, v in tc.items() if k in EDIT_TOOLS)
    shell = sum(v for k, v in tc.items() if k in SHELL_TOOLS)
    research = sum(v for k, v in tc.items() if k in RESEARCH_TOOLS)
    if edits or int(st.get("lines_added") or 0) > 0:
        return "coding"
    if st.get("plan_mode"):
        return "planning"
    if shell and shell >= research:
        return "shell"
    if sum(tc.values()):
        return "research"
    return "conversation"


def list_sessions(cfg: dict, state: dict, now: float | None = None) -> list[dict]:
    """Every Claude Code session on this machine touched in the last 24 h, newest
    first: a session is *active* when its transcript changed within
    `active_window_seconds`. Built from `state["session_stats"]` (see
    transcript_deltas), so it costs no file reads."""
    now = now or time.time()
    window = int(cfg.get("active_window_seconds", 300))
    out = []
    for sid, st in (state.get("session_stats") or {}).items():
        mtime = float(st.get("mtime") or 0)
        if not mtime or now - mtime > 86400:
            continue
        cwd = st.get("cwd")
        if not cwd and not int(st.get("turns") or 0):
            continue                     # an empty/aborted transcript, nothing to show
        out.append({
            "session_id": sid,
            "project": os.path.basename(cwd.rstrip("/\\")) if cwd else None,
            "project_path": cwd,
            "started_at": st.get("started_at"),
            "last_activity": datetime.fromtimestamp(mtime, timezone.utc).isoformat(),
            "active": (now - mtime) <= window,
            "model": st.get("model"),
            "turns": int(st.get("turns") or 0),
            "tokens": dict(st.get("tokens") or {}),
            "purpose": classify_session(st),
            "title": st.get("title") if cfg.get("capture_session_titles", True) else None,
            "plan_mode": bool(st.get("plan_mode")),
            "tool_counts": dict(st.get("tool_counts") or {}),
            "lines_added": int(st.get("lines_added") or 0),
            "lines_removed": int(st.get("lines_removed") or 0),
            "local_cost_usd": st.get("local_cost_usd"),
        })
    out.sort(key=lambda s: s["last_activity"], reverse=True)
    return out[:25]


def claude_processes() -> int | None:
    """Best-effort count of running Claude Code processes (no admin needed)."""
    try:
        if platform.system() == "Windows":
            out = _run(["tasklist", "/FI", "IMAGENAME eq claude.exe", "/NH"]) or ""
            return sum(1 for ln in out.splitlines() if ln.strip().lower().startswith("claude"))
        out = _run(["ps", "-eo", "comm="])
        if out is None:
            return None
        return sum(1 for ln in out.splitlines() if ln.strip() in ("claude", "claude.exe"))
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Report sinks
# --------------------------------------------------------------------------- #

CSV_FIELDS = ["timestamp", "event", "terminal", "os_user", "hostname",
              "source", "account_email", "org_name", "detail"]


class Reporter:
    def __init__(self, cfg: dict, identity: dict):
        self.cfg = cfg
        self.identity = identity
        self.local_dir = expand(cfg["local_report_dir"])
        os.makedirs(self.local_dir, exist_ok=True)
        self.jsonl_path = os.path.join(self.local_dir, "report.jsonl")
        self.csv_path = os.path.join(self.local_dir, "report.csv")
        self.log_path = os.path.join(self.local_dir, "monitor.log")
        self.spool_path = os.path.join(self.local_dir, "central-spool.jsonl")
        self.snap_spool_path = os.path.join(self.local_dir, "snapshot-spool.jsonl")
        self.snap_local_path = os.path.join(self.local_dir, "snapshots.jsonl")
        self.event_spool_path = os.path.join(self.local_dir, "event-spool.jsonl")

    def log(self, msg: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
        print(line, file=sys.stderr)

    def record(self, event: str, acct: dict | None = None, detail: str = "") -> dict:
        rec = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "terminal": self.identity["terminal"],
            "os_user": self.identity["os_user"],
            "hostname": self.identity["hostname"],
            "machine_id": self.identity.get("machine_id"),
            "ip": self.identity.get("ip"),
            "source": acct["source"] if acct else None,
            "account_email": (acct.get("email") if acct else None),
            "org_name": (acct.get("org") if acct else None),
            "detail": detail or (acct.get("detail", "") if acct else ""),
        }
        self._write_local(rec)
        self._push_central(rec)
        try:
            self.push_event(rec)
        except Exception as exc:  # never let the fleet push break local recording
            self.log(f"event push error: {exc}")
        return rec

    # --- fleet event push (to the central collector /events) ------------- #

    def _fleet(self) -> tuple[str | None, dict]:
        fleet = self.cfg.get("central_fleet") or {}
        return fleet.get("url"), fleet

    def push_event(self, rec: dict) -> None:
        """Send an account event to the fleet collector, with spool + retry."""
        url, fleet = self._fleet()
        if not url or not fleet.get("events", True):
            return
        endpoint = url.rstrip("/") + "/events"
        extra_headers = fleet.get("headers") or {}
        pending = self._read_json_lines(self.event_spool_path)
        pending.append(rec)
        still_failed = []
        for item in pending:
            if self._post_json(endpoint, item, fleet.get("token"), extra_headers) == "retry":
                still_failed.append(item)
        self._write_json_lines(self.event_spool_path, still_failed)

    def replay_history(self, batch_size: int = 500) -> dict:
        """One-shot: push this machine's local report.jsonl + snapshots.jsonl to
        the collector's /replay so past activity shows up in the history."""
        url, fleet = self._fleet()
        if not url:
            raise RuntimeError("central_fleet.url is not configured")
        endpoint = url.rstrip("/") + "/replay"
        extra_headers = fleet.get("headers") or {}
        events = self._read_json_lines(self.jsonl_path)
        snaps = self._read_json_lines(self.snap_local_path)
        for ev in events:
            ev.setdefault("machine_id", self.identity.get("machine_id"))
            if not ev.get("event_id"):
                key = json.dumps([ev.get("timestamp"), ev.get("event"), ev.get("hostname"),
                                  ev.get("os_user"), ev.get("source"), ev.get("account_email"),
                                  ev.get("detail")], sort_keys=True)
                ev["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "claude-monitor-event:" + key))
        sent = {"events": 0, "snapshots": 0, "failed_batches": 0}
        i = j = 0
        while i < len(events) or j < len(snaps):
            payload = {"events": events[i:i + batch_size], "snapshots": snaps[j:j + batch_size]}
            i += batch_size
            j += batch_size
            res = self._post_json(endpoint, payload, fleet.get("token"), extra_headers)
            if res == "ok":
                sent["events"] += len(payload["events"])
                sent["snapshots"] += len(payload["snapshots"])
            else:
                sent["failed_batches"] += 1
        return sent

    def _write_local(self, rec: dict) -> None:
        with open(self.jsonl_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        new_file = not os.path.exists(self.csv_path)
        with open(self.csv_path, "a", newline="", encoding="utf-8") as fh:
            # CSV keeps its original columns; the JSONL carries the full record
            # (event_id, machine_id, ip) so existing report.csv files stay valid.
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
            if new_file:
                writer.writeheader()
            writer.writerow(rec)

    # --- central push (fail-safe with spool + retry) --------------------- #

    def _push_central(self, rec: dict) -> None:
        central = self.cfg.get("central") or {"type": "none"}
        if central.get("type", "none") == "none":
            return
        # Retry anything spooled from previous failures, then this record.
        pending = self._read_spool()
        pending.append(rec)
        still_failed = []
        for item in pending:
            if not self._send_one(central, item):
                still_failed.append(item)
        self._write_spool(still_failed)

    def _send_one(self, central: dict, rec: dict) -> bool:
        try:
            if central["type"] == "fs":
                base = expand(central["path"])
                os.makedirs(base, exist_ok=True)
                target = os.path.join(base, f"{self.identity['hostname']}.jsonl")
                with open(target, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec) + "\n")
                return True
            if central["type"] == "http":
                data = json.dumps(rec).encode("utf-8")
                req = urllib.request.Request(
                    central["url"], data=data, method="POST",
                    headers={"Content-Type": "application/json"},
                )
                if central.get("token"):
                    req.add_header("Authorization", f"Bearer {central['token']}")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
        except (OSError, urllib.error.URLError, ValueError) as exc:
            self.log(f"central push failed ({central.get('type')}): {exc}")
            return False
        return False

    def _read_spool(self) -> list[dict]:
        if not os.path.exists(self.spool_path):
            return []
        out = []
        try:
            with open(self.spool_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        return out

    def _write_spool(self, items: list[dict]) -> None:
        try:
            if not items:
                if os.path.exists(self.spool_path):
                    os.remove(self.spool_path)
                return
            with open(self.spool_path, "w", encoding="utf-8") as fh:
                for item in items:
                    fh.write(json.dumps(item) + "\n")
        except OSError:
            pass

    # --- fleet snapshot push (to the central collector /ingest) ---------- #

    def push_snapshot(self, snap: dict) -> None:
        """Send a merged per-machine snapshot to the fleet collector.

        Always mirrored locally first, then pushed; failed pushes are spooled and
        retried on the next cycle so a collector outage never loses data.
        """
        try:
            with open(self.snap_local_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(snap) + "\n")
        except OSError:
            pass

        fleet = self.cfg.get("central_fleet") or {}
        url = fleet.get("url")
        if not url:
            return
        endpoint = url.rstrip("/") + "/ingest"

        extra_headers = fleet.get("headers") or {}
        pending = self._read_json_lines(self.snap_spool_path)
        pending.append(snap)
        still_failed = []
        for item in pending:
            if self._post_json(endpoint, item, fleet.get("token"), extra_headers) == "retry":
                still_failed.append(item)
        self._write_json_lines(self.snap_spool_path, still_failed)

    def _post_json(self, url: str, payload: dict, token: str | None,
                   extra_headers: dict | None = None) -> str:
        """POST JSON. Returns "ok" (2xx), "drop" (4xx: never retry, e.g. a bad
        token or malformed record) or "retry" (network error / 5xx)."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            if token:
                req.add_header("Authorization", f"Bearer {token}")
            for key, value in (extra_headers or {}).items():
                req.add_header(key, value)
            with urllib.request.urlopen(req, timeout=10) as resp:
                return "ok" if 200 <= resp.status < 300 else "retry"
        except urllib.error.HTTPError as exc:
            self.log(f"push to {url} rejected: HTTP {exc.code}")
            return "drop" if 400 <= exc.code < 500 else "retry"
        except (OSError, urllib.error.URLError, ValueError) as exc:
            self.log(f"push to {url} failed: {exc}")
            return "retry"

    @staticmethod
    def _read_json_lines(path: str) -> list[dict]:
        if not os.path.exists(path):
            return []
        out = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        out.append(json.loads(line))
        except (OSError, json.JSONDecodeError):
            pass
        return out

    SPOOL_MAX_LINES = 5000

    @classmethod
    def _write_json_lines(cls, path: str, items: list[dict]) -> None:
        """Atomically rewrite a spool, keeping at most the newest SPOOL_MAX_LINES."""
        try:
            if not items:
                if os.path.exists(path):
                    os.remove(path)
                return
            items = items[-cls.SPOOL_MAX_LINES:]
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                for item in items:
                    fh.write(json.dumps(item) + "\n")
            os.replace(tmp, path)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Snapshot assembly
# --------------------------------------------------------------------------- #

def build_snapshot(cfg: dict, identity: dict, state: dict | None = None) -> dict:
    """Assemble one merged per-machine record for the fleet dashboard.

    When `state` is given (the daemon's persisted state), the snapshot also
    carries `usage_deltas`: new assistant turns since the previous poll, with
    their transcript timestamps, so the collector can roll usage up per day.
    """
    accounts = detect_accounts(cfg)
    cc = next((a for a in accounts if a["source"] == "claude-code"), None)
    activity = scan_active_session(cfg)

    tokens = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0}
    tokens_by_model: dict = {}
    tokens_source = None
    model = None
    if cfg.get("transcript_usage", True) and activity.get("_transcript_path"):
        usage = transcript_usage(activity["_transcript_path"])
        if usage["ok"]:
            tokens = usage["tokens"]
            tokens_by_model = usage["tokens_by_model"]
            tokens_source = usage["tokens_source"]
            model = usage["model"]

    deltas: list[dict] = []
    sessions: list[dict] = []
    if cfg.get("transcript_usage", True):
        # --print has no persisted state: tail into a throwaway one so the
        # session list is still shown (nothing is pushed in that mode).
        tail_state = state if state is not None else {}
        try:
            deltas = transcript_deltas(cfg, tail_state)
        except Exception:  # transcript format drift must never break the snapshot
            deltas = []
        try:
            sessions = list_sessions(cfg, tail_state)
        except Exception:
            sessions = []
    sessions_active = sum(1 for s in sessions if s.get("active"))
    procs = claude_processes()

    return {
        "usage_deltas": deltas,
        "tokens_by_model": tokens_by_model,
        "sessions": sessions,                       # every session touched in 24 h, newest first
        "sessions_active": sessions_active,         # how many are running right now
        "claude_processes": procs,                  # running `claude` processes (best effort)
        "account_plan": (cc.get("plan") if cc else None),      # subscription: Max 20x / Pro / Team ...
        "account_limits": (cc.get("limits") if cc else None),  # cached /usage: 5 h + 7 day % used, resets
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "machine_id": identity.get("machine_id"),
        "hostname": identity["hostname"],
        "os_user": identity["os_user"],
        "terminal": identity["terminal"],
        "ip": identity.get("ip"),
        "platform": identity.get("platform"),
        "account_email": (cc.get("email") if cc else None),
        "org_name": (cc.get("org") if cc else None),
        "claude_code_active": activity["claude_code_active"],
        "session_active": activity["session_active"] or sessions_active > 0,
        "session_id": activity["session_id"],       # newest session (kept for older collectors)
        "current_model": model,
        "tokens": tokens,
        "tokens_source": tokens_source,   # OTEL fills this on the collector side
        "cost_usd": None,                 # OTEL-only, merged centrally
        "last_updated": activity["last_updated"],
        "browser_session": any(a["source"] == "browser" for a in accounts),
    }


# --------------------------------------------------------------------------- #
# State (last-seen accounts)
# --------------------------------------------------------------------------- #

def load_state(path: str) -> dict:
    p = expand(path)
    if not os.path.isfile(p):
        return {"accounts": {}}
    try:
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {"accounts": {}}


def save_state(path: str, state: dict) -> None:
    p = expand(path)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, p)


# --------------------------------------------------------------------------- #
# Core diff / event emission
# --------------------------------------------------------------------------- #

def poll_once(cfg: dict, reporter: Reporter, state: dict,
              startup: bool = False) -> dict:
    """Detect accounts, diff against prior state, emit events. Returns new state."""
    current = detect_accounts(cfg)
    current_map = {state_key(a): a for a in current}
    prev_map = state.get("accounts", {})

    prev_keys = set(prev_map)
    curr_keys = set(current_map)

    if startup:
        if current:
            for a in current:
                reporter.record("startup", a)
        else:
            reporter.record("startup", None, detail="no Claude account detected")
        # Startup already records presence; don't fire an immediate heartbeat.
        state["last_heartbeat"] = time.time()

    # Per-source switch detection for the emailed sources (claude-code, desktop).
    # Keys consumed by a switch are not also reported as login/logout.
    consumed: set[str] = set()
    for src in ("claude-code", "desktop"):
        prev_k = next((k for k in prev_keys
                       if prev_map[k]["source"] == src and prev_map[k].get("email")), None)
        curr_k = next((k for k in curr_keys
                       if current_map[k]["source"] == src and current_map[k].get("email")), None)
        prev_email = prev_map[prev_k]["email"] if prev_k else None
        curr_email = current_map[curr_k]["email"] if curr_k else None
        if prev_email and curr_email and prev_email != curr_email:
            reporter.record("switch", current_map[curr_k],
                            detail=f"from {prev_email} to {curr_email}")
            consumed.add(prev_k)
            consumed.add(curr_k)

    # Plain appear/disappear for everything not already reported as a switch.
    if not startup:
        for k in (curr_keys - prev_keys) - consumed:
            reporter.record("login", current_map[k])
        for k in (prev_keys - curr_keys) - consumed:
            gone = prev_map[k]
            reporter.record("logout", {
                "source": gone["source"], "email": gone.get("email"),
                "org": gone.get("org"), "detail": gone.get("detail", ""),
            })

    # Heartbeat for accounts that persist.
    hb = cfg.get("heartbeat_seconds", 3600)
    now = time.time()
    last_hb = state.get("last_heartbeat", 0)
    if current and hb and (now - last_hb) >= hb:
        for a in current:
            reporter.record("heartbeat", a)
        state["last_heartbeat"] = now

    state["accounts"] = {k: {"source": a["source"], "email": a.get("email"),
                             "org": a.get("org"), "detail": a.get("detail", "")}
                         for k, a in current_map.items()}

    # Push a merged per-machine snapshot to the fleet dashboard every cycle.
    try:
        reporter.push_snapshot(build_snapshot(cfg, reporter.identity, state))
    except Exception as exc:  # never let snapshot trouble stop event tracking
        reporter.log(f"snapshot error: {exc}")

    return state


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #

_STOP = False


def _handle_signal(signum, frame):  # noqa: ARG001
    global _STOP
    _STOP = True


def run_daemon(cfg: dict, reporter: Reporter) -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    interval = int(cfg.get("poll_interval_seconds", 15))
    state = load_state(cfg["state_file"])
    reporter.log(f"daemon start (interval={interval}s, sources={cfg.get('sources')})")
    state = poll_once(cfg, reporter, state, startup=True)
    save_state(cfg["state_file"], state)
    while not _STOP:
        for _ in range(interval):
            if _STOP:
                break
            time.sleep(1)
        if _STOP:
            break
        try:
            state = poll_once(cfg, reporter, state)
            save_state(cfg["state_file"], state)
        except Exception as exc:  # keep the daemon alive on transient errors
            reporter.log(f"poll error: {exc}")
    reporter.record("shutdown", None, detail="daemon stopping")
    reporter.log("daemon stopped")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Monitor the signed-in Claude account.")
    ap.add_argument("--config", help="path to config.json")
    ap.add_argument("--interval", type=int, help="override poll interval (seconds)")
    ap.add_argument("--once", action="store_true", help="write one snapshot and exit")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print current detection without writing")
    ap.add_argument("--replay", action="store_true",
                    help="push this machine's local history (report.jsonl + snapshots.jsonl) "
                         "to the collector once, then exit")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    if args.interval:
        cfg["poll_interval_seconds"] = args.interval

    identity = system_identity()

    if args.print_only:
        print(json.dumps(build_snapshot(cfg, identity), indent=2))
        return 0

    reporter = Reporter(cfg, identity)

    if args.replay:
        result = reporter.replay_history()
        reporter.log(f"replay done: {result}")
        print(json.dumps(result))
        return 0 if not result.get("failed_batches") else 1

    if args.once:
        state = load_state(cfg["state_file"])
        state = poll_once(cfg, reporter, state, startup=True)
        save_state(cfg["state_file"], state)
        reporter.log("single snapshot written")
        return 0

    run_daemon(cfg, reporter)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
