#!/usr/bin/env python3
"""provenance-gate: a Claude Code hook that authorizes outbound tool calls by provenance.

One script, three hook events (argv[1]):

* prompt - UserPromptSubmit: record what the user wrote (trusted).
* pre    - PreToolUse: for calls that leave the machine or change remote state
           (MCP write tools, WebFetch, network commands in Bash), check where each
           control value came from. If a value came only from tool output (untrusted)
           or was produced by the model after untrusted content arrived, ask the user,
           and say exactly which value and why.
* post   - PostToolUse: record tool output as untrusted. If a call we asked about ran,
           the user approved it, so its destination values become "known" and are not
           asked about again.

It never reads text to decide whether it "looks malicious". Standard library only.
State lives in ~/.provenance-gate (override with PGATE_HOME). PGATE_MODE=deny turns
"ask" into "deny" (for unattended agents).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HOME = Path(os.environ.get("PGATE_HOME") or os.environ.get("CLAUDE_PLUGIN_DATA") or Path.home() / ".provenance-gate")
MODE = os.environ.get("PGATE_MODE", "ask")
MAX_UNTRUSTED = 2_000_000  # characters of tool output kept per session

# --- which calls are gated -------------------------------------------------------

# MCP tools: the part after mcp__<server>__ is classified by its verb, as in the AgentDojo POC.
SINK_VERBS = ("send", "share", "post", "create", "update", "delete", "remove", "add", "invite",
              "append", "schedule", "reserve", "cancel", "reschedule", "push", "merge", "comment",
              "reply", "forward", "publish", "upload", "write", "edit", "move", "transfer", "pay",
              "execute", "run", "set", "fork", "close", "assign", "label", "trash")
READ_VERBS = ("get", "list", "search", "read", "fetch", "find", "query", "view", "download", "describe")

# Free text is data. Everything else in a gated call is control (who / where / which / how much).
CONTENT_ARGS = {"body", "subject", "content", "description", "title", "text", "message", "markdown",
                "comment", "notes", "summary", "html", "attachments", "commit_message", "prompt"}
# Network commands in Bash: their URLs, hosts and addresses are control values.
NET_CMD = re.compile(r"(?:^|[\s;&|(`])(curl|wget|http|httpie|nc|ncat|ssh|scp|rsync|sftp|ftp|telnet|"
                     r"git\s+push|git\s+remote\s+add|gh\s+(?:api|pr|issue|gist|release|repo)|"
                     r"aws\s+s3|gsutil|mail|sendmail)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+|(?<![\w@.])(?:www\.)[a-z0-9.-]+\.[a-z]{2,}[^\s'\"<>)\]]*", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
HOST_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|ai|app|co|xyz|site|info|me|sh|cloud|"
                     r"ru|cn|top|link|click)(?![\w-])", re.I)


def gated(tool: str, args: dict) -> bool:
    if tool in ("WebFetch",):
        return True
    if tool == "Bash":
        return bool(NET_CMD.search(str(args.get("command", ""))))
    if tool.startswith("mcp__"):
        op = tool.split("__", 2)[-1].lower()
        if op.startswith(READ_VERBS) and "url" not in args:
            return False
        return op.startswith(SINK_VERBS) or "url" in args or "to" in args or "recipient" in args
    return False


def control_values(tool: str, args: dict) -> list[tuple[str, str]]:
    """(argument, value) pairs whose origin decides the call."""
    out = []
    if tool == "Bash":
        cmd = str(args.get("command", ""))
        for v in URL_RE.findall(cmd) + EMAIL_RE.findall(cmd) + HOST_RE.findall(cmd):
            out.append(("command", v))
        return out
    for k, v in args.items():
        if k in CONTENT_ARGS:
            # a link inside free text is a destination too
            for u in URL_RE.findall(" ".join(_atoms(v))):
                out.append((k, u))
            continue
        out.extend((k, a) for a in _atoms(v))
    return out


def _atoms(v) -> list[str]:
    if v is None or isinstance(v, bool):
        return []
    if isinstance(v, (list, tuple)):
        return [a for x in v for a in _atoms(x)]
    if isinstance(v, dict):
        return [a for x in v.values() for a in _atoms(x)]
    s = str(v).strip()
    return [s] if s else []


def _in(text: str, atom: str) -> bool:
    a = atom.lower().rstrip(".,;:/")
    if len(a) < 2:
        return True  # single characters carry no provenance signal
    return re.search(r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])", text) is not None


# --- state ----------------------------------------------------------------------

def _session_path(sid: str) -> Path:
    return HOME / "sessions" / (hashlib.sha1(sid.encode()).hexdigest()[:16] + ".json")


def load(sid: str) -> dict:
    p = _session_path(sid)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {"user": "", "untrusted": "", "tainted": False, "asked": {}, "ids": []}


def save(sid: str, st: dict) -> None:
    p = _session_path(sid)
    p.parent.mkdir(parents=True, exist_ok=True)
    st["untrusted"] = st["untrusted"][-MAX_UNTRUSTED:]
    p.write_text(json.dumps(st))


def known() -> set[str]:
    try:
        return set(json.loads((HOME / "known.json").read_text()))
    except (OSError, ValueError):
        return set()


def remember(values: list[str]) -> None:
    k = known() | {v.lower() for v in values}
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "known.json").write_text(json.dumps(sorted(k), indent=1))


def log(event: dict) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    with open(HOME / "decisions.jsonl", "a") as f:
        f.write(json.dumps({"t": round(time.time()), **event}) + "\n")


# --- decisions --------------------------------------------------------------------

def provenance(st: dict, value: str) -> str:
    if _in(st["user"], value):
        return "user"
    if _in(st["untrusted"], value):
        return "untrusted"
    return "model"


ID_ARG = re.compile(r"(^|_)(id|number|num|key)$")


def structured_ids(resp) -> set[str]:
    """IDs of objects a tool returned, from the parsed structure (never from free text, so an
    attacker cannot mint one by writing "id: 13" in an issue body)."""
    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except ValueError:
            return set()
    found: set[str] = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if ID_ARG.search(str(k).lower()) and isinstance(v, (str, int)) and not isinstance(v, bool):
                    found.add(str(v).lower())
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(resp)
    return found


def decide(st: dict, tool: str, args: dict) -> tuple[str, str, list[str]]:
    """Returns (decision, reason, values to remember if the user approves)."""
    if not gated(tool, args):
        return "allow", "", []
    kn = known()
    problems, dests = [], []
    for k, v in control_values(tool, args):
        dests.append(v)
        if v.lower() in kn:
            continue
        # which object: an ID the user's own data returned as a structured field (not for deletes)
        if ID_ARG.search(k.lower()) and v.lower() in st.get("ids", []) and "delete" not in tool.lower():
            continue
        p = provenance(st, v)
        if p == "untrusted":
            problems.append(f"{k}={v!r} appeared only in content from a tool, not in anything you wrote")
        elif p == "model" and st["tainted"]:
            problems.append(f"{k}={v!r} was produced by the model after it read external content")
    if not problems:
        return "allow", "", []
    reason = "provenance-gate: " + "; ".join(problems[:3]) + (" (and more)" if len(problems) > 3 else "")
    return ("deny" if MODE == "deny" else "ask"), reason, dests


def call_key(tool: str, args: dict) -> str:
    return hashlib.sha1((tool + json.dumps(args, sort_keys=True, default=str)).encode()).hexdigest()


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    data = json.load(sys.stdin)
    sid = data.get("session_id", "default")
    st = load(sid)

    if event == "prompt":
        st["user"] += "\n" + str(data.get("prompt", "")).lower()
        save(sid, st)
        return

    tool, args = data.get("tool_name", ""), data.get("tool_input") or {}

    if event == "pre":
        decision, reason, dests = decide(st, tool, args)
        if decision == "allow":
            return
        st["asked"][call_key(tool, args)] = dests
        save(sid, st)
        log({"session": sid[:8], "tool": tool, "decision": decision, "reason": reason})
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "permissionDecision": decision,
                                                 "permissionDecisionReason": reason}}))
        return

    if event == "post":
        key = call_key(tool, args)
        if key in st["asked"]:  # it ran, so the user approved it
            remember(st["asked"].pop(key))
            log({"session": sid[:8], "tool": tool, "decision": "approved"})
        resp = data.get("tool_response", data.get("tool_output", ""))
        st["ids"] = sorted(set(st.get("ids", [])) | structured_ids(resp))[-5000:]
        text = resp if isinstance(resp, str) else json.dumps(resp, default=str)
        # Only tools that bring in content someone else could have written taint the session.
        if tool.startswith("mcp__") or tool in ("WebFetch", "WebSearch", "Bash", "Read", "Grep"):
            st["untrusted"] += "\n" + text.lower()
            st["tainted"] = True
        save(sid, st)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # noqa: BLE001
        # Fail closed on the gate itself: an outbound call we could not check is put to the user.
        if len(sys.argv) > 1 and sys.argv[1] == "pre":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                                     "permissionDecisionReason": f"provenance-gate could not check this call: {e}"}}))
        else:
            print(f"provenance-gate error: {e}", file=sys.stderr)
