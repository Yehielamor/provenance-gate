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
# bare host:port and IP addresses (localhost:3000, 10.0.0.5, root@164.90.1.2)
ADDR_RE = re.compile(r"(?<![\w.-])(?:localhost|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?(?:/[^\s'\"<>)]*)?")
HOST_RE = re.compile(r"(?<![\w.-])(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|ai|app|co|xyz|site|info|me|sh|cloud|"
                     r"ru|cn|top|link|click)(?![\w-])", re.I)


# --- secrets (the flow rule) ------------------------------------------------------

SENSITIVE_PATH = re.compile(r"(^|/)(\.env(?!\.(?:example|sample|template|dist|defaults)\b)(\.[\w.-]+)?|\.envrc|\.netrc|\.npmrc|\.pypirc|\.git-credentials|"
                            r"id_(rsa|ed25519|ecdsa|dsa)[^/]*|[^/]*\.(pem|key|p12|pfx|jks|keystore)|"
                            r"credentials(\.json)?|secrets?(\.\w+)?|service[-_]account[^/]*\.json|kubeconfig)$|"
                            r"(^|/)\.(ssh|aws|gnupg|kube|docker)/", re.I)
SECRET_CMD = re.compile(r"(^|[\s;&|(])(printenv|env\s*($|[|;&>])|set\s*($|[|;&>])|security\s+find-\w+-password|gh\s+auth\s+token|"
                        r"aws\s+configure\s+get|gcloud\s+auth\s+print-\w+-token|op\s+read|vault\s+(kv\s+)?get)\b")
SECRET_VALUE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{30,}|xox[abposr]-[\w-]{10,}|"
    r"sk-[A-Za-z0-9_-]{20,}|sk_(live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{30,}|hf_[A-Za-z0-9]{30,}|"
    r"glpat-[\w-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
# KEY=value / "key": "value" lines in sensitive files: the value is the secret
ASSIGN = re.compile(r"""(?im)^\s*(?:export\s+)?[\w.-]*(?:key|token|secret|pass(?:word)?|pwd|auth|credential)[\w.-]*\s*[:=]\s*["']?([^\s"'#]{8,})""")
TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.]{8,}")
EXTERNAL_TOOLS = ("WebFetch", "WebSearch")
READ_CMD = re.compile(r"(^|[\s;&|(])(cat|less|more|head|tail|grep|rg|awk|sed|jq|yq|bat|strings|xxd|base64|source|\.)\s")
# Tools that return content someone else wrote. MCP tools count when they read (get/list/search/...),
# except servers that only report local app state.
LOCAL_MCP = re.compile(r"^mcp__(ccd_[a-z_]+|scheduled-tasks|terminal|visualize|mcp-registry)__")


def brings_external(tool: str, cmd: str) -> bool:
    if tool in EXTERNAL_TOOLS:
        return True
    if tool.startswith("mcp__"):
        op = tool.split("__", 2)[-1].lower()
        return not LOCAL_MCP.match(tool) and (op.startswith(READ_VERBS) or "page" in op or "navigate" in op)
    if tool == "Bash":  # the output of a web request to somewhere else, not of ssh or a local server
        if not re.search(r"(^|[\s;&|(])(curl|wget|http|httpie)\b", cmd):
            return False
        urls = URL_RE.findall(cmd) + HOST_RE.findall(cmd) + ADDR_RE.findall(cmd)
        return not urls or any(not LOCAL_DEST.match(u) for u in urls)
    return False


def reads_sensitive(tool: str, args: dict, cmd: str) -> str:
    path = str(args.get("file_path") or args.get("path") or "")
    if tool in ("Read", "Grep") and SENSITIVE_PATH.search(path):
        return path
    if tool == "Bash":
        if SECRET_CMD.search(cmd):
            return cmd[:60]
        if READ_CMD.search(cmd):
            for w in re.split(r"[\s;&|<>()'\"]+", cmd):
                if SENSITIVE_PATH.search(w):
                    return w
    return ""


def _strings(x) -> str:
    """All string values inside a tool response, joined with newlines (so line-based patterns work
    on file contents that arrive JSON-escaped)."""
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return "\n".join(_strings(v) for v in x.values())
    if isinstance(x, list):
        return "\n".join(_strings(v) for v in x)
    return ""


HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n.*?\n\s*\2\s*(?:\n|$)", re.S)


def command_head(cmd: str) -> str:
    """The command without heredoc bodies. Used only to decide whether a command *read* something
    sensitive or external: text the agent writes into a heredoc (code, docs) is neither. Gating an
    outbound call still looks at the whole command."""
    return HEREDOC.sub("<<heredoc\n", cmd)


def _fp(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:20]


def secrets_in(text: str, sensitive_source: bool) -> set[str]:
    vals = {m.group(0) for m in SECRET_VALUE.finditer(text)}
    if sensitive_source:
        vals |= {m.group(1) for m in ASSIGN.finditer(text)}
    return {_fp(v) for v in vals if len(v) >= 8}


def carries_secret(st: dict, args: dict) -> bool:
    fps = set(st.get("secrets", []))
    if not fps:
        return False
    blob = json.dumps(args, default=str)
    return any(_fp(t) in fps for t in TOKEN.findall(blob)) or any(
        _fp(m.group(0)) in fps for m in SECRET_VALUE.finditer(blob))


# Destinations on this machine or the local network: nothing leaves the machine.
LOCAL_DEST = re.compile(r"^(?:[a-z+]+://)?(?:[^@/\s]+@)?(localhost|127(?:\.\d+){3}|0\.0\.0\.0|\[?::1\]?|"
                        r"10(?:\.\d+){3}|192\.168(?:\.\d+){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d+){2}|[\w-]+\.(?:local|localhost|test|internal))"
                        r"(?=[:/?#]|$)|^file://", re.I)


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
        for v in URL_RE.findall(cmd) + EMAIL_RE.findall(cmd) + HOST_RE.findall(cmd) + ADDR_RE.findall(cmd):
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
        return {"user": "", "untrusted": "", "tainted": False, "asked": {}, "ids": [],
                "private": False, "external": False, "secrets": [], "flow_ok": [], "pending_flow": {}}


def load_checked(sid: str) -> dict:
    st = load(sid)
    revalidate(st)
    return st


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


ID_ARG = re.compile(r"((^|_)(id|number|num|key)|[a-z](Id|ID|Number|Key))$")


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
                if ID_ARG.search(str(k)) and isinstance(v, (str, int)) and not isinstance(v, bool):
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
    # Flow rule 1: a secret this session read is inside what is about to leave. Always asked,
    # whoever chose the destination.
    if carries_secret(st, args):
        src = st.get("private_ev", {}).get("label", "a sensitive source")
        problems.append(f"this call contains a secret that came from {src}")
    # Flow rule 2: private data and external content in one session, then egress: asked once per destination.
    hosts = sorted({_host(v) for _, v in control_values(tool, args) if not LOCAL_DEST.match(v)}) or [tool]
    new_hosts = [h for h in hosts if h not in st.get("flow_ok", [])]
    flow_key = ",".join(new_hosts)
    if st.get("private") and st.get("external") and new_hosts:
        problems.append(f"this session read {st.get('private_ev', {}).get('label', 'sensitive data')} and also "
                        f"{st.get('external_ev', {}).get('label', 'external content')}; "
                        f"data could leave with this call to {', '.join(new_hosts)}")
        st.setdefault("pending_flow", {})[call_key(tool, args)] = flow_key
    cv = control_values(tool, args)
    outbound = [(k, v) for k, v in cv if not LOCAL_DEST.match(v.strip())]
    if cv and not outbound and all(re.match(r"https?://|www\.|[\w.-]+:\d", v) or LOCAL_DEST.match(v) for _, v in cv):
        return "allow", "", []  # every destination is local (a dev server, the local network)
    for k, v in outbound:
        dests.append(v)
        if v.lower() in kn:
            continue
        # which object: an ID the user's own data returned as a structured field (not for deletes)
        if ID_ARG.search(k) and v.lower() in st.get("ids", []) and "delete" not in tool.lower():
            continue
        p = provenance(st, v)
        what = f"destination {v!r} in the command" if tool == "Bash" else f"{k}={v!r}"
        if p == "untrusted":
            problems.append(f"{what} appeared only in content from a tool, not in anything you wrote")
        elif p == "model" and st["tainted"]:
            problems.append(f"{what} was produced by the model after it read external content")
    if not problems:
        return "allow", "", []
    reason = "provenance-gate: " + "; ".join(problems[:3]) + (" (and more)" if len(problems) > 3 else "")
    return ("deny" if MODE == "deny" else "ask"), reason, dests


def _host(v: str) -> str:
    m = re.match(r"(?:https?://)?(?:[^@/\s]+@)?([^/:?#\s]+)", v.lower())
    return m.group(1) if m else v.lower()


def label_private(tool: str, args: dict, source: str) -> str:
    path = str(args.get("file_path") or args.get("path") or "")
    if path:
        return f"the file {Path(path).name}"
    if source and tool == "Bash":
        m = SECRET_CMD.search(source)
        if m:
            return f"the output of `{m.group(2).strip()}`"
        return f"the file {Path(source).name}" if "/" in source or source.startswith(".") else "a sensitive file"
    return {"WebFetch": "a web page", "Bash": "a command's output"}.get(tool, f"the output of {tool.split('__')[-1]}") + \
        " that contained a key or token"


def label_external(tool: str, args: dict, cmd: str) -> str:
    if tool == "WebSearch":
        return "a web search"
    url = str(args.get("url") or "")
    if not url and tool == "Bash":
        urls = URL_RE.findall(cmd) + HOST_RE.findall(cmd)
        url = next((u for u in urls if not LOCAL_DEST.match(u)), "")
    if url:
        return f"the site {_host(url)}"
    if tool.startswith("mcp__"):
        return f"the {tool.split('__')[1]} connector"
    return "external content"


def revalidate(st: dict) -> None:
    """Drop flow flags whose recorded evidence no longer qualifies under the current rules (a rule
    was fixed since the session was marked). Secrets actually seen are never dropped."""
    ev = st.get("private_ev")
    if st.get("private") and ev and not st.get("secrets") and not reads_sensitive(ev["tool"], ev["args"], ev["cmd"]):
        st["private"] = False
        st.pop("private_ev", None)
    ev = st.get("external_ev")
    if st.get("external") and ev and not brings_external(ev["tool"], ev["cmd"]):
        st["external"] = False
        st.pop("external_ev", None)
    # sessions marked before evidence was recorded: keep only what can still be justified
    if st.get("private") and not st.get("private_ev") and not st.get("secrets"):
        st["private"] = False
    if st.get("external") and not st.get("external_ev"):
        st["external"] = False


def reset_all() -> int:
    """`pgate.py reset`: clear the flow flags (not approvals, not the prompt history) of every session."""
    n = 0
    for p in (HOME / "sessions").glob("*.json"):
        st = json.loads(p.read_text())
        for k in ("private", "external"):
            st[k] = False
        for k in ("private_ev", "external_ev", "private_from", "external_from", "secrets"):
            st.pop(k, None)
        p.write_text(json.dumps(st))
        n += 1
    return n


def call_key(tool: str, args: dict) -> str:
    return hashlib.sha1((tool + json.dumps(args, sort_keys=True, default=str)).encode()).hexdigest()


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    if event == "reset":
        print(f"provenance-gate: cleared flow flags in {reset_all()} session(s)")
        return
    out = handle(event, json.load(sys.stdin))
    if out:
        print(json.dumps(out))


def handle(event: str, data: dict) -> dict | None:
    """One hook event. Returns the hook's JSON output, or None (no opinion). Also used by the
    offline benchmarks, which feed recorded sessions through exactly this function."""
    sid = data.get("session_id", "default")
    st = load_checked(sid)

    if event == "prompt":
        st["user"] += "\n" + str(data.get("prompt", "")).lower()
        save(sid, st)
        return None

    tool, args = data.get("tool_name", ""), data.get("tool_input") or {}

    if event == "pre":
        decision, reason, dests = decide(st, tool, args)
        if decision == "allow":
            save(sid, st)
            return None
        st["asked"][call_key(tool, args)] = dests
        save(sid, st)
        log({"session": sid[:8], "tool": tool, "decision": decision, "reason": reason})
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                       "permissionDecisionReason": reason}}

    if event == "post":
        key = call_key(tool, args)
        if key in st["asked"]:  # it ran, so the user approved it
            remember(st["asked"].pop(key))
            if key in st.get("pending_flow", {}):
                st["flow_ok"] = sorted(set(st.get("flow_ok", [])) | set(st["pending_flow"].pop(key).split(",")))
            log({"session": sid[:8], "tool": tool, "decision": "approved"})
        resp = data.get("tool_response", data.get("tool_output", ""))
        st["ids"] = sorted(set(st.get("ids", [])) | structured_ids(resp))[-5000:]
        text = resp if isinstance(resp, str) else json.dumps(resp, default=str)
        # Private data: a sensitive file or a secret-printing command, or secrets anywhere in output.
        cmd = command_head(str(args.get("command", "")))
        source = reads_sensitive(tool, args, cmd)
        found = secrets_in(_strings(resp), bool(source))
        if source or found:
            st["private"] = True
            st.setdefault("private_ev", {"tool": tool, "args": {k: args[k] for k in ("file_path", "path") if k in args},
                                         "cmd": cmd[:300], "label": label_private(tool, args, source)})
            st["secrets"] = sorted(set(st.get("secrets", [])) | found)[-2000:]
        # External content: the web, MCP servers, and network commands.
        if brings_external(tool, cmd):
            st["external"] = True
            st.setdefault("external_ev", {"tool": tool, "cmd": cmd[:300], "label": label_external(tool, args, cmd)})
        # Only tools that bring in content someone else could have written taint the session.
        if tool.startswith("mcp__") or tool in ("WebFetch", "WebSearch", "Bash", "Read", "Grep"):
            st["untrusted"] += "\n" + text.lower()
            st["tainted"] = True
        save(sid, st)
    return None


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
