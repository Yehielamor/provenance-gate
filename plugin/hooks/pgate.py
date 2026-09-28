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
MAX_CALL = 200_000  # an outbound call larger than this is not scanned; it is put to the user

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
EMAIL_RE = re.compile(r"[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
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


def brings_external(tool: str, cmd: str, args: dict | None = None) -> bool:
    if tool in EXTERNAL_TOOLS:
        return True
    if tool.startswith("mcp__"):
        op = tool.split("__", 2)[-1].lower()
        url = str((args or {}).get("url") or "")
        if url and LOCAL_DEST.match(url):  # a browser tool on your own local app
            return False
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


MAX_DEPTH = 64


def _walk(x):
    """Yield (key, value) for every scalar in a nested structure, iteratively and depth-capped, so a
    deeply nested tool output cannot crash the gate (a crash would skip marking the session)."""
    stack = [(None, x, 0)]
    while stack:
        k, v, d = stack.pop()
        if isinstance(v, dict) and d < MAX_DEPTH:
            stack.extend((kk, vv, d + 1) for kk, vv in v.items())
        elif isinstance(v, (list, tuple)) and d < MAX_DEPTH:
            stack.extend((k, vv, d + 1) for vv in v)
        elif isinstance(v, (dict, list, tuple)):
            yield k, json.dumps(v, default=str)[:100000]
        else:
            yield k, v


def _strings(x) -> str:
    """All string values inside a tool response, joined with newlines (so line-based patterns work
    on file contents that arrive JSON-escaped)."""
    return "\n".join(v for _, v in _walk(x) if isinstance(v, str))


HEREDOC_START = re.compile(r"<<-?[ \t]*(['\"]?)(\w{1,64})\1[^\n]{0,4000}\n")


def command_head(cmd: str) -> str:
    """The command without heredoc bodies. Used only to decide whether a command *read* something
    sensitive or external: text the agent writes into a heredoc (code, docs) is neither. Gating an
    outbound call still looks at the whole command. Linear-time (no backtracking regex)."""
    out, i = [], 0
    while True:
        m = HEREDOC_START.search(cmd, i)
        if not m:
            out.append(cmd[i:])
            return "".join(out)
        out.append(cmd[i:m.start()] + "<<heredoc\n")
        body_start, term = m.end(), m.group(2)
        pos = body_start
        while True:
            nl = cmd.find("\n", pos)
            line = cmd[pos:] if nl < 0 else cmd[pos:nl]
            if line.strip() == term:
                i = len(cmd) if nl < 0 else nl + 1
                break
            if nl < 0:
                return "".join(out)  # unterminated: the rest is heredoc body
            pos = nl + 1


def _fp(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:20]


def redact(text: str) -> str:
    """Tool output is kept (to trace where values came from), but never with secrets in it."""
    text = SECRET_VALUE.sub("[secret]", text)
    return ASSIGN.sub(lambda m: m.group(0).replace(m.group(1), "[secret]"), text)


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


# Interpreter one-liners can make network requests without any network binary in sight.
EVAL_CMD = re.compile(r"(?:^|[\s;&|(])(python[\d.]*|node|ruby|perl|php|deno|bun)\s+(?:-[a-z]*[ce]\b|-r\b|eval\b|--eval\b)", re.I)
# Hosts written without a scheme: a dotted name with an alphabetic TLD, not a file name.
BARE_HOST = re.compile(r"(?<![\w@./-])((?:[a-z0-9][a-z0-9-]{0,62}\.){1,8}[a-z]{2,24})(?::\d{1,5})?(/[^\s'\"<>)]{0,2000})?(?![\w(])", re.I)
GTLDS = {"com", "net", "org", "io", "dev", "ai", "app", "co", "xyz", "site", "info", "me", "cloud", "online", "store",
         "tech", "biz", "top", "link", "click", "live", "shop", "pro", "run", "page", "zip", "mov", "example", "test",
         "invalid", "onion", "workers", "vercel", "digital", "email", "network", "systems", "services", "global", "one"}
FILE_EXT = {"py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "json", "md", "txt", "sh", "yml", "yaml", "toml", "lock",
            "log", "html", "htm", "css", "go", "rs", "rb", "java", "kt", "swift", "c", "h", "cc", "cpp", "hpp", "env",
            "cfg", "ini", "conf", "xml", "csv", "tsv", "png", "jpg", "jpeg", "gif", "svg", "pdf", "gz", "zip", "tar",
            "tgz", "whl", "so", "dylib", "exe", "bin", "out", "pem", "key", "crt", "db", "sqlite", "sql", "php", "pl",
            "lua", "vue", "scss", "map", "wasm", "ipynb", "jsonl", "parquet", "bak"}
CWD = ""  # set per event from the hook input, to tell files from hostnames


def bare_hosts(text: str) -> list[str]:
    out = []
    for m in BARE_HOST.finditer(text):
        tld = m.group(1).rsplit(".", 1)[-1].lower()
        if not (tld in GTLDS or (len(tld) == 2 and tld not in FILE_EXT)):
            continue  # json.load, com.apple.quarantine, a.b.c: not hostnames
        if tld in FILE_EXT or (CWD and os.path.exists(os.path.join(CWD, m.group(0)))):
            continue
        out.append(m.group(0))
    return out


def gated(tool: str, args: dict) -> bool:
    """Fail closed: anything that is not clearly a local read or local work is checked."""
    if tool in ("WebFetch",):
        return True
    if tool == "Bash":
        cmd = str(args.get("command", ""))
        return bool(NET_CMD.search(cmd) or EVAL_CMD.search(cmd) or re.search(r"git\s+remote\s+(add|set-url)\b", cmd))
    if tool.startswith("mcp__"):
        op = tool.split("__", 2)[-1].lower()
        if op.startswith(READ_VERBS) and not ({"url", "to", "recipient", "recipients", "email"} & set(args)):
            return False
        return not LOCAL_MCP.match(tool)  # any other verb (notify, message_send, ...) may send
    return False


def git_remotes(cmd: str) -> list[str]:
    """`git push` sends to a remote whose URL is not in the command: resolve it from the repo."""
    out = []
    for m in re.finditer(r"git\s+(?:-C\s+(\S+)\s+)?push\b([^;&|\n]*)", cmd):
        where = m.group(1) or CWD or "."
        words = [w for w in m.group(2).split() if not w.startswith("-")]
        remote = words[0] if words else "origin"
        if URL_RE.match(remote) or "@" in remote:
            continue  # an explicit URL is extracted elsewhere
        try:
            import subprocess
            r = subprocess.run(["git", "-C", where, "remote", "get-url", "--push", remote], capture_output=True,
                               text=True, timeout=2)
            if r.returncode == 0 and r.stdout.strip():
                out.append(r.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return out


def control_values(tool: str, args: dict) -> list[tuple[str, str]]:
    """(argument, value) pairs whose origin decides the call."""
    out = []
    if tool == "Bash":
        cmd = str(args.get("command", ""))
        seen = set()
        for v in URL_RE.findall(cmd) + EMAIL_RE.findall(cmd) + ADDR_RE.findall(cmd) + bare_hosts(cmd) + git_remotes(cmd):
            if v not in seen and not any(v in s for s in seen):
                seen.add(v)
                out.append(("command", v))
        return out
    for k, v in args.items():
        if k in CONTENT_ARGS:
            # a link or address inside free text is a destination too (with or without a scheme)
            text = " ".join(_atoms(v))
            for u in URL_RE.findall(text) + EMAIL_RE.findall(text) + [h for h in bare_hosts(text) if "/" in h]:
                out.append((k, u))
            continue
        out.extend((k, a) for a in _atoms(v))
    return out


def _atoms(v) -> list[str]:
    out = []
    for _, x in _walk(v):
        if x is None or isinstance(x, bool):
            continue
        s = str(x).strip()
        if s:
            out.append(s)
    return out


def _in(text: str, atom: str) -> bool:
    a = atom.lower().rstrip(".,;:/")
    if len(a) < 2:
        return True  # single characters carry no provenance signal
    return re.search(r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])", text) is not None


# --- state ----------------------------------------------------------------------

def _session_path(sid: str) -> Path:
    return HOME / "sessions" / (hashlib.sha1(sid.encode()).hexdigest()[:16] + ".json")


DEFAULT_STATE = {"user": "", "untrusted": "", "tainted": False, "asked": {}, "ids": [], "private": False,
                 "external": False, "secrets": [], "flow_ok": [], "pending_flow": {}}


def load(sid: str) -> dict:
    p = _session_path(sid)
    try:
        st = json.loads(p.read_text())
        if not isinstance(st, dict):
            raise ValueError("state is not an object")
        for k, dv in DEFAULT_STATE.items():  # repair missing or wrongly typed fields
            if not isinstance(st.get(k), type(dv)):
                st[k] = type(dv)(dv) if not isinstance(dv, (dict, list)) else type(dv)()
        return st
    except (OSError, ValueError):
        return {"user": "", "untrusted": "", "tainted": False, "asked": {}, "ids": [],
                "private": False, "external": False, "secrets": [], "flow_ok": [], "pending_flow": {}}


def load_checked(sid: str) -> dict:
    st = load(sid)
    revalidate(st)
    return st


def _private_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(HOME, 0o700)
    except OSError:
        pass


def save(sid: str, st: dict) -> None:
    p = _session_path(sid)
    _private_dir(p.parent)
    st["untrusted"] = st["untrusted"][-MAX_UNTRUSTED:]
    p.write_text(json.dumps(st))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def known() -> set[str]:
    try:
        k = json.loads((HOME / "known.json").read_text())
        return {str(x) for x in k} if isinstance(k, list) else set()
    except (OSError, ValueError):
        return set()


def remember(values: list[str]) -> None:
    k = known() | {v.lower() for v in values}
    HOME.mkdir(parents=True, exist_ok=True)
    (HOME / "known.json").write_text(json.dumps(sorted(k), indent=1))


class _Lock:
    """One lock for all state: hook processes run in parallel and read-modify-write the same files."""

    def __enter__(self):
        _private_dir(HOME)
        self.f = open(HOME / ".lock", "a")
        try:
            import fcntl
            fcntl.flock(self.f, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass  # no flock (Windows): best effort
        return self

    def __exit__(self, *exc):
        self.f.close()


def prune(days: int = 14, max_log: int = 5_000_000) -> None:
    """Keep state bounded: drop sessions untouched for `days`, rotate the decision log."""
    cutoff = time.time() - days * 86400
    for p in (HOME / "sessions").glob("*.json"):
        try:
            if p.stat().st_mtime < cutoff:
                p.unlink()
        except OSError:
            pass
    lg = HOME / "decisions.jsonl"
    try:
        if lg.stat().st_size > max_log:
            lg.replace(HOME / "decisions.1.jsonl")
    except OSError:
        pass


def log(event: dict) -> None:
    _private_dir(HOME)
    with open(HOME / "decisions.jsonl", "a") as f:
        f.write(json.dumps({"t": round(time.time()), **event}) + "\n")


# --- decisions --------------------------------------------------------------------

def provenance(st: dict, value: str) -> str:
    if _in(st["user"], value):
        return "user"
    if _in(st["untrusted"], value):
        return "untrusted"
    return "model"


DEST_ARGS = {"url", "uri", "href", "link", "to", "cc", "bcc", "recipient", "recipients", "email", "emails",
             "address", "channel", "channel_id", "user", "user_email", "users", "participants", "attendees",
             "host", "hostname", "endpoint", "webhook", "webhook_url", "callback_url", "target", "destination",
             "server", "domain", "phone", "number_to", "iban", "account"}
ID_ARG = re.compile(r"((^|_)(id|number|num|key)|[a-z](Id|ID|Number|Key))$")


def structured_ids(resp) -> set[str]:
    """IDs of objects a tool returned, from the parsed structure (never from free text, so an
    attacker cannot mint one by writing "id: 13" in an issue body)."""
    if isinstance(resp, str):
        try:
            resp = json.loads(resp)
        except ValueError:
            return set()
    return {str(v).lower() for k, v in _walk(resp)
            if k is not None and ID_ARG.search(str(k)) and isinstance(v, (str, int)) and not isinstance(v, bool)}


def decide(st: dict, tool: str, args: dict) -> tuple[str, str, list[str]]:
    """Returns (decision, reason, values to remember if the user approves)."""
    if not gated(tool, args):
        return "allow", "", []
    size = len(json.dumps(args, default=str))
    if size > MAX_CALL:  # fail closed rather than spend seconds scanning (or let padding hide a destination)
        return ("deny" if MODE == "deny" else "ask"), \
            f"provenance-gate: this outbound call is too large to check ({size:,} characters)", []
    kn = known()
    problems, dests = [], []
    # Flow rule 1: a secret this session read is inside what is about to leave. Always asked,
    # whoever chose the destination.
    if carries_secret(st, args):
        src = st.get("private_ev", {}).get("label", "a sensitive source")
        problems.append(f"this call contains a secret that came from {src}")
    cv = control_values(tool, args)
    unknown_verb = tool.startswith("mcp__") and not tool.split("__", 2)[-1].lower().startswith(SINK_VERBS)
    if unknown_verb:
        # checked because it might send (fail closed), but only where it would send to
        cv = [(k, v) for k, v in cv if k.lower() in DEST_ARGS or k in CONTENT_ARGS]
    # Flow rule 2: private data and external content in one session, then egress: asked once per destination.
    hosts = sorted({_host(v) for _, v in cv if not LOCAL_DEST.match(v)}) or [tool]
    new_hosts = [h for h in hosts if h not in st.get("flow_ok", [])]
    flow_key = ",".join(new_hosts)
    # a click or a screenshot (unknown verb, no destination) is not a way out; secrets are checked above
    if st.get("private") and st.get("external") and new_hosts and not (unknown_verb and not cv):
        problems.append(f"this session read {st.get('private_ev', {}).get('label', 'sensitive data')} and also "
                        f"{st.get('external_ev', {}).get('label', 'external content')}; "
                        f"data could leave with this call to {', '.join(new_hosts)}")
        st.setdefault("pending_flow", {})[call_key(tool, args)] = flow_key
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
    if st.get("external") and ev and not ev.get("forced") and not brings_external(ev["tool"], ev["cmd"], ev.get("args")):
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
        with _Lock():
            print(f"provenance-gate: cleared flow flags in {reset_all()} session(s)")
        return
    data = json.load(sys.stdin)
    with _Lock():
        if event == "prompt" and not (HOME / ".pruned").exists() or \
                (HOME / ".pruned").exists() and time.time() - (HOME / ".pruned").stat().st_mtime > 86400:
            prune()
            (HOME / ".pruned").touch()
        try:
            out = handle(event, data)
        except Exception:
            if event == "post":  # we could not read this output: assume the worst about it
                st = load(data.get("session_id", "default"))
                st.update(tainted=True, external=True)
                st.setdefault("external_ev", {"tool": data.get("tool_name", ""), "cmd": "", "forced": True,
                                              "label": "a tool output the gate could not read"})
                save(data.get("session_id", "default"), st)
            raise
    if out:
        print(json.dumps(out))


def handle(event: str, data: dict) -> dict | None:
    """One hook event. Returns the hook's JSON output, or None (no opinion). Also used by the
    offline benchmarks, which feed recorded sessions through exactly this function."""
    global CWD
    sid = data.get("session_id", "default")
    CWD = str(data.get("cwd") or "")
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
        if tool not in ("WebFetch", "WebSearch", "Bash") and not brings_external(tool, "", args) or \
                (tool.startswith("mcp__") and not re.search(r"page|navigate|browser|chrome|fetch", tool, re.I)):
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
        if brings_external(tool, cmd, args):
            st["external"] = True
            st.setdefault("external_ev", {"tool": tool, "cmd": cmd[:300], "args": {k: args[k] for k in ("url",) if k in args},
                                          "label": label_external(tool, args, cmd)})
        # Any tool output is "not from the user": a value copied from it is untrusted (a planted
        # address in a local file is still caught). But only content from outside the machine makes
        # values the model *produced itself* suspect; `ls` or `pytest` output does not.
        if tool.startswith("mcp__") or tool in ("WebFetch", "WebSearch", "Bash", "Read", "Grep"):
            st["untrusted"] += "\n" + redact(text[:MAX_UNTRUSTED]).lower()
        if brings_external(tool, cmd, args):
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
