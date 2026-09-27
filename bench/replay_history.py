"""Replay real Claude Code sessions through the gate, offline, to measure real-world friction.

Reads the transcripts Claude Code keeps on this machine (~/.claude/projects/*/*.jsonl) and feeds
every user prompt, tool call and tool result through plugin/hooks/pgate.py's handle(), in order,
exactly as the live hooks would have seen them. Nothing leaves the machine. The printed summary
has counts only; --examples adds the reasons (tool, argument, value) for your own review and
should not be published as-is.

A call the gate would have asked about is treated as approved (it did run in the recorded
session), so its destinations are remembered for the rest of the replay, as with the live hook.

    python3 bench/replay_history.py                 # summary
    python3 bench/replay_history.py --examples 40   # plus redacted-at-your-discretion reasons
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import sys
import tempfile
from pathlib import Path

os.environ["PGATE_HOME"] = tempfile.mkdtemp(prefix="pgate-bench-")  # never touch the real state
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "plugin" / "hooks"))
import pgate  # noqa: E402

PROJECTS = Path.home() / ".claude" / "projects"


def session_events(path: Path):
    """Yield ("prompt", text) / ("pre", tool, input) / ("post", tool, input, output) in order."""
    pending: dict[str, tuple[str, dict]] = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("isMeta") or d.get("isSidechain"):
            continue
        msg = d.get("message") or {}
        content = msg.get("content")
        if d.get("type") == "user":
            if isinstance(content, str):
                if not content.lstrip().startswith("<"):  # skip command/system wrappers
                    yield ("prompt", content)
            elif isinstance(content, list):
                for b in content:
                    if b.get("type") == "tool_result" and b.get("tool_use_id") in pending:
                        name, inp = pending.pop(b["tool_use_id"])
                        yield ("post", name, inp, b.get("content"))
        elif d.get("type") == "assistant" and isinstance(content, list):
            for b in content:
                if b.get("type") == "tool_use":
                    inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                    pending[b.get("id")] = (b.get("name", ""), inp)
                    yield ("pre", b.get("name", ""), inp)


def classify(reason: str) -> str:
    if "contains a secret" in reason:
        return "secret in payload"
    if "this session read" in reason:
        return "private + external flow"
    if "appeared only in content" in reason:
        return "destination from tool output"
    if "produced by the model" in reason:
        return "model-made destination"
    return "other"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--examples", type=int, default=0)
    ap.add_argument("--exclude", default="", help="regex of project folder names to skip")
    args = ap.parse_args()

    files = sorted(glob.glob(str(PROJECTS / "*" / "*.jsonl")))
    skip = re.compile(args.exclude) if args.exclude else None
    stats = collections.Counter()
    by_tool, by_kind = collections.Counter(), collections.Counter()
    asked_sessions, examples = set(), []
    for f in files:
        proj = Path(f).parent.name
        if skip and skip.search(proj):
            continue
        sid = f"bench-{Path(f).stem}"
        stats["sessions"] += 1
        had_tool = False
        for ev in session_events(Path(f)):
            if ev[0] == "prompt":
                pgate.handle("prompt", {"session_id": sid, "prompt": ev[1]})
            elif ev[0] == "pre":
                _, tool, inp = ev
                had_tool = True
                stats["tool_calls"] += 1
                if pgate.gated(tool, inp):
                    stats["outbound_calls"] += 1
                out = pgate.handle("pre", {"session_id": sid, "tool_name": tool, "tool_input": inp})
                if out:
                    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
                    stats["asks"] += 1
                    by_tool[tool if not tool.startswith("mcp__") else "mcp__" + tool.split("__")[1]] += 1
                    by_kind[classify(reason)] += 1
                    asked_sessions.add(sid)
                    if len(examples) < args.examples:
                        examples.append(f"[{proj[-25:]}] {tool}: {reason[:220]}")
            else:
                _, tool, inp, output = ev
                pgate.handle("post", {"session_id": sid, "tool_name": tool, "tool_input": inp,
                                      "tool_response": output})
        stats["sessions_with_tools"] += had_tool

    s = stats
    print(f"Sessions replayed: {s['sessions']} ({s['sessions_with_tools']} with tool calls)")
    print(f"Tool calls: {s['tool_calls']:,}; outbound (gated) calls: {s['outbound_calls']:,}")
    print(f"Questions the gate would have asked: {s['asks']} "
          f"= {100 * s['asks'] / max(1, s['tool_calls']):.2f} per 100 tool calls, "
          f"{100 * s['asks'] / max(1, s['outbound_calls']):.1f}% of outbound calls")
    print(f"Sessions with at least one question: {len(asked_sessions)} of {s['sessions_with_tools']} "
          f"({100 * len(asked_sessions) / max(1, s['sessions_with_tools']):.1f}%)")
    print("By rule:", dict(by_kind.most_common()))
    print("By tool:", dict(by_tool.most_common(10)))
    for e in examples:
        print(" -", e)


if __name__ == "__main__":
    main()
