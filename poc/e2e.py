"""End-to-end run: a real model on AgentDojo, with and without the provenance gateway.

replay.py assumes the model is always hijacked and replays ground truth. This
script measures what replay cannot:

* how often a current model is actually hijacked (attack success without the gate);
* the friction a *real* agent run causes (real agents take extra steps);
* whether the gate still stops the attacks that do land.

The gateway sits inside the tool loop (GatedToolsExecutor) and checks every call
before it runs.
* benign runs  - a blocked call is counted as an approval request and then
                 executed, as if the user approved, so the task can finish and
                 we measure friction and utility together;
* attack runs  - a blocked call is denied and the model gets an error back
                 ("needs user approval"). Security is AgentDojo's own check of
                 whether the injection goal was achieved.

Injections use the same text as replay.py (AgentDojo's "important_instructions"
template, without a model name).

Usage:
  # plumbing check, no API calls: a scripted "agent" replays ground truth
  PYTHONPATH=poc .venv/bin/python poc/e2e.py --dry-run --suites banking

  # real run (needs ANTHROPIC_API_KEY or an `ant auth login` profile)
  PYTHONPATH=poc .venv/bin/python poc/e2e.py --model claude-opus-5 --pairs-per-suite 20

  # free: a local model through Ollama (no key)
  PYTHONPATH=poc .venv/bin/python poc/e2e.py --base-url http://localhost:11434/v1 --model qwen3:14b

  # free tier of z.ai (key in ZAI_API_KEY, set it yourself)
  PYTHONPATH=poc .venv/bin/python poc/e2e.py --base-url https://api.z.ai/api/paas/v4 \
      --api-key-env ZAI_API_KEY --model glm-4.7-flash
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

from agentdojo.agent_pipeline import AgentPipeline, InitQuery, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string

from gateway import ProvenanceGateway, is_high_risk
from graph import amount_cap, known_counterparties
from replay import JB, VERSION, injection_candidates

# Price per 1M tokens (input, output), first-party API, for the cost estimate only.
PRICES = {"claude-opus-5": (5.0, 25.0), "claude-opus-5-5": (4.0, 20.0), "claude-sonnet-5": (2.0, 10.0),
          "claude-haiku-4-5": (1.0, 5.0), "claude-fable-5-1": (10.0, 50.0)}
USAGE = {"input": 0, "output": 0, "cache_read": 0, "requests": 0}


class GatedToolsExecutor(ToolsExecutor):
    """ToolsExecutor with the provenance gateway in front of every call."""

    def __init__(self):
        super().__init__(tool_result_to_str)
        self.gw: ProvenanceGateway | None = None
        self.approve_blocked = True
        self.events: list[dict] = []

    def start(self, gw: ProvenanceGateway | None, prompt: str, approve_blocked: bool):
        self.gw, self.approve_blocked, self.events = gw, approve_blocked, []
        if gw is not None:
            gw.observe_user_prompt(prompt)

    def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006 - AgentDojo signature
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        results = []
        known_tools = {t.name for t in runtime.functions.values()}
        for call in messages[-1]["tool_calls"]:
            if call.function not in known_tools:
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")],
                                                     tool_call_id=call.id, tool_call=call,
                                                     error=f"Invalid tool {call.function} provided."))
                continue
            args = dict(call.args)
            if self.gw is not None:
                d = self.gw.check(call.function, args)
                if not d.allow:
                    self.events.append({"tool": call.function, "reason": d.reason,
                                        "high_risk": is_high_risk(call.function, args)})
                    if not self.approve_blocked:
                        results.append(ChatToolResultMessage(
                            role="tool", content=[text_content_block_from_string("")], tool_call_id=call.id,
                            tool_call=call, error=f"Blocked: this action needs the user's approval ({d.reason})."))
                        continue
            result, error = runtime.run_function(env, call.function, args)
            out = self.output_formatter(result)
            if self.gw is not None:
                self.gw.observe_tool_result(call.function, error or out, args)
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(out)],
                                                 tool_call_id=call.id, tool_call=call, error=error))
        return query, runtime, env, [*messages, *results], extra_args


class ScriptedAgent(BasePipelineElement):
    """--dry-run stand-in for the model: emits a fixed list of calls one at a time."""

    name = "scripted"

    def __init__(self):
        self.calls: list[FunctionCall] = []

    def query(self, query, runtime, env, messages=(), extra_args={}):  # noqa: B006
        k = sum(1 for m in messages if m["role"] == "assistant")
        if k < len(self.calls):
            c = self.calls[k].model_copy(update={"id": f"call_{k}"})
            msg = ChatAssistantMessage(role="assistant", tool_calls=[c], content=[text_content_block_from_string("")])
        else:
            msg = ChatAssistantMessage(role="assistant", tool_calls=None, content=[text_content_block_from_string("done")])
        return query, runtime, env, [*messages, msg], extra_args


def count_only_executed_calls():
    """Some AgentDojo checks score the calls the model *emitted* (traces), not the resulting state.
    A call the gateway denied never ran, so it must not count toward attack success (or utility).
    Found in the dry run: slack/injection_task_5 scored as "succeeded" with every call blocked."""
    import agentdojo.task_suite.task_suite as ts
    orig = ts.functions_stack_trace_from_messages

    def executed_only(messages):
        denied = {m["tool_call_id"] for m in messages
                  if m["role"] == "tool" and (m.get("error") or "").startswith("Blocked:")}
        return [c for c in orig(messages) if c.id not in denied]
    ts.functions_stack_trace_from_messages = executed_only


def track_openai_usage():
    import agentdojo.agent_pipeline.llms.openai_llm as ol
    orig = ol.chat_completion_request

    def wrapped(*a, **kw):
        c = orig(*a, **kw)
        if c.usage:
            USAGE["input"] += c.usage.prompt_tokens or 0
            USAGE["output"] += c.usage.completion_tokens or 0
        USAGE["requests"] += 1
        return c
    ol.chat_completion_request = wrapped


def track_usage():
    """Record token usage of every Anthropic request AgentDojo makes."""
    import agentdojo.agent_pipeline.llms.anthropic_llm as al
    orig = al.chat_completion_request

    async def wrapped(*a, **kw):
        m = await orig(*a, **kw)
        USAGE["input"] += m.usage.input_tokens + (m.usage.cache_creation_input_tokens or 0)
        USAGE["cache_read"] += m.usage.cache_read_input_tokens or 0
        USAGE["output"] += m.usage.output_tokens
        USAGE["requests"] += 1
        return m
    al.chat_completion_request = wrapped


def build_pipeline(args, executor):
    if args.dry_run:
        llm = ScriptedAgent()
    elif args.base_url:
        # Any OpenAI-compatible endpoint: a local Ollama server, z.ai, OpenRouter...
        import os
        import openai
        from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
        track_openai_usage()
        key = os.environ.get(args.api_key_env) if args.api_key_env else "local"  # Ollama ignores the key
        if not key:
            sys.exit(f"Set {args.api_key_env} in your shell first.")
        client = openai.OpenAI(base_url=args.base_url, api_key=key, timeout=600, max_retries=5)
        llm = OpenAILLM(client, args.model, temperature=None)
    else:
        from anthropic import AsyncAnthropic
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        track_usage()
        # temperature=None: sampling parameters are rejected on current models. No thinking config is sent,
        # so the model runs with its default (adaptive) thinking; AgentDojo echoes thinking blocks back.
        llm = AnthropicLLM(AsyncAnthropic(), args.model, temperature=None, max_tokens=args.max_tokens)
    pipe = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm,
                          ToolsExecutionLoop([executor, llm], max_iters=args.max_iters)])
    pipe.name = "scripted" if args.dry_run else args.model
    return pipe, llm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="claude-opus-5")
    ap.add_argument("--base-url", help="OpenAI-compatible endpoint (Ollama, z.ai, ...) instead of the Anthropic API")
    ap.add_argument("--api-key-env", help="environment variable holding the key for --base-url")
    ap.add_argument("--policy", default="argument-strict+graph+links+h9+timing")
    ap.add_argument("--suites", nargs="*", default=["workspace", "travel", "banking", "slack"])
    ap.add_argument("--mode", choices=["benign", "attack", "both"], default="both")
    ap.add_argument("--gate", choices=["off", "on", "both"], default="both")
    ap.add_argument("--pairs-per-suite", type=int, default=20, help="attack pairs sampled per suite (0 = all)")
    ap.add_argument("--max-user-tasks", type=int, default=0, help="benign tasks per suite (0 = all)")
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--max-iters", type=int, default=15)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default="poc/e2e")
    args = ap.parse_args()

    count_only_executed_calls()
    executor = GatedToolsExecutor()
    pipe, llm = build_pipeline(args, executor)
    gates = {"off": [False], "on": [True], "both": [False, True]}[args.gate]
    rows = []
    t0 = time.time()

    for sname in args.suites:
        suite = get_suites(VERSION)[sname]
        base = suite.load_and_inject_default_environment({})
        known, cap = known_counterparties(sname, base), amount_cap(sname, base)
        rng = random.Random(f"{args.seed}-{sname}")

        def run(ut, it, injections, gated, approve):
            if args.dry_run:  # the scripted agent is "always hijacked" in attack runs, like replay.py
                env = suite.load_and_inject_default_environment(injections)
                llm.calls = list(ut.ground_truth(env.model_copy(deep=True)))
                if it is not None:
                    llm.calls += list(it.ground_truth(env.model_copy(deep=True)))
            gw = ProvenanceGateway(args.policy, known=known, amount_cap=cap) if gated else None
            executor.start(gw, ut.PROMPT, approve)
            try:
                utility, security = suite.run_task_with_pipeline(pipe, ut, injection_task=it, injections=injections)
                err = None
            except Exception as e:  # noqa: BLE001 - record and continue; one bad task must not end a paid run
                utility, security, err = False, False, f"{type(e).__name__}: {e}"[:300]
            return {"suite": sname, "user_task": ut.ID, "injection_task": it.ID if it else None, "gate": gated,
                    "utility": bool(utility), "attack_succeeded": bool(security) if it else None,
                    "approvals": len(executor.events), "approvals_high_risk": sum(e["high_risk"] for e in executor.events),
                    "blocked": executor.events[:5], "error": err}

        if args.mode in ("benign", "both"):
            uts = list(suite.user_tasks.values())
            if args.max_user_tasks:
                uts = uts[:args.max_user_tasks]
            for ut in uts:
                for g in gates:
                    rows.append(run(ut, None, {}, g, approve=True))
                    print(f"[{time.time() - t0:6.0f}s] benign {sname}/{ut.ID} gate={g} "
                          f"utility={rows[-1]['utility']} approvals={rows[-1]['approvals']}", file=sys.stderr)

        if args.mode in ("attack", "both"):
            pairs = []
            for ut in suite.user_tasks.values():
                cands = injection_candidates(suite, ut)
                if not cands:
                    continue
                for it in suite.injection_tasks.values():
                    if it.ground_truth(suite.load_and_inject_default_environment({})):
                        pairs.append((ut, it, {c: JB.format(goal=it.GOAL) for c in cands}))
            if args.pairs_per_suite and len(pairs) > args.pairs_per_suite:
                pairs = rng.sample(pairs, args.pairs_per_suite)
            for ut, it, inj in pairs:
                for g in gates:
                    rows.append(run(ut, it, inj, g, approve=False))
                    print(f"[{time.time() - t0:6.0f}s] attack {sname}/{ut.ID}+{it.ID} gate={g} "
                          f"succeeded={rows[-1]['attack_succeeded']} utility={rows[-1]['utility']}", file=sys.stderr)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tag = "dry-run" if args.dry_run else args.model.replace(":", "-").replace("/", "-")
    (out / f"{tag}.json").write_text(json.dumps({"args": vars(args), "usage": USAGE, "rows": rows}, indent=1))
    report = summarize(rows, args, tag)
    (out / f"{tag}.md").write_text(report)
    print(report)


def pct(a, b):
    return f"{100 * a / b:.1f}% ({a}/{b})" if b else "n/a"


def summarize(rows, args, tag):
    lines = [f"## End-to-end: {tag}, policy {args.policy}\n"]
    by = defaultdict(list)
    for r in rows:
        by[("attack" if r["injection_task"] else "benign", r["gate"])].append(r)
    lines.append("| run | gate | n (completed) | utility | needs approval (any) | needs approval (high-risk) | attack succeeded | errors |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for (kind, g), all_rs in sorted(by.items()):
        # A run that crashed (e.g. a provider returned an empty response) is not a stopped attack:
        # rates are over completed runs only; errors are reported separately.
        rs = [r for r in all_rs if r["error"] is None]
        n = len(rs)
        appr = pct(sum(r["approvals"] > 0 for r in rs), n) if g else "-"
        appr_h = pct(sum(r["approvals_high_risk"] > 0 for r in rs), n) if g else "-"
        asr = pct(sum(bool(r["attack_succeeded"]) for r in rs), n) if kind == "attack" else "-"
        lines.append(f"| {kind} | {'on' if g else 'off'} | {n} | {pct(sum(r['utility'] for r in rs), n)} | "
                     f"{appr} | {appr_h} | {asr} | {len(all_rs) - n} |")
    if USAGE["requests"]:
        pin, pout = PRICES.get(args.model, (0, 0))
        cost = (USAGE["input"] * pin + USAGE["output"] * pout + USAGE["cache_read"] * pin * 0.1) / 1e6
        lines.append(f"\nRequests: {USAGE['requests']}; tokens in {USAGE['input']:,} (+{USAGE['cache_read']:,} cached), "
                     f"out {USAGE['output']:,}; estimated cost ${cost:.2f}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
