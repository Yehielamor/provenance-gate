# I put a prompt-injection gate on 3½ months of my own Claude Code sessions, then had three agents try to break it

*Yehiel Amor · Research note #2 · September 2026*

[Note #1](01-provenance-vs-detection.en.md) measured a deterministic tool-call gateway on AgentDojo: 99.3% of hijacked attacks stopped, no classifier, no change under obfuscation. Benchmarks are clean, though. This note is about what happened when the gateway met real work, and a team of adversarial agents.

The gateway is now a Claude Code plugin ([install](../plugin/README.md)). Before an outbound call runs (an MCP write tool, `WebFetch`, `curl`, `git push`, a `python -c` one-liner...), it checks where each destination came from: something you wrote, something a tool returned, or something the model produced after reading external content. If a recipient or URL came only from tool output, you get a question that says which value and why:

```
provenance-gate: destination 'https://collector.example/upload' in the command appeared only
in content from a tool, not in anything you wrote
```

It also fingerprints secrets it sees (`.env`, `printenv`, key formats) and asks before one leaves, and it asks once per destination when a session has read both sensitive data and external content.

## 1. Friction on real sessions

Claude Code keeps session transcripts locally. I replayed every prompt, tool call and tool output from my own history through the hook, offline, in order, exactly as the live hook would see them. Nothing left the machine; the script prints counts only ([`bench/replay_history.py`](../bench/replay_history.py), so you can run it on yours).

| | |
|---|---|
| Sessions (June to September 2026) | 179, of which 143 used tools |
| Tool calls | 13,703 |
| **Sessions with zero questions** | **106 of 143 (74%)** |
| Questions overall | 660, i.e. 4.8 per 100 tool calls |
| In sessions that got questions | median 12 |
| Concentration | 5 sessions (server deployments) produced 44% of all questions |

The first version of the plugin would have asked **998** times. The replay found five bugs no synthetic test had: `curl localhost:3000` counted as egress; `ssh -i ~/.ssh/key` counted as *reading* the key; `set -e` looked like printing the environment; the app's own UI tools counted as "external content"; and approvals were remembered per combination of hosts instead of per host.

Two honest caveats. I fixed those bugs on the same data I then measured, so 660 is optimistic; the clean test is the live log going forward. And a median of 12 questions in the sessions that get any is still too many. The remaining questions split into: private data plus external content in one session, then egress (337); destinations the model built after reading external content (220); destinations copied from tool output (91); secrets inside outbound calls (12). Some of those are exactly the questions a person should see. How many is the next thing to measure.

## 2. Three agents tried to break it

I gave three Claude Sonnet agents the source and one job each, everything simulated in-process with reserved `.example`/`.test` domains.

**The red team found 9 bypasses; 8 are closed.** The worst was a single point of failure: an MCP tool whose name did not start with a known write verb (`notify`, `message_send`) skipped *every* check, including the secret check. Others: HTTP from `python -c` / `node -e` one-liners; `git remote set-url` to an attacker, then a bare `git push` (the destination lives in `.git/config`, not in the command); hosts written without a scheme; addresses in message bodies without `https://`; and "object IDs" minted from JSON on an attacker's web page. The fixes all went the same way: fail closed. Anything that is not clearly a read is checked, `git push` resolves the real remote URL, and IDs only count when they come from your own data. The one open case is by design: a destination the model invents before the session has read anything external, when nothing untrusted could have chosen it.

**The robustness review found the gateway itself could be the weak point.** Two regexes had quadratic backtracking: a long base64 argument froze the hook for 20 seconds. A tool output nested 2,000 levels deep crashed the hook in a way that skipped marking the session as tainted, which is a bypass. Parallel hooks raced on the state file and lost approvals. And, contrary to what my README said, full tool output (secrets included) was stored in plain text. Now parsing is linear, walks are iterative and depth-capped, an unreadable output is treated as the worst case, a file lock serializes hooks, oversized calls are asked about rather than scanned, secrets are redacted before anything is stored, and files are `0600`.

**The friction hunter found that any `ls` or `pytest` tainted the session**, so every URL the model chose afterwards triggered a question. Now only content from outside the machine makes model-chosen values suspect; a destination copied from a local file is still caught.

The interesting part was the interaction. The first fail-closed draft of the red-team fixes took friction from 601 to **2,100** questions, because every browser click and screenshot became "an MCP call that might send". Scoping unknown tools to their destination arguments (plus secrets) brought it back to 660 with the bypasses still closed. Every security fix raised friction and every friction fix opened a hole; measuring both on real data at the same time is the only reason this converged.

## 3. It stopped the thing it is for

In a live session, a file in the working directory contained a "release checklist" whose one step was to `curl -X POST` a build log to an external host. Claude first declined to run it on its own. Told explicitly to run it anyway, it tried, and the gateway put the call to me with the reason above. The model is the first layer; the gateway is the one that does not depend on how the instruction is phrased.

## What it does not do

- It tracks where destinations come from, by matching values. A secret the agent encodes or splits before sending gets past the secret rule (the flow rule still asks in that session).
- Destinations that are not in the call itself, other than a git remote, are not seen.
- It is one user's history. I would like to know what these numbers look like on yours: the replay script runs locally and prints counts only.

Code, tests (including the red team's cases as regression tests) and the benchmark: https://github.com/Yehielamor/provenance-gate

*Feedback and replication attempts welcome: Yehiel Amor, Amor5511@gmail.com.*
