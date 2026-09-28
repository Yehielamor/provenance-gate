# Provenance gate

A deterministic authorization gateway for AI agents, and the experiments that test it.

The gateway sits between an agent and its tools. It never reads tool outputs to decide whether they "look malicious". For every side-effect call it asks where each control value came from: the user, untrusted content (email, files, web pages), or the model itself. It allows the call, or stops it for a human with the reason attached ("recipient UK12... came from `bill-december-2023.txt`, not from you, and you have never paid it").

## Use it in Claude Code

The gateway is also a Claude Code plugin: it asks before an outbound call (MCP write tools, `WebFetch`, `curl`/`gh`/`git push`) uses a recipient or URL that came from tool output instead of from you. See [`plugin/README.md`](plugin/README.md).

```bash
git clone https://github.com/Yehielamor/provenance-gate
claude --plugin-dir provenance-gate/plugin
```

## Results on AgentDojo v1.2.1

Model-free replay of all 97 user tasks and 609 hijacked attack pairs, assuming the model is **always** hijacked:

| Defense | Legit tasks stopped ↓ | Attacks stopped: plain | base64 | unicode tags | German |
|---|---|---|---|---|---|
| **gateway** (strict + graph + links + derived values + payment dates) | **28.9%** | **99.3%** | 99.3%* | 99.3%* | 99.3%* |
| protectai-deberta-v3-prompt-injection-v2 | 72.2% | 70.2% | 65.4% | 21.2% | 35.3% |
| Llama Prompt Guard 2 (86M) | 0.0% | 26.1% | 0.0% | 0.0% | 0.0% |

\* measured for strict + graph + links; the derived-value rules do not change how provenance is traced. Classifier columns count injections caught among pairs whose clean output was not already flagged.

What else we measured:

- **Poisoned graph:** with the attacker's destinations already in the known-counterparty graph, the gateway stops 53–66%.
- **Adaptive attacks** on each relaxation (laundered IDs, amounts under the cap): no gain for the attacker.
- **Real incidents:** EchoLeak, GitHub MCP, Supabase MCP and ForcedLeak, analyzed structurally ([`poc/incidents_analysis.md`](poc/incidents_analysis.md)). Control-value provenance alone stops none of them, because the data leaves through content or rendered output.
- **End to end:** [`poc/e2e.py`](poc/e2e.py) runs a live model with the gateway in AgentDojo's tool loop. A dry run reproduces the replay exactly; a five-pair pilot with Nemotron-3-Ultra is in [`poc/e2e/`](poc/e2e/).

Write-ups: [#1 the benchmark](posts/01-provenance-vs-detection.en.md) · [#2 real sessions and a red team](posts/02-real-sessions.en.md). Full lab notes: [`poc/README.md`](poc/README.md).

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHONPATH=poc .venv/bin/python poc/replay.py > poc/results.md      # all policies, ~5 min on CPU
PYTHONPATH=poc .venv/bin/python poc/poison.py                       # poisoned-graph / adaptive adversaries

PYTHONPATH=poc .venv/bin/python poc/compare.py                      # classifiers vs. gateway, 5 encodings

# end to end: --dry-run (no model), a local Ollama model, or any OpenAI-compatible / Anthropic endpoint
PYTHONPATH=poc .venv/bin/python poc/e2e.py --dry-run
PYTHONPATH=poc .venv/bin/python poc/e2e.py --base-url http://localhost:11434/v1 --model qwen3:14b
```

## Layout

| Path | What |
|---|---|
| `poc/gateway.py` | the gateway and its policies |
| `poc/graph.py` | known-counterparty graph and amount cap, from outbound history only |
| `poc/replay.py` | model-free replay of AgentDojo through the gateway |
| `poc/compare.py`, `poc/detectors.py` | open classifiers vs. the gateway under adaptive encodings |
| `poc/poison.py` | adversaries that target the graph and each relaxation |
| `poc/e2e.py` | live-model harness |

## Limitations

Model-free replay is a perfect agent; real agents take extra steps and add friction. Stop rates are conditional on hijack. Provenance is traced by string matching; a product needs typed IDs or labels. AgentDojo is small and synthetic. See the write-up for the full list.

## License and contact

Apache-2.0 (see `LICENSE`). Yehiel Amor, Amor5511@gmail.com.
