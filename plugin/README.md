# provenance-gate for Claude Code

A Claude Code plugin that asks before an agent sends data, money or access to a destination that came from a tool output instead of from you.

It does not try to recognize malicious text. It tracks where each value came from:

- **you**: your prompts;
- **tool output**: issues, emails, web pages, files, command output (anyone could have written them);
- **the model**: values that appear in neither, produced after the agent read external content.

Before an outbound call runs (any MCP tool that is not clearly a read; `WebFetch`; and in Bash: `curl`, `gh`, `git push` (the remote's URL is resolved from the repo), `scp`, `ssh`, `python -c` / `node -e` one-liners and `git remote set-url`), it checks the recipient, URL, channel, host, amount and so on. If one of them came only from tool output, or was produced by the model after it read external content, Claude Code asks you first and says which value and why:

```
provenance-gate: destination 'https://collector.example/upload' in the command appeared only in content from a tool, not in anything you wrote
```

What you approve is remembered, so the same destination is not asked about again. Reads, local edits and local commands are never gated.

### Secrets

Two more rules watch for data leaving, not just where it goes:

- **A secret inside an outbound call is always put to you.** When the agent reads a sensitive file (`.env`, `~/.ssh/*`, `*.pem`, `.aws/credentials`, `.npmrc`, ...), runs a command that prints secrets (`printenv`, `gh auth token`, ...), or any output contains a recognizable key (AWS, GitHub, Slack, Stripe, OpenAI-style, private-key blocks), the gate keeps a fingerprint of each secret (a hash, never the value). If one of them appears in an outbound call, you are asked, even when you chose the destination.
- **Private data plus external content, then egress, is put to you once per destination.** If one session has read a sensitive source and also content from outside (a web page, an MCP server, a network command), the next outbound call to each destination asks first. Approve it and that destination is not asked again in the session.


## Install

```bash
git clone https://github.com/Yehielamor/provenance-gate
claude --plugin-dir provenance-gate/plugin
```

Or, in Claude Code: `/plugin marketplace add Yehielamor/provenance-gate`, then `/plugin install provenance-gate@provenance-gate`.

Requires `python3` (standard library only).

## State and privacy

State lives in `PGATE_HOME` (files are created readable by you only). Tool output is kept per session to trace where values came from, with secrets replaced by `[secret]`; secrets themselves are kept only as hashes. Sessions untouched for 14 days are deleted and the decision log is rotated at 5 MB. `python3 plugin/hooks/pgate.py reset` clears the "sensitive + external" flags of all sessions (approvals are kept).

The gate fails closed: if it cannot check a call (an internal error, or a call over 200,000 characters) it asks. Concurrent hook processes are serialized with a file lock.

## Settings

| Variable | Default | Effect |
|---|---|---|
| `PGATE_MODE` | `ask` | `deny` refuses instead of asking (for unattended agents) |
| `PGATE_HOME` | plugin data dir, else `~/.provenance-gate` | where session state, `known.json` and `decisions.jsonl` live |

`decisions.jsonl` logs every question the gate asked and every approval, so you can see how often it interrupts you. `known.json` is the list of approved destinations; edit it to add or revoke one.

## Limits

- A destination the model invents before the session has read any external content is not asked about: nothing untrusted could have chosen it yet.

- Provenance is traced by matching values against text, with token boundaries. Short or common values can collide.
- Secrets are matched by exact value. An agent that encodes, splits or paraphrases a secret before sending it gets past the secret rule; the private-plus-external rule still asks in that session.
- Destinations that are not written in the call itself (a configured `git remote`, an environment variable) are not seen.
- The agent can write files, including this plugin's state, through its own tools. Treat `known.json` as a convenience, not a security boundary, until state is kept out of the agent's reach.
- Measured on AgentDojo only so far (see [`../posts/01-provenance-vs-detection.en.md`](../posts/01-provenance-vs-detection.en.md)). Real-world friction is not yet measured; `decisions.jsonl` is how we will measure it.

## Tests

```bash
python3 plugin/tests/test_pgate.py     # scenarios
python3 plugin/tests/redteam_cases.py  # bypass attempts found by a red-team pass, all caught except one documented case
python3 bench/replay_history.py        # friction on your own Claude Code history (local only, counts only)
```
