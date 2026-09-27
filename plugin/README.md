# provenance-gate for Claude Code

A Claude Code plugin that asks before an agent sends data, money or access to a destination that came from a tool output instead of from you.

It does not try to recognize malicious text. It tracks where each value came from:

- **you**: your prompts;
- **tool output**: issues, emails, web pages, files, command output (anyone could have written them);
- **the model**: values that appear in neither, produced after the agent read external content.

Before an outbound call runs (MCP write tools such as `send_*`, `create_*`, `post_*`; `WebFetch`; and `curl`, `gh`, `git push`, `scp` and similar in Bash), it checks the recipient, URL, channel, host, amount and so on. If one of them came only from tool output, or was produced by the model after it read external content, Claude Code asks you first and says which value and why:

```
provenance-gate: destination 'https://collector.example/upload' in the command appeared only in content from a tool, not in anything you wrote
```

What you approve is remembered, so the same destination is not asked about again. Reads, local edits and local commands are never gated.

## Install

```bash
git clone https://github.com/Yehielamor/provenance-gate
claude --plugin-dir provenance-gate/plugin
```

Or, in Claude Code: `/plugin marketplace add Yehielamor/provenance-gate`, then `/plugin install provenance-gate@provenance-gate`.

Requires `python3` (standard library only).

## Settings

| Variable | Default | Effect |
|---|---|---|
| `PGATE_MODE` | `ask` | `deny` refuses instead of asking (for unattended agents) |
| `PGATE_HOME` | plugin data dir, else `~/.provenance-gate` | where session state, `known.json` and `decisions.jsonl` live |

`decisions.jsonl` logs every question the gate asked and every approval, so you can see how often it interrupts you. `known.json` is the list of approved destinations; edit it to add or revoke one.

## Limits

- Provenance is traced by matching values against text, with token boundaries. Short or common values can collide.
- It checks where control values came from, not what content is sent. A leak of private data to a destination you chose (the GitHub MCP pattern) needs an information-flow rule that is not in this version.
- The agent can write files, including this plugin's state, through its own tools. Treat `known.json` as a convenience, not a security boundary, until state is kept out of the agent's reach.
- Measured on AgentDojo only so far (see [`../posts/01-provenance-vs-detection.en.md`](../posts/01-provenance-vs-detection.en.md)). Real-world friction is not yet measured; `decisions.jsonl` is how we will measure it.

## Tests

```bash
python3 plugin/tests/test_pgate.py
```
