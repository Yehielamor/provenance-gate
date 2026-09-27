# Four incidents vs. the gateway: what `gateway.py` would actually decide

Structural analysis only, from a defender's point of view. There is no injection text and there are no reproduction steps here. For each incident we checked which tool calls (or channels) occur, which control values they carry, where each value comes from, and what each policy in `gateway.py` would decide.

**Legend for value source:** user / untrusted (content written by a third party) / model-generated (a value the model assembled; `unknown` in the gateway) / private (data read from a private source).

**Reminder of the gateway rules:** `argument-permissive` blocks a control value whose source is untrusted. `argument-strict` also blocks an `unknown` value once the session is "tainted". `+graph` approves a known recipient, and only in destination arguments (`recipients`, `channel`, etc.). `+links` checks URLs inside content arguments. The `+flow` rule blocks a sink marked `external` when the session has read both private data and untrusted content. We have not measured `+flow` yet. The gateway compares a whole value as a string, not the host of a URL.

## 1. EchoLeak (M365 Copilot, CVE-2025-32711)

**The chain:** an external email is retrieved via RAG (untrusted) → Copilot also brings organizational data (private) into context → the answer contains a Markdown image reference. The chat interface loads it automatically through a Teams endpoint that the CSP allows. The data leaves in the URL parameters. **There is no tool call on egress** ([Aim/arXiv](https://arxiv.org/html/2509.10540v1)).

| Step | Tool/channel | Control values | Source | permissive | strict | strict+graph+links | +flow |
|---|---|---|---|---|---|---|---|
| Retrieval | RAG (internal) | — | untrusted + private | not a sink | not a sink | not a sink | marks tainted + private |
| Egress | image rendering in the answer | URL | prefix from the email, tail is private data, assembled by the model | **not visible**. If rendering is mediated: passes (the whole URL is `unknown`, not `untrusted`) | not visible. If mediated: blocks (`unknown` in a tainted session) | same as strict | not visible. If mediated and marked external: blocks |

**Key assumption:** a tool-call gateway does not see this channel. Blocking is possible only if the gateway also mediates the rendered output and treats every auto-loaded URL as a sink. `permissive` would block only with host-level comparison (the host appears in the email). But here the host is a Microsoft domain that is allowed anyway.

## 2. GitHub MCP (Invariant Labs, May 2025)

**The chain:** the user asks the agent to handle issues in their public repo → an issue written by an attacker (untrusted) → the agent reads private repos (private) → the agent opens a PR in the same public repo, and the private data is in the PR content ([Invariant](https://invariantlabs.ai/blog/mcp-github-vulnerability)).

| Step | Tool | Control values | Source | permissive | strict | strict+graph+links | +flow |
|---|---|---|---|---|---|---|---|
| Read issues | `list_issues` | owner, repo | user | not a sink | not a sink | not a sink | tainted |
| Read private repo | `get_file_contents` etc. | private repo | model-generated/untrusted | not a sink | not a sink | not a sink | private |
| Create branch/file | `create_branch`, `create_or_update_file` | owner, repo, branch, message | owner/repo: user. branch/message: model-generated | passes | **blocks**, but because of a branch name or commit message the model invented | same as strict (`owner`/`repo` are not destination arguments in graph) | blocks if the repo is marked public=external |
| PR | `create_pull_request` | owner, repo, head, base | owner/repo: user | passes | same as above | same as above. `+links` not relevant, no URL | blocks |

**Assumptions:** the destination was chosen by the user, so the control-value provenance question answers "trusted". The damage is in `body`/`content`, which are content arguments the gateway does not check. The `strict` block is a side effect: it would fire the same way on a legitimate PR that resolves the issue. Only `+flow` blocks for the right reason.

## 3. Supabase MCP (General Analysis, July 2025)

**The chain:** a developer asks the agent to review tickets → a customer message in a ticket (untrusted) → SQL that reads `integration_tokens` with `service_role` (private) → SQL that adds a row to `support_messages` in the same thread, which the customer sees ([General Analysis](https://www.generalanalysis.com/blog/supabase-mcp-blog); [Willison](https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/)).

| Step | Tool | Control values | Source | permissive | strict | strict+graph+links | +flow |
|---|---|---|---|---|---|---|---|
| Read tickets | `execute_sql` | query | model-generated (at the user's request) | in the original classification: not a sink. With `execute_`: passes | passes only if the session is not yet tainted. After `list_tables` it is already tainted | same as strict | tainted |
| Read tokens | `execute_sql` | query | model-generated, following an untrusted instruction | passes, unless the SQL was copied verbatim from the ticket | blocks (with `execute_`) | same as strict | private |
| Write to thread | `execute_sql` | query (table + values) | model-generated. The values are private | same as above | blocks (with `execute_`) | same as strict. graph does not apply to `query` | blocks only if `execute_sql` (or a customer-visible table) is marked external |

**Assumptions:** in the original classification `execute_sql` was not a sink, so **all policies would approve**. The `execute_` prefix was added only recently. Even with it, `strict` blocks every query after the first taint, including legitimate ones. That is friction; it does not tell legitimate queries from malicious ones. A single `query` mixes control and data, so the separation between control and content does not hold. The "destination" (a row the customer sees) can be identified only from the SQL itself.

## 4. ForcedLeak (Salesforce Agentforce, Noma, September 2025)

**The chain:** a public Web-to-Lead form, the description field (untrusted) → an internal employee asks the agent to handle the lead → the agent retrieves lead email addresses (private) → the output contains an image tag pointing to a domain that was still on the CSP allowlist but had expired and been re-registered. The browser loads the image ([Noma](https://noma.security/blog/forcedleak-agent-risks-exposed-in-salesforce-agentforce)).

| Step | Tool/channel | Control values | Source | permissive | strict | strict+graph+links | +flow |
|---|---|---|---|---|---|---|---|
| Read lead | CRM read | lead id | user | not a sink | not a sink | not a sink | tainted |
| Query leads | CRM read | query | model-generated | not a sink | not a sink | not a sink | private |
| Egress | image rendering | URL | host from the form, parameters are private data | **not visible**. If mediated: passes (`unknown`) | not visible. If mediated: blocks | same as strict | not visible. If mediated: blocks |

**Assumptions:** as in EchoLeak. The host appears in the untrusted content, so host-level comparison would have been enough even for `permissive`. But the current gateway compares the whole URL.

## Summary

| Incident | argument-permissive | argument-strict | strict+graph+links | +flow |
|---|---|---|---|---|
| EchoLeak | no (only if rendering is mediated and provenance is host-level) | only if rendering is mediated | only if rendering is mediated | only if rendering is mediated |
| GitHub MCP | no | yes, but for an incidental reason (a model-generated branch name or commit message) that also blocks a legitimate PR | same as strict | yes, if a public repo is marked external |
| Supabase MCP | no (only if the SQL was copied verbatim) | only with `execute_` as a sink, and then it also blocks legitimate work | same as strict | only if `execute_sql` or a customer-visible table is marked external |
| ForcedLeak | no (only if rendering is mediated and provenance is host-level) | only if rendering is mediated | only if rendering is mediated | only if rendering is mediated |

## What this means for the thesis

The question "who set the control value?" on its own (`permissive`) stops none of the four incidents as the gateway is built today. In two of them the egress is not a tool call at all. In the third the destination was chosen by the user. In the fourth control and data are mixed in a single query. `strict` "stops" more, but mostly thanks to the `unknown` rule. That rule behaves like coarse session tainting: it also blocks the legitimate work of the same session.

In most cases the damage is **content flow** (private data inside `body`, `query` or a URL), not **destination choice**. So we need labels that travel with the content: confidentiality on what was read, and integrity on what influenced the decision, as in CaMeL ([arXiv 2503.18813](https://arxiv.org/abs/2503.18813)) and FIDES ([arXiv 2505.23643](https://arxiv.org/abs/2505.23643)). These would add two things. First, blocking a private value that enters an external sink, even when the destination is trusted (GitHub, Supabase). Second, separating "the model read untrusted content" from "this value was derived from it", instead of a blanket `unknown` rule. Alongside this, the gateway must also mediate the rendered output (auto-loaded URLs), not only tool calls. The `+flow` rule is a coarse approximation of this. It has not yet been measured on legitimate tasks, so its friction cost is unknown.
