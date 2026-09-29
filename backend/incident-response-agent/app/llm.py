"""LLM reasoning: live provider (Anthropic or OpenAI-compatible) or a deterministic mock.

The mock ("demo mode") exists so the whole pipeline can run without an API key. It reasons over the
SAME context object the live model receives - playbook, tool results and RETRIEVED memory text -
using keyword heuristics. It never looks up incident IDs from a hardcoded table: if a memory is not
retrieved, it cannot influence the output.
"""
from __future__ import annotations

import json
import re

from .config import Settings
from .errors import ConfigError, UpstreamError

SYSTEM_PROMPT = """You are an incident-response agent assisting a SOC analyst.

Inputs you receive as JSON: the current incident, the organization's APPROVED PLAYBOOK, results of read-only
investigation tools, and (optionally) HISTORICAL MEMORIES recalled from past incidents.

Rules:
1. The playbook is POLICY (what we should do). Memories are EXPERIENCE (what happened before). Never let a
   memory silently override the playbook. If experience suggests deviating from a playbook default, say so in
   "policy_conflicts", keep the playbook default as an "optional" action, and recommend the alternative.
2. Use memories only if they are genuinely relevant to THIS incident. Say exactly how each one influenced you.
   If memories are absent or irrelevant, leave "historical_context" empty. Do not invent memories.
3. You may only recommend these tools: preserve_evidence, revoke_sessions, disable_account, isolate_endpoint,
   block_indicator, remove_unauthorized_access, create_ticket. Targets must be entities that appear in the
   incident (users, hosts, indicators); create_ticket target is a short summary.
4. Every action needs analyst approval. Order actions and use "depends_on" (list of order numbers).
5. Collect evidence (preserve_evidence) before destructive containment, per the playbook.
6. Respond with ONE JSON object and nothing else, with keys:
 assessment (str), severity ("P1".."P4"), confidence (0-1), playbook_steps (list of playbook step ids used),
 evidence_considered (list of str), historical_context (list of {memory_ref, source_incident, summary, lesson, influence}),
 recommended_actions (list of {order:int, tool, target, reason, evidence:[str], playbook_step, historical_experience, risk,
   depends_on:[int], recommendation:"recommended"|"optional"}),
 policy_conflicts (list of str), reasoning_summary (str), next_step (str)."""


def parse_json_object(text: str) -> dict:
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        a, b = text.find("{"), text.rfind("}")
        if a == -1 or b <= a:
            raise UpstreamError("LLM did not return JSON", hint="Retry, or switch LLM_MODEL.")
        try:
            obj = json.loads(text[a:b + 1])
        except json.JSONDecodeError as e:
            raise UpstreamError(f"LLM returned malformed JSON: {e}")
    if not isinstance(obj, dict):
        raise UpstreamError("LLM JSON was not an object")
    return obj


class LLMClient:
    def __init__(self, settings: Settings):
        self.s = settings

    @property
    def mode(self) -> str:
        return "mock" if self.s.llm_mode == "mock" else f"live:{self.s.llm_provider}"

    def complete_json(self, context: dict) -> dict:
        if self.s.llm_mode == "mock":
            return mock_reason(context)
        if self.s.llm_mode != "live":
            raise ConfigError(f"Unknown LLM_MODE '{self.s.llm_mode}'", hint="Use 'live' or 'mock'.")
        if not self.s.llm_api_key:
            raise ConfigError("LLM is not configured: LLM_API_KEY is missing",
                              hint="Set LLM_API_KEY in .env, or run with LLM_MODE=mock for the offline demo reasoner.")
        user = "Analyze this incident and respond with the JSON object described.\n\n" + json.dumps(context, indent=2)
        try:
            import requests
            if self.s.llm_provider == "anthropic":
                r = requests.post(
                    (self.s.llm_base_url or "https://api.anthropic.com") + "/v1/messages",
                    headers={"x-api-key": self.s.llm_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                    json={"model": self.s.llm_model or "claude-sonnet-5", "max_tokens": 3000, "system": SYSTEM_PROMPT,
                          "messages": [{"role": "user", "content": user}]}, timeout=120)
                r.raise_for_status()
                text = "".join(b.get("text", "") for b in r.json().get("content", []))
            elif self.s.llm_provider == "openai":
                r = requests.post(
                    (self.s.llm_base_url or "https://api.openai.com/v1") + "/chat/completions",
                    headers={"Authorization": f"Bearer {self.s.llm_api_key}"},
                    json={"model": self.s.llm_model or "gpt-4o-mini", "response_format": {"type": "json_object"},
                          "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user}]}, timeout=120)
                r.raise_for_status()
                text = r.json()["choices"][0]["message"]["content"]
            else:
                raise ConfigError(f"Unknown LLM_PROVIDER '{self.s.llm_provider}'", hint="Use 'anthropic' or 'openai'.")
        except (ConfigError, UpstreamError):
            raise
        except Exception as e:
            raise UpstreamError(f"LLM request failed: {e}", hint="Check LLM_API_KEY, LLM_MODEL and network access.")
        return parse_json_object(text)


# ============================================================ mock reasoner
WEIGHTS = {"new_geo": 2, "mfa_prompt_spam": 1, "privileged_change": 2, "new_credential_created": 1, "mailbox_rule": 2}


def _flags(tr: dict) -> set[str]:
    f: set[str] = set()
    for key in ("auth", "activity"):
        for ev in (tr.get(key) or {}).get("events", []):
            f |= set(ev.get("flags", []))
    for r in (tr.get("logs") or {}).get("results", []):
        if "credentials-form" in r.get("message", ""):
            f.add("credential_submission")
    return f


def _score(flags: set[str], tr: dict, privileged: bool) -> tuple[int, list[str]]:
    s, why = 0, []
    for fl in sorted(flags):
        w = WEIGHTS.get(fl, 3 if fl == "credential_submission" else 0)
        if w:
            s += w
            why.append(fl)
    for ind, res in (tr.get("indicators") or {}).items():
        rep = res.get("reputation")
        if rep == "malicious":
            s += 2; why.append(f"malicious_indicator:{ind}")
        elif rep == "suspicious":
            s += 1; why.append(f"suspicious_indicator:{ind}")
    if privileged:
        s += 1; why.append("privileged_identity")
    return s, why


def _memory_signals(memories: list[dict]) -> list[dict]:
    out = []
    for m in memories:
        t = m["text"].lower()
        sig = set()
        if "before" in t and re.search(r"evidence|snapshot|capture", t) and re.search(r"revok|isolat|re-imag|contain", t):
            sig.add("evidence_before_containment")
        if "disabl" in t and re.search(r"disrupt|fail|dependen|depend on|outage", t):
            sig.add("disable_caused_disruption")
        if re.search(r"mailbox rule|forwarding rule|inbox rule|forwarding", t):
            sig.add("check_mailbox_rules")
        if re.search(r"new api key|newly created credential|new credential|api key", t):
            sig.add("check_new_credentials")
        if re.search(r"phone|out-of-band", t):
            sig.add("notify_out_of_band")
        if re.search(r"legal|hr\b", t):
            sig.add("involve_legal_hr")
        inc = re.search(r"(?:INC|CUR)-\d+", m["text"])
        lesson = re.search(r"Lessons learned:\s*(.+)", m["text"])
        fb = re.search(r"Analyst feedback:\s*(.+)", m["text"])
        out.append({"ref": m["ref"], "source": inc.group(0) if inc else "unknown", "signals": sig,
                    "lesson": (lesson.group(1) if lesson else (fb.group(1) if fb else m["text"]))[:400],
                    "summary": m["text"].splitlines()[0][:220]})
    return out


def mock_reason(ctx: dict) -> dict:
    inc, tr, pb = ctx["incident"], ctx["tool_results"], ctx["playbook"]
    mem = _memory_signals(ctx.get("memories") or [])
    sigs = set().union(*[m["signals"] for m in mem]) if mem else set()
    user = inc.get("affected_user")
    hosts = inc.get("hosts") or []
    host = inc.get("affected_host") or (hosts[0] if hosts else None)
    itype = inc["incident_type"]
    profile = (tr.get("activity") or {}).get("profile") or {}
    privileged = bool(profile.get("privileged"))
    deps = profile.get("dependent_services") or []
    flags = _flags(tr)
    score, why = _score(flags, tr, privileged)
    sev = "P1" if score >= 11 else "P2" if score >= 6 else "P3" if score >= 3 else "P4"
    confidence = round(min(0.9, 0.5 + 0.05 * len(why) + (0.05 if mem else 0)), 2)
    steps = {s["id"]: s for s in pb["steps"]}

    def step_for(tool: str) -> str:
        for s in pb["steps"]:
            if tool in (s.get("tools") or []):
                return s["id"]
        return pb["steps"][0]["id"]

    evidence = []
    for ev in (tr.get("auth") or {}).get("events", []):
        if ev.get("flags"):
            evidence.append(f"Login {ev['time']} from {ev.get('geo')} ({ev.get('ip')}), flags: {', '.join(ev['flags'])}, MFA: {ev.get('mfa')}")
    for ev in (tr.get("activity") or {}).get("events", []):
        evidence.append(f"Activity {ev['time']}: {ev['action']} on {ev['resource']}")
    for ind, res in (tr.get("indicators") or {}).items():
        evidence.append(f"Indicator {ind}: {res.get('reputation')} {res.get('tags')}")
    for r in (tr.get("logs") or {}).get("results", [])[:4]:
        evidence.append(f"Log [{r.get('source')}] {r['message']}")

    actions: list[dict] = []
    conflicts: list[str] = []
    used_mem: dict[str, str] = {}   # ref -> influence text

    def add(tool, target, reason, step_id=None, exp=None, risk="Low", deps_on=None, level="recommended"):
        actions.append({"order": len(actions) + 1, "tool": tool, "target": target, "reason": reason, "evidence": evidence[:4],
                        "playbook_step": step_id or step_for(tool), "historical_experience": exp, "risk": risk,
                        "depends_on": deps_on or [], "recommendation": level})
        return len(actions)

    def ref_with(sig):
        return next((m for m in mem if sig in m["signals"]), None)

    account_types = {"suspicious_login", "account_compromise", "privileged_access", "suspicious_access"}
    if itype in account_types or (itype not in ("phishing", "malware", "data_exfiltration")):
        target = user or host
        m_ev = ref_with("evidence_before_containment")
        exp = None
        reason = "Playbook requires evidence to be preserved before containment."
        if m_ev:
            exp = f"{m_ev['source']} ({m_ev['ref']}): evidence was captured before revoking sessions and this preserved investigation context."
            reason += " Specifically capture the active session list, any newly created credentials and permission-change audit records, because they are hard to reconstruct after revocation."
            used_mem[m_ev["ref"]] = "Made the evidence step more specific (sessions, new credentials, permission changes) and made it an explicit prerequisite of revoke_sessions."
        e1 = add("preserve_evidence", target, reason, exp=exp, risk="Low - read-only snapshot")
        e2 = add("revoke_sessions", target, "Attacker holds an active session; revoking cuts access with low disruption (user simply re-authenticates).",
                 deps_on=[e1], exp=(exp if m_ev else None), risk="Low - user must sign in again")
        if flags & {"new_credential_created", "privileged_change", "mailbox_rule"}:
            m_c = ref_with("check_new_credentials") or ref_with("check_mailbox_rules")
            exp2 = None
            if m_c:
                exp2 = f"{m_c['source']} ({m_c['ref']}): attacker-created credentials/rules were persistence and had to be removed."
                used_mem.setdefault(m_c["ref"], "Reinforced checking for attacker-created credentials, grants or rules and removing them.")
            add("remove_unauthorized_access", target, "Post-login activity shows attacker-created credentials/permissions/rules that would survive session revocation.",
                exp=exp2, deps_on=[e1], risk="Low if confirmed unauthorized")
        if sev in ("P1", "P2") and privileged:
            m_d = ref_with("disable_caused_disruption")
            if m_d and deps:
                used_mem[m_d["ref"]] = f"Changed the containment choice: playbook default (disable account) is downgraded to optional because {target} has dependent services {deps}."
                conflicts.append(f"Playbook default ({step_for('disable_account')}) is to disable privileged accounts at {sev}. {m_d['source']} ({m_d['ref']}) shows disabling an account with dependent automation caused prolonged disruption; {target} has dependent services {deps}. "
                                 "Recommending session revocation + removal of attacker access + secret rotation instead. The playbook default is kept as an OPTIONAL action; the analyst decides.")
                add("disable_account", target, "Playbook default for P1/P2 privileged identities.", exp=f"{m_d['source']} ({m_d['ref']}): disabling caused disruption to dependent jobs.",
                    risk=f"HIGH - would stop dependent services: {', '.join(deps)}", deps_on=[e1], level="optional")
            else:
                add("disable_account", target, "Playbook default for a P1/P2 privileged identity with confirmed suspicious use.",
                    risk="Medium - user and anything running as the account stop working" + (f" (dependents: {', '.join(deps)})" if deps else ""), deps_on=[e1])
        for ind, res in (tr.get("indicators") or {}).items():
            if res.get("reputation") == "malicious":
                add("block_indicator", ind, f"Indicator {ind} has a malicious verdict.", risk="Low - possible false positive", deps_on=[e1])
    elif itype == "phishing":
        e1 = add("preserve_evidence", user, "Preserve mailbox, proxy and authentication evidence before clean-up.", risk="Low")
        for ind, res in (tr.get("indicators") or {}).items():
            if res.get("reputation") == "malicious":
                add("block_indicator", ind, f"{ind} is a confirmed phishing indicator.", risk="Low", deps_on=[e1])
        if flags & {"credential_submission", "new_geo"}:
            add("revoke_sessions", user, "Credentials were likely submitted and an attacker session exists.", deps_on=[e1], risk="Low")
        if "mailbox_rule" in flags:
            m_c = ref_with("check_mailbox_rules")
            exp = None
            if m_c:
                exp = f"{m_c['source']} ({m_c['ref']}): a forwarding rule was persistence in a similar phishing case."
                used_mem[m_c["ref"]] = "Confirmed that attacker mailbox rules are persistence to remove."
            add("remove_unauthorized_access", user, "Attacker-created mailbox rule forwards mail externally.", exp=exp, deps_on=[e1], risk="Low")
    elif itype == "malware":
        t = host or user
        e1 = add("preserve_evidence", t, "Capture memory/triage data before isolation.")
        add("isolate_endpoint", t, "Host shows compromise indicators.", deps_on=[e1], risk="Medium - host goes offline")
    elif itype == "data_exfiltration":
        e1 = add("preserve_evidence", user or host, "Preserve proxy and file-access logs first.")
        for ind, res in (tr.get("indicators") or {}).items():
            add("block_indicator", ind, "Block exfiltration destination.", deps_on=[e1])
        if user:
            add("revoke_sessions", user, "Stop further uploads.", deps_on=[e1])
    add("create_ticket", f"{inc['incident_id']}: {inc['summary'][:100]}", "Record the incident and actions for the case file and hotwash.", step_id=step_for("create_ticket"), risk="Low")

    historical = []
    for m in mem:
        historical.append({"memory_ref": m["ref"], "source_incident": m["source"], "summary": m["summary"], "lesson": m["lesson"],
                           "influence": used_mem.get(m["ref"], "Retrieved but did not change this recommendation.")})

    if used_mem:
        rs = ("Followed the current approved playbook and used recalled experience to refine how it is applied: "
              + " ".join(f"[{r}] {t}" for r, t in used_mem.items()))
    elif mem:
        rs = "Followed the current approved playbook. Recalled memories were reviewed but did not change the recommendation."
    else:
        rs = "Followed the current approved playbook using only the current incident evidence. No historical experience was available."
    used_ids = [s["id"] for s in pb["steps"] if any(a["playbook_step"] == s["id"] for a in actions)]
    lead = [s["id"] for s in pb["steps"]][:3]
    next_step = "Review and approve the first action (evidence preservation); later actions unlock in order."
    if "notify_out_of_band" in sigs:
        next_step += " Notify the affected user by phone, not email."
    return {
        "assessment": f"{inc['summary']} Signals: {', '.join(why) or 'none'}. Likely {itype.replace('_', ' ')} with active attacker access; scope should be re-checked after containment.",
        "severity": sev, "confidence": confidence,
        "playbook_steps": list(dict.fromkeys(lead + used_ids)),
        "evidence_considered": evidence, "historical_context": historical,
        "recommended_actions": actions, "policy_conflicts": conflicts,
        "reasoning_summary": rs, "next_step": next_step,
    }
