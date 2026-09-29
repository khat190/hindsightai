# Incident Response Agent — learning from experience with Hindsight
HackwithHyderabad 3.0 · problem statement: **AI Agents That Learn Using Hindsight**

An incident-response agent for a **SOC analyst**. It investigates with simulated tools, follows the organization's
**approved playbook**, recalls **what happened in similar past incidents** from Hindsight, recommends actions, and
**waits for human approval** before anything (simulated) is executed. Approved/rejected decisions and analyst feedback
are written back to Hindsight, so the next similar incident benefits.

## Problem
Analysts work from static playbooks. Playbooks say *what we should do*, but not *what actually happened the last
time we did it*: which step saved the investigation, which default action took down a backup job. That knowledge lives in
people's heads and is lost between incidents.

## Solution
```
Current incident + Current approved playbook + Relevant Hindsight experience
        -> LLM reasoning -> Recommendation -> Analyst approval -> Simulated action
        -> Outcome + analyst feedback -> retained in Hindsight
```

| Component | Role |
|---|---|
| **Playbook** (`playbooks/*.yaml`) | Current approved procedure = **policy**. "What should we do?" |
| **Hindsight** | Historical **experience**. "What happened when we dealt with something like this?" Never overrides the playbook. |
| **LLM** | Reasoning over incident + playbook + tool results + recalled memories |
| **Tools** (`app/tools.py`) | **Simulated** execution. Nothing touches real systems |
| **Human** | Approval authority for every consequential action |

If experience conflicts with a playbook default, the agent says so (`policy_conflicts`), keeps the playbook default as an
`optional` action, and recommends the alternative. The analyst decides.

## Architecture
```
            POST /incidents/analyze                       POST /incidents/{id}/approve-action
                     │                                                   │
                     ▼                                                   ▼
┌───────────────────────── FastAPI (app/main.py) ─────────────────────────────┐
│                     AgentController (app/agent.py)                          │
│  1 load incident   2 pick playbook   3 run read-only mock tools             │
│  4 Hindsight recall (if USE_HINDSIGHT)   5 LLM reasoning (JSON)             │
│  6 validate + enforce policy (targets, evidence-before-containment)         │
│  7 return actions as "pending_approval"                                     │
│  ── on approve: check prerequisites → run SIMULATED tool → retain to Hindsight
└───────┬──────────────┬──────────────┬───────────────┬───────────────────────┘
        ▼              ▼              ▼               ▼
   playbooks/      Hindsight       llm.py          tools.py
   (YAML policy)   retain/recall   live | mock     mock security tools
```

## Before vs. after Hindsight (the demo)
Same code, one flag (`USE_HINDSIGHT` or `"use_hindsight"` per request).

* **A — Hindsight OFF.** `CUR-001` (suspicious login on a platform admin, then unusual privileged activity). Agent uses incident + playbook:
  preserve evidence → revoke sessions → remove attacker access → **disable account** (playbook default for privileged P1/P2).
* **B — Retain.** Analyst approves steps and rejects disabling ("raj.m runs nightly-backup"). Outcome + comment + lessons are retained.
  (Historical incidents INC-001…005 are seeded with `scripts/seed_hindsight.py`.)
* **C — Similar incident.** `CUR-003` with Hindsight ON. The agent recalls INC-001 (evidence before revocation; check newly created credentials),
  INC-004 (disabling an account with dependent automation caused ~9h of disruption) and the just-retained CUR-001, then:
  makes evidence collection an explicit prerequisite, and **demotes `disable_account` to optional** because `anita.p` has dependent services,
  with a `policy_conflicts` note. Every claim is tied to a retrieved memory (`retrieved_memories` shows Hindsight's raw output).

Try it offline in one command (mock LLM + in-process memory double, no keys, no FastAPI): `python scripts/demo_cli.py`

## Setup
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in keys
```
| Variable | Purpose |
|---|---|
| `HINDSIGHT_API_KEY`, `HINDSIGHT_BASE_URL`, `HINDSIGHT_BANK_ID` | Hindsight (required for `MEMORY_BACKEND=hindsight`) |
| `LLM_API_KEY`, `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL` | Live LLM (`anthropic` or OpenAI-compatible) |
| `USE_HINDSIGHT` | default recall on/off (per-request override available) |
| `LLM_MODE=mock` | offline demo reasoner (heuristics over the *same* retrieved context; not a real LLM) |
| `MEMORY_BACKEND=local` | offline test double for Hindsight (**not** Hindsight; responses say `"backend": "local"`) |

Missing credentials give a clear `503 not_configured` error with a hint, never a crash. Hindsight/LLM outages give `502 upstream_failure`.

## Run
```bash
python scripts/seed_hindsight.py     # retain INC-001..005 into your Hindsight bank
python run.py                        # or: uvicorn app.main:app --reload     -> http://127.0.0.1:8000/docs
# no keys? LLM_MODE=mock MEMORY_BACKEND=local python run.py
```

## API examples
```bash
curl localhost:8000/health
curl localhost:8000/playbooks/suspicious_login
curl -X POST localhost:8000/memory/seed -H 'content-type: application/json' -d '{}'

# A. Hindsight OFF
curl -X POST localhost:8000/incidents/analyze -H 'content-type: application/json' \
  -d '{"incident_id":"CUR-001","use_hindsight":false}'

# Approve the first action (evidence). Containment actions are blocked until prerequisites are executed (409).
curl -X POST localhost:8000/incidents/CUR-001/approve-action -H 'content-type: application/json' \
  -d '{"action_id":"CUR-001-r1-a1","decision":"approve","analyst_comment":"Snapshot first"}'
curl -X POST localhost:8000/incidents/CUR-001/approve-action -H 'content-type: application/json' \
  -d '{"action_id":"CUR-001-r1-a4","decision":"reject","analyst_comment":"raj.m runs nightly-backup",
       "lessons_learned":["Prefer revoke + remove access over disabling admin accounts that run automation"]}'

# C. Similar incident, Hindsight ON
curl -X POST localhost:8000/incidents/analyze -H 'content-type: application/json' \
  -d '{"incident_id":"CUR-003","use_hindsight":true}'

curl -X POST localhost:8000/memory/recall -H 'content-type: application/json' -d '{"query":"privileged login then new API key"}'
curl -X POST localhost:8000/memory/retain -H 'content-type: application/json' -d '{"text":"Free-text lesson..."}'
curl localhost:8000/incidents/CUR-001      # full state + audit trail
```
Analysis response highlights: `severity`, `confidence`, `playbook.steps_applied`, `evidence_considered`, `retrieved_memories`,
`historical_context[].influence`, `policy_conflicts`, and `recommended_actions[]` each with `reason`, `evidence`, `playbook_step`,
`historical_experience`, `risk`, `depends_on`, `recommendation` (`recommended`/`optional`), `status: pending_approval`.

## Project structure
```
app/           main.py (HTTP) · agent.py (orchestration + policy checks + approval) · hindsight_client.py (retain/recall)
               llm.py (live + mock) · playbooks.py · incidents.py · tools.py (simulated) · models.py · config.py · errors.py
playbooks/     generic (14-step lifecycle), suspicious_login, account_compromise, phishing
incidents/     historical/ INC-001..005 (seeded to Hindsight) · current/ CUR-001..003 (demo; include mock telemetry)
scripts/       seed_hindsight.py · demo_cli.py
tests/         unittest suite (pytest also works)
```
Playbooks were designed from the three provided sources (CISA Federal IR Playbook; AWS STS Token Abuse; AWS Identity Center Compromise),
generalized into vendor-neutral steps (evidence before containment, scoping, persistence removal, verification, hotwash, detection gaps).
AWS-specific actions are mapped to generic tools (e.g. CloudTrail search → `search_logs`, session revocation → `revoke_sessions`). Each playbook lists its `source_notes`.

## Tests
`python -m unittest discover -s tests -t . -v` (or `pytest`). `tests/test_api.py` needs `fastapi` + `httpx` and is skipped otherwise.

## Limitations
* All tools are **simulated**; no AWS, SIEM, EDR, IdP, firewall or IAM is ever contacted. Incidents are **synthetic**.
* Every consequential action requires analyst approval; policy enforces evidence-before-containment.
* Hindsight is historical memory, **not** the policy source. The playbook stays authoritative.
* Session state (analysis runs, approvals, audit) is in-memory and resets on restart; only Hindsight persists.
* Mock LLM mode is a heuristic stand-in for offline demos. It shows the pipeline, not real model reasoning.
* Hindsight integration follows the official `hindsight-client` (`retain`/`recall`), with a REST fallback; see the implementation report for what was and wasn't verified against a live service.
