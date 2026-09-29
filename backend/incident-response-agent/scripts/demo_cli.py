"""Offline end-to-end demo of the Hindsight learning effect (no API keys, no FastAPI needed).

Uses the mock LLM + the in-process memory test double, so it shows the PIPELINE. For the real thing,
run the API with Hindsight/LLM credentials (see README).

  A. CUR-001 with Hindsight OFF          -> playbook-only recommendation
  B. Analyst approves; experience retained
  C. CUR-003 (similar) with Hindsight ON -> recommendation shaped by recalled experience
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agent import AgentController  # noqa: E402
from app.config import Settings  # noqa: E402


def show(title, r):
    print(f"\n=== {title} ===")
    print(f"mode={r['mode']}  severity={r['severity']}  confidence={r['confidence']}")
    for a in r["recommended_actions"]:
        print(f"  #{a['order']} {a['tool']:<28} {a['target'][:34]:<34} [{a['recommendation']}] needs approval, after={len(a['depends_on'])} prereq")
    for h in r["historical_context"]:
        print(f"  memory {h['memory_ref']} ({h['source_incident']}): {h['influence']}")
    for c in r["policy_conflicts"]:
        print(f"  POLICY NOTE: {c}")
    print(f"  reasoning: {r['reasoning_summary']}")


c = AgentController(Settings(llm_mode="mock", memory_backend="local"))
c.seed()  # historical incidents INC-001..005 (Hindsight would hold these)

r1 = c.analyze("CUR-001", use_hindsight=False)
show("A. CUR-001, Hindsight OFF", r1)

print("\n--- B. Analyst approves evidence + revocation + removal; rejects disabling ---")
acts = {a["tool"]: a for a in r1["recommended_actions"]}
for tool in ("preserve_evidence", "revoke_sessions", "remove_unauthorized_access"):
    out = c.approve_action("CUR-001", acts[tool]["action_id"], "approve")
    print(f"  approved {tool}: {out['outcome']}  (retained={out['memory']['retained']})")
out = c.approve_action("CUR-001", acts["disable_account"]["action_id"], "reject",
                       analyst_comment="raj.m runs nightly-backup; disabling would break it",
                       lessons_learned=["Prefer revoke + remove access over disabling admin accounts that run automation"])
print(f"  rejected disable_account: {out['outcome']}")

r3 = c.analyze("CUR-003", use_hindsight=True)
show("C. CUR-003 (similar), Hindsight ON", r3)
print("\nRecalled from experience:", [m["memory_id"] for m in r3["retrieved_memories"]])
