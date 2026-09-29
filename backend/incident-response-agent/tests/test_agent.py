import unittest

from tests.helpers import make_controller
from app.errors import ConfigError, ConflictError, NotFoundError, ValidationFailed
from app.agent import AgentController
from app.config import Settings


def actions_by_tool(result):
    return {a["tool"]: a for a in result["recommended_actions"]}


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.c = make_controller()

    def test_hindsight_off_has_no_history(self):
        r = self.c.analyze("CUR-001", use_hindsight=False)
        self.assertFalse(r["mode"]["use_hindsight"])
        self.assertEqual(r["retrieved_memories"], [])
        self.assertEqual(r["historical_context"], [])
        self.assertIsNotNone(r["historical_note"])
        self.assertTrue(r["requires_human_approval"])
        self.assertIn(r["severity"], ("P1", "P2", "P3", "P4"))
        # baseline follows the playbook default: disable_account is a normal recommendation
        self.assertEqual(actions_by_tool(r)["disable_account"]["recommendation"], "recommended")

    def test_all_actions_require_approval_and_start_pending(self):
        r = self.c.analyze("CUR-001", use_hindsight=False)
        for a in r["recommended_actions"]:
            self.assertTrue(a["requires_approval"])
            self.assertEqual(a["status"], "pending_approval")

    def test_evidence_precedes_containment_by_policy(self):
        r = self.c.analyze("CUR-001", use_hindsight=False)
        acts = actions_by_tool(r)
        ev = acts["preserve_evidence"]["action_id"]
        for tool in ("revoke_sessions", "disable_account", "remove_unauthorized_access"):
            self.assertIn(ev, acts[tool]["depends_on"])

    def test_hindsight_on_uses_retrieved_memory_and_changes_recommendation(self):
        self.c.seed()
        off = self.c.analyze("CUR-001", use_hindsight=False)
        on = self.c.analyze("CUR-001", use_hindsight=True)
        self.assertTrue(on["retrieved_memories"])
        sources = {h["source_incident"] for h in on["historical_context"]}
        self.assertIn("INC-001", sources)
        self.assertIn("INC-004", sources)
        self.assertEqual(actions_by_tool(off)["disable_account"]["recommendation"], "recommended")
        self.assertEqual(actions_by_tool(on)["disable_account"]["recommendation"], "optional")
        self.assertTrue(on["policy_conflicts"])
        self.assertIn("HIGH", actions_by_tool(on)["disable_account"]["risk"])
        self.assertNotEqual(off["reasoning_summary"], on["reasoning_summary"])

    def test_no_memory_no_influence(self):
        """Without seeded memories, Hindsight ON must not fabricate historical context."""
        r = self.c.analyze("CUR-001", use_hindsight=True)
        self.assertEqual(r["retrieved_memories"], [])
        self.assertEqual(r["historical_context"], [])
        self.assertEqual(actions_by_tool(r)["disable_account"]["recommendation"], "recommended")

    def test_phishing_incident(self):
        r = self.c.analyze("CUR-002", use_hindsight=False)
        tools = {a["tool"] for a in r["recommended_actions"]}
        self.assertTrue({"preserve_evidence", "block_indicator", "revoke_sessions", "remove_unauthorized_access"} <= tools)
        self.assertEqual(r["playbook"]["incident_type"], "phishing")

    def test_inline_incident_and_generic_fallback(self):
        inc = {"incident_id": "X-1", "incident_type": "weird_type", "summary": "Odd thing", "affected_user": "bob"}
        r = self.c.analyze(incident=inc, use_hindsight=False)
        self.assertTrue(r["playbook"]["fell_back_to_generic"])

    def test_invalid_requests(self):
        with self.assertRaises(NotFoundError):
            self.c.analyze("NOPE")
        with self.assertRaises(ValidationFailed):
            self.c.analyze()
        with self.assertRaises(ValidationFailed):
            self.c.analyze(incident={"incident_id": "X"})

    def test_hindsight_on_without_credentials_fails_clearly(self):
        c = AgentController(Settings(llm_mode="mock", memory_backend="hindsight"))
        with self.assertRaises(ConfigError):
            c.analyze("CUR-001", use_hindsight=True)
        self.assertEqual(c.analyze("CUR-001", use_hindsight=False)["severity"], "P2")   # OFF still works

    def test_normalizer_rejects_hallucinated_targets_and_tools(self):
        class BadLLM:
            mode = "bad"
            def complete_json(self, ctx):
                return {"severity": "P9", "confidence": "high", "recommended_actions": [
                    {"order": 1, "tool": "revoke_sessions", "target": "ghost.user", "reason": "x"},
                    {"order": 2, "tool": "search_logs", "target": "raj.m"},
                    {"order": 3, "tool": "delete_everything", "target": "raj.m"},
                    {"order": 4, "tool": "revoke_sessions", "target": "raj.m", "reason": "ok"}]}
        c = AgentController(Settings(llm_mode="mock", memory_backend="local"), llm=BadLLM())
        r = c.analyze("CUR-001", use_hindsight=False)
        self.assertEqual(r["severity"], "P3")
        self.assertEqual([a["tool"] for a in r["recommended_actions"]], ["preserve_evidence", "revoke_sessions"])
        self.assertTrue(len(r["warnings"]) >= 4)


class ApprovalFlowTests(unittest.TestCase):
    def setUp(self):
        self.c = make_controller()
        self.r = self.c.analyze("CUR-001", use_hindsight=False)
        self.acts = actions_by_tool(self.r)

    def approve(self, tool, decision="approve", **kw):
        return self.c.approve_action("CUR-001", self.acts[tool]["action_id"], decision, **kw)

    def test_cannot_skip_evidence_step(self):
        with self.assertRaises(ConflictError):
            self.approve("revoke_sessions")
        # nothing executed
        self.assertEqual(self.c.sessions["CUR-001"]["tools"].state["revoked"], [])

    def test_approve_executes_records_and_retains(self):
        ev = self.approve("preserve_evidence")
        self.assertEqual(ev["status"], "executed")
        self.assertTrue(ev["memory"]["retained"])
        self.assertIn(self.acts["revoke_sessions"]["action_id"], ev["unlocked_actions"])
        rv = self.approve("revoke_sessions", analyst_comment="Confirmed with user by phone", lessons_learned=["Phone confirmation was quick"])
        self.assertEqual(rv["tool_result"]["status"], "simulated_success")
        self.assertEqual(self.c.sessions["CUR-001"]["tools"].state["revoked"], ["raj.m"])
        # retained experience is recallable and contains the analyst's words
        hits = self.c.recall("suspicious login platform administrator revoke sessions")
        self.assertTrue(any("Phone confirmation was quick" in h["text"] for h in hits))

    def test_reject_does_not_execute_but_is_recorded(self):
        self.approve("preserve_evidence")
        rj = self.approve("revoke_sessions", "reject", analyst_comment="User is mid-deployment")
        self.assertEqual(rj["status"], "rejected")
        self.assertIsNone(rj["tool_result"])
        self.assertEqual(self.c.sessions["CUR-001"]["tools"].state["revoked"], [])
        self.assertTrue(rj["memory"]["retained"])
        self.assertIn("User is mid-deployment", self.c.recall("mid-deployment")[0]["text"])

    def test_double_decision_conflicts(self):
        self.approve("preserve_evidence")
        with self.assertRaises(ConflictError):
            self.approve("preserve_evidence")

    def test_invalid_approvals(self):
        with self.assertRaises(NotFoundError):
            self.c.approve_action("CUR-999", "x", "approve")
        with self.assertRaises(NotFoundError):
            self.c.approve_action("CUR-001", "nope", "approve")
        with self.assertRaises(ValidationFailed):
            self.c.approve_action("CUR-001", self.acts["preserve_evidence"]["action_id"], "maybe")

    def test_memory_failure_does_not_undo_action(self):
        c = AgentController(Settings(llm_mode="mock", memory_backend="hindsight"))   # no credentials
        r = c.analyze("CUR-001", use_hindsight=False)
        a = actions_by_tool(r)["preserve_evidence"]
        out = c.approve_action("CUR-001", a["action_id"], "approve")
        self.assertEqual(out["status"], "executed")
        self.assertFalse(out["memory"]["retained"])
        self.assertIn("HINDSIGHT_API_KEY", out["memory"]["error"])

    def test_full_learning_loop(self):
        """Complete CUR-001 (Hindsight off), then a similar incident recalls what was learned."""
        for tool in ("preserve_evidence", "revoke_sessions", "remove_unauthorized_access"):
            self.approve(tool)
        self.approve("disable_account", analyst_comment="Disabling broke nightly-backup again", lessons_learned=["Do not disable raj.m-style admin accounts with backup jobs"])
        r = self.c.analyze("CUR-003", use_hindsight=True)   # similar incident, different user
        self.assertTrue(any("CUR-001" in h["text"] for h in r["retrieved_memories"]))


if __name__ == "__main__":
    unittest.main()
