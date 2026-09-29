import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import make_controller  # noqa: F401  (sets sys.path)
from app.config import ROOT, Settings, load_dotenv
from app.errors import AppError, ConfigError, DataFileError, NotFoundError, UpstreamError, ValidationFailed
from app.hindsight_client import HindsightBackend, LocalBackend, MemoryService, incident_to_memory_text
from app.incidents import IncidentStore, incident_entities, validate_incident
from app.llm import LLMClient, parse_json_object
from app.playbooks import PlaybookLibrary, validate_playbook
from app.tools import CONSEQUENTIAL, READ_ONLY, MockSecurityTools


class PlaybookTests(unittest.TestCase):
    def setUp(self):
        self.lib = PlaybookLibrary(ROOT / "playbooks")

    def test_all_playbooks_load_and_validate(self):
        names = {p["file"] for p in self.lib.list()}
        self.assertEqual(names, {"generic_incident_response", "suspicious_login", "account_compromise", "phishing"})

    def test_generic_has_14_step_lifecycle(self):
        self.assertEqual(len(self.lib.get("generic")["steps"]), 14)

    def test_alias_and_fallback(self):
        self.assertEqual(self.lib.get("privileged_access")["incident_type"], "account_compromise")
        pb = self.lib.get("something_new")
        self.assertTrue(pb["_fallback_to_generic"])

    def test_missing_playbook_file(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(NotFoundError):
                PlaybookLibrary(Path(d)).get("phishing")

    def test_malformed_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "phishing.yaml").write_text("name: [unclosed\n  - x: : :")
            with self.assertRaises(DataFileError):
                PlaybookLibrary(Path(d)).get("phishing")

    def test_missing_required_keys(self):
        with self.assertRaises(DataFileError):
            validate_playbook({"name": "x"})


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.store = IncidentStore(ROOT / "incidents")

    def test_counts(self):
        self.assertGreaterEqual(len(self.store.historical()), 5)
        self.assertGreaterEqual(len(self.store.current()), 2)

    def test_historical_have_required_fields(self):
        for inc in self.store.historical().values():
            for k in ("summary", "evidence", "investigation", "actions_taken", "outcome", "analyst_feedback", "lessons_learned", "detection_gaps"):
                self.assertIn(k, inc)

    def test_unknown_incident(self):
        with self.assertRaises(NotFoundError):
            self.store.get_current("NOPE")

    def test_invalid_incident(self):
        with self.assertRaises(ValidationFailed):
            validate_incident({"incident_id": "X"})

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "current").mkdir()
            (Path(d) / "current" / "bad.json").write_text("{not json")
            with self.assertRaises(DataFileError):
                IncidentStore(Path(d)).current()

    def test_entities(self):
        ents = incident_entities(self.store.get_current("CUR-001"))
        self.assertIn("raj.m", ents)
        self.assertIn("185.220.101.47", ents)


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.inc = IncidentStore(ROOT / "incidents").get_current("CUR-001")
        self.t = MockSecurityTools(self.inc["telemetry"])

    def test_read_only_tools(self):
        self.assertEqual(self.t.get_authentication_history("raj.m")["status"], "simulated_success")
        self.assertEqual(len(self.t.get_user_activity("raj.m")["events"]), 3)
        self.assertEqual(self.t.check_indicator("185.220.101.47")["reputation"], "suspicious")
        self.assertEqual(self.t.check_indicator("1.2.3.4")["reputation"], "unknown")
        self.assertGreaterEqual(len(self.t.search_logs("api_key")["results"]), 1)

    def test_revoke_sessions_mutates_only_simulation(self):
        r = self.t.execute("revoke_sessions", "raj.m")
        self.assertEqual(r["status"], "simulated_success")
        self.assertTrue(r["simulated"])
        self.assertEqual(r["revoked_count"], 1)
        self.assertEqual(self.t.get_user_activity("raj.m")["active_sessions"], [])

    def test_disable_reports_impacted_services(self):
        self.assertIn("nightly-backup", self.t.execute("disable_account", "raj.m")["services_impacted"])

    def test_remove_unauthorized_access(self):
        self.assertEqual(len(self.t.execute("remove_unauthorized_access", "raj.m")["removed"]), 2)

    def test_all_consequential_tools_run(self):
        for tool in CONSEQUENTIAL:
            self.assertTrue(self.t.execute(tool, "raj.m")["simulated"])

    def test_invalid_tool_and_target(self):
        with self.assertRaises(ValidationFailed):
            self.t.execute("rm_rf", "x")
        with self.assertRaises(ValidationFailed):
            self.t.execute("revoke_sessions", "  ")

    def test_tool_sets_disjoint(self):
        self.assertFalse(set(READ_ONLY) & set(CONSEQUENTIAL))


class FakeHindsightClient:
    def __init__(self):
        self.retained = []

    def retain(self, **kw):
        self.retained.append(kw)

    def recall(self, bank_id, query):
        class R:  # mimics an SDK response object
            results = [type("F", (), {"text": "INCIDENT INC-001 lesson", "id": "abc", "type": "experience", "context": None})()]
        return R()


class HindsightWrapperTests(unittest.TestCase):
    def test_missing_credentials(self):
        with self.assertRaises(ConfigError) as cm:
            MemoryService(Settings(memory_backend="hindsight")).recall("x")
        self.assertIn("HINDSIGHT_API_KEY", cm.exception.message)

    def test_unknown_backend(self):
        with self.assertRaises(ConfigError):
            MemoryService(Settings(memory_backend="nope")).backend

    def test_retain_and_recall_via_client(self):
        b = HindsightBackend(Settings(hindsight_api_key="k", hindsight_base_url="http://x", hindsight_bank_id="bank1"))
        b._client = FakeHindsightClient()
        svc = MemoryService(Settings(), backend=b)
        r = svc.retain("hello", context="ctx", document_id="D1")
        self.assertTrue(r["retained"])
        self.assertEqual(b._client.retained[0]["bank_id"], "bank1")
        self.assertEqual(b._client.retained[0]["document_id"], "D1")
        hits = svc.recall("q")
        self.assertEqual(hits[0].ref, "M1")
        self.assertEqual(hits[0].memory_id, "abc")

    def test_upstream_failure_is_wrapped(self):
        class Boom:
            def recall(self, **kw):
                raise RuntimeError("503 from server")
        b = HindsightBackend(Settings(hindsight_api_key="k", hindsight_base_url="http://x"))
        b._client = Boom()
        with self.assertRaises(UpstreamError):
            b.recall("q", 3)

    def test_empty_inputs(self):
        svc = MemoryService(Settings(memory_backend="local"))
        with self.assertRaises(ValidationFailed):
            svc.retain(" ")
        with self.assertRaises(ValidationFailed):
            svc.recall("")

    def test_local_double_ranks_by_overlap(self):
        b = LocalBackend()
        b.retain("phishing mailbox forwarding rule", None, "a", None)
        b.retain("endpoint malware beacon", None, "b", None)
        self.assertEqual(b.recall("mailbox forwarding", 3)[0].memory_id, "a")

    def test_memory_text_contains_lessons(self):
        t = incident_to_memory_text(IncidentStore(ROOT / "incidents").historical()["INC-001"])
        self.assertIn("Lessons learned", t)
        self.assertIn("before revoking sessions", t.lower())


class LLMTests(unittest.TestCase):
    def test_missing_key(self):
        with self.assertRaises(ConfigError):
            LLMClient(Settings(llm_mode="live", llm_api_key="")).complete_json({})

    def test_parse_json_variants(self):
        self.assertEqual(parse_json_object('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(parse_json_object('Sure! {"a": 2} done'), {"a": 2})
        with self.assertRaises(UpstreamError):
            parse_json_object("no json here")


class ConfigTests(unittest.TestCase):
    def test_dotenv_parser(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / ".env"
            p.write_text('# c\nTEST_IR_KEY="abc"\nTEST_IR_EMPTY=\n')
            os.environ.pop("TEST_IR_KEY", None)
            load_dotenv(p)
            self.assertEqual(os.environ["TEST_IR_KEY"], "abc")


if __name__ == "__main__":
    unittest.main()
