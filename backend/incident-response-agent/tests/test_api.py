"""HTTP-level tests. Require fastapi + httpx (pip install -r requirements.txt); skipped otherwise."""
import os
import unittest

os.environ["LLM_MODE"] = "mock"
os.environ["MEMORY_BACKEND"] = "local"

try:
    from fastapi.testclient import TestClient
    from app.main import app
    HAVE_API = True
except ImportError:
    HAVE_API = False


@unittest.skipUnless(HAVE_API, "fastapi/httpx not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "ok")

    def test_playbook(self):
        self.assertEqual(self.client.get("/playbooks/phishing").json()["incident_type"], "phishing")

    def test_analyze_approve_flow(self):
        a = self.client.post("/incidents/analyze", json={"incident_id": "CUR-001", "use_hindsight": False}).json()
        first = a["recommended_actions"][0]
        self.assertEqual(first["tool"], "preserve_evidence")
        ok = self.client.post("/incidents/CUR-001/approve-action", json={"action_id": first["action_id"], "decision": "approve"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json()["status"], "executed")

    def test_invalid_requests(self):
        self.assertEqual(self.client.post("/incidents/analyze", json={"incident_id": "NOPE"}).status_code, 404)
        self.assertEqual(self.client.post("/incidents/analyze", json={}).status_code, 422)
        self.assertEqual(self.client.post("/incidents/CUR-001/approve-action", json={"action_id": "x", "decision": "maybe"}).status_code, 422)
        self.assertEqual(self.client.post("/incidents/NOPE/approve-action", json={"action_id": "x", "decision": "approve"}).status_code, 404)
        self.assertEqual(self.client.post("/memory/recall", json={"query": ""}).status_code, 422)

    def test_memory_endpoints(self):
        self.assertEqual(self.client.post("/memory/seed", json={}).json()["seeded"], 5)
        r = self.client.post("/memory/recall", json={"query": "privileged login api key"})
        self.assertTrue(r.json()["results"])
        self.assertTrue(self.client.post("/memory/retain", json={"text": "note"}).json()["retained"])


if __name__ == "__main__":
    unittest.main()
