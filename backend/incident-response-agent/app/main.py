"""FastAPI app. All logic lives in AgentController; this file only maps HTTP <-> controller."""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .agent import AgentController
from .errors import AppError
from .models import AnalyzeRequest, ApprovalRequest, RecallRequest, RetainRequest, SeedRequest

app = FastAPI(title="Incident Response Agent (Hindsight)", version="0.1.0",
              description="SOC incident-response agent: playbook (policy) + Hindsight (experience) + LLM + simulated tools + human approval.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

controller = AgentController()


@app.exception_handler(AppError)
async def app_error_handler(_: Request, exc: AppError):
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


@app.exception_handler(Exception)
async def unexpected_handler(_: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": "internal_error", "message": f"{type(exc).__name__}: {exc}"})


@app.get("/health")
def health():
    return controller.health()


@app.get("/playbooks/{incident_type}")
def get_playbook(incident_type: str):
    return controller.get_playbook(incident_type)


@app.get("/incidents")
def list_incidents():
    return controller.list_current()


@app.post("/incidents/analyze")
def analyze(req: AnalyzeRequest):
    return controller.analyze(incident_id=req.incident_id, incident=req.incident, use_hindsight=req.use_hindsight)


@app.get("/incidents/{incident_id}")
def incident_state(incident_id: str):
    return controller.get_incident_state(incident_id)


@app.post("/incidents/{incident_id}/approve-action")
def approve_action(incident_id: str, req: ApprovalRequest):
    return controller.approve_action(incident_id, req.action_id, req.decision, req.analyst_comment, req.lessons_learned)


@app.post("/memory/seed")
def seed(req: SeedRequest | None = None):
    return controller.seed(req.incident_ids if req else None)


@app.post("/memory/recall")
def recall(req: RecallRequest):
    return {"query": req.query, "results": controller.recall(req.query, req.max_results)}


@app.post("/memory/retain")
def retain(req: RetainRequest):
    return controller.retain(text=req.text, incident=req.incident, context=req.context)
