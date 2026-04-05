import os
import uuid
import threading
import mlflow
import spacy
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from dotenv import load_dotenv

from src.scoring.risk_scorer import assess_risk, get_ml_pipeline
from src.policy.engine import make_decision
from src.guardrails.output_guard import guard_output
from src.audit.logger import log_request, get_recent_logs, get_stats

load_dotenv()

mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlruns.db"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-load heavy models on startup to avoid per-request cold start."""
    await run_in_threadpool(get_ml_pipeline)
    await run_in_threadpool(spacy.load, "en_core_web_sm")
    yield


app = FastAPI(
    title       = "AI Security Gateway",
    description = "3-layer hybrid security gateway for LLM applications",
    version     = "1.0.0",
    lifespan    = lifespan,
)


# ── Request / Response Models ─────────────────────────────────────

class CheckRequest(BaseModel):
    text:    str
    use_llm: bool = True


class ScanRequest(BaseModel):
    text:    str
    use_llm: bool = False


class OutputCheckRequest(BaseModel):
    text: str


class GatewayResponse(BaseModel):
    request_id:      str
    action:          str
    risk_score:      float
    reason:          str
    safe_text:       str
    injection_score: float
    jailbreak_score: float
    pii_score:       float
    llm_score:       float
    pii_entities:    list


# ── Helpers ───────────────────────────────────────────────────────

def _log_mlflow_async(request_id: str, use_llm: bool,
                       assessment, decision) -> None:
    """Log to MLflow in a background thread — non-blocking."""
    def _log():
        try:
            mlflow.set_experiment("security-gateway")
            with mlflow.start_run(run_name="gateway_check"):
                mlflow.log_param("request_id", request_id)
                mlflow.log_param("use_llm",    use_llm)
                mlflow.log_metrics({
                    "risk_score":      assessment.risk_score,
                    "injection_score": assessment.injection_score,
                    "jailbreak_score": assessment.jailbreak_score,
                    "pii_score":       assessment.pii_score,
                })
                mlflow.log_param("action", decision.action)
        except Exception:
            pass
    threading.Thread(target=_log, daemon=True).start()


# ── Endpoints ─────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "gateway": "active"}


@app.post("/gateway/check", response_model=GatewayResponse)
async def gateway_check(req: CheckRequest):
    """Full 3-layer security check — rule + ML + LLM."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        request_id = str(uuid.uuid4())[:8]

        # Run blocking detection in threadpool — keeps event loop free
        assessment = await run_in_threadpool(
            assess_risk, req.text, req.use_llm
        )
        decision   = await run_in_threadpool(make_decision, assessment)

        # Non-blocking MLflow logging
        _log_mlflow_async(request_id, req.use_llm, assessment, decision)

        # Non-blocking audit log
        await run_in_threadpool(
            log_request,
            req.text,
            assessment.risk_score,
            assessment.injection_score,
            assessment.jailbreak_score,
            assessment.pii_score,
            assessment.llm_score,
            decision.action,
            decision.reason,
            [e["label"] for e in assessment.pii_entities],
            request_id,
        )

        return GatewayResponse(
            request_id      = request_id,
            action          = decision.action,
            risk_score      = assessment.risk_score,
            reason          = decision.reason,
            safe_text       = decision.safe_text,
            injection_score = assessment.injection_score,
            jailbreak_score = assessment.jailbreak_score,
            pii_score       = assessment.pii_score,
            llm_score       = assessment.llm_score,
            pii_entities    = assessment.pii_entities,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/scan")
async def gateway_scan(req: ScanRequest):
    """Fast scan — rule + ML only, no LLM, no MLflow logging."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        assessment = await run_in_threadpool(assess_risk, req.text, False)
        decision   = await run_in_threadpool(make_decision, assessment)
        return {
            "action":     decision.action,
            "risk_score": assessment.risk_score,
            "reason":     decision.reason,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/output")
async def check_output(req: OutputCheckRequest):
    """Check LLM output before returning to user."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        result = await run_in_threadpool(guard_output, req.text)
        return {
            "safe":          result.safe,
            "action":        result.action,
            "reason":        result.reason,
            "filtered_text": result.filtered_text,
            "pii_found":     result.pii_found,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit")
async def audit(limit: int = 100):
    return await run_in_threadpool(get_recent_logs, limit)


@app.get("/audit/stats")
async def audit_stats():
    return await run_in_threadpool(get_stats)

@app.get("/ping")
async def ping():
    return {"pong": True}