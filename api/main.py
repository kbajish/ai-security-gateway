import os
import uuid
import mlflow
import spacy
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from src.scoring.risk_scorer import assess_risk, get_ml_pipeline
from src.policy.engine import make_decision
from src.guardrails.output_guard import guard_output
from src.audit.logger import log_request, get_recent_logs, get_stats

load_dotenv()

mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlruns.db"))

app = FastAPI(
    title       = "AI Security Gateway",
    description = "3-layer hybrid security gateway for LLM applications",
    version     = "1.0.0"
)


@app.on_event("startup")
async def startup_event():
    """Pre-load heavy models on startup to avoid per-request loading."""
    get_ml_pipeline()
    spacy.load("en_core_web_sm")


class CheckRequest(BaseModel):
    text:    str
    use_llm: bool = True


class ScanRequest(BaseModel):
    text:    str
    use_llm: bool = False


class OutputCheckRequest(BaseModel):
    text: str


class GatewayResponse(BaseModel):
    request_id:     str
    action:         str
    risk_score:     float
    reason:         str
    safe_text:      str
    injection_score: float
    jailbreak_score: float
    pii_score:      float
    llm_score:      float
    pii_entities:   list


@app.get("/health")
def health():
    return {"status": "ok", "version": "1.0.0", "gateway": "active"}


@app.post("/gateway/check", response_model=GatewayResponse)
def gateway_check(req: CheckRequest):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        request_id = str(uuid.uuid4())[:8]

        assessment = assess_risk(req.text, use_llm=req.use_llm)
        decision   = make_decision(assessment)

        # MLflow logging — non-blocking
        try:
            mlflow.set_experiment("security-gateway")
            with mlflow.start_run(run_name="gateway_check"):
                mlflow.log_param("request_id", request_id)
                mlflow.log_param("use_llm",    req.use_llm)
                mlflow.log_metrics({
                    "risk_score":      assessment.risk_score,
                    "injection_score": assessment.injection_score,
                    "jailbreak_score": assessment.jailbreak_score,
                    "pii_score":       assessment.pii_score,
                })
                mlflow.log_param("action", decision.action)
        except Exception as mlflow_err:
            pass  # MLflow unavailable — continue without logging

        log_request(
            input_text      = req.text,
            risk_score      = assessment.risk_score,
            injection_score = assessment.injection_score,
            jailbreak_score = assessment.jailbreak_score,
            pii_score       = assessment.pii_score,
            llm_score       = assessment.llm_score,
            action          = decision.action,
            reason          = decision.reason,
            pii_types       = [e["label"] for e in assessment.pii_entities],
            request_id      = request_id
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
            pii_entities    = assessment.pii_entities
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/scan")
def gateway_scan(req: ScanRequest):
    """Quick scan without LLM — low latency."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        assessment = assess_risk(req.text, use_llm=False)
        decision   = make_decision(assessment)
        return {
            "action":     decision.action,
            "risk_score": assessment.risk_score,
            "reason":     decision.reason
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/output")
def check_output(req: OutputCheckRequest):
    """Check LLM output before returning to user."""
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    try:
        result = guard_output(req.text)
        return {
            "safe":          result.safe,
            "action":        result.action,
            "reason":        result.reason,
            "filtered_text": result.filtered_text,
            "pii_found":     result.pii_found
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit")
def audit(limit: int = 100):
    return get_recent_logs(limit)


@app.get("/audit/stats")
def audit_stats():
    return get_stats()