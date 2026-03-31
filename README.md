# 🛡️ AI Security Gateway

![CI](https://github.com/kbajish/ai-security-gateway/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-compose-blue)
![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-red)
![EU AI Act](https://img.shields.io/badge/EU_AI_Act-aligned-orange)

A middleware security gateway for LLM applications that intercepts requests and responses, applying a three-layer hybrid detection pipeline — rule-based, ML-based, and LLM-based — before forwarding traffic to the protected AI system. Designed around the security patterns and compliance frameworks relevant to enterprise AI deployments in regulated industries.

Aligned with OWASP LLM Top 10, EU AI Act, NIST AI RMF, MITRE ATLAS, and BSI IT-Grundschutz.

---

## 🎯 What It Protects Against

| Threat | OWASP LLM | Detection Layer |
|---|---|---|
| Prompt injection | LLM01 | Rules + ML + LLM |
| Sensitive data leakage | LLM02 | spaCy NER + Regex |
| Jailbreak attempts | LLM01 | Rules + LLM |
| Toxic / unsafe outputs | LLM09 | Output guardrails |
| PII in responses | LLM06 | Output guardrails |

---

## 🚀 Key Features

- 🔍 3-layer hybrid detection — rule-based patterns + ML classifier + LLM semantic reasoning
- 💉 Prompt injection detection using regex rules and a TF-IDF + LogisticRegression classifier
- 🕵️ PII detection — spaCy NER combined with regex for IBAN, credit cards, and German tax IDs
- 🔓 Jailbreak detection — 50+ known patterns combined with Ollama semantic intent classification
- 🛡️ Output guardrails — PII leak detection and toxicity filtering on LLM responses
- 📋 GDPR-aligned audit trail — inputs hashed with SHA-256, PII redacted before storage
- ⚖️ Weighted risk scorer — configurable Allow / Sanitize / Block thresholds
- 📊 Streamlit SOC dashboard — blocked requests, risk scores, and audit log viewer
- ⚡ FastAPI gateway endpoints
- 🐳 Docker Compose deployment
- 🔄 GitHub Actions CI/CD — 24 tests passing

---

## 🧠 System Architecture

```
Incoming request
        ↓
src/detection/rule_detector.py    — regex + pattern rules (zero latency)
src/detection/ml_detector.py      — TF-IDF + LogisticRegression + spaCy NER
src/detection/llm_detector.py     — Ollama semantic intent classification
src/detection/pii_detector.py     — NER + regex PII detection
        ↓
src/scoring/risk_scorer.py        — weighted risk aggregation
src/policy/engine.py              — Allow / Sanitize / Block decision
        ↓
Protected AI system (RAG / Agent / any LLM API)
        ↓
src/guardrails/output_guard.py    — output PII + toxicity filtering
        ↓
src/audit/logger.py               — GDPR-aligned audit logging (SQLite)
        ↓
api/main.py                       — FastAPI gateway
        ↓
dashboard/app.py                  — Streamlit SOC dashboard
```

---

## ⚙️ How It Works

Every incoming request passes through three detection layers in sequence. The rule-based layer applies regex patterns for known injection strings, jailbreak prefixes, and PII formats — this handles obvious threats without any model inference. The ML layer uses a TF-IDF + LogisticRegression classifier trained on injection examples and spaCy NER for entity detection. The LLM layer uses Ollama to semantically classify adversarial intent for cases that require contextual reasoning.

The weighted risk scorer aggregates all detection scores into a single risk value using configurable weights. The policy engine maps this value to Allow, Sanitize, or Block based on configurable thresholds. Allowed requests are forwarded to the protected AI system. The response is then checked by output guardrails for PII leakage and toxic content before being returned to the user. Every request and decision is written to a GDPR-aligned audit log with raw inputs never persisted.

---

## 📊 Risk Scoring

```python
risk_score = (
    0.35 * injection_score  +
    0.25 * jailbreak_score  +
    0.25 * pii_score        +
    0.15 * toxicity_score
)

# Policy thresholds (configurable via .env)
if risk_score >= 0.7:  →  BLOCK
if risk_score >= 0.3:  →  SANITIZE
if risk_score <  0.3:  →  ALLOW
```

---

## 🏛️ Framework Alignment

| Framework | Implementation |
|---|---|
| OWASP LLM Top 10 | LLM01 injection, LLM02 data leakage, LLM06 sensitive info, LLM09 overreliance |
| EU AI Act | Art. 13 transparency logging, Art. 9 risk management, Art. 17 quality system |
| NIST AI RMF | GOVERN, MAP, MEASURE, MANAGE functions |
| MITRE ATLAS | AML.T0051 prompt injection, AML.T0048 societal harm |
| BSI IT-Grundschutz | OPS.1.1.4 logging, CON.8 data security |

---

## 📊 Dashboard Overview

The Streamlit SOC dashboard provides:

- 🚨 Real-time security check with decision, risk score, and detection breakdown
- 📊 Risk score gauge — colour-coded by threshold zone
- 🔍 PII entity panel showing detected entities and types
- 📋 GDPR audit log with SHA-256 hashed inputs and colour-coded decisions
- 📈 Running stats — total requests, blocked, sanitized, allowed, average risk score

---

## 🛠 Tech Stack

| Layer | Tool |
|---|---|
| Rule detection | Python regex, custom pattern library |
| ML detection | scikit-learn (TF-IDF + LogisticRegression) |
| NLP / PII | spaCy |
| LLM detection | LangChain + Ollama (llama3.2, local, no API key) |
| Risk scoring | Custom weighted scorer |
| Audit | SQLite, GDPR-aligned |
| Backend | FastAPI, Uvicorn |
| Dashboard | Streamlit, Plotly |
| Experiment tracking | MLflow |
| Containerisation | Docker Compose |
| CI/CD | GitHub Actions |
| Testing | pytest (24 tests) |

---

## 📂 Project Structure

```
ai-security-gateway/
│
├── src/
│   ├── detection/
│   │   ├── rule_detector.py       # Regex + pattern rules
│   │   ├── ml_detector.py         # TF-IDF + LogisticRegression
│   │   ├── llm_detector.py        # Ollama semantic classification
│   │   └── pii_detector.py        # spaCy NER + regex PII
│   ├── scoring/
│   │   └── risk_scorer.py         # Weighted risk aggregation
│   ├── policy/
│   │   └── engine.py              # Allow / Sanitize / Block
│   ├── guardrails/
│   │   └── output_guard.py        # Output PII + toxicity filter
│   └── audit/
│       └── logger.py              # GDPR audit trail
│
├── api/
│   └── main.py                    # FastAPI gateway
│
├── dashboard/
│   └── app.py                     # Streamlit SOC dashboard
│
├── tests/
│   ├── test_detectors.py          # Detection module tests (16 tests)
│   └── test_imports.py            # Import tests (8 tests)
│
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions pipeline
│
├── mlruns/                        # MLflow tracking (not committed)
├── data/audit/                    # SQLite audit database (not committed)
├── docker-compose.yml
├── Dockerfile.api
├── Dockerfile.dashboard
├── .env.example
├── requirements.api.txt
├── requirements.dashboard.txt
├── requirements.dev.txt
├── AI_SECURITY_COMPLIANCE.md
└── README.md
```

---

## ▶️ Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/kbajish/ai-security-gateway.git
cd ai-security-gateway
```

### 2. Create and activate virtual environment
```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/Mac
```

### 3. Install dependencies
```bash
pip install -r requirements.dev.txt
python -m spacy download en_core_web_sm
```

### 4. Copy environment config
```bash
cp .env.example .env
```

### 5. Start all services
```bash
docker compose up --build
```

### 6. Access services

| Service   | URL                        |
|-----------|----------------------------|
| API       | http://localhost:8000      |
| API docs  | http://localhost:8000/docs |
| Dashboard | http://localhost:8501      |
| MLflow    | http://localhost:5000      |

---

## 🧪 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/gateway/check` | Full security check — returns risk score, decision, and detection breakdown |
| `POST` | `/gateway/scan` | Fast scan without LLM layer — rule + ML only |
| `POST` | `/gateway/output` | Check LLM output before returning to user |
| `GET` | `/audit` | Retrieve GDPR-aligned audit log |
| `GET` | `/audit/stats` | Aggregated stats — totals, averages, decision breakdown |
| `GET` | `/health` | Health check |

---

## 🧪 Tests

```bash
pytest tests/ -v
# 24 passed
```

Tests cover rule detection, ML classifier, output guardrails, risk scorer, and policy engine — all without requiring a live Ollama instance.

---

## 📈 Possible Extensions

- Adversarial robustness testing using IBM ART (Adversarial Robustness Toolbox)
- Real-time threat intelligence feed integration
- Role-based access control (RBAC) on gateway endpoints
- Kafka streaming for high-throughput request processing
- Cloud deployment with managed audit storage and retention policies

---

## 👤 Author

Experienced IT professional with a background in development, cybersecurity, and ERP systems, with expertise in Industrial AI. Focused on building well-engineered AI systems with explainability, LLM integration, security, and MLOps practices.
