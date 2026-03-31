# 🛡️ AI Security Gateway

![CI](https://github.com/kbajish/ai-security-gateway/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Docker](https://img.shields.io/badge/docker-compose-blue)
![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-red)
![EU AI Act](https://img.shields.io/badge/EU_AI_Act-compliant-orange)

A production-ready middleware security gateway for LLM applications that intercepts every request and response, applying a three-layer hybrid detection pipeline — rule-based, ML-based, and LLM-based — before allowing traffic to reach the protected AI system. Aligned with OWASP LLM Top 10, EU AI Act, NIST AI RMF, MITRE ATLAS, and BSI IT-Grundschutz.

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

- 🔍 3-layer hybrid detection — rule-based + ML + LLM semantic reasoning
- 💉 Prompt injection detection trained on Deepset prompt-injections dataset
- 🕵️ PII detection — spaCy NER + regex for IBAN, credit cards, German tax IDs
- 🔓 Jailbreak detection — 50+ known patterns + Ollama intent classification
- 🛡️ Output guardrails — PII leak + toxicity filtering on LLM responses
- 📋 DSGVO-compliant audit trail — PII redacted, SQLite persistence
- ⚖️ Weighted risk scorer — Allow / Block / Sanitize decisions
- 📊 Streamlit SOC dashboard — blocked requests, risk scores, compliance log
- ⚡ FastAPI gateway endpoints
- 🐳 Docker Compose deployment
- 🔄 GitHub Actions CI/CD

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
src/policy/engine.py              — Allow / Block / Sanitize decision
        ↓
Protected AI system (RAG / Agent / any LLM API)
        ↓
src/guardrails/output_guard.py    — output PII + toxicity filtering
        ↓
src/audit/logger.py               — DSGVO-compliant audit logging
        ↓
api/main.py                       — FastAPI gateway
        ↓
dashboard/app.py                  — Streamlit SOC dashboard
```

---

## ⚙️ How It Works

Every incoming request passes through three detection layers in sequence. The rule-based layer applies regex patterns for known injection strings, jailbreak prefixes, and PII formats — this is instant and filters obvious threats. The ML layer uses a TF-IDF + LogisticRegression classifier trained on the Deepset prompt-injections dataset and spaCy NER for entity detection. The LLM layer uses Ollama to semantically classify adversarial intent for borderline cases.

The weighted risk scorer aggregates all detection scores into a single risk value. The policy engine maps this to Allow, Sanitize, or Block. Allowed requests are forwarded to the protected AI system. The response is then checked by output guardrails for PII leakage and toxic content before being returned to the user. Every request is logged to a DSGVO-compliant audit trail with PII redacted before storage.

---

## 📊 Risk Scoring

```python
risk_score = (
    0.35 * injection_score  +
    0.25 * jailbreak_score  +
    0.25 * pii_score        +
    0.15 * toxicity_score
)

# Policy decision
if risk_score >= 0.7:  →  BLOCK
if risk_score >= 0.4:  →  SANITIZE
if risk_score <  0.4:  →  ALLOW
```

---

## 🏛️ Framework Alignment

| Framework | Coverage |
|---|---|
| OWASP LLM Top 10 | LLM01 injection, LLM02 data leakage, LLM06 sensitive info, LLM09 overreliance |
| EU AI Act | Art. 13 transparency, Art. 9 risk management, Art. 17 quality system |
| NIST AI RMF | GOVERN, MAP, MEASURE, MANAGE functions |
| MITRE ATLAS | AML.T0051 prompt injection, AML.T0048 societal harm |
| BSI IT-Grundschutz | OPS.1.1.4 logging, CON.8 data security |

---

## 📊 Dashboard Overview

The Streamlit SOC dashboard provides:

- 🚨 Blocked request feed with threat type and risk score
- 📊 Risk score distribution chart
- 🔍 Attack type breakdown — injection vs jailbreak vs PII
- 📋 DSGVO audit log viewer (PII redacted)
- ✅ Allow / Sanitize / Block decision metrics

---

## 🛠 Tech Stack

| Layer | Tool |
|---|---|
| Rule detection | Python regex, custom pattern library |
| ML detection | scikit-learn (TF-IDF + LogisticRegression) |
| NLP / PII | spaCy (en_core_web_sm) |
| LLM detection | LangChain + Ollama (llama3.2, local) |
| Risk scoring | Custom weighted scorer |
| Audit | SQLite, DSGVO-compliant |
| Backend | FastAPI, Uvicorn |
| Dashboard | Streamlit |
| Experiment tracking | MLflow |
| Containerisation | Docker Compose |
| CI/CD | GitHub Actions |
| Testing | pytest |

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
│   │   └── engine.py              # Allow / Block / Sanitize
│   ├── guardrails/
│   │   └── output_guard.py        # Output PII + toxicity filter
│   └── audit/
│       └── logger.py              # DSGVO audit trail
│
├── api/
│   └── main.py                    # FastAPI gateway
│
├── dashboard/
│   └── app.py                     # Streamlit SOC dashboard
│
├── tests/
│   ├── test_detectors.py          # Detection module tests
│   └── test_imports.py            # CI-safe import tests
│
├── .github/
│   └── workflows/
│       └── ci.yml                 # GitHub Actions pipeline
│
├── mlruns/                        # MLflow tracking (not committed)
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

### 4. Start all services
```bash
docker compose up --build
```

### 5. Access services

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
| `POST` | `/gateway/check` | Full security check — returns risk score + decision |
| `POST` | `/gateway/scan` | Input-only scan without forwarding to AI system |
| `GET` | `/audit` | Retrieve DSGVO-compliant audit log |
| `GET` | `/health` | Health check |

---

## 📈 Future Improvements

- Adversarial robustness testing using IBM ART (Adversarial Robustness Toolbox)
- Real-time threat intelligence feed integration
- Role-based access control (RBAC) on gateway endpoints
- Kafka streaming for high-throughput deployment
- Cloud deployment with managed audit storage

---

## 👤 Author

Experienced IT professional with a background in development, cybersecurity, and ERP systems, with expertise in Industrial AI. Focused on building production-ready AI systems with explainability, LLM integration, and MLOps best practices.
