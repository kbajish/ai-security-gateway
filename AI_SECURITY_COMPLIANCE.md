# AI Security & Compliance Notes

## Framework Alignment

### OWASP LLM Top 10
- LLM01 Prompt Injection — rule + ML + LLM detection layers
- LLM02 Insecure Output Handling — output guardrails module
- LLM06 Sensitive Information Disclosure — PII detector + output guard
- LLM09 Overreliance — audit trail + human review flags

### EU AI Act
- Art. 13 Transparency — every decision logged with reasoning
- Art. 9 Risk Management — weighted risk scoring with thresholds
- Art. 17 Quality Management — MLflow experiment tracking

### NIST AI RMF
- GOVERN — policy engine with configurable thresholds
- MAP — threat taxonomy mapped to detection modules
- MEASURE — risk scores tracked per request
- MANAGE — block/sanitize/allow decisions enforced

### MITRE ATLAS
- AML.T0051 LLM Prompt Injection — primary detection target
- AML.T0048 Societal Harm — output toxicity guardrails

### BSI IT-Grundschutz
- OPS.1.1.4 Logging — full audit trail per request
- CON.8 Data Security — PII redacted before storage

## GDPR Measures
- Input text is hashed (SHA-256) before audit storage
- PII detected in inputs is redacted before logging
- No raw user input is persisted
- Audit logs support Art. 22 accountability requirements
