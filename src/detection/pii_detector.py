import spacy
from dataclasses import dataclass
from typing import List
from src.detection.rule_detector import detect_pii_rules

nlp = spacy.load("en_core_web_sm")

SENSITIVE_ENTITY_TYPES = {
    "PERSON", "ORG", "GPE", "LOC", "EMAIL",
    "PHONE", "MONEY", "CARDINAL"
}

REDACT_TYPES = {"PERSON", "EMAIL", "PHONE"}


@dataclass
class PIIDetectionResult:
    detected:       bool
    score:          float
    entities:       List[dict]
    redacted_text:  str
    rule_matches:   List[str]


def detect_pii(text: str) -> PIIDetectionResult:
    # Rule-based detection
    rule_result = detect_pii_rules(text)

    # spaCy NER detection
    doc      = nlp(text)
    entities = []
    for ent in doc.ents:
        if ent.label_ in SENSITIVE_ENTITY_TYPES:
            entities.append({
                "text":  ent.text,
                "label": ent.label_,
                "start": ent.start_char,
                "end":   ent.end_char
            })

    # Redact sensitive entities
    redacted = text
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        if ent["label"] in REDACT_TYPES:
            redacted = (
                redacted[:ent["start"]] +
                f"[{ent['label']}_REDACTED]" +
                redacted[ent["end"]:]
            )

    # Combined score
    ner_score  = min(1.0, len(entities) * 0.3)
    combined   = max(rule_result.score, ner_score)

    return PIIDetectionResult(
        detected      = combined > 0.1,
        score         = round(combined, 4),
        entities      = entities,
        redacted_text = redacted,
        rule_matches  = rule_result.matched_rules
    )


if __name__ == "__main__":
    tests = [
        "Contact John Smith at john.smith@company.de or call +49 170 1234567.",
        "Our client Deutsche Bank in Frankfurt placed an order worth 50000 EUR.",
        "My IBAN is DE89 3704 0044 0532 0130 00 and tax ID is 86 815 327.",
        "What are the top products by revenue this quarter?",
    ]

    for text in tests:
        result = detect_pii(text)
        print(f"\nInput:    {text[:80]}")
        print(f"Detected: {result.detected} (score={result.score})")
        print(f"Entities: {result.entities}")
        print(f"Redacted: {result.redacted_text[:80]}")