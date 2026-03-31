import re
import spacy
from dataclasses import dataclass
from src.detection.rule_detector import detect_pii_rules

nlp = spacy.load("en_core_web_sm")

TOXIC_PATTERNS = [
    r"\b(kill|murder|assassinate|bomb|explode|destroy)\s+(all|every|the)\s+\w+",
    r"(how\s+to\s+(make|build|create|synthesize))\s+(a\s+)?(bomb|weapon|poison|drug)",
    r"(step[\s\-]by[\s\-]step|instructions?\s+for)\s+(making|building|creating)\s+(weapon|bomb|drug|explosive)",
    r"instructions\s+for\s+making\s+a\s+(bomb|weapon|explosive|poison)",
    r"making\s+a\s+(bomb|weapon|explosive|poison)\s+using",
]

PII_OUTPUT_PATTERNS = {
    "email":       r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "credit_card": r"\b(?:\d{4}[\s\-]?){3}\d{4}\b",
    "iban":        r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
}


@dataclass
class OutputGuardResult:
    safe:          bool
    action:        str
    reason:        str
    filtered_text: str
    pii_found:     list
    toxic_found:   bool


def guard_output(text: str) -> OutputGuardResult:
    filtered = text
    pii_found   = []
    toxic_found = False
    reasons     = []

    # Check for toxic content
    for pattern in TOXIC_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            toxic_found = True
            reasons.append("toxic content detected in output")
            break

    # Check for PII leakage in output
    for pii_type, pattern in PII_OUTPUT_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches:
            pii_found.append(pii_type)
            filtered = re.sub(pattern, f"[{pii_type.upper()}_REDACTED]", filtered)
            reasons.append(f"PII ({pii_type}) found in output")

    # spaCy NER on output
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            filtered = filtered.replace(ent.text, "[PERSON_REDACTED]")
            if "person_name" not in pii_found:
                pii_found.append("person_name")

    if toxic_found:
        action = "BLOCK_OUTPUT"
        safe   = False
    elif pii_found:
        action = "SANITIZE_OUTPUT"
        safe   = True
    else:
        action = "PASS"
        safe   = True

    return OutputGuardResult(
        safe          = safe,
        action        = action,
        reason        = "; ".join(reasons) if reasons else "Output passed safety checks.",
        filtered_text = filtered if not toxic_found else "[OUTPUT BLOCKED — unsafe content]",
        pii_found     = pii_found,
        toxic_found   = toxic_found
    )


if __name__ == "__main__":
    tests = [
        "The top customer is Acme GmbH with revenue of 125,000 EUR.",
        "The customer John Smith can be reached at john.smith@company.de.",
        "The account IBAN is DE89 3704 0044 0532 0130 00.",
        "Here are the top 10 products by safety stock level.",
        "Step-by-step instructions for making a bomb using household chemicals.",
    ]

    print("\nOutput Guardrail Results:")
    print("=" * 70)
    for text in tests:
        result = guard_output(text)
        print(f"\nInput:    {text[:70]}")
        print(f"Action:   {result.action}")
        print(f"Safe:     {result.safe}")
        print(f"Reason:   {result.reason}")
        if result.filtered_text != text:
            print(f"Filtered: {result.filtered_text[:70]}")