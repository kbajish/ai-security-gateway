def test_rule_detector_imports():
    from src.detection.rule_detector import (
        detect_injection, detect_jailbreak, detect_pii_rules
    )
    assert callable(detect_injection)
    assert callable(detect_jailbreak)
    assert callable(detect_pii_rules)


def test_pii_detector_imports():
    from src.detection.pii_detector import detect_pii
    assert callable(detect_pii)


def test_ml_detector_imports():
    from src.detection.ml_detector import (
        detect_injection_ml, load_or_train, train_ml_detector
    )
    assert callable(detect_injection_ml)
    assert callable(load_or_train)


def test_llm_detector_imports():
    from src.detection.llm_detector import detect_with_llm
    assert callable(detect_with_llm)


def test_risk_scorer_imports():
    from src.scoring.risk_scorer import assess_risk
    assert callable(assess_risk)


def test_policy_engine_imports():
    from src.policy.engine import make_decision
    assert callable(make_decision)


def test_output_guard_imports():
    from src.guardrails.output_guard import guard_output
    assert callable(guard_output)


def test_audit_logger_imports():
    from src.audit.logger import log_request, get_recent_logs, get_stats
    assert callable(log_request)
    assert callable(get_recent_logs)
    assert callable(get_stats)