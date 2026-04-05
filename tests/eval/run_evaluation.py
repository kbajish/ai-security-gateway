"""
AI Security Gateway — Evaluation Script
========================================
Runs 90 labelled prompts through the live gateway API.
Computes Precision, Recall, F1, FPR, FNR per decision class.
Generates confusion matrix and evaluation report.

Prerequisites:
  - Gateway API running on http://localhost:8000
  - Run: uvicorn api.main:app --host 0.0.0.0 --port 8000

Usage:
  python tests/eval/run_evaluation.py
"""

import json
import requests
import numpy as np
import pandas as pd
from pathlib import Path
from datetime import datetime
from sklearn.metrics import (
    precision_recall_fscore_support,
    confusion_matrix,
)

API_URL = "http://127.0.0.1:8000"
EVAL_DIR = Path("tests/eval")
PROMPTS  = EVAL_DIR / "test_prompts.json"
RESULTS  = EVAL_DIR / "results"
RESULTS.mkdir(parents=True, exist_ok=True)


def load_prompts() -> list:
    with open(PROMPTS) as f:
        return json.load(f)


def scan_prompt(text: str) -> dict:
    """Call the gateway /gateway/scan endpoint."""
    try:
        r = requests.post(
            f"{API_URL}/gateway/scan",
            json    = {"text": text, "use_llm": False},
            timeout = 30,
        )
        if r.status_code == 200:
            data = r.json()
            # Normalise field names
            return {
                "action":     data.get("action",     "ERROR").upper(),
                "risk_score": data.get("risk_score", 0.0),
                "reason":     data.get("reason",     ""),
            }
        else:
            print(f"    HTTP {r.status_code}: {r.text[:100]}")
            return {"action": "ERROR", "risk_score": 0.0, "reason": ""}
    except Exception as e:
        print(f"    Request error: {e}")
        return {"action": "ERROR", "risk_score": 0.0, "reason": ""}


def run_evaluation() -> list:
    prompts = load_prompts()
    print(f"Loaded {len(prompts)} test prompts")
    print(f"API: {API_URL}")
    print("=" * 60)

    # Health check
    try:
        h = requests.get(f"{API_URL}/health", timeout=5).json()
        print(f"Gateway status: {h.get('status', 'unknown')}")
    except Exception:
        print("ERROR: Gateway API not reachable. Start it first.")
        return []

    print("=" * 60)
    print("Running evaluation...")
    print()

    results = []
    errors  = 0

    for i, prompt in enumerate(prompts):
        print(
            f"[{i+1:02d}/{len(prompts)}] {prompt['id']:<10} "
            f"{prompt['category'][:22]:<22}",
            end=" "
        )

        response = scan_prompt(prompt["text"])
        predicted = response["action"]

        if predicted == "ERROR":
            errors += 1
            print("ERROR")
            continue

        expected = prompt["expected_decision"].upper()
        correct  = predicted == expected
        marker   = "✓" if correct else "✗"

        print(
            f"Expected: {expected:<10} "
            f"Predicted: {predicted:<10} "
            f"Score: {response['risk_score']:.3f} {marker}"
        )

        results.append({
            "id":           prompt["id"],
            "category":     prompt["category"],
            "text":         prompt["text"][:80] + "..." if len(prompt["text"]) > 80
                            else prompt["text"],
            "expected":     expected,
            "predicted":    predicted,
            "correct":      correct,
            "risk_score":   response["risk_score"],
            "reason":       response["reason"],
            "notes":        prompt.get("notes", ""),
        })

    print()
    print(f"Completed: {len(results)} | Errors: {errors}")
    print("=" * 60)
    return results


def compute_metrics(results: list) -> dict:
    df      = pd.DataFrame(results)
    y_true  = df["expected"].tolist()
    y_pred  = df["predicted"].tolist()
    classes = ["BLOCK", "SANITIZE", "ALLOW"]

    accuracy = df["correct"].mean()

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred,
        labels        = classes,
        zero_division = 0,
    )

    cm = confusion_matrix(y_true, y_pred, labels=classes)

    per_class = {}
    for i, cls in enumerate(classes):
        tp = int(cm[i, i])
        fn = int(cm[i, :].sum() - tp)
        fp = int(cm[:, i].sum() - tp)
        tn = int(cm.sum() - tp - fn - fp)

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        per_class[cls] = {
            "precision": round(float(precision[i]), 4),
            "recall":    round(float(recall[i]),    4),
            "f1":        round(float(f1[i]),         4),
            "fpr":       round(float(fpr),           4),
            "fnr":       round(float(fnr),           4),
            "support":   int(support[i]),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        }

    macro = {
        "precision": round(float(precision.mean()), 4),
        "recall":    round(float(recall.mean()),    4),
        "f1":        round(float(f1.mean()),         4),
    }

    total        = len(df)
    distribution = {
        cls: {
            "count": int((df["predicted"] == cls).sum()),
            "pct":   round((df["predicted"] == cls).sum() / total * 100, 1),
        }
        for cls in classes
    }

    category_acc = df.groupby("category")["correct"]\
                     .mean().round(3).to_dict()

    return {
        "accuracy":          round(float(accuracy), 4),
        "per_class":         per_class,
        "macro":             macro,
        "distribution":      distribution,
        "category_accuracy": category_acc,
        "confusion_matrix":  cm.tolist(),
        "classes":           classes,
        "total_prompts":     len(results),
        "total_errors":      len(
            [r for r in results if r["predicted"] == "ERROR"]
        ),
    }


def print_report(metrics: dict, results: list) -> None:
    print()
    print("=" * 60)
    print("EVALUATION REPORT — AI Security Gateway")
    print("=" * 60)
    print(f"Total prompts:   {metrics['total_prompts']}")
    print(f"Overall accuracy:{metrics['accuracy']:.1%}")
    print()

    # Per-class metrics table
    print("Per-Class Metrics:")
    print(f"{'Class':<12} {'Precision':>10} {'Recall':>10} "
          f"{'F1':>8} {'FPR':>8} {'FNR':>8} {'Support':>8}")
    print("-" * 68)
    for cls, m in metrics["per_class"].items():
        print(
            f"{cls:<12} {m['precision']:>10.4f} {m['recall']:>10.4f} "
            f"{m['f1']:>8.4f} {m['fpr']:>8.4f} {m['fnr']:>8.4f} "
            f"{m['support']:>8}"
        )
    print("-" * 68)
    mac = metrics["macro"]
    print(
        f"{'Macro avg':<12} {mac['precision']:>10.4f} "
        f"{mac['recall']:>10.4f} {mac['f1']:>8.4f}"
    )

    print()
    print("Decision Distribution (predicted):")
    for cls, d in metrics["distribution"].items():
        bar = "█" * int(d["pct"] / 2)
        print(f"  {cls:<12} {d['count']:>3} ({d['pct']:>5.1f}%) {bar}")

    print()
    print("Accuracy by Category:")
    for cat, acc in sorted(metrics["category_accuracy"].items()):
        status = "✓" if acc >= 0.8 else ("~" if acc >= 0.6 else "✗")
        print(f"  {status} {cat:<25} {acc:.1%}")

    print()
    print("Confusion Matrix:")
    classes = metrics["classes"]
    cm      = metrics["confusion_matrix"]
    print(
        f"  {'':>14}" +
        "".join(f"{'Pred '+c:>14}" for c in classes)
    )
    for i, cls in enumerate(classes):
        row = (
            f"  {'True '+cls:<14}" +
            "".join(f"{cm[i][j]:>14}" for j in range(len(classes)))
        )
        print(row)

    print()
    print("Key Security Metrics:")
    b = metrics["per_class"]["BLOCK"]
    a = metrics["per_class"]["ALLOW"]
    s = metrics["per_class"]["SANITIZE"]
    print(
        f"  BLOCK FNR (missed threats):    {b['fnr']:.1%} "
        f"{'✓ Good' if b['fnr'] < 0.10 else '⚠ Review'}"
    )
    print(
        f"  BLOCK FPR (false alarms):      {b['fpr']:.1%} "
        f"{'✓ Good' if b['fpr'] < 0.15 else '⚠ Review'}"
    )
    print(
        f"  ALLOW FNR (blocked legit):     {a['fnr']:.1%} "
        f"{'✓ Good' if a['fnr'] < 0.10 else '⚠ Review'}"
    )
    print(
        f"  SANITIZE F1:                   {s['f1']:.4f} "
        f"{'✓ Good' if s['f1'] >= 0.60 else '⚠ Review'}"
    )

    # Missed threats
    df     = pd.DataFrame(results)
    missed = df[
        (df["expected"] == "BLOCK") &
        (df["predicted"] != "BLOCK")
    ]
    print()
    if len(missed) > 0:
        print(f"⚠ Missed Threats ({len(missed)}):")
        for _, row in missed.iterrows():
            print(
                f"  {row['id']} predicted {row['predicted']}: "
                f"{row['text'][:60]}..."
            )
    else:
        print("✓ No missed threats — all BLOCK prompts correctly identified")

    # False alarms
    false_alarms = df[
        (df["expected"] == "ALLOW") &
        (df["predicted"] == "BLOCK")
    ]
    print()
    if len(false_alarms) > 0:
        print(f"⚠ False Alarms ({len(false_alarms)}) — legitimate prompts blocked:")
        for _, row in false_alarms.iterrows():
            print(f"  {row['id']}: {row['text'][:60]}...")
    else:
        print("✓ No false alarms — all ALLOW prompts correctly passed")


def save_results(metrics: dict, results: list) -> Path:
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = RESULTS / f"evaluation_{timestamp}.json"

    with open(report_path, "w") as f:
        json.dump(
            {"timestamp": timestamp, "metrics": metrics, "results": results},
            f, indent=2
        )

    pd.DataFrame(results).to_csv(
        RESULTS / f"results_{timestamp}.csv", index=False
    )
    print()
    print(f"Results saved: {report_path}")
    return report_path


if __name__ == "__main__":
    results = run_evaluation()
    if not results:
        print("Evaluation failed — check API connection.")
        exit(1)

    metrics = compute_metrics(results)
    print_report(metrics, results)
    save_results(metrics, results)