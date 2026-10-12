from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from backend.app.engine.analyzer import analyze


DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "evaluation" / "corpus.jsonl"


def confusion_metrics(rows: list[tuple[str, str]]) -> dict[str, int | float]:
    """Compute binary metrics. Labels are 'phishing' and 'benign'."""
    tp = sum(expected == "phishing" and predicted == "phishing" for expected, predicted in rows)
    tn = sum(expected == "benign" and predicted == "benign" for expected, predicted in rows)
    fp = sum(expected == "benign" and predicted == "phishing" for expected, predicted in rows)
    fn = sum(expected == "phishing" and predicted == "benign" for expected, predicted in rows)

    def ratio(numerator: int, denominator: int) -> float:
        return round(numerator / denominator, 4) if denominator else 0.0

    return {
        "samples": len(rows),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "accuracy": ratio(tp + tn, len(rows)),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
    }


def load_corpus(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Line {line_number} must contain a JSON object.")
        if not isinstance(record.get("id"), str) or not record["id"].strip():
            raise ValueError(f"Line {line_number} is missing a non-empty id.")
        if record["id"] in seen_ids:
            raise ValueError(f"Duplicate sample id: {record['id']}")
        if record.get("label") not in {"phishing", "benign"}:
            raise ValueError(f"Sample {record['id']} must have label phishing or benign.")
        if not isinstance(record.get("raw_email"), str) or not record["raw_email"].strip():
            raise ValueError(f"Sample {record['id']} is missing raw_email.")
        if record.get("source") != "synthetic":
            raise ValueError(f"Sample {record['id']} must declare source=synthetic for this starter corpus.")
        seen_ids.add(record["id"])
        records.append(record)
    if not records:
        raise ValueError("Evaluation corpus is empty.")
    return records


def evaluate(records: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[tuple[str, str]] = []
    samples: list[dict[str, Any]] = []
    for record in records:
        result = analyze(record["raw_email"])
        predicted = "phishing" if result.risk.verdict in {"suspicious", "malicious"} else "benign"
        rows.append((record["label"], predicted))
        samples.append({
            "id": record["id"],
            "expected": record["label"],
            "predicted": predicted,
            "verdict": result.risk.verdict,
            "score": result.risk.score,
            "correct": record["label"] == predicted,
        })
    return {"metrics": confusion_metrics(rows), "samples": samples}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate PhishScan against a labeled JSONL corpus.")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args()
    try:
        records = load_corpus(args.corpus)
        report = evaluate(records)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
