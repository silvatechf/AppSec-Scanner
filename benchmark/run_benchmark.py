"""
run_benchmark.py
-----------------
Calcula precisión, recall y F1 del motor appsec_scanner frente a un corpus
propio de casos etiquetados (benchmark/cases + manifest.json).

Nota de honestidad metodológica: este NO es el corpus oficial OWASP Benchmark
(ese proyecto evalúa herramientas Java/JVM y no aplica a un escáner Python).
Es un corpus propio, más pequeño, construido con la misma filosofía:
casos positivos y negativos conocidos, para poder hablar de métricas reales
en vez de afirmaciones sin evidencia.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "appsec_scanner"))
from scanner import scan_file, DEFAULT_RULES  # noqa: E402


def main() -> None:
    cases_dir = Path(__file__).parent / "cases"
    manifest = json.loads((Path(__file__).parent / "manifest.json").read_text())

    tp = fp = fn = tn = 0
    per_rule = {}

    for filename, expected in manifest.items():
        path = cases_dir / filename
        findings = scan_file(path, DEFAULT_RULES)
        detected = len(findings) > 0
        rule = expected["expected_rule"] or "none"
        per_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})

        if expected["vulnerable"] and detected:
            tp += 1
            per_rule[rule]["tp"] += 1
        elif expected["vulnerable"] and not detected:
            fn += 1
            per_rule[rule]["fn"] += 1
        elif not expected["vulnerable"] and detected:
            fp += 1
            per_rule[rule]["fp"] += 1
        else:
            tn += 1
            per_rule[rule]["tn"] += 1

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")

    print("=== Resultado global ===")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Precisión: {precision:.2f}  Recall: {recall:.2f}  F1: {f1:.2f}")

    print("\n=== Detalle por regla ===")
    for rule, counts in per_rule.items():
        print(f"{rule}: {counts}")


if __name__ == "__main__":
    main()
