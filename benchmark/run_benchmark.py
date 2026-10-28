"""
run_benchmark.py
-----------------
Calcula métricas globales y por regla para el corpus propio etiquetado
(benchmark/cases + manifest.json).

Nota metodológica: este NO es el corpus oficial OWASP Benchmark. Es un corpus
pequeño, creado para verificar el comportamiento previsto del proyecto; sus
resultados no demuestran generalización a código real.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "appsec_scanner"))
from scanner import DEFAULT_RULES, scan_file  # noqa: E402


def _metrics(counts: dict[str, int]) -> tuple[float, float, float]:
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return precision, recall, f1


def main() -> None:
    cases_dir = Path(__file__).parent / "cases"
    manifest_path = Path(__file__).parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    global_counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    per_rule: dict[str, dict[str, int]] = {}

    for filename, expected in manifest.items():
        path = cases_dir / filename
        if not path.is_file():
            raise SystemExit(f"Benchmark case listed in manifest is missing: {path}")

        expected_vulnerable = expected["vulnerable"]
        expected_rule = expected["expected_rule"]
        findings = scan_file(path, DEFAULT_RULES)
        detected_any = bool(findings)
        detected_expected_rule = any(
            finding.rule == expected_rule for finding in findings
        )

        # Global metrics answer whether a labelled vulnerable case produced
        # any finding. Rule-level metrics only count findings from the expected
        # rule, so a different rule cannot make that rule appear to pass.
        if expected_vulnerable and detected_any:
            global_counts["tp"] += 1
        elif expected_vulnerable:
            global_counts["fn"] += 1
        elif detected_any:
            global_counts["fp"] += 1
        else:
            global_counts["tn"] += 1

        rule_key = expected_rule or "no_expected_rule"
        counts = per_rule.setdefault(
            rule_key, {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        )
        detected_for_case = (
            detected_expected_rule if expected_rule else detected_any
        )

        if expected_vulnerable and detected_for_case:
            counts["tp"] += 1
        elif expected_vulnerable:
            counts["fn"] += 1
        elif detected_for_case:
            counts["fp"] += 1
        else:
            counts["tn"] += 1

    precision, recall, f1 = _metrics(global_counts)
    print("=== Resultado global (cualquier hallazgo) ===")
    print(
        f"TP={global_counts['tp']} FP={global_counts['fp']} "
        f"FN={global_counts['fn']} TN={global_counts['tn']}"
    )
    print(f"Precisión: {precision:.2f}  Recall: {recall:.2f}  F1: {f1:.2f}")

    print("\n=== Detalle por regla esperada ===")
    for rule, counts in per_rule.items():
        precision, recall, f1 = _metrics(counts)
        print(
            f"{rule}: TP={counts['tp']} FP={counts['fp']} "
            f"FN={counts['fn']} TN={counts['tn']} | "
            f"Precision={precision:.2f} Recall={recall:.2f} F1={f1:.2f}"
        )


if __name__ == "__main__":
    main()
