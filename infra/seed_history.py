"""
seed_history.py
----------------
Genera un historial REAL de eventos de auditoría corriendo el scanner varias
veces con pausas reales entre cada ejecución. No fabrica timestamps: cada
evento tiene la hora real en que ocurrió, solo automatizamos la espera para
no tener que disparar el scanner a mano cada pocos minutos.

Uso:
    python seed_history.py --runs 6 --interval-seconds 120

Con los valores por defecto genera ~12 minutos de historial real, suficiente
para que "Eventos por tipo (serie temporal)" muestre varias barras distintas
en vez de un único pico.
"""

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera historial real para el dashboard")
    parser.add_argument("--runs", type=int, default=6, help="Cuántas veces correr el scanner")
    parser.add_argument("--interval-seconds", type=int, default=120,
                         help="Segundos reales de espera entre cada corrida")
    parser.add_argument("--audit-log", default="tests/security_audit.jsonl")
    args = parser.parse_args()

    cases_dir = Path("benchmark/cases")
    scratch_dir = Path("benchmark/_seed_scratch")

    for i in range(1, args.runs + 1):
        # Copiamos el corpus a un directorio temporal fresco en cada corrida,
        # para que el --fix no se quede sin nada que remediar tras la primera vez.
        if scratch_dir.exists():
            shutil.rmtree(scratch_dir)
        shutil.copytree(cases_dir, scratch_dir)

        print(f"[{i}/{args.runs}] Ejecutando scanner (hora real)...")
        subprocess.run([
            sys.executable, "appsec_scanner/scanner.py", str(scratch_dir),
            "--audit-log", args.audit_log, "--fix",
        ], check=True)

        if i < args.runs:
            print(f"Esperando {args.interval_seconds}s reales antes de la siguiente corrida...")
            time.sleep(args.interval_seconds)

    shutil.rmtree(scratch_dir, ignore_errors=True)
    print("Historial generado. Revisa tests/security_audit.jsonl")


if __name__ == "__main__":
    main()
