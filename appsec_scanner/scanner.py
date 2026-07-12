# ---------------------------------------------------------------------------
# Author: Fernando da Silva Félix | MLOps & AppSec Engineer | 2026
# Project: AppSec Scanner
# ---------------------------------------------------------------------------
"""
scanner.py
----------
Motor de análisis estático (AST) para Python, con arquitectura de reglas
extensible. Cada regla detecta una clase de vulnerabilidad, decide si es
remediable de forma automática y segura, y emite eventos auditables.

Reglas incluidas:
  - SQLInjectionRule    : SQL construido vía f-string / concatenación / %-format
  - PathTraversalRule   : rutas de archivo construidas con entrada no validada

Diseño: una regla NUNCA aplica una reescritura que no pueda demostrarse segura
sin ejecutar el código. Si no puede probarlo, reporta el hallazgo como no
remediable y lo deja para revisión humana. Esto es deliberado: preferimos un
falso "no remediado" auditado, a un falso "remediado" que rompa producción.
"""

from __future__ import annotations

import ast
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# --------------------------------------------------------------------------- #
# Auditoría estructurada (compatible con Promtail/Loki/Grafana)
# --------------------------------------------------------------------------- #

class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, severity: str, details: dict) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    kind: str
    snippet: str
    severity: str
    remediable: bool


# --------------------------------------------------------------------------- #
# Interfaz de regla
# --------------------------------------------------------------------------- #

class Rule(ABC):
    name: str

    @abstractmethod
    def visit(self, tree: ast.AST, filename: str) -> list[Finding]:
        ...

    def remediate(self, line: str, finding: Finding) -> Optional[str]:
        """Devuelve la línea reescrita si existe una remediación segura, si no None."""
        return None


# --------------------------------------------------------------------------- #
# Regla 1: SQL Injection
# --------------------------------------------------------------------------- #

SQL_KEYWORDS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
PERCENT_PATTERN = re.compile(r'("(?:[^"\\]|\\.)*")\s*%\s*\(?([\w.\[\]\'", ]+)\)?')


class SQLInjectionRule(Rule):
    name = "sql_injection"

    class _Visitor(ast.NodeVisitor):
        def __init__(self, filename: str) -> None:
            self.filename = filename
            self.findings: list[Finding] = []

        def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
            text = self._render(node)
            if text and SQL_KEYWORDS.search(text):
                self.findings.append(Finding("sql_injection", self.filename, node.lineno,
                                              "f-string", text.strip(), "CRITICAL", False))
            self.generic_visit(node)

        def visit_BinOp(self, node: ast.BinOp) -> None:
            if isinstance(node.op, (ast.Add, ast.Mod)):
                text = self._render(node)
                if text and SQL_KEYWORDS.search(text):
                    is_percent = isinstance(node.op, ast.Mod)
                    kind = "percent-format" if is_percent else "concatenation"
                    sev = "HIGH" if is_percent else "CRITICAL"
                    self.findings.append(Finding("sql_injection", self.filename, node.lineno,
                                                  kind, text.strip(), sev, is_percent))
            self.generic_visit(node)

        @staticmethod
        def _render(node: ast.AST) -> Optional[str]:
            try:
                return ast.unparse(node)
            except Exception:
                return None

    def visit(self, tree: ast.AST, filename: str) -> list[Finding]:
        v = self._Visitor(filename)
        v.visit(tree)
        return v.findings

    def remediate(self, line: str, finding: Finding) -> Optional[str]:
        if finding.kind != "percent-format":
            return None
        match = PERCENT_PATTERN.search(line)
        if not match:
            return None
        template, params = match.groups()
        safe_template = re.sub(r"%s", "?", template)
        return line.replace(match.group(0), f"{safe_template}, ({params},)")


# --------------------------------------------------------------------------- #
# Regla 2: Path Traversal
# --------------------------------------------------------------------------- #

FILE_FUNCS = {"open", "remove", "unlink", "rmdir"}
FILE_MODULES = {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}


class PathTraversalRule(Rule):
    name = "path_traversal"

    class _Visitor(ast.NodeVisitor):
        def __init__(self, filename: str) -> None:
            self.filename = filename
            self.findings: list[Finding] = []

        def visit_Call(self, node: ast.Call) -> None:
            func_repr = self._func_name(node.func)
            if func_repr in FILE_FUNCS or func_repr in FILE_MODULES:
                if node.args and self._is_dynamic(node.args[0]):
                    snippet = self._render(node) or func_repr
                    # remediable=False: no existe una reescritura genérica que
                    # pueda garantizar sin contexto cuál es el directorio base permitido.
                    self.findings.append(Finding("path_traversal", self.filename, node.lineno,
                                                  "unvalidated-path", snippet.strip(),
                                                  "CRITICAL", False))
            self.generic_visit(node)

        @staticmethod
        def _func_name(node: ast.AST) -> str:
            try:
                return ast.unparse(node)
            except Exception:
                return ""

        @staticmethod
        def _render(node: ast.AST) -> Optional[str]:
            try:
                return ast.unparse(node)
            except Exception:
                return None

        @staticmethod
        def _is_dynamic(node: ast.AST) -> bool:
            # Un literal de texto puro se considera estático y seguro.
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return False
            # f-strings, BinOp de concatenación y llamadas (os.path.join con var) son dinámicos.
            return isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Name, ast.Attribute))

    def visit(self, tree: ast.AST, filename: str) -> list[Finding]:
        v = self._Visitor(filename)
        v.visit(tree)
        return v.findings


# --------------------------------------------------------------------------- #
# Orquestación
# --------------------------------------------------------------------------- #

DEFAULT_RULES: list[Rule] = [SQLInjectionRule(), PathTraversalRule()]


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule.visit(tree, str(path)))
    return findings


def run(target_dir: str, audit_log: str, apply_fix: bool,
        rules: list[Rule] = DEFAULT_RULES) -> list[Finding]:
    logger = AuditLogger(Path(audit_log))
    rule_by_name = {r.name: r for r in rules}
    all_findings: list[Finding] = []

    for path in Path(target_dir).rglob("*.py"):
        try:
            findings = scan_file(path, rules)
        except SyntaxError as exc:
            logger.log("SCAN_FAILURE", "WARNING", {"file": str(path), "error": str(exc)})
            continue

        all_findings.extend(findings)

        for finding in findings:
            rule = rule_by_name[finding.rule]

            if apply_fix and finding.remediable:
                lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
                fixed = rule.remediate(lines[finding.line - 1], finding)
                if fixed:
                    lines[finding.line - 1] = fixed
                    path.write_text("".join(lines), encoding="utf-8")
                    logger.log("REMEDIATION_SUCCESS", finding.severity,
                               {"file": str(path), "line": finding.line,
                                "rule": finding.rule, "kind": finding.kind})
                    continue

            logger.log(
                "REMEDIATION_FAILURE" if apply_fix else "VULNERABILITY_DETECTED",
                finding.severity,
                {"file": str(path), "line": finding.line, "rule": finding.rule,
                 "kind": finding.kind, "snippet": finding.snippet[:200]},
            )

    return all_findings


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Motor AppSec: AST + auditoría + gate de CI")
    parser.add_argument("target", help="Directorio a escanear")
    parser.add_argument("--audit-log", default="tests/security_audit.jsonl")
    parser.add_argument("--fix", action="store_true", help="Aplica remediación automática segura")
    parser.add_argument("--fail-on-critical", action="store_true",
                         help="Sale con código 1 si queda algún hallazgo CRITICAL sin remediar")
    args = parser.parse_args()

    results = run(args.target, args.audit_log, args.fix)

    if args.fail_on_critical:
        unresolved_critical = [f for f in results if f.severity == "CRITICAL"]
        if unresolved_critical:
            print(f"AppSec gate: {len(unresolved_critical)} hallazgo(s) CRITICAL sin remediar", file=sys.stderr)
            sys.exit(1)

    print(f"AppSec scan: {len(results)} hallazgo(s) totales")
