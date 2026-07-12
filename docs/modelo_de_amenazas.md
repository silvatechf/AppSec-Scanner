# Modelo de amenazas — AppSec Scanner (SQL Injection + Path Traversal)

## 1. Objetivo del sistema

Detectar, de forma estática y sin ejecutar código, dos clases de vulnerabilidad
en código Python (inyección SQL y path traversal), decidir cuáles son
remediables automáticamente sin riesgo, y dejar evidencia auditable de cada
decisión para su ingestión en Loki/Grafana y su uso como gate de CI/CD.

## 2. Alcance (in-scope)

- Inyección SQL construida mediante f-strings, concatenación (`+`) y
  formateo `%` dentro de código Python analizado vía AST.
- Path traversal en llamadas a `open()`, `os.remove()`, `os.unlink()`,
  `os.rmdir()` y `shutil.rmtree()` cuando el argumento de ruta se construye
  de forma dinámica (variable, f-string, concatenación o llamada a función).
- Remediación automática **únicamente** del caso SQL `%`-format, por ser el
  único donde la reescritura a consulta parametrizada puede demostrarse
  segura sin ejecutar el programa.

## 3. Fuera de alcance (out-of-scope) — y por qué

- **ORMs y query builders** (SQLAlchemy, Django ORM): estos ya parametrizan
  por diseño; incluirlos generaría ruido de falsos positivos sin valor real.
- **SQL dinámico multi-línea o construido en tiempo de ejecución mediante
  `eval`/`exec`**: un analizador estático de AST no puede razonar sobre
  cadenas que se ensamblan y evalúan dinámicamente sin ejecutar el programa.
- **Path traversal a través de librerías de terceros** (por ejemplo, un
  framework web que internamente resuelve rutas): el análisis se limita a
  llamadas directas del stdlib, porque seguir la resolución de rutas dentro
  de dependencias externas requeriría análisis interprocedural, fuera del
  alcance de esta versión.
- **Remediación automática de path traversal**: no existe una reescritura
  genérica válida sin conocer cuál es el directorio base permitido en cada
  contexto de negocio. Por eso, todo hallazgo de esta regla se marca como
  no remediable y se deja para revisión humana.

## 4. Supuestos

- El código analizado es Python válido (sintácticamente parseable).
- El objetivo es reducir el volumen de revisión manual, no reemplazar
  una revisión de seguridad completa ni un pentest.
- Los eventos de auditoría son consumidos por un sistema de logging
  centralizado (Loki) que preserva la integridad del log; este sistema no
  implementa protección contra manipulación del propio archivo JSONL.

## 5. Metodología de evaluación y sus límites

Las métricas de precisión/recall/F1 se calculan contra un **corpus propio**
de 10 casos etiquetados (`benchmark/manifest.json`), no contra el corpus
oficial de OWASP Benchmark. Esa aclaración es importante: OWASP Benchmark
evalúa herramientas para aplicaciones Java/JVM y no es aplicable directamente
a un escáner de Python. Los resultados actuales (precisión 1.00, recall 1.00
sobre el corpus propio) deben leerse como **validación de que la lógica
implementada se comporta como se diseñó**, no como una garantía de
generalización a código de producción real y heterogéneo. Un corpus de 10
casos, construido por el mismo autor del motor, tiene un sesgo estructural
esperable: es necesario ampliarlo con código real, revisado por un tercero,
antes de citar estas cifras como evidencia de efectividad en producción.

## 6. Próximas iteraciones honestas (no exageradas)

- Ampliar el corpus de benchmark con muestras de proyectos open-source reales.
- Añadir una tercera clase de vulnerabilidad para confirmar que el patrón
  detección → clasificación de remediabilidad → auditoría generaliza más
  allá de dos reglas.
- Medir falsos positivos contra un repositorio grande y real (no solo el
  corpus sintético), y publicar esa cifra aunque no sea perfecta.
