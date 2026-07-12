# Ficha de referencia — Dashboard AppSec

Campos reales del log tras `| json`: `event_type`, `severity`, `details_file`,
`details_line`, `details_rule`, `details_kind`, `details_snippet`, `timestamp`.

---

## 1. Total hallazgos
- **Tipo:** Stat
- **Query:**
```
sum(count_over_time({job="sql_defender"} [30m]))
```
- **Panel options → Graph mode:** Area (activa sparkline)

---

## 2. Archivos afectados
- **Tipo:** Stat
- **Query:**
```
count(count by (details_file) (count_over_time({job="sql_defender"} | json [30m])))
```
- **Graph mode:** Area

---

## 3. Reglas activas
- **Tipo:** Stat
- **Query:**
```
count(count by (details_rule) (count_over_time({job="sql_defender"} | json [30m])))
```
- **Graph mode:** Area

---

## 4. Tasa de éxito de remediación
- **Tipo:** Gauge
- **Query:**
```
sum(count_over_time({job="sql_defender"} | json | event_type="REMEDIATION_SUCCESS" [30m])) / sum(count_over_time({job="sql_defender"} | json | event_type=~"REMEDIATION_.*" [30m]))
```
- **Field → Unit:** Percent (0.0-1.0)
- **Field → Thresholds:** 0–0.5 rojo, 0.5–0.8 amarillo, 0.8–1 verde

---

## 5. Eventos por tipo (serie temporal)
- **Tipo:** Time series (estilo Bars)
- **Query:**
```
sum by (event_type) (count_over_time({job="sql_defender"} | json | __error__="" [1m]))
```
- **Graph styles → Style:** Bars, Fill opacity ~40, Bar alignment: Center
- **Overrides:**
  - `{event_type="REMEDIATION_FAILURE"}` → Color scheme → Single color → rojo
  - `{event_type="REMEDIATION_SUCCESS"}` → Color scheme → Single color → verde
- **Legend → Mode:** Table, **Values:** Total

---

## 6. Distribución por severidad
- **Tipo:** Pie chart
- **Query:**
```
sum by (severity) (count_over_time({job="sql_defender"} | json | __error__="" [6h]))
```
- **Overrides:**
  - `{severity="CRITICAL"}` → Color scheme → Single color → rojo
  - `{severity="HIGH"}` → Color scheme → Single color → ámbar

---

## 7. Top archivos con más hallazgos
- **Tipo:** Bar chart (Horizontal)
- **Query:**
```
topk(5, sum by (details_file) (count_over_time({job="sql_defender"} | json [30m])))
```
- **Panel options → Orientation:** Horizontal
- **Legend → Mode:** Hidden

---

## 8. Últimos eventos críticos (tabla)
- **Tipo:** Table
- **Query:**
```
{job="sql_defender"} | json | severity="CRITICAL"
```
- **Transform 1 → Extract fields:** Source: `Line`, Format: `JSON`
- **Transform 2 → Organize fields:** visibles solo `timestamp`, `details_file`, `details_line`, `event_type`, `severity`
- **Overrides sobre `severity`:**
  - **Value mappings:** `CRITICAL` → color rojo, `HIGH` → color ámbar
  - **Cell options → Cell type:** Colored background

---

## Nota sobre el rango de tiempo
Usa **"Last 30 minutes"** mientras el historial generado con `seed_history.py`
sea reciente. Si vuelves más tarde, ajusta a un rango que cubra los timestamps
reales del log (por ejemplo "Last 24 hours") o las series van a verse vacías
aunque los datos existan.
