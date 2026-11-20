---
name: noartex
description: >
  NOARTEX — Defensive Coordination Infrastructure.
  Converts AI agents into governed defensive operators with controlled capabilities,
  audit trail, and policy enforcement. Use this skill to discover capabilities,
  manage sessions, submit tasks (Sentinel SAST/CI/CD/Supply Chain, M3 Observers,
  M4 Intelligence, M5 Permissions, M6 Defense Lab, M7 Memory, and M8 End-to-End Orchestration),
  and query the audit log via the noartex CLI.
  The agent thinks. NOARTEX provides capabilities and governs execution.
version: 0.9.0-m9
commands:
  - noartex
  - noartex doctor
  - noartex capabilities
  - noartex session
  - noartex task
  - noartex audit
  - noartex incident
  - noartex triage
  - noartex memory
---

# NOARTEX Skill — M1–M9 Complete Platform (v0.9.0-m9)

## Misión

NOARTEX es la infraestructura de coordinación defensiva para agentes de IA. No reemplaza al agente: le otorga capacidades gobernadas para observar el entorno, auditar código, correlacionar eventos heterogéneos, gestionar incidentes, evaluar políticas ABAC/RBAC, ejecutar contención en laboratorio con rollback verificado, mantener memoria de casos con hashes de integridad y orquestar flujos de respuesta defensiva end-to-end.

**Principio rector:** *El agente piensa. NOARTEX proporciona capacidades y gobierna su ejecución.*

## Diagnóstico y Salud del Sistema

Antes de solicitar operaciones complejas, verifica el estado del plano de control y adaptadores:

```bash
noartex doctor --format json
```

> [!IMPORTANT]
> Un adaptador no disponible (`UNAVAILABLE`) o con fallos (`ERROR`/`DEGRADED`)
> **NUNCA** debe interpretarse como que el sistema está limpio o seguro (`CLEAN`).
> Reporta las limitaciones honestamente al usuario.

---

## Modelo de Permisos y Postura de Ejecución (M5)

NOARTEX implementa una matriz determinista de niveles de riesgo R0 a R4:

| Nivel de Riesgo | Tipo de Operación | Modo MANUAL (Por defecto) | Modo AUTOMATIC (Sin permisos del agente) |
|---|---|---|---|
| **R0** | Lectura segura / Discovery / Health / Auditoría / Consultas | `ALLOW` con sesión válida | `ALLOW` con sesión válida |
| **R1** | Recolección / Análisis estático / Correlación / Triage / Casos | `ALLOW_WITH_CONSTRAINTS` | `ALLOW_WITH_CONSTRAINTS` |
| **R2** | Cambios reversibles (cuarentena lógica, tagging, rollback, retención) | `REQUIRE_APPROVAL` | `ALLOW_WITH_CONSTRAINTS` (solo si pre-autorizada en política) |
| **R3** | Contención / Impacto operativo (aislar host, bloquear red) | `REQUIRE_APPROVAL` | `ALLOW_WITH_CONSTRAINTS` (solo si pre-autorizada en política) |
| **R4** | Remediación en producción / Parches / Restauración | `REQUIRE_APPROVAL` | `REQUIRE_APPROVAL` (requiere aprobación explícita humana) |

### Invariante Central: Modo Automático sin Permisos del Agente
> [!NOTE]
> En modo `AUTOMATIC`, el Policy Engine puede auto-aprobar acciones pre-autorizadas sin necesidad de un clic manual humano para respuestas defensivas automatizadas de alta velocidad.
> **Sin embargo, el agente NUNCA se auto-asigna permisos:** la autorización proviene estrictamente de las reglas configuradas en el motor de políticas. Cualquier acción fuera del alcance permitido es denegada (`DENIED`) en modo fail-closed.

---

## Control de Contingencias: Kill Switch y Revocación

- **Kill Switch Global:** Bloquea de inmediato toda nueva ejecución privilegiada en caso de emergencia.
- **Kill Switch por Dominio:** Bloquea selectivamente dominios afectados (ej. `defense`, `observer`, `sentinel`) preservando el resto del plano de control.
- **Tokens de Aprobación de Un Solo Uso:** Las aprobaciones humanas cuentan con TTL estricto y quedan invalidadas inmediatamente tras ser consumidas (prevención de ataques de retransmisión / replay).
- **Revocación Inmediata:** Sesiones y aprobaciones pueden ser revocadas al instante invalidando cualquier intento de re-dispatch.

---

## Catálogo de Capacidades Disponibles (51 Registradas)

### 1. Capacidades Core (R0 / R1 — M1)
- `core.capabilities.list`, `core.capabilities.describe`, `core.doctor.health`
- `core.session.create`, `core.session.list`, `core.session.show`, `core.session.close`
- `core.task.status`, `core.task.result`, `core.audit.query`

### 2. Capacidades de Gobernanza y Permisos (R0 / R3 — M5)
- `policy.status`: Consulta modo de ejecución, kill switches activos y reglas automáticas.
- `policy.approval.grant`: Emite token de aprobación temporal para tarea privilegiada (R3).
- `policy.approval.revoke`: Revoca un token de aprobación concedido (R3).
- `policy.approvals.list`: Consulta lista de tokens de aprobación activos y consumidos.
- `policy.killswitch.activate`: Activa el interruptor de emergencia global o por dominio (R3).
- `policy.killswitch.deactivate`: Desactiva el interruptor de emergencia para un alcance dado (R3).
- `policy.session.revoke`: Invalida y cierra inmediatamente una sesión de agente (R3).

### 3. Capacidades de Inteligencia e Incidentes (R0 / R1 — M4)
- `intelligence.correlate`: Correlación multi-fuente en timeline cronológico y brechas de incertidumbre.
- `intelligence.incident.create`, `intelligence.incident.update`, `intelligence.incident.show`, `intelligence.incident.list`
- `intelligence.triage.evaluate`: Evaluación determinista de triage validada por JSON Schema.

### 4. Capacidades de Observación de Solo Lectura (R0 — M3 / M9)
- `observer.host.processes`, `observer.host.files`, `observer.host.network`
- `observer.agent.activity`, `observer.agent.denials`
- `observer.web.headers`, `observer.web.dns`
- `observer.tetragon.stream`: Ingesta reactiva y continua de stream eBPF Tetragon (M9)

### 5. Capacidades Sentinel CLI Adapter (R1 — M2)
- `sentinel.sast.scan`, `sentinel.cicd.audit`, `sentinel.supply_chain.audit`, `sentinel.report.generate`

### 6. Capacidades Defense Lab (R2 / R3 / R4 — M6)
- `defense.artifact.quarantine` (R2): Mueve artefacto sospechoso a cuarentena con plan de reversión automático.
- `defense.artifact.tag` (R2): Etiqueta metadatos de contención en artefactos de laboratorio.
- `defense.host.isolate` (R3): Aislamiento lógico de host de pruebas / sandbox.
- `defense.host.remediate` (R4): Remediación controlada con verificación de estado previo.
- `defense.action.rollback` (R2): Reversión determinista mediante `plan_id` registrado.

### 7. Capacidades Memory & Case Management (R0 / R1 / R2 — M7)
- `memory.case.create`, `memory.case.show`, `memory.case.list`: Gestión completa de expedientes.
- `memory.note.add`: Anotaciones estructuradas (human, agent, system).
- `memory.evidence.add`: Vinculación de evidencia con cálculo de integridad SHA256.
- `memory.followup.add`, `memory.followup.update`, `memory.followup.list`, `memory.followup.overdue`: Seguimiento de acciones con vencimiento.
- `memory.export` (R1): Exportación determinista en JSON canonical con `export_hash` SHA256.
- `memory.retention` (R2): Archivado automático de casos por antigüedad con preservación estricta de auditoría.

---

## Flujo Integral Orquestado (M8 End-to-End)

El ciclo de vida completo de un incidente defensivo en NOARTEX comprende 9 etapas gobernadas:

```
[1. Detección (Observer)] → [2. Investigación (Evidence)] → [3. Correlación (Timeline)]
                                                                    ↓
[6. Contención (Defense)] ← [5. Autorización (Policy)]   ← [4. Triage (Deterministic)]
           ↓
[7. Validación (Post-Action)] → [8. Rollback (si fallo)] → [9. Memoria & Cierre (Case & Audit)]
```

---

## Reglas de Seguridad y Restricciones (INVARIANTES)

> [!CAUTION]
> 1. **Anti-Path Traversal:** No intentes pasar rutas con `..` fuera de las raíces autorizadas.
> 2. **Sin Inyecciones de Shell:** Los adaptadores NO invocan shells (`shell=False`).
> 3. **Degradación Honesta:** Un sensor degradado o no disponible **NUNCA** produce una afirmación de seguridad limpia.
> 4. **One-Time Approvals:** Un token de aprobación consumido no puede volver a usarse (prevención de replay).
> 5. **Fail-Closed Ante Todo:** Desconexión, fallo de almacenamiento o ausencia de regla produce `DENIED`.
> 6. **Defense Lab Only:** Las acciones de contención y remediación operan exclusivamente en entornos autorizados (`lab`, `test`, `sandbox`).
