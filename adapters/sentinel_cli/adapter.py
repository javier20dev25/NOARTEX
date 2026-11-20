"""
NOARTEX — Sentinel CLI Adapter
Integración gobernada de Sentinel CLI (SAST, CI/CD audit, Supply Chain).
M2-B Specification.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.adapters.base import (
    AdapterInterface,
    AdapterLimits,
    AdapterMetadata,
    AdapterStatus,
)
from core.contracts.models import (
    AvailabilityStatus,
    Capability,
    DecisionKind,
    PolicyDecision,
    RiskLevel,
    TaskRequest,
    TaskResult,
    TaskStatus,
)


def _extract_json_payload(raw_stdout: str) -> Optional[dict]:
    """
    Extrae de forma robusta el objeto JSON de la salida de Sentinel CLI,
    descartando banners decorativos, spinners o líneas de texto previo.
    """
    if not raw_stdout:
        return None
    # Buscar el primer '{' y el último '}'
    first_brace = raw_stdout.find("{")
    last_brace = raw_stdout.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_slice = raw_stdout[first_brace : last_brace + 1]
        try:
            return json.loads(json_slice)
        except json.JSONDecodeError:
            pass
    return None


class SentinelCLIAdapter(AdapterInterface):
    """
    Adaptador oficial para Sentinel CLI.
    Ejecuta comandos de análisis estático y supply chain bajo mediación de NOARTEX.
    """

    DEFAULT_METADATA = AdapterMetadata(
        adapter_id="adapter.sentinel.cli",
        name="Sentinel CLI Adapter",
        version="1.0.0",
        provenance="local npm binary (@sentinel/cli or global sentinel)",
        license="Proprietary / Sentinel Ecosystem Internal",
        author="Sentinel Security Intelligence Team",
        description="SAST, supply chain analysis, and CI/CD audit via Sentinel CLI",
        limits=AdapterLimits(
            timeout_seconds=30,
            max_output_bytes=10 * 1024 * 1024,
            allowed_target_roots=[],
            allow_network=False,
            allow_subprocesses=False,
        ),
    )

    def __init__(
        self,
        binary_path: Optional[str] = None,
        metadata: Optional[AdapterMetadata] = None,
    ):
        meta = metadata or self.DEFAULT_METADATA
        super().__init__(meta)
        self._binary_override = binary_path

    def _resolve_binary(self) -> Optional[str]:
        if self._binary_override:
            if Path(self._binary_override).exists():
                return str(Path(self._binary_override).resolve())
            return None
        return shutil.which("sentinel") or shutil.which("sentinel.cmd")

    def describe_capabilities(self) -> list[Capability]:
        status = AvailabilityStatus.AVAILABLE if self._resolve_binary() else AvailabilityStatus.UNAVAILABLE
        return [
            Capability(
                capability_id="sentinel.sast.scan",
                version="1.0.0",
                domain="intelligence",
                operations=["scan"],
                risk=RiskLevel.R1,
                description="Static application security testing (SAST) of source code",
                availability=status,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="sentinel.cicd.audit",
                version="1.0.0",
                domain="intelligence",
                operations=["audit"],
                risk=RiskLevel.R1,
                description="Audit CI/CD GitHub Actions workflows for supply chain risks",
                availability=status,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="sentinel.supply_chain.audit",
                version="1.0.0",
                domain="intelligence",
                operations=["audit"],
                risk=RiskLevel.R1,
                description="Audit dependency tree and packages for malicious supply chain signals",
                availability=status,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="sentinel.report.generate",
                version="1.0.0",
                domain="intelligence",
                operations=["generate"],
                risk=RiskLevel.R1,
                description="Generate structured Markdown or SARIF security reports",
                availability=status,
                adapter_id=self.metadata.adapter_id,
            ),
        ]

    def health(self) -> dict[str, Any]:
        binary = self._resolve_binary()
        if not binary:
            return {
                "adapter_id": self.metadata.adapter_id,
                "status": AdapterStatus.UNAVAILABLE.value,
                "version": self.metadata.version,
                "binary": None,
                "limitations": ["Sentinel CLI binary not found in PATH"],
            }

        # Comprobar versión de manera segura
        try:
            res = subprocess.run(
                [binary, "-V"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            cli_ver = res.stdout.strip() or res.stderr.strip()
            return {
                "adapter_id": self.metadata.adapter_id,
                "status": AdapterStatus.AVAILABLE.value,
                "version": self.metadata.version,
                "binary": binary,
                "cli_version": cli_ver,
                "limitations": [],
            }
        except subprocess.TimeoutExpired:
            return {
                "adapter_id": self.metadata.adapter_id,
                "status": AdapterStatus.DEGRADED.value,
                "binary": binary,
                "limitations": ["Health check timed out querying Sentinel CLI version"],
            }
        except Exception as e:
            return {
                "adapter_id": self.metadata.adapter_id,
                "status": AdapterStatus.ERROR.value,
                "binary": binary,
                "limitations": [f"Error checking Sentinel CLI health: {e}"],
            }

    def execute(
        self,
        request: TaskRequest,
        decision: PolicyDecision,
    ) -> TaskResult:
        started = datetime.now(timezone.utc).isoformat()
        binary = self._resolve_binary()

        # Invariante 1: Si no hay binario, falla honestamente (NUNCA inferir CLEAN)
        if not binary:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.UNAVAILABLE,
                decision_ref=decision.decision_id,
                data={},
                observations=["Sentinel CLI is not installed or not in PATH"],
                limitations=["Tool unavailable: cannot assert security state"],
                started_at=started,
            )

        op = request.operation
        params = request.parameters or {}
        raw_target = params.get("target_path") or (request.target.get("id") if request.target else ".")

        # Invariante 2: Validación estricta de rutas (Anti-Traversal)
        valid_path, target_resolved_or_err = self.validate_target_path(raw_target)
        if not valid_path:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.DENIED,
                decision_ref=decision.decision_id,
                data={},
                observations=[f"Target path validation failed: {target_resolved_or_err}"],
                limitations=["Path outside authorized boundary or non-existent"],
                started_at=started,
            )

        target_path = target_resolved_or_err

        # Construir argumentos de forma segura (vector de argumentos, SIN shell=True)
        cmd_args = [binary]

        if op == "sentinel.sast.scan":
            cmd_args.extend(["scan", target_path, "--json"])
        elif op == "sentinel.cicd.audit":
            workflows_dir = Path(target_path) / ".github" / "workflows"
            audit_path = str(workflows_dir) if workflows_dir.exists() else target_path
            cmd_args.extend(["scan", audit_path, "--json"])
        elif op == "sentinel.supply_chain.audit":
            # Si se pide auditoría de paquetes
            pkg = params.get("package")
            if pkg:
                # Sanitizar nombre de paquete (sin flags ni caracteres de escape)
                if not re.match(r"^[@a-zA-Z0-9_\-\./]+$", pkg):
                    return TaskResult(
                        task_id=request.task_id,
                        status=TaskStatus.DENIED,
                        decision_ref=decision.decision_id,
                        observations=["Invalid package name syntax rejected for security"],
                        started_at=started,
                    )
                cmd_args.extend(["verify-pkg", pkg, "--json"])
            else:
                cmd_args.extend(["deps-tree", target_path, "--json"])
        elif op == "sentinel.report.generate":
            fmt = params.get("format", "md")
            if fmt == "sarif":
                cmd_args.extend(["scan", target_path, "--sarif"])
            else:
                cmd_args.extend(["scan", target_path, "--md"])
        else:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.DENIED,
                decision_ref=decision.decision_id,
                observations=[f"Operation '{op}' is not supported by SentinelCLIAdapter"],
                started_at=started,
            )

        # Invariante 3: Limpieza y contención de variables de entorno
        clean_env = os.environ.copy()
        clean_env["NO_COLOR"] = "1"
        clean_env["CI"] = "true"

        # Invariante 4: Ejecución mediada con timeout estricto
        timeout = decision.constraints.get("max_duration_ms", self.metadata.limits.timeout_seconds * 1000) / 1000.0

        try:
            proc = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                env=clean_env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.TIMED_OUT,
                decision_ref=decision.decision_id,
                observations=[f"Sentinel CLI timed out after {timeout}s"],
                limitations=["Execution aborted due to timeout constraint"],
                started_at=started,
            )
        except Exception as exc:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.FAILED,
                decision_ref=decision.decision_id,
                observations=[f"Subprocess launch failed: {exc}"],
                started_at=started,
            )

        # Invariante 5: Parsing seguro y degradación honesta
        parsed_json = _extract_json_payload(proc.stdout)
        
        # En operaciones de scan, exit code 1 puede indicar hallazgos (fail-on),
        # por lo que si hay JSON válido, se procesan los hallazgos.
        if parsed_json is not None:
            findings = parsed_json.get("findings", [])
            host_info = parsed_json.get("host", {})
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data={
                    "target": target_path,
                    "findings_count": len(findings),
                    "findings": findings,
                    "host": host_info,
                    "raw_json": parsed_json,
                },
                evidence=[
                    {
                        "type": "cli_output",
                        "adapter": self.metadata.adapter_id,
                        "exit_code": proc.returncode,
                    }
                ],
                observations=[
                    f"Scan completed on '{target_path}'. Findings count: {len(findings)}."
                ],
                started_at=started,
            )

        # Si no hubo JSON y es un reporte MD o SARIF:
        if op == "sentinel.report.generate":
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED if proc.returncode == 0 else TaskStatus.DEGRADED,
                decision_ref=decision.decision_id,
                data={"report_content": proc.stdout},
                observations=["Report generation completed"],
                started_at=started,
            )

        # Si el proceso falló o la salida no fue JSON válido -> DEGRADED / FAILED, NUNCA 'CLEAN'
        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.DEGRADED if proc.returncode == 0 else TaskStatus.FAILED,
            decision_ref=decision.decision_id,
            data={"stdout_sample": proc.stdout[:1000], "stderr": proc.stderr[:1000]},
            observations=[
                f"Sentinel CLI exited with code {proc.returncode} but valid JSON payload was not found."
            ],
            limitations=[
                "Output unparseable: cannot verify security findings. Degrading verdict."
            ],
            started_at=started,
        )
