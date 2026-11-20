"""
NOARTEX — Host Observer Adapter (M3-A)
Observación gobernada y de solo lectura del host:
- observer.host.processes: Snapshot de procesos (PID, PPID, name, cmdline).
- observer.host.files: Verificación de integridad y drift en rutas autorizadas (hashes SHA256, mtime, size).
- observer.host.network: Conexiones activas y puertos en escucha (local/remote port, owning process).
Invariante: ESTRICTAMENTE SOLO LECTURA. Cero modificación de archivos o procesos.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
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
from core.observer.models import (
    ObservationDomain,
    ObservationEvent,
    ObservationState,
)


class HostObserverAdapter(AdapterInterface):
    DEFAULT_METADATA = AdapterMetadata(
        adapter_id="adapter.observer.host",
        name="Host System Observer",
        version="1.0.0",
        provenance="native python / os standard utilities",
        license="MIT",
        author="NOARTEX Core Team",
        description="Read-only host observer: processes, file changes, and network sockets",
        limits=AdapterLimits(
            timeout_seconds=20,
            max_output_bytes=10 * 1024 * 1024,
            allowed_target_roots=[],
            allow_network=False,
            allow_subprocesses=False,
        ),
    )

    def __init__(self, metadata: Optional[AdapterMetadata] = None):
        super().__init__(metadata or self.DEFAULT_METADATA)

    def describe_capabilities(self) -> list[Capability]:
        return [
            Capability(
                capability_id="observer.host.processes",
                version="1.0.0",
                domain="observer",
                operations=["snapshot"],
                risk=RiskLevel.R0,
                description="Capture read-only snapshot of running processes and execution tree",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="observer.host.files",
                version="1.0.0",
                domain="observer",
                operations=["snapshot", "diff"],
                risk=RiskLevel.R0,
                description="Inspect file integrity, size, mtime, and SHA256 hashes in authorized paths",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="observer.host.network",
                version="1.0.0",
                domain="observer",
                operations=["snapshot"],
                risk=RiskLevel.R0,
                description="List listening ports and active network socket endpoints",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
        ]

    def health(self) -> dict[str, Any]:
        return {
            "adapter_id": self.metadata.adapter_id,
            "status": AdapterStatus.AVAILABLE.value,
            "version": self.metadata.version,
            "os": sys.platform,
            "limitations": [],
        }

    def execute(self, request: TaskRequest, decision: PolicyDecision) -> TaskResult:
        started = datetime.now(timezone.utc).isoformat()
        op = request.operation
        params = request.parameters or {}

        try:
            if op == "observer.host.processes":
                return self._observe_processes(request, decision, params, started)
            elif op == "observer.host.files":
                return self._observe_files(request, decision, params, started)
            elif op == "observer.host.network":
                return self._observe_network(request, decision, params, started)
            else:
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.DENIED,
                    decision_ref=decision.decision_id,
                    observations=[f"Operation '{op}' not supported by HostObserverAdapter"],
                    started_at=started,
                )
        except Exception as exc:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.FAILED,
                decision_ref=decision.decision_id,
                observations=[f"Host observation failed: {exc}"],
                limitations=["Collector encountered unhandled exception"],
                started_at=started,
            )

    def _observe_processes(
        self, request: TaskRequest, decision: PolicyDecision, params: dict, started: str
    ) -> TaskResult:
        """Captura snapshot de procesos en Windows o Unix."""
        processes: list[dict] = []
        limitations: list[str] = []

        if sys.platform == "win32":
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine | ConvertTo-Json -Compress",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if proc.returncode == 0 and proc.stdout.strip():
                    raw = json.loads(proc.stdout)
                    if isinstance(raw, dict):
                        raw = [raw]
                    for p in raw:
                        processes.append({
                            "pid": p.get("ProcessId"),
                            "ppid": p.get("ParentProcessId"),
                            "name": p.get("Name"),
                            "cmdline": p.get("CommandLine"),
                        })
                else:
                    limitations.append("PowerShell CIM returned non-zero or empty")
            except Exception as e:
                limitations.append(f"Process query exception: {e}")
        else:
            # Fallback Unix
            try:
                proc = subprocess.run(["ps", "-eo", "pid,ppid,comm,args"], capture_output=True, text=True, timeout=10)
                if proc.returncode == 0:
                    lines = proc.stdout.splitlines()[1:]
                    for l in lines:
                        parts = l.strip().split(None, 3)
                        if len(parts) >= 3:
                            processes.append({
                                "pid": int(parts[0]),
                                "ppid": int(parts[1]),
                                "name": parts[2],
                                "cmdline": parts[3] if len(parts) > 3 else "",
                            })
            except Exception as e:
                limitations.append(f"Unix ps query exception: {e}")

        # Distinción de estado
        if limitations and not processes:
            state = ObservationState.OBSERVATION_UNAVAILABLE
        elif limitations:
            state = ObservationState.DEGRADED
        else:
            state = ObservationState.NO_ACTIVITY_OBSERVED if len(processes) == 0 else ObservationState.NO_ACTIVITY_OBSERVED

        obs_event = ObservationEvent(
            domain=ObservationDomain.HOST,
            event_type="process_snapshot",
            state=state,
            target_scope="localhost",
            coverage={"total_processes": len(processes), "platform": sys.platform},
            limitations=limitations,
            data={"count": len(processes), "processes": processes[:100]}, # max sample
            evidence=[{"type": "process_snapshot", "sample_size": min(len(processes), 100)}],
        )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.SUCCEEDED if processes else TaskStatus.DEGRADED,
            decision_ref=decision.decision_id,
            data={"observation": obs_event.to_dict()},
            evidence=obs_event.evidence,
            observations=[f"Observed {len(processes)} active processes on host"],
            limitations=limitations,
            started_at=started,
        )

    def _observe_files(
        self, request: TaskRequest, decision: PolicyDecision, params: dict, started: str
    ) -> TaskResult:
        """Snapshot de integridad de archivos en la ruta objetivo."""
        target_path = params.get("target_path", ".")
        valid, resolved_or_err = self.validate_target_path(target_path)
        if not valid:
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.DENIED,
                decision_ref=decision.decision_id,
                observations=[f"File observer target path rejected: {resolved_or_err}"],
                started_at=started,
            )

        root = Path(resolved_or_err)
        file_entries: list[dict] = []
        limitations: list[str] = []
        max_files = params.get("max_files", 50)

        try:
            if root.is_file():
                targets = [root]
            else:
                targets = list(root.rglob("*"))[:max_files]

            for f in targets:
                if f.is_file():
                    try:
                        stat = f.stat()
                        hasher = hashlib.sha256()
                        # Solo hashear si tamaño < 5MB
                        if stat.st_size <= 5 * 1024 * 1024:
                            with open(f, "rb") as fh:
                                hasher.update(fh.read())
                            sha256 = hasher.hexdigest()
                        else:
                            sha256 = "OMITTED_EXCEEDS_5MB"

                        file_entries.append({
                            "path": str(f.resolve()),
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "sha256": sha256,
                        })
                    except Exception as fe:
                        limitations.append(f"Cannot read {f.name}: {fe}")
        except Exception as e:
            limitations.append(f"Directory traversal error: {e}")

        obs_event = ObservationEvent(
            domain=ObservationDomain.FILE,
            event_type="file_snapshot",
            state=ObservationState.NO_ACTIVITY_OBSERVED,
            target_scope=str(root),
            coverage={"scanned_files": len(file_entries), "max_files": max_files},
            limitations=limitations,
            data={"files": file_entries, "count": len(file_entries)},
            evidence=[{"type": "file_integrity_records", "count": len(file_entries)}],
        )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.SUCCEEDED,
            decision_ref=decision.decision_id,
            data={"observation": obs_event.to_dict()},
            evidence=obs_event.evidence,
            observations=[f"Captured integrity snapshot of {len(file_entries)} files in '{root}'"],
            limitations=limitations,
            started_at=started,
        )

    def _observe_network(
        self, request: TaskRequest, decision: PolicyDecision, params: dict, started: str
    ) -> TaskResult:
        """Snapshot de sockets y puertos en escucha."""
        connections: list[dict] = []
        limitations: list[str] = []

        if sys.platform == "win32":
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Compress",
            ]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if proc.returncode == 0 and proc.stdout.strip():
                    raw = json.loads(proc.stdout)
                    if isinstance(raw, dict):
                        raw = [raw]
                    for c in raw:
                        connections.append({
                            "local_address": c.get("LocalAddress"),
                            "local_port": c.get("LocalPort"),
                            "owning_pid": c.get("OwningProcess"),
                            "state": "LISTEN",
                        })
                else:
                    limitations.append("Get-NetTCPConnection returned no data")
            except Exception as e:
                limitations.append(f"PowerShell network query error: {e}")
        else:
            limitations.append("Unix network inspection not configured in this profile")

        obs_event = ObservationEvent(
            domain=ObservationDomain.NETWORK,
            event_type="socket_snapshot",
            state=ObservationState.NO_ACTIVITY_OBSERVED if connections else ObservationState.DEGRADED,
            target_scope="localhost",
            coverage={"listening_endpoints": len(connections)},
            limitations=limitations,
            data={"listeners": connections[:50]},
            evidence=[{"type": "network_listeners", "count": len(connections)}],
        )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.SUCCEEDED if connections else TaskStatus.DEGRADED,
            decision_ref=decision.decision_id,
            data={"observation": obs_event.to_dict()},
            evidence=obs_event.evidence,
            observations=[f"Observed {len(connections)} listening network sockets"],
            limitations=limitations,
            started_at=started,
        )
