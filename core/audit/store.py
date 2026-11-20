"""
NOARTEX — Audit Log (append-only JSONL)
Registro inmutable de todas las operaciones del sistema.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


AUDIT_EVENTS = {
    "TASK_REQUESTED",
    "POLICY_EVALUATED",
    "APPROVAL_REQUESTED",
    "APPROVAL_GRANTED",
    "APPROVAL_DENIED",
    "TASK_DISPATCHED",
    "TASK_COMPLETED",
    "TASK_FAILED",
    "TASK_DENIED",
    "TASK_UNAVAILABLE",
    "SESSION_CREATED",
    "SESSION_CLOSED",
    "NOTE_ADDED",
    "INCIDENT_UPDATED",
    "CAPABILITY_CHANGED",
    "SYSTEM_STARTUP",
    "SYSTEM_ERROR",
}


class AuditLog:
    """
    Store append-only en JSONL.
    Thread-safe. Cada línea es un evento JSON con timestamp e índice secuencial.
    """

    def __init__(self, log_path: str | Path):
        self._path = Path(log_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = self._load_seq()

    def _load_seq(self) -> int:
        """Cuenta líneas existentes para continuar el índice."""
        if not self._path.exists():
            return 0
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0

    def append(
        self,
        event_type: str,
        actor_id: Optional[str] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        data: Optional[dict[str, Any]] = None,
    ) -> dict:
        """
        Escribe un evento al log. Retorna el registro escrito.
        """
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "event_type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor_id": actor_id,
                "session_id": session_id,
                "task_id": task_id,
                "decision_id": decision_id,
                "data": data or {},
            }
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
            return record

    def query(
        self,
        task_id: Optional[str] = None,
        session_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Consulta el log con filtros opcionales. Retorna hasta `limit` registros
        más recientes que coincidan (desde el final del archivo).
        """
        if not self._path.exists():
            return []
        results = []
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if task_id and rec.get("task_id") != task_id:
                    continue
                if session_id and rec.get("session_id") != session_id:
                    continue
                if actor_id and rec.get("actor_id") != actor_id:
                    continue
                if event_type and rec.get("event_type") != event_type:
                    continue
                results.append(rec)
                if len(results) >= limit:
                    break
        except Exception:
            pass
        return list(reversed(results))

    def stats(self) -> dict:
        """Estadísticas básicas del log."""
        with self._lock:
            count = self._seq
        size = self._path.stat().st_size if self._path.exists() else 0
        return {
            "total_events": count,
            "log_path": str(self._path),
            "size_bytes": size,
        }
