"""
NOARTEX — Approvals Store & Manager (M5)
Administra solicitudes y concesiones de aprobación con persistencia JSONL.
Garantiza:
- No reutilización fuera de alcance (one-time use tokens)
- Expiración estricta por TTL
- Revocación inmediata
- Registro auditable
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.policy.models import ApprovalGrant, ApprovalStatus, _now, _new_id


class ApprovalManager:
    """
    Gestor de aprobaciones persistente.
    """

    def __init__(self, data_dir: str | Path):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._file = self._dir / "approvals.jsonl"
        self._lock = threading.Lock()
        self._grants: dict[str, ApprovalGrant] = {}
        self._load()

    def _load(self) -> None:
        if not self._file.exists():
            return
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        g = ApprovalGrant.from_dict(json.loads(line))
                        self._grants[g.approval_id] = g
                    except Exception:
                        continue
        except Exception:
            pass

    def _persist(self) -> None:
        tmp = self._file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for g in self._grants.values():
                f.write(json.dumps(g.to_dict(), ensure_ascii=False) + "\n")
        tmp.replace(self._file)

    def grant(
        self,
        task_id: str,
        operation: str,
        approver: str = "operator",
        approver_type: str = "human",
        scope: Optional[dict[str, Any]] = None,
        ttl_seconds: int = 600,
    ) -> ApprovalGrant:
        """Emite una nueva aprobación con TTL."""
        with self._lock:
            now_dt = datetime.now(timezone.utc)
            expires_at = datetime.fromtimestamp(now_dt.timestamp() + ttl_seconds, tz=timezone.utc).isoformat()
            grant = ApprovalGrant(
                approval_id=_new_id("appr"),
                task_id=task_id,
                operation=operation,
                approver=approver,
                approver_type=approver_type,
                scope=scope or {},
                created_at=now_dt.isoformat(),
                expires_at=expires_at,
                status=ApprovalStatus.GRANTED,
                used=False,
            )
            self._grants[grant.approval_id] = grant
            self._persist()
            return grant

    def validate_and_consume(
        self,
        approval_id: str,
        task_id: str,
        operation: str,
        actor_id: str = "",
    ) -> tuple[bool, str]:
        """
        Valida que la aprobación exista, coincida con la tarea/operación,
        no esté expirada, no esté revocada y no haya sido utilizada previamente.
        Si es válida, la marca como consumida (one-time use).
        """
        with self._lock:
            grant = self._grants.get(approval_id)
            if not grant:
                return False, f"Approval ID '{approval_id}' not found"

            if grant.status == ApprovalStatus.REVOKED:
                return False, "Approval has been REVOKED"

            if grant.used:
                return False, f"Approval '{approval_id}' has already been used at {grant.used_at}"

            # Validar expiración
            if grant.expires_at:
                try:
                    exp_dt = datetime.fromisoformat(grant.expires_at.replace("Z", "+00:00"))
                    if datetime.now(timezone.utc) > exp_dt:
                        grant.status = ApprovalStatus.EXPIRED
                        self._persist()
                        return False, f"Approval '{approval_id}' EXPIRED at {grant.expires_at}"
                except Exception:
                    pass

            # Validar alcance de tarea u operación
            if grant.task_id and grant.task_id != task_id:
                return False, f"Approval is scoped to task '{grant.task_id}', cannot be used for '{task_id}'"

            if grant.operation and grant.operation != operation:
                return False, f"Approval is scoped to operation '{grant.operation}', cannot be used for '{operation}'"

            # Marcar como consumida
            grant.used = True
            grant.used_at = _now()
            self._persist()
            return True, "Approval valid and successfully consumed"

    def revoke(self, approval_id: str, revoker: str = "operator") -> bool:
        """Revoca inmediatamente una aprobación."""
        with self._lock:
            grant = self._grants.get(approval_id)
            if not grant:
                return False
            grant.status = ApprovalStatus.REVOKED
            self._persist()
            return True

    def get(self, approval_id: str) -> Optional[ApprovalGrant]:
        with self._lock:
            return self._grants.get(approval_id)

    def list_grants(self, task_id: Optional[str] = None) -> list[ApprovalGrant]:
        with self._lock:
            res = list(self._grants.values())
            if task_id:
                res = [g for g in res if g.task_id == task_id]
            return res
