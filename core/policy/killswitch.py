"""
NOARTEX — Kill Switch Manager (M5)
Control de emergencia para detener operaciones de forma inmediata.
Soporta:
- Kill switch global: bloquea todas las ejecuciones de tareas R1+
- Kill switch por dominio: bloquea dominios específicos (ej. defense, observer, sentinel)
- Persistencia y trazabilidad
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.policy.models import KillSwitchState, _now


class KillSwitchManager:
    """
    Gestiona el estado de activación de kill switches.
    """

    def __init__(self, data_dir: str | Path):
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._file = self._dir / "killswitch.json"
        self._lock = threading.Lock()
        self._switches: dict[str, KillSwitchState] = {}
        self._load()

    def _load(self) -> None:
        if not self._file.exists():
            return
        try:
            with open(self._file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    self._switches[k] = KillSwitchState.from_dict(v)
        except Exception:
            pass

    def _persist(self) -> None:
        tmp = self._file.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            data = {k: v.to_dict() for k, v in self._switches.items()}
            json.dump(data, f, ensure_ascii=False, indent=2)
        tmp.replace(self._file)

    def activate(self, scope: str = "global", activated_by: str = "operator", reason: str = "") -> KillSwitchState:
        with self._lock:
            state = KillSwitchState(
                active=True,
                scope=scope,
                activated_at=_now(),
                activated_by=activated_by,
                reason=reason or f"Emergency kill switch activated for scope '{scope}'",
            )
            self._switches[scope] = state
            self._persist()
            return state

    def deactivate(self, scope: str = "global") -> bool:
        with self._lock:
            if scope in self._switches:
                self._switches[scope].active = False
                self._persist()
                return True
            return False

    def is_blocked(self, operation: str) -> tuple[bool, str]:
        """
        Determina si una operación está bloqueada por el kill switch global
        o por el kill switch específico de su dominio.
        """
        with self._lock:
            # 1. Comprobar kill switch global
            glob = self._switches.get("global")
            if glob and glob.active:
                return True, f"Blocked by GLOBAL KILL SWITCH activated by '{glob.activated_by}': {glob.reason}"

            # 2. Comprobar kill switch por dominio (ej: defense.*, observer.*, sentinel.*)
            parts = operation.split(".")
            domain = parts[0] if parts else ""
            dom_switch = self._switches.get(domain)
            if dom_switch and dom_switch.active:
                return True, f"Blocked by DOMAIN KILL SWITCH for '{domain}' activated by '{dom_switch.activated_by}': {dom_switch.reason}"

            return False, "Not blocked"

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {k: v.to_dict() for k, v in self._switches.items() if v.active}
