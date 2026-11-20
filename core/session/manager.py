"""
NOARTEX — Session Manager (con persistencia JSONL para M1)
Registro de identidades, sesiones y TTL.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from core.contracts.models import AgentType, Session


class SessionManager:
    """
    Gestiona sesiones con persistencia en JSONL.
    Cada sesión se escribe en disco al crear/cerrar para sobrevivir entre invocaciones CLI.
    """

    def __init__(self, data_dir: Optional[str | Path] = None, default_ttl_seconds: int = 3600):
        if data_dir is None:
            data_dir = Path(os.environ.get("NOARTEX_DATA_DIR", Path.home() / ".noartex"))
        self._dir = Path(data_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._store_path = self._dir / "sessions.jsonl"
        self._lock = threading.Lock()
        self._default_ttl = default_ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._load()

    def _load(self) -> None:
        """Carga sesiones desde disco al inicio."""
        if not self._store_path.exists():
            return
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        sess = Session(
                            session_id=d["session_id"],
                            agent_id=d["agent_id"],
                            agent_type=AgentType(d.get("agent_type", "unknown")),
                            created_at=d.get("created_at", ""),
                            expires_at=d.get("expires_at"),
                            state=d.get("state", "ACTIVE"),
                            capabilities_requested=d.get("capabilities_requested", []),
                            ttl_seconds=d.get("ttl_seconds", self._default_ttl),
                        )
                        self._sessions[sess.session_id] = sess
                    except (KeyError, ValueError):
                        continue
        except Exception:
            pass

    def _persist(self) -> None:
        """Reescribe todas las sesiones al disco (simple, correcto para M1)."""
        try:
            with open(self._store_path, "w", encoding="utf-8") as f:
                for sess in self._sessions.values():
                    f.write(json.dumps(sess.to_dict(), ensure_ascii=False) + "\n")
        except Exception:
            pass

    def create(
        self,
        agent_id: str,
        agent_type: str = "unknown",
        ttl_seconds: Optional[int] = None,
        capabilities_requested: Optional[list[str]] = None,
    ) -> Session:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        try:
            atype = AgentType(agent_type)
        except ValueError:
            atype = AgentType.UNKNOWN

        expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
        session = Session(
            agent_id=agent_id,
            agent_type=atype,
            ttl_seconds=ttl,
            expires_at=expires,
            capabilities_requested=capabilities_requested or [],
        )
        with self._lock:
            self._sessions[session.session_id] = session
            self._persist()
        return session

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def is_active(self, session_id: str) -> bool:
        sess = self.get(session_id)
        if sess is None or sess.state != "ACTIVE":
            return False
        if sess.expires_at:
            try:
                exp = datetime.fromisoformat(sess.expires_at)
                if datetime.now(timezone.utc) > exp:
                    self._expire(session_id)
                    return False
            except ValueError:
                pass
        return True

    def close(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].state = "CLOSED"
                self._persist()
                return True
        return False

    def _expire(self, session_id: str) -> None:
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].state = "EXPIRED"
                self._persist()

    def list_sessions(self, agent_id: Optional[str] = None) -> list[Session]:
        with self._lock:
            sessions = list(self._sessions.values())
        if agent_id:
            sessions = [s for s in sessions if s.agent_id == agent_id]
        return sessions
