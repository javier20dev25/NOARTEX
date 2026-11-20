"""
NOARTEX — Tetragon Streaming Adapter
Real-time eBPF event stream consumer for kernel-level security telemetry.
Connects to Tetragon export stream (JSONL/Unix socket) and translates to NOARTEX Reactive Events.
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

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
from core.observer.models import ObservationDomain, ObservationState


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TetragonStreamAdapter(AdapterInterface):
    """
    Adapter for continuous, streaming observation of Tetragon eBPF telemetry.
    Filters high-volume kernel events to emit high-fidelity NOARTEX security signals.
    """

    SENSITIVE_TARGETS = (
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh",
        "/root",
        "/srv/sentinel-enterprise-lab",
        "/tmp/noartex",
    )

    SUSPICIOUS_BINARIES = (
        "python",
        "node",
        "dash",
        "sh",
        "bash",
        "curl",
        "wget",
        "socat",
        "nc",
        "ncat",
    )

    def __init__(
        self,
        log_path: Optional[str | Path] = None,
        event_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ):
        meta = AdapterMetadata(
            adapter_id="adapter.observer.tetragon.stream",
            name="Tetragon eBPF Streaming Observer",
            version="1.0.0",
            provenance="in-tree:adapters/tetragon_stream",
            license="BUSL-1.1",
            author="NOARTEX Core Team",
            description="Kernel-level eBPF stream watcher consuming Tetragon security telemetry",
            limits=AdapterLimits(timeout_seconds=60, max_output_bytes=50 * 1024 * 1024, allow_subprocesses=False),
        )
        super().__init__(meta)
        self.log_path = Path(log_path) if log_path else None
        self.callback = event_callback
        self._tail_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.RLock()

        # Telemetry metrics
        self.events_read = 0
        self.events_filtered = 0
        self.events_published = 0
        self.last_event_ts: Optional[str] = None
        self._total_parse_latency_ms = 0.0

    def describe_capabilities(self) -> list[Capability]:
        return [
            Capability(
                capability_id="observer.tetragon.stream",
                version="1.0.0",
                domain="observer",
                operations=["observer.tetragon.stream", "observer.tetragon.status", "observer.tetragon.stop"],
                risk=RiskLevel.R0,
                description="Stream, monitor and inspect kernel-level Tetragon eBPF events",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            )
        ]

    def health(self) -> dict[str, Any]:
        with self._lock:
            status = AdapterStatus.AVAILABLE if (not self._running or (self.log_path and self.log_path.exists())) else AdapterStatus.DEGRADED
            avg_parse_ms = (self._total_parse_latency_ms / self.events_read) if self.events_read > 0 else 0.0
            return {
                "adapter_id": self.metadata.adapter_id,
                "status": status.value,
                "version": self.metadata.version,
                "streaming_active": self._running,
                "log_path": str(self.log_path) if self.log_path else None,
                "events_read": self.events_read,
                "events_filtered": self.events_filtered,
                "events_published": self.events_published,
                "avg_parse_latency_ms": round(avg_parse_ms, 3),
                "last_event_timestamp": self.last_event_ts,
                "limitations": [] if status == AdapterStatus.AVAILABLE else ["Log file unreachable or stream degraded"],
            }

    def start_streaming(self, log_path: Optional[str | Path] = None, callback: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        with self._lock:
            if self._running:
                return
            if log_path:
                self.log_path = Path(log_path)
            if callback:
                self.callback = callback
            self._running = True
            self._tail_thread = threading.Thread(target=self._tail_loop, daemon=True, name="tetragon-stream-tail")
            self._tail_thread.start()

    def stop_streaming(self, timeout: float = 2.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._tail_thread and self._tail_thread.is_alive():
            self._tail_thread.join(timeout=timeout)

    def _tail_loop(self) -> None:
        if not self.log_path:
            return

        # Ensure file exists before tailing
        while self._running and not self.log_path.exists():
            time.sleep(0.05)

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                # Seek to end or read from beginning if brand new
                f.seek(0, os.SEEK_END)
                while self._running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.02)
                        continue

                    t0 = time.perf_counter()
                    parsed = self._parse_line(line.strip())
                    parse_ms = (time.perf_counter() - t0) * 1000.0

                    with self._lock:
                        self.events_read += 1
                        self._total_parse_latency_ms += parse_ms

                    if parsed:
                        with self._lock:
                            self.events_published += 1
                            self.last_event_ts = parsed.get("collected_at", _now())

                        if self.callback:
                            try:
                                self.callback(parsed)
                            except Exception:
                                pass
                    else:
                        with self._lock:
                            self.events_filtered += 1
        except Exception:
            with self._lock:
                self._running = False

    def _parse_line(self, line: str) -> Optional[dict[str, Any]]:
        if not line:
            return None
        try:
            raw = json.loads(line)
        except Exception:
            return None

        # 1. Kprobe event
        if "process_kprobe" in raw:
            kprobe = raw["process_kprobe"]
            proc = kprobe.get("process", {})
            fn = kprobe.get("function_name", "")
            args = kprobe.get("args", [])
            ts = raw.get("time", _now())

            target_val = ""
            for a in args:
                if "string_arg" in a:
                    target_val = a["string_arg"]
                elif "sockaddr_arg" in a:
                    sa = a["sockaddr_arg"]
                    target_val = f"{sa.get('addr')}:{sa.get('port')}"

            # Check sensitivity
            is_suspicious = False
            for s in self.SENSITIVE_TARGETS:
                if target_val.startswith(s):
                    is_suspicious = True
                    break

            if "tcp" in fn:
                is_suspicious = True  # Network connection

            bin_name = proc.get("binary", "")
            uid = proc.get("uid", 0)

            return {
                "event_id": f"tet_{int(time.time()*1000)}_{self.events_read}",
                "domain": ObservationDomain.NETWORK.value if "tcp" in fn else ObservationDomain.HOST.value,
                "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value if is_suspicious else ObservationState.NO_ACTIVITY_OBSERVED.value,
                "event_type": f"kprobe_{fn}",
                "process_binary": bin_name,
                "process_args": proc.get("arguments", ""),
                "pid": proc.get("pid"),
                "uid": uid,
                "target_scope": target_val,
                "policy_name": kprobe.get("policy_name", ""),
                "collected_at": ts,
                "confidence": "HIGH",
                "raw_event": raw,
            }

        # 2. Process Exec event
        elif "process_exec" in raw:
            exec_event = raw["process_exec"]
            proc = exec_event.get("process", {})
            bin_name = proc.get("binary", "")
            args_str = proc.get("arguments", "")
            uid = proc.get("uid", 0)
            ts = raw.get("time", _now())

            # Check if execution involves suspicious binaries or arguments
            is_suspicious = any(b in bin_name for b in self.SUSPICIOUS_BINARIES) and uid != 0

            return {
                "event_id": f"tet_exec_{int(time.time()*1000)}_{self.events_read}",
                "domain": ObservationDomain.HOST.value,
                "state": ObservationState.SUSPICIOUS_ACTIVITY_OBSERVED.value if is_suspicious else ObservationState.NO_ACTIVITY_OBSERVED.value,
                "event_type": "process_execution",
                "process_binary": bin_name,
                "process_args": args_str,
                "pid": proc.get("pid"),
                "uid": uid,
                "target_scope": bin_name,
                "collected_at": ts,
                "confidence": "HIGH",
                "raw_event": raw,
            }

        return None

    def execute(self, request: TaskRequest, decision: PolicyDecision) -> TaskResult:
        started = _now()
        op = request.operation

        if op == "observer.tetragon.status":
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data=self.health(),
                observations=[f"Tetragon stream status: active={self._running}, read={self.events_read}"],
                started_at=started,
            )

        elif op == "observer.tetragon.stream":
            p = request.parameters
            path = p.get("log_path") or str(self.log_path)
            self.start_streaming(path)
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data={"streaming": True, "log_path": path},
                observations=["Tetragon stream tailing started"],
                started_at=started,
            )

        elif op == "observer.tetragon.stop":
            self.stop_streaming()
            return TaskResult(
                task_id=request.task_id,
                status=TaskStatus.SUCCEEDED,
                decision_ref=decision.decision_id,
                data={"streaming": False},
                observations=["Tetragon stream tailing stopped"],
                started_at=started,
            )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.FAILED,
            decision_ref=decision.decision_id,
            observations=[f"Unknown operation: {op}"],
            started_at=started,
        )
