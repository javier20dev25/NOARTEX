"""
NOARTEX — Reactive Event Bus
Thread-safe priority event bus for sub-millisecond asynchronous security dispatch.
"""
from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str = "evt") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class EventType(str, Enum):
    TELEMETRY_EVENT = "TELEMETRY_EVENT"
    OBSERVATION_EVENT = "OBSERVATION_EVENT"
    FINDING_EVENT = "FINDING_EVENT"
    CORRELATION_TRIGGER = "CORRELATION_TRIGGER"
    TRIAGE_TRIGGER = "TRIAGE_TRIGGER"
    CONTAINMENT_TRIGGER = "CONTAINMENT_TRIGGER"
    AUDIT_EVENT = "AUDIT_EVENT"


class EventPriority(int, Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass
class ReactiveEvent:
    event_type: EventType | str
    payload: dict[str, Any]
    event_id: str = field(default_factory=lambda: _new_id("evt"))
    source: str = "core"
    priority: EventPriority = EventPriority.MEDIUM
    timestamp: str = field(default_factory=_now)
    enqueue_time: float = field(default_factory=time.perf_counter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value if isinstance(self.event_type, EventType) else str(self.event_type),
            "source": self.source,
            "priority": self.priority.name if isinstance(self.priority, EventPriority) else str(self.priority),
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


class ReactiveEventBus:
    """
    Priority-aware, thread-safe asynchronous dispatcher.
    Ensures CRITICAL containment & kill signals preempt background telemetry.
    """

    def __init__(self, maxsize: int = 10000):
        self._queue: queue.PriorityQueue = queue.PriorityQueue(maxsize=maxsize)
        self._subscribers: dict[str, list[Callable[[ReactiveEvent], None]]] = {}
        self._lock = threading.RLock()
        self._worker_thread: Optional[threading.Thread] = None
        self._running = False
        self._seq = 0  # Monotonic counter for stable priority ordering

        # Metrics
        self._events_published = 0
        self._events_dispatched = 0
        self._total_dispatch_latency_ms = 0.0
        self._max_dispatch_latency_ms = 0.0
        self._last_dispatch_latency_ms = 0.0

    def subscribe(self, event_type: EventType | str, callback: Callable[[ReactiveEvent], None]) -> None:
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        with self._lock:
            if etype not in self._subscribers:
                self._subscribers[etype] = []
            if callback not in self._subscribers[etype]:
                self._subscribers[etype].append(callback)

    def unsubscribe(self, event_type: EventType | str, callback: Callable[[ReactiveEvent], None]) -> bool:
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        with self._lock:
            if etype in self._subscribers and callback in self._subscribers[etype]:
                self._subscribers[etype].remove(callback)
                return True
        return False

    def publish(self, event: ReactiveEvent) -> str:
        priority_val = event.priority.value if isinstance(event.priority, EventPriority) else int(event.priority)
        with self._lock:
            self._seq += 1
            seq = self._seq
            self._events_published += 1

        self._queue.put((priority_val, seq, event), block=False)
        return event.event_id

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._worker_thread = threading.Thread(target=self._dispatch_loop, daemon=True, name="noartex-event-bus")
            self._worker_thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

    def drain(self, timeout: float = 3.0) -> bool:
        """Drains all remaining events in queue up to timeout."""
        start_t = time.perf_counter()
        while not self._queue.empty():
            if time.perf_counter() - start_t > timeout:
                return False
            time.sleep(0.01)
        return True

    def _dispatch_loop(self) -> None:
        while self._running or not self._queue.empty():
            try:
                priority_val, seq, event = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue

            dispatch_start = time.perf_counter()
            latency_ms = (dispatch_start - event.enqueue_time) * 1000.0

            etype = event.event_type.value if isinstance(event.event_type, EventType) else str(event.event_type)
            with self._lock:
                callbacks = list(self._subscribers.get(etype, []))
                # Also wildcards if any
                callbacks.extend(self._subscribers.get("*", []))

            for cb in callbacks:
                try:
                    cb(event)
                except Exception as exc:
                    # Invariant: subscriber exceptions must not crash event bus
                    pass

            with self._lock:
                self._events_dispatched += 1
                self._last_dispatch_latency_ms = latency_ms
                self._total_dispatch_latency_ms += latency_ms
                if latency_ms > self._max_dispatch_latency_ms:
                    self._max_dispatch_latency_ms = latency_ms

            self._queue.task_done()

    def get_metrics(self) -> dict[str, Any]:
        with self._lock:
            dispatched = self._events_dispatched
            avg_latency = (self._total_dispatch_latency_ms / dispatched) if dispatched > 0 else 0.0
            return {
                "running": self._running,
                "events_published": self._events_published,
                "events_dispatched": dispatched,
                "queue_size": self._queue.qsize(),
                "avg_dispatch_latency_ms": round(avg_latency, 3),
                "max_dispatch_latency_ms": round(self._max_dispatch_latency_ms, 3),
                "last_dispatch_latency_ms": round(self._last_dispatch_latency_ms, 3),
            }
