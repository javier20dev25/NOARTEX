"""
NOARTEX — Web & Domain Observer Adapter (M3-B)
Observación de recursos web autorizados:
- Inspección de cabeceras HTTP, códigos de estado, redirecciones.
- Resolución DNS e indicadores de reputación/seguridad externa.
Invariante: Observa metadatos y superficie autorizada, sin vulnerar controles de acceso.
"""
from __future__ import annotations

import socket
import urllib.parse
import urllib.request
from datetime import datetime, timezone
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


class WebObserverAdapter(AdapterInterface):
    DEFAULT_METADATA = AdapterMetadata(
        adapter_id="adapter.observer.web",
        name="Web & Network Resource Observer",
        version="1.0.0",
        provenance="standard urllib / socket",
        license="MIT",
        author="NOARTEX Core Team",
        description="Inspects authorized web endpoints, HTTP headers, redirects, and DNS metadata",
        limits=AdapterLimits(
            timeout_seconds=15,
            max_output_bytes=1 * 1024 * 1024,
            allowed_target_roots=[],
            allow_network=True,
            allow_subprocesses=False,
        ),
    )

    def __init__(self, metadata: Optional[AdapterMetadata] = None):
        super().__init__(metadata or self.DEFAULT_METADATA)

    def describe_capabilities(self) -> list[Capability]:
        return [
            Capability(
                capability_id="observer.web.headers",
                version="1.0.0",
                domain="observer",
                operations=["inspect"],
                risk=RiskLevel.R0,
                description="Inspect HTTP response headers, security flags (HSTS, CSP), and status code",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
            Capability(
                capability_id="observer.web.dns",
                version="1.0.0",
                domain="observer",
                operations=["lookup"],
                risk=RiskLevel.R0,
                description="Resolve IP addresses and basic DNS metadata for authorized domain",
                availability=AvailabilityStatus.AVAILABLE,
                adapter_id=self.metadata.adapter_id,
            ),
        ]

    def health(self) -> dict[str, Any]:
        return {
            "adapter_id": self.metadata.adapter_id,
            "status": AdapterStatus.AVAILABLE.value,
            "version": self.metadata.version,
            "limitations": [],
        }

    def execute(self, request: TaskRequest, decision: PolicyDecision) -> TaskResult:
        started = datetime.now(timezone.utc).isoformat()
        op = request.operation
        params = request.parameters or {}

        if op == "observer.web.dns":
            host = params.get("host")
            if not host:
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.DENIED,
                    decision_ref=decision.decision_id,
                    observations=["Missing 'host' parameter for DNS lookup"],
                    started_at=started,
                )
            try:
                ips = socket.gethostbyname_ex(host)[2]
                obs_event = ObservationEvent(
                    domain=ObservationDomain.WEB,
                    event_type="dns_lookup",
                    state=ObservationState.NO_ACTIVITY_OBSERVED,
                    target_scope=host,
                    coverage={"addresses_resolved": len(ips)},
                    data={"host": host, "resolved_ips": ips},
                    evidence=[{"type": "dns_record", "host": host, "ips": ips}],
                )
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.SUCCEEDED,
                    decision_ref=decision.decision_id,
                    data={"observation": obs_event.to_dict()},
                    evidence=obs_event.evidence,
                    observations=[f"Resolved {len(ips)} IP addresses for '{host}'"],
                    started_at=started,
                )
            except Exception as e:
                obs_event = ObservationEvent(
                    domain=ObservationDomain.WEB,
                    event_type="dns_lookup",
                    state=ObservationState.DEGRADED,
                    target_scope=host,
                    limitations=[f"DNS resolution failed: {e}"],
                    data={"host": host, "error": str(e)},
                )
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.DEGRADED,
                    decision_ref=decision.decision_id,
                    data={"observation": obs_event.to_dict()},
                    observations=[f"DNS lookup failed for '{host}': {e}"],
                    limitations=["Host unreachable or resolution failed"],
                    started_at=started,
                )

        elif op == "observer.web.headers":
            url = params.get("url")
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.DENIED,
                    decision_ref=decision.decision_id,
                    observations=["Invalid or missing 'url' parameter (http/https required)"],
                    started_at=started,
                )
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "NOARTEX-Observer/1.0"},
                    method="HEAD",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    headers = dict(resp.headers)
                    status_code = resp.status
                    obs_event = ObservationEvent(
                        domain=ObservationDomain.WEB,
                        event_type="http_headers",
                        state=ObservationState.NO_ACTIVITY_OBSERVED,
                        target_scope=url,
                        coverage={"status_code": status_code},
                        data={"url": url, "status_code": status_code, "headers": headers},
                        evidence=[{"type": "http_response", "status": status_code}],
                    )
                    return TaskResult(
                        task_id=request.task_id,
                        status=TaskStatus.SUCCEEDED,
                        decision_ref=decision.decision_id,
                        data={"observation": obs_event.to_dict()},
                        evidence=obs_event.evidence,
                        observations=[f"HTTP HEAD returned status {status_code}"],
                        started_at=started,
                    )
            except Exception as e:
                obs_event = ObservationEvent(
                    domain=ObservationDomain.WEB,
                    event_type="http_headers",
                    state=ObservationState.DEGRADED,
                    target_scope=url,
                    limitations=[f"HTTP request error: {e}"],
                    data={"url": url, "error": str(e)},
                )
                return TaskResult(
                    task_id=request.task_id,
                    status=TaskStatus.DEGRADED,
                    decision_ref=decision.decision_id,
                    data={"observation": obs_event.to_dict()},
                    observations=[f"HTTP inspection failed: {e}"],
                    limitations=["Endpoint unreachable or connection error"],
                    started_at=started,
                )

        return TaskResult(
            task_id=request.task_id,
            status=TaskStatus.DENIED,
            decision_ref=decision.decision_id,
            observations=[f"Unsupported web observer operation: '{op}'"],
            started_at=started,
        )
