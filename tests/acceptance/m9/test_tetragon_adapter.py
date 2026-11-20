"""
NOARTEX M9-B Acceptance Tests — Tetragon Streaming Adapter
Validates kernel-level eBPF stream processing, sensitive kprobe interception,
network connection tracking, and sub-100ms streaming latency.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(ROOT))

from adapters.tetragon_stream.adapter import TetragonStreamAdapter
from core.adapters.base import AdapterStatus


def run_tests() -> bool:
    print("=" * 75)
    print("  NOARTEX M9-B Acceptance Tests — Tetragon Streaming Adapter")
    print("=" * 75)

    passed = 0
    failed = 0

    def check(desc: str, condition: bool):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  \u2705 {desc}")
        else:
            failed += 1
            print(f"  \u274c FAIL: {desc}")

    temp_dir = tempfile.TemporaryDirectory()
    log_file = Path(temp_dir.name) / "tetragon_test.log"
    log_file.touch()

    captured_events = []
    def on_event(ev: dict):
        captured_events.append(ev)

    adapter = TetragonStreamAdapter(log_path=log_file, event_callback=on_event)

    # -------------------------------------------------------------------------
    # M9-B-T1: Start Streaming & Synthetic Event Ingestion
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T1: Streaming initialization and event ingestion ---")
    adapter.start_streaming()
    time.sleep(0.05)

    # Write synthetic process_exec event
    event_1 = {
        "process_exec": {
            "process": {"binary": "/usr/bin/whoami", "arguments": "", "pid": 1001, "uid": 0},
            "parent": {"binary": "/bin/bash"},
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:00:00Z",
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_1) + "\n")

    time.sleep(0.1)
    check("M9-B-T1: Tetragon adapter started streaming", adapter._running)
    check("M9-B-T1: First event received by callback", len(captured_events) >= 1)
    check("M9-B-T1: Captured process binary is /usr/bin/whoami", captured_events[0].get("process_binary") == "/usr/bin/whoami")

    # -------------------------------------------------------------------------
    # M9-B-T2: Security-Relevant Kprobe (/etc/shadow access)
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T2: Kprobe sensitive path interception ---")
    event_kprobe_shadow = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/python3", "arguments": "recon.py", "pid": 4510, "uid": 1001},
            "function_name": "do_sys_openat2",
            "args": [{"int_arg": 0}, {"string_arg": "/etc/shadow"}],
            "policy_name": "sentinel-runtime-observability",
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:00:01Z",
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_kprobe_shadow) + "\n")

    time.sleep(0.1)
    shadow_events = [e for e in captured_events if e.get("target_scope") == "/etc/shadow"]
    check("M9-B-T2: Sensitive /etc/shadow access intercepted", len(shadow_events) >= 1)
    if shadow_events:
        ev = shadow_events[0]
        check("M9-B-T2: Classified as SUSPICIOUS_ACTIVITY_OBSERVED", ev.get("state") == "SUSPICIOUS_ACTIVITY_OBSERVED")
        check("M9-B-T2: Tracked PID and UID correctly (4510 / 1001)", ev.get("pid") == 4510 and ev.get("uid") == 1001)

    # -------------------------------------------------------------------------
    # M9-B-T3: Network Connection Kprobe (tcp_v4_connect)
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T3: Network socket telemetry ---")
    event_net = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/dash", "arguments": "c2_connect.sh", "pid": 4511, "uid": 1001},
            "function_name": "tcp_v4_connect",
            "args": [{"sock_arg": {"family": "AF_INET"}}, {"sockaddr_arg": {"addr": "192.168.1.50", "port": 4444}}],
            "policy_name": "sentinel-runtime-observability",
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:00:02Z",
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_net) + "\n")

    time.sleep(0.1)
    net_events = [e for e in captured_events if "192.168.1.50:4444" in e.get("target_scope", "")]
    check("M9-B-T3: TCP connection event intercepted", len(net_events) >= 1)
    if net_events:
        ev = net_events[0]
        check("M9-B-T3: Domain mapped to network", ev.get("domain") == "network")
        check("M9-B-T3: Event type mapped to kprobe_tcp_v4_connect", ev.get("event_type") == "kprobe_tcp_v4_connect")

    # -------------------------------------------------------------------------
    # M9-B-T4: Real-Time Latency Benchmark (< 100ms from write to callback)
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T4: Streaming latency benchmark ---")
    benchmark_flag = {"arrived": False, "latency_ms": 0.0}
    benchmark_target = f"/srv/sentinel-enterprise-lab/secret_{int(time.time()*1000)}.txt"

    def latency_checker(ev: dict):
        if ev.get("target_scope") == benchmark_target:
            benchmark_flag["arrived"] = True

    adapter.callback = latency_checker
    event_bench = {
        "process_kprobe": {
            "process": {"binary": "/usr/bin/cat", "arguments": "read_secret", "pid": 4599, "uid": 1001},
            "function_name": "do_sys_openat2",
            "args": [{"int_arg": 0}, {"string_arg": benchmark_target}],
            "policy_name": "sentinel-runtime-observability",
        },
        "node_name": "lab-node",
        "time": "2026-11-20T02:00:03Z",
    }

    t_bench_start = time.perf_counter()
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_bench) + "\n")

    # Poll for arrival
    while not benchmark_flag["arrived"] and (time.perf_counter() - t_bench_start) < 1.0:
        time.sleep(0.005)

    latency_ms = (time.perf_counter() - t_bench_start) * 1000.0
    check("M9-B-T4: Benchmark event arrived at callback", benchmark_flag["arrived"])
    check(f"M9-B-T4: Streaming write-to-callback latency < 100ms (measured: {round(latency_ms, 2)}ms)", latency_ms < 100.0)

    # -------------------------------------------------------------------------
    # M9-B-T5: Health Reporting and Telemetry Metrics
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T5: Health and metrics verification ---")
    h = adapter.health()
    check("M9-B-T5: Health status is AVAILABLE", h.get("status") == AdapterStatus.AVAILABLE.value)
    check("M9-B-T5: Streaming active is True", h.get("streaming_active") is True)
    check("M9-B-T5: Events read count tracked (> 0)", h.get("events_read", 0) >= 4)
    check("M9-B-T5: Average parse latency tracked (< 10ms)", h.get("avg_parse_latency_ms", 0.0) < 10.0)

    # -------------------------------------------------------------------------
    # M9-B-T6: Clean Shutdown
    # -------------------------------------------------------------------------
    print("\n--- M9-B-T6: Stream shutdown ---")
    adapter.stop_streaming()
    check("M9-B-T6: Streaming thread stopped", not adapter._running)
    temp_dir.cleanup()

    print("\n" + "=" * 75)
    print(f"  M9-B Results: {passed}/{passed + failed} PASS  |  {failed} FAIL")
    print("=" * 75)
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
