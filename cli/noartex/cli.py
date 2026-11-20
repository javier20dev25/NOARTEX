#!/usr/bin/env python3
"""
NOARTEX CLI — Defensive Coordination Infrastructure
Punto de entrada para agentes humanos y de IA.

Usage:
    noartex --help
    noartex doctor [--format json|table]
    noartex capabilities [--domain DOMAIN] [--format json|table]
    noartex session create --agent AGENT_ID [--type TYPE] [--ttl SECONDS]
    noartex session list [--agent AGENT_ID] [--format json|table]
    noartex session show SESSION_ID [--format json]
    noartex session close SESSION_ID
    noartex task submit --session SESSION_ID --operation OP [--params JSON]
    noartex task status TASK_ID
    noartex task result TASK_ID [--format json]
    noartex audit query [--task TASK_ID] [--session SESSION_ID] [--limit N] [--format json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Ajustar path para importar desde el proyecto
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from adapters.defense_lab import DefenseLabAdapter
from adapters.observer_agent.adapter import AgentObserverAdapter
from adapters.observer_host.adapter import HostObserverAdapter
from adapters.observer_web.adapter import WebObserverAdapter
from adapters.sentinel_cli.adapter import SentinelCLIAdapter
from core.audit.store import AuditLog
from core.contracts.models import ActorIdentity, AgentType
from core.discovery.registry import CapabilityRegistry
from core.intelligence import IncidentStore
from core.orchestrator import Orchestrator
from core.policy import ApprovalManager, ExecutionMode, KillSwitchManager, PolicyEngine
from core.session.manager import SessionManager

# ---------------------------------------------------------------------------
# Configuración de paths
# ---------------------------------------------------------------------------
NOARTEX_DATA_DIR = Path(os.environ.get("NOARTEX_DATA_DIR", Path.home() / ".noartex"))
AUDIT_LOG_PATH = NOARTEX_DATA_DIR / "audit.jsonl"

VERSION = "0.6.0-m6"
CONTRACT_VERSION = "1.0"


def _build_orchestrator(execution_mode: ExecutionMode = ExecutionMode.MANUAL) -> Orchestrator:
    NOARTEX_DATA_DIR.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(AUDIT_LOG_PATH)
    sessions = SessionManager(data_dir=NOARTEX_DATA_DIR)
    registry = CapabilityRegistry()
    # Registrar adaptadores M2, M3 y M6
    registry.register_adapter(SentinelCLIAdapter())
    registry.register_adapter(HostObserverAdapter())
    registry.register_adapter(AgentObserverAdapter(audit_log=audit))
    registry.register_adapter(WebObserverAdapter())
    registry.register_adapter(DefenseLabAdapter())
    # M5 Policy managers
    approvals = ApprovalManager(data_dir=NOARTEX_DATA_DIR)
    killswitch = KillSwitchManager(data_dir=NOARTEX_DATA_DIR)
    policy = PolicyEngine(
        execution_mode=execution_mode,
        approval_manager=approvals,
        killswitch_manager=killswitch,
    )
    incidents = IncidentStore(data_dir=NOARTEX_DATA_DIR)
    return Orchestrator(audit, sessions, registry, policy, incident_store=incidents)


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    sep = "  "
    header_line = sep.join(h.ljust(widths[i]) for i, h in enumerate(headers))
    divider = sep.join("-" * w for w in widths)
    print(header_line)
    print(divider)
    for row in rows:
        print(sep.join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)))


# ---------------------------------------------------------------------------
# Subcomandos
# ---------------------------------------------------------------------------

def cmd_doctor(args, orch: Orchestrator):
    """noartex doctor — health check del sistema."""
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    result = orch.task_submit(
        operation="core.doctor.health",
        actor=actor,
        session_id=sess["session_id"],
    )
    health = result.get("data", {})
    if args.format == "json":
        _print_json(health)
    else:
        overall = health.get("overall", "unknown")
        print(f"\n🛡  NOARTEX Doctor — v{VERSION}")
        print(f"   Overall status: {overall.upper()}\n")
        components = health.get("components", {})
        rows = [[k, v.get("status", "?"), str({kk: vv for kk, vv in v.items() if kk != "status"})]
                for k, v in components.items()]
        _print_table(["Component", "Status", "Details"], rows)
        limitations = health.get("limitations", [])
        if limitations:
            print("\n⚠  Limitations:")
            for lim in limitations:
                print(f"   • {lim}")
        print()


def cmd_capabilities(args, orch: Orchestrator):
    """noartex capabilities — lista capacidades registradas."""
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    params = {}
    if args.domain:
        params["query"] = {"domain": args.domain}
    result = orch.task_submit(
        operation="core.capabilities.list",
        actor=actor,
        session_id=sess["session_id"],
        parameters=params,
    )
    caps = result.get("data", {}).get("capabilities", [])
    if args.format == "json":
        _print_json({"capabilities": caps, "total": len(caps)})
    else:
        print(f"\n🔍  NOARTEX Capabilities ({len(caps)} registered)\n")
        rows = [
            [c["capability_id"], c["version"], c["risk"], c["availability"], c["domain"]]
            for c in caps
        ]
        _print_table(["Capability ID", "Version", "Risk", "Status", "Domain"], rows)
        print()


def cmd_session_create(args, orch: Orchestrator):
    agent = args.agent
    atype = getattr(args, "type", "unknown") or "unknown"
    ttl = getattr(args, "ttl", 3600) or 3600
    sess = orch.session_create(agent_id=agent, agent_type=atype, ttl_seconds=int(ttl))
    if getattr(args, "format", "table") == "json":
        _print_json(sess)
    else:
        print(f"\n✅  Session created")
        print(f"   session_id  : {sess['session_id']}")
        print(f"   agent_id    : {sess['agent_id']}")
        print(f"   agent_type  : {sess['agent_type']}")
        print(f"   state       : {sess['state']}")
        print(f"   expires_at  : {sess['expires_at']}")
        print()


def cmd_session_list(args, orch: Orchestrator):
    agent = getattr(args, "agent", None)
    sessions = orch.session_list(agent)
    if getattr(args, "format", "table") == "json":
        _print_json({"sessions": sessions, "total": len(sessions)})
    else:
        print(f"\n📋  Sessions ({len(sessions)})\n")
        rows = [[s["session_id"], s["agent_id"], s["agent_type"], s["state"], s["expires_at"] or ""]
                for s in sessions]
        _print_table(["Session ID", "Agent", "Type", "State", "Expires"], rows)
        print()


def cmd_session_show(args, orch: Orchestrator):
    sess = orch.session_show(args.session_id)
    if not sess:
        print(f"Session '{args.session_id}' not found.", file=sys.stderr)
        sys.exit(1)
    _print_json(sess)


def cmd_session_close(args, orch: Orchestrator):
    ok = orch.session_close(args.session_id, actor_id="cli:operator")
    if ok:
        print(f"✅  Session {args.session_id} closed.")
    else:
        print(f"❌  Session {args.session_id} not found.", file=sys.stderr)
        sys.exit(1)


def cmd_task_submit(args, orch: Orchestrator):
    if not orch.sessions.is_active(args.session):
        print(f"❌  Session '{args.session}' is not active.", file=sys.stderr)
        sys.exit(1)
    params = {}
    if args.params:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            print(f"❌  Invalid JSON in --params: {e}", file=sys.stderr)
            sys.exit(1)
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    result = orch.task_submit(
        operation=args.operation,
        actor=actor,
        session_id=args.session,
        parameters=params,
    )
    _print_json(result)


def cmd_task_status(args, orch: Orchestrator):
    status = orch.task_status(args.task_id)
    if not status:
        print(f"Task '{args.task_id}' not found (tasks are in-memory; restart loses them).",
              file=sys.stderr)
        sys.exit(1)
    _print_json(status)


def cmd_task_result(args, orch: Orchestrator):
    result = orch.task_result(args.task_id)
    if not result:
        print(f"Task '{args.task_id}' not found.", file=sys.stderr)
        sys.exit(1)
    _print_json(result)


def cmd_audit_query(args, orch: Orchestrator):
    records = orch.audit.query(
        task_id=getattr(args, "task", None),
        session_id=getattr(args, "session", None),
        actor_id=getattr(args, "actor", None),
        event_type=getattr(args, "event_type", None),
        limit=getattr(args, "limit", 50),
    )
    if getattr(args, "format", "json") == "json":
        _print_json({"records": records, "count": len(records)})
    else:
        print(f"\n📝  Audit Log ({len(records)} records)\n")
        rows = [[str(r["seq"]), r["event_type"], r["timestamp"][:19],
                 r.get("actor_id") or "", r.get("task_id") or ""]
                for r in records]
        _print_table(["Seq", "Event", "Timestamp", "Actor", "Task ID"], rows)
        print()


def cmd_incident_list(args, orch: Orchestrator):
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    params = {}
    if getattr(args, "state", None):
        params["state"] = args.state
    if getattr(args, "severity", None):
        params["severity"] = args.severity
    res = orch.task_submit(
        operation="intelligence.incident.list",
        actor=actor,
        session_id=sess["session_id"],
        parameters=params,
    )
    incs = res.get("data", {}).get("incidents", [])
    if getattr(args, "format", "table") == "json":
        _print_json({"incidents": incs, "count": len(incs)})
    else:
        print(f"\n🚨  Security Incidents ({len(incs)})\n")
        rows = [
            [i["incident_id"], i["title"][:30], i["state"], i["severity"], i.get("owner") or "unassigned"]
            for i in incs
        ]
        _print_table(["Incident ID", "Title", "State", "Severity", "Owner"], rows)
        print()


def cmd_incident_show(args, orch: Orchestrator):
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    res = orch.task_submit(
        operation="intelligence.incident.show",
        actor=actor,
        session_id=sess["session_id"],
        parameters={"incident_id": args.incident_id},
    )
    inc = res.get("data", {}).get("incident")
    if not inc:
        print(f"Incident '{args.incident_id}' not found.")
        sys.exit(1)
    _print_json(inc)


def cmd_incident_create(args, orch: Orchestrator):
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    params = {
        "title": args.title,
        "severity": getattr(args, "severity", "MEDIUM") or "MEDIUM",
        "owner": getattr(args, "owner", None) or "cli:operator",
    }
    res = orch.task_submit(
        operation="intelligence.incident.create",
        actor=actor,
        session_id=sess["session_id"],
        parameters=params,
    )
    inc = res.get("data", {}).get("incident")
    if getattr(args, "format", "table") == "json":
        _print_json(inc)
    else:
        print(f"\n✅  Incident created: {inc['incident_id']}")
        print(f"   Title   : {inc['title']}")
        print(f"   Severity: {inc['severity']}")
        print(f"   State   : {inc['state']}\n")


def cmd_triage_evaluate(args, orch: Orchestrator):
    actor = ActorIdentity(agent_id="cli:operator", agent_type=AgentType.HUMAN)
    sess = orch.session_create(agent_id="cli:operator", agent_type="human", ttl_seconds=60)
    params = {"incident_id": args.incident_id}
    res = orch.task_submit(
        operation="intelligence.triage.evaluate",
        actor=actor,
        session_id=sess["session_id"],
        parameters=params,
    )
    verdict = res.get("data", {}).get("verdict")
    if not verdict:
        print(f"Triage evaluation failed or incident '{args.incident_id}' not found.")
        sys.exit(1)
    if getattr(args, "format", "json") == "json":
        _print_json(verdict)
    else:
        print(f"\n⚖️  Triage Verdict — {verdict['verdict_id']}")
        print(f"   Incident      : {verdict['incident_id']}")
        print(f"   Classification: {verdict['classification']}")
        print(f"   Confidence    : {verdict['confidence']}")
        print(f"   Severity      : {verdict['severity']}")
        print(f"   Summary       : {verdict['summary']}\n")


# ---------------------------------------------------------------------------
# Parser principal
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noartex",
        description=(
            f"NOARTEX v{VERSION} — Defensive Coordination Infrastructure\n"
            f"Contract version: {CONTRACT_VERSION}\n\n"
            "Converts AI agents into governed defensive operators.\n"
            "The agent thinks. NOARTEX provides capabilities and governs execution.\n\n"
            "Available commands:\n"
            "  doctor        Health check of NOARTEX core components\n"
            "  capabilities  List registered capabilities\n"
            "  session       Manage agent sessions (create/list/show/close)\n"
            "  task          Submit and query tasks (submit/status/result)\n"
            "  audit         Query the append-only audit log\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"noartex {VERSION}")
    parser.add_argument(
        "--data-dir",
        default=str(NOARTEX_DATA_DIR),
        help="NOARTEX data directory (default: ~/.noartex)",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # doctor
    p_doc = sub.add_parser("doctor", help="Health check of NOARTEX components")
    p_doc.add_argument("--format", choices=["json", "table"], default="table")

    # capabilities
    p_cap = sub.add_parser("capabilities", help="List registered capabilities")
    p_cap.add_argument("--domain", help="Filter by domain")
    p_cap.add_argument("--format", choices=["json", "table"], default="table")

    # session
    p_sess = sub.add_parser("session", help="Manage agent sessions")
    sess_sub = p_sess.add_subparsers(dest="session_cmd", metavar="SUBCOMMAND")

    p_sc = sess_sub.add_parser("create", help="Create a new session")
    p_sc.add_argument("--agent", required=True, help="Agent ID (e.g. opencode:local)")
    p_sc.add_argument("--type", default="unknown", dest="type",
                      help="Agent type: codex|claude|opencode|antigravity|human|service")
    p_sc.add_argument("--ttl", type=int, default=3600, help="TTL in seconds (default: 3600)")
    p_sc.add_argument("--format", choices=["json", "table"], default="table")

    p_sl = sess_sub.add_parser("list", help="List sessions")
    p_sl.add_argument("--agent", help="Filter by agent ID")
    p_sl.add_argument("--format", choices=["json", "table"], default="table")

    p_ss = sess_sub.add_parser("show", help="Show a session")
    p_ss.add_argument("session_id", help="Session ID")

    p_sc2 = sess_sub.add_parser("close", help="Close a session")
    p_sc2.add_argument("session_id", help="Session ID")

    # task
    p_task = sub.add_parser("task", help="Submit and query tasks")
    task_sub = p_task.add_subparsers(dest="task_cmd", metavar="SUBCOMMAND")

    p_ts = task_sub.add_parser("submit", help="Submit a task")
    p_ts.add_argument("--session", required=True, help="Session ID")
    p_ts.add_argument("--operation", required=True, help="Operation (e.g. core.capabilities.list)")
    p_ts.add_argument("--params", help="Parameters as JSON string")

    p_tst = task_sub.add_parser("status", help="Query task status")
    p_tst.add_argument("task_id", help="Task ID")

    p_tr = task_sub.add_parser("result", help="Get task result")
    p_tr.add_argument("task_id", help="Task ID")

    # audit
    p_audit = sub.add_parser("audit", help="Query the audit log")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd", metavar="SUBCOMMAND")

    p_aq = audit_sub.add_parser("query", help="Query audit events")
    p_aq.add_argument("--task", help="Filter by task_id")
    p_aq.add_argument("--session", help="Filter by session_id")
    p_aq.add_argument("--actor", help="Filter by actor_id")
    p_aq.add_argument("--event-type", dest="event_type", help="Filter by event type")
    p_aq.add_argument("--limit", type=int, default=50, help="Max records (default: 50)")
    p_aq.add_argument("--format", choices=["json", "table"], default="json")

    # incident
    p_inc = sub.add_parser("incident", help="Manage security incidents")
    inc_sub = p_inc.add_subparsers(dest="incident_cmd", metavar="SUBCOMMAND")

    p_il = inc_sub.add_parser("list", help="List incidents")
    p_il.add_argument("--state", help="Filter by state (OPEN|INVESTIGATING|CONTAINED|CLOSED)")
    p_il.add_argument("--severity", help="Filter by severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)")
    p_il.add_argument("--format", choices=["json", "table"], default="table")

    p_is = inc_sub.add_parser("show", help="Show an incident")
    p_is.add_argument("incident_id", help="Incident ID")

    p_ic = inc_sub.add_parser("create", help="Create a new incident")
    p_ic.add_argument("--title", required=True, help="Incident title")
    p_ic.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="MEDIUM")
    p_ic.add_argument("--owner", help="Owner / Assigned agent ID")
    p_ic.add_argument("--format", choices=["json", "table"], default="table")

    # triage
    p_trg = sub.add_parser("triage", help="Run deterministic triage evaluation")
    trg_sub = p_trg.add_subparsers(dest="triage_cmd", metavar="SUBCOMMAND")

    p_te = trg_sub.add_parser("evaluate", help="Evaluate incident and produce triage verdict")
    p_te.add_argument("--incident", dest="incident_id", required=True, help="Incident ID to evaluate")
    p_te.add_argument("--format", choices=["json", "table"], default="table")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Configurar data dir si se pasó como arg
    global AUDIT_LOG_PATH, NOARTEX_DATA_DIR
    if hasattr(args, "data_dir") and args.data_dir:
        NOARTEX_DATA_DIR = Path(args.data_dir)
        AUDIT_LOG_PATH = NOARTEX_DATA_DIR / "audit.jsonl"

    orch = _build_orchestrator()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Routing de comandos
    if args.command == "doctor":
        cmd_doctor(args, orch)
    elif args.command == "capabilities":
        cmd_capabilities(args, orch)
    elif args.command == "session":
        if args.session_cmd == "create":
            cmd_session_create(args, orch)
        elif args.session_cmd == "list":
            cmd_session_list(args, orch)
        elif args.session_cmd == "show":
            cmd_session_show(args, orch)
        elif args.session_cmd == "close":
            cmd_session_close(args, orch)
        else:
            p_sess = [a for a in parser._subparsers._group_actions
                      if a.choices and "session" in a.choices]
            parser.parse_args(["session", "--help"])
    elif args.command == "task":
        if args.task_cmd == "submit":
            cmd_task_submit(args, orch)
        elif args.task_cmd == "status":
            cmd_task_status(args, orch)
        elif args.task_cmd == "result":
            cmd_task_result(args, orch)
        else:
            parser.parse_args(["task", "--help"])
    elif args.command == "audit":
        if args.audit_cmd == "query":
            cmd_audit_query(args, orch)
        else:
            parser.parse_args(["audit", "--help"])
    elif args.command == "incident":
        if args.incident_cmd == "list":
            cmd_incident_list(args, orch)
        elif args.incident_cmd == "show":
            cmd_incident_show(args, orch)
        elif args.incident_cmd == "create":
            cmd_incident_create(args, orch)
        else:
            parser.parse_args(["incident", "--help"])
    elif args.command == "triage":
        if args.triage_cmd == "evaluate":
            cmd_triage_evaluate(args, orch)
        else:
            parser.parse_args(["triage", "--help"])
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
