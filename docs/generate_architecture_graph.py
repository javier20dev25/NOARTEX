import json
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "architecture_graph.json"

def build_graph():
    nodes = []
    edges = []

    def add_node(id_, type_, label, path=None, **extra):
        n = {"id": id_, "type": type_, "label": label}
        if path:
            n["path"] = path
        n.update(extra)
        nodes.append(n)

    def add_edge(src, dst, rel, **extra):
        e = {"from": src, "to": dst, "relation": rel}
        e.update(extra)
        edges.append(e)

    add_node("layer.interface", "layer", "Interface", description="CLI entrypoints and agent skill surfaces")
    add_node("layer.core", "layer", "Core", description="Contracts, orchestration, policy, sessions, audit, discovery, intelligence, memory")
    add_node("layer.adapters", "layer", "Adapters", description="Tool and environment integrations behind AdapterInterface")
    add_node("layer.schemas", "layer", "Schemas", description="Validation schemas")
    add_node("layer.tests", "layer", "Acceptance Tests", description="M1-M8 acceptance suites (lab/prototype evidence)")
    add_node("layer.skills", "layer", "Skills", description="Canonical and coordination skills for agent usage")
    add_node("layer.state", "layer", "Runtime State (local)", description="~/.noartex and data dirs, not release artifacts", external=True)

    for nid, label, path in [
        ("mod.launcher", "Global launcher (.cmd)", "C:/Users/sleyt/.gemini/antigravity/bin/noartex.cmd"),
        ("mod.entry", "Python entry wrapper", "noartex.py"),
        ("mod.cli", "CLI implementation", "cli/noartex/cli.py"),
    ]:
        add_node(nid, "module", label, path=path)
        add_edge("layer.interface", nid, "contains")

    for nid, label, path in [
        ("mod.contracts", "Contracts and Models", "core/contracts/models.py"),
        ("mod.orchestrator", "Orchestrator", "core/orchestrator.py"),
        ("mod.registry", "Capability Registry", "core/discovery/registry.py"),
        ("mod.policy", "Policy Engine", "core/policy/engine.py"),
        ("mod.approval", "Approvals", "core/policy/approval.py"),
        ("mod.killswitch", "Kill Switch", "core/policy/killswitch.py"),
        ("mod.session", "Session Manager", "core/session/manager.py"),
        ("mod.audit", "Audit Store (JSONL)", "core/audit/store.py"),
        ("mod.intel", "Intelligence", "core/intelligence/"),
        ("mod.memory", "Memory and Case Manager", "core/memory/case_manager.py"),
        ("mod.adapter_base", "Adapter Interface", "core/adapters/base.py"),
    ]:
        add_node(nid, "module", label, path=path)
        add_edge("layer.core", nid, "contains")

    adapters = [
        ("adapter.sentinel.cli", "Sentinel CLI Adapter", "adapters/sentinel_cli/adapter.py", "AVAILABLE", ["sentinel.sast.scan", "sentinel.cicd.audit", "sentinel.supply_chain.audit", "sentinel.report.generate"]),
        ("adapter.observer.host", "Host Observer", "adapters/observer_host/adapter.py", "AVAILABLE", ["observer.host.processes", "observer.host.files", "observer.host.network"]),
        ("adapter.observer.agent", "Agent Observer", "adapters/observer_agent/adapter.py", "AVAILABLE", ["observer.agent.activity", "observer.agent.denials"]),
        ("adapter.observer.web", "Web Observer", "adapters/observer_web/adapter.py", "AVAILABLE", ["observer.web.headers", "observer.web.dns"]),
        ("adapter.defense.lab", "Defense Lab", "adapters/defense_lab/adapter.py", "AVAILABLE", ["defense.artifact.quarantine", "defense.artifact.tag", "defense.host.isolate", "defense.host.remediate", "defense.action.rollback"]),
    ]
    for aid, label, path, status, caps in adapters:
        add_node(aid, "adapter", label, path=path, status=status, capabilities=caps)
        add_edge("layer.adapters", aid, "contains")
        add_edge("mod.registry", aid, "registers")
        add_edge("mod.orchestrator", aid, "dispatches_to")

    domains = {
        "core": ["core.capabilities.list", "core.capabilities.describe", "core.doctor.health", "core.session.create", "core.session.list", "core.session.show", "core.session.close", "core.task.status", "core.task.result", "core.audit.query"],
        "intelligence": ["intelligence.correlate", "intelligence.incident.create", "intelligence.incident.update", "intelligence.incident.show", "intelligence.incident.list", "intelligence.triage.evaluate"],
        "policy": ["policy.status", "policy.approval.grant", "policy.approval.revoke", "policy.approvals.list", "policy.killswitch.activate", "policy.killswitch.deactivate", "policy.session.revoke"],
        "observer": ["observer.host.processes", "observer.host.files", "observer.host.network", "observer.agent.activity", "observer.agent.denials", "observer.web.headers", "observer.web.dns"],
        "sentinel": ["sentinel.sast.scan", "sentinel.cicd.audit", "sentinel.supply_chain.audit", "sentinel.report.generate"],
        "defense": ["defense.artifact.quarantine", "defense.artifact.tag", "defense.host.isolate", "defense.host.remediate", "defense.action.rollback"],
        "memory": ["memory.case.create", "memory.case.show", "memory.case.list", "memory.note.add", "memory.followup.add", "memory.followup.update", "memory.followup.list", "memory.export", "memory.retention", "memory.evidence.add", "memory.followup.overdue"],
    }
    for dom, caps in domains.items():
        did = f"domain.{dom}"
        add_node(did, "capability_domain", dom, count=len(caps), capabilities=caps)
        add_edge("mod.registry", did, "exposes")

    add_edge("mod.launcher", "mod.entry", "invokes")
    add_edge("mod.entry", "mod.cli", "calls_main")
    add_edge("mod.cli", "mod.orchestrator", "routes_commands")
    add_edge("mod.orchestrator", "mod.policy", "evaluates")
    add_edge("mod.orchestrator", "mod.session", "validates")
    add_edge("mod.orchestrator", "mod.audit", "records")
    add_edge("mod.orchestrator", "mod.registry", "resolves_capabilities")
    add_edge("mod.orchestrator", "mod.intel", "invokes")
    add_edge("mod.orchestrator", "mod.memory", "invokes")
    add_edge("layer.schemas", "mod.intel", "validates", path="schemas/triage_verdict.json")

    skills = [
        ("skill.canonical", "Canonical NOARTEX skill", "skills/canonical/SKILL.md", False),
        ("skill.portable", "Portable NOARTEX skill (external copy)", "C:/Users/sleyt/.agents/skills/noartex/SKILL.md", True),
        ("skill.coord.runtime", "Coordination: Sentinel Runtime", "skills/coordination/sentinel-runtime/SKILL.md", False),
        ("skill.coord.audit", "Coordination: Sentinel Audit", "skills/coordination/sentinel-audit/SKILL.md", False),
        ("skill.coord.oracle", "Coordination: Sentinel Oracle", "skills/coordination/sentinel-oracle/SKILL.md", False),
        ("skill.coord.cloud_usage", "Usage: Sentinel Cloud via Sentinel CLI", "skills/coordination/sentinel-cloud-usage/SKILL.md", False),
    ]
    for sid, label, path, external in skills:
        add_node(sid, "skill", label, path=path, external=external)
        add_edge("layer.skills", sid, "contains")

    ecosystem = [
        ("ext.sentinel.cli", "Sentinel CLI", "integrated", "Installed binary; invoked by adapter.sentinel.cli subprocess. May use user-configured Sentinel Cloud features if user enabled them in CLI."),
        ("ext.sentinel.runtime", "Sentinel Runtime", "coordination-skill-only", "Separate project/service. No in-tree NOARTEX adapter."),
        ("ext.sentinel.audit", "Sentinel Audit", "coordination-skill-only", "Separate project. No in-tree NOARTEX adapter."),
        ("ext.sentinel.oracle", "Sentinel Oracle", "coordination-skill-only", "Separate merge-authorization enclave. No in-tree NOARTEX adapter."),
        ("ext.sentinel.cloud", "Sentinel Cloud", "usage-skill-only", "External service. NO Sentinel Cloud code in NOARTEX. Usage possible through Sentinel CLI if user has API key/config."),
        ("ext.artex", "ARTEX", "context-only", "Adversarial/context reference. Execution not performed. No active-defense certification."),
    ]
    for eid, label, status, note in ecosystem:
        add_node(eid, "external", label, integration=status, note=note)
    add_edge("adapter.sentinel.cli", "ext.sentinel.cli", "invokes_subprocess")
    add_edge("skill.coord.runtime", "ext.sentinel.runtime", "guides_coordination")
    add_edge("skill.coord.audit", "ext.sentinel.audit", "guides_coordination")
    add_edge("skill.coord.oracle", "ext.sentinel.oracle", "guides_coordination")
    add_edge("skill.coord.cloud_usage", "ext.sentinel.cloud", "guides_usage_via_sentinel_cli")

    return {
        "meta": {
            "product": "NOARTEX",
            "declared_release_target": "v0.8.0-m8",
            "observed_cli_version": "0.6.0-m6",
            "observed_core_version_doctor": "1.0.0-m1",
            "contract_version": "1.0",
            "capabilities_total_observed": 50,
            "adapters_observed": 5,
            "status": "prototype-lab; release identity not frozen",
            "purpose": "Compact machine-readable architecture graph for AI agents",
        },
        "nodes": nodes,
        "edges": edges,
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()
    graph = build_graph()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {out} ({len(graph['nodes'])} nodes, {len(graph['edges'])} edges)")

if __name__ == "__main__":
    main()
