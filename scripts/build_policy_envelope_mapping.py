#!/usr/bin/env python3
"""Build a policy-envelope map from Bitcoin fossils to Litecoin live isomorphisms."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OVERLAY_JSON = ROOT / "artifacts" / "grants" / "overlay_hook_summary.json"
DEFAULT_CARRIER_BENCH_JSON = ROOT / "artifacts" / "grants" / "overlay_carrier_bench_2013.json"
DEFAULT_TRANSCRIPT_JSON = (
    ROOT
    / "artifacts"
    / "litecoin-bitvm"
    / "procedural"
    / "2026-04-17-procedural-transcript-c"
    / "run-summary.json"
)
DEFAULT_IDENTIFIER_JSON = (
    ROOT
    / "artifacts"
    / "litecoin-bitvm"
    / "procedural"
    / "2026-04-17-procedural-identifier-a"
    / "run-summary.json"
)
DEFAULT_RECEIPT_JSON = (
    ROOT
    / "artifacts"
    / "litecoin-bitvm"
    / "procedural"
    / "2026-04-17-procedural-receipt-e"
    / "run-summary.json"
)
DEFAULT_ROUTER_JSON = (
    ROOT
    / "artifacts"
    / "litecoin-bitvm"
    / "procedural"
    / "2026-04-17-procedural-router-a"
    / "run-summary.json"
)
DEFAULT_HYBRID_JSON = (
    ROOT
    / "artifacts"
    / "litecoin-bitvm"
    / "procedural"
    / "2026-04-17-procedural-hybrid-a"
    / "run-summary.json"
)
DEFAULT_TX30_JSON = ROOT / "artifacts" / "litecoin-bitvm" / "2026-04-17" / "run-summary.json"
DEFAULT_RETRY_ALIAS_REPLAY_JSON = (
    ROOT
    / "artifacts"
    / "oracle-sidecar-2013-replay"
    / "oracle-sidecar-spray202-retry-alias-attestation-h279209"
    / "summary.json"
)
DEFAULT_BRANCH_SPLIT_REPLAY_JSON = (
    ROOT
    / "artifacts"
    / "oracle-sidecar-2013-replay"
    / "oracle-sidecar-exact100-branch-split-settlement-h279234"
    / "summary.json"
)
DEFAULT_OUT_JSON = ROOT / "artifacts" / "grants" / "policy_envelope_mapping.json"
DEFAULT_OUT_MD = ROOT / "artifacts" / "grants" / "policy_envelope_mapping.md"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def pick_subsurface(overlay_summary: dict, group_key: str, surface_id: str) -> dict:
    group = overlay_summary[group_key]
    for subsurface in group.get("subsurfaces", []):
        if subsurface.get("surface") == surface_id:
            return subsurface
    raise RuntimeError(f"subsurface {surface_id} not found in {group_key}")


def pick_bench(carrier_report: dict, bench_id: str) -> dict:
    for bench in carrier_report.get("benchmarks", []):
        if bench.get("id") == bench_id:
            return bench
    raise RuntimeError(f"benchmark {bench_id} not found")


def first_run(summary: dict) -> dict:
    runs = summary.get("runs") or []
    if not runs:
        raise RuntimeError("run summary has no runs")
    return runs[0]


def compact_txids(values: list[str], limit: int = 4) -> list[str]:
    return list(values[:limit])


def build_proposal_one(
    overlay_summary: dict,
    transcript_summary: dict,
    hybrid_summary: dict,
    overlay_path: Path,
    transcript_path: Path,
    hybrid_path: Path,
) -> dict:
    finddelete = pick_subsurface(
        overlay_summary,
        "transcript_multiplicity",
        "findanddelete_context_split",
    )
    sighash_single = pick_subsurface(
        overlay_summary,
        "transcript_multiplicity",
        "sighash_single_collapse",
    )
    live = first_run(transcript_summary)
    hybrid_live = first_run(hybrid_summary)
    return {
        "proposal_id": 1,
        "name": "Transcript Multiplicity",
        "historical_surfaces": [
            {
                "surface_id": "findanddelete_context_split",
                "historical_class": "policy_rejected_legacy_fossil",
                "relay_status": "consensus_replay_only",
                "source_artifact": str(overlay_path),
                "metrics": {
                    "variant_count": finddelete["variant_count"],
                    "distinct_sighash_context_tags": finddelete["distinct_sighash_context_tags"],
                    "distinct_sighash_digests": finddelete["distinct_sighash_digests"],
                    "shared_core_reason": finddelete["shared_core_reason"],
                },
                "fixture_ids": [row["fixture_id"] for row in finddelete["rows"]],
            },
            {
                "surface_id": "sighash_single_collapse",
                "historical_class": "policy_rejected_legacy_fossil",
                "relay_status": "consensus_replay_only",
                "source_artifact": str(overlay_path),
                "role": "hazard_filter",
                "metrics": {
                    "variant_count": sighash_single["variant_count"],
                    "bug_variant_count": sighash_single["bug_variant_count"],
                    "control_variant_count": sighash_single["control_variant_count"],
                    "bug_digests_constant_one": sighash_single["bug_digests_constant_one"],
                },
                "fixture_ids": [row["fixture_id"] for row in sighash_single["rows"]],
            },
        ],
        "modern_isomorphisms": [
            {
                "surface_id": "transcript_alias_relay",
                "live_class": "relay_surface_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "relay_only",
                "source_artifact": str(transcript_path),
                "metrics": {
                    "oracle_id": live["oracle_id"],
                    "property_id": live["property_id"],
                    "accepted_relay_count": live["accepted_relay_count"],
                    "signature_use_count": live["signature_use_count"],
                    "state_hash": live["state_hash"],
                    "alias_tags": live["alias_tags"],
                    "relay_txids": compact_txids(live["relay_txids"]),
                },
            },
            {
                "surface_id": "transcript_alias_router_dispute_graft",
                "live_class": "settlement_and_dispute_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "relay_prelude_plus_challengeable_route",
                "source_artifact": str(hybrid_path),
                "metrics": {
                    "contract_ref": hybrid_live["contract_ref"],
                    "prelude_state_hash": hybrid_live["prelude_state_hash"],
                    "prelude_relay_doc_count": hybrid_live["prelude_relay_doc_count"],
                    "transcript_alias_tags": hybrid_live["transcript_alias_tags"],
                    "transcript_relay_txids": compact_txids(hybrid_live["transcript_relay_txids"]),
                    "route_labels": hybrid_live["route_labels"],
                    "route_verdicts": hybrid_live["route_verdicts"],
                    "final_statuses": hybrid_live["final_statuses"],
                },
            }
        ],
        "verdict": {
            "historical_envelope": "policy-rejected legacy seam; usable as a replay/measuring fossil only",
            "modern_envelope": "clean LTCTEST relay surface plus a live graft onto the fused short_epoch_router_dispute graph",
            "usable_today": "yes, as a modern relay selector and as a live prelude on a challengeable procedural-token route",
            "blocker": "the Bitcoin fossil remains replay-only; the fused live graft exists on Litecoin today",
        },
    }


def build_proposal_two(
    overlay_summary: dict,
    identifier_summary: dict,
    hybrid_summary: dict,
    overlay_path: Path,
    identifier_path: Path,
    hybrid_path: Path,
) -> dict:
    dummygrind = pick_subsurface(
        overlay_summary,
        "identifier_bifurcation",
        "dummygrind_identifier_bifurcation",
    )
    live = first_run(identifier_summary)
    hybrid_live = first_run(hybrid_summary)
    return {
        "proposal_id": 2,
        "name": "Identifier Bifurcation",
        "historical_surfaces": [
            {
                "surface_id": "dummygrind_identifier_bifurcation",
                "historical_class": "policy_rejected_legacy_fossil",
                "relay_status": "consensus_replay_only",
                "source_artifact": str(overlay_path),
                "metrics": {
                    "variant_count": dummygrind["variant_count"],
                    "distinct_txids": dummygrind["distinct_txids"],
                    "distinct_sighash_digests": dummygrind["distinct_sighash_digests"],
                    "dummy_affects_sighash_any": dummygrind["dummy_affects_sighash_any"],
                },
                "fixture_ids": [row["fixture_id"] for row in dummygrind["rows"]],
            }
        ],
        "modern_isomorphisms": [
            {
                "surface_id": "identifier_namespace_bifurcation",
                "live_class": "relay_surface_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "relay_only",
                "source_artifact": str(identifier_path),
                "metrics": {
                    "oracle_id": live["oracle_id"],
                    "property_id": live["property_id"],
                    "accepted_relay_count": live["accepted_relay_count"],
                    "signature_use_count": live["signature_use_count"],
                    "state_hash": live["state_hash"],
                    "blob_refs": live["blob_refs"],
                    "relay_txids": compact_txids(live["relay_txids"]),
                },
            },
            {
                "surface_id": "identifier_namespace_router_dispute_graft",
                "live_class": "settlement_and_dispute_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "relay_prelude_plus_challengeable_route",
                "source_artifact": str(hybrid_path),
                "metrics": {
                    "contract_ref": hybrid_live["contract_ref"],
                    "prelude_state_hash": hybrid_live["prelude_state_hash"],
                    "prelude_relay_doc_count": hybrid_live["prelude_relay_doc_count"],
                    "identifier_blob_refs": hybrid_live["identifier_blob_refs"],
                    "identifier_relay_txids": compact_txids(hybrid_live["identifier_relay_txids"]),
                    "route_labels": hybrid_live["route_labels"],
                    "route_verdicts": hybrid_live["route_verdicts"],
                    "final_statuses": hybrid_live["final_statuses"],
                },
            }
        ],
        "verdict": {
            "historical_envelope": "policy-rejected NULLDUMMY-era seam; replay-only as a fossil",
            "modern_envelope": "clean LTCTEST namespace surface plus a live graft onto the fused short_epoch_router_dispute graph",
            "usable_today": "yes, as a namespace or session-id search surface and as a live prelude on a challengeable procedural-token route",
            "blocker": "the Bitcoin fossil remains replay-only; the fused live graft exists on Litecoin today",
        },
    }


def build_proposal_three(
    carrier_report: dict,
    receipt_summary: dict,
    router_summary: dict,
    hybrid_summary: dict,
    tx30_summary: dict,
    retry_alias_replay_summary: dict,
    branch_split_replay_summary: dict,
    carrier_path: Path,
    receipt_path: Path,
    router_path: Path,
    hybrid_path: Path,
    tx30_path: Path,
    retry_alias_path: Path,
    branch_split_path: Path,
) -> dict:
    oracle_bench = pick_bench(carrier_report, "oracle_sidecar_2013")
    receipt_live = first_run(receipt_summary)
    router_live = first_run(router_summary)
    hybrid_live = first_run(hybrid_summary)
    return {
        "proposal_id": 3,
        "name": "Carrier Camouflage",
        "historical_surfaces": [
            {
                "surface_id": "oracle_sidecar_2013",
                "historical_class": "ordinary_historical_cover",
                "relay_status": "historical_mainnet_native",
                "source_artifact": str(carrier_path),
                "metrics": {
                    "accepted_case_ids": [
                        case["case_id"] for case in oracle_bench.get("synthetic_cases", []) if case["status"] == "accepted"
                    ],
                    "primary_carrier_labels": [
                        carrier["label"] for carrier in oracle_bench.get("primary_carriers", [])
                    ],
                    "reference_carrier_labels": [
                        carrier["label"] for carrier in oracle_bench.get("topology_references", [])
                    ],
                },
            },
            {
                "surface_id": "oracle_sidecar_retry_alias_replay",
                "historical_class": "synthetic_replay_materialization_blocked",
                "relay_status": "needs_live_prevouts",
                "source_artifact": str(retry_alias_path),
                "metrics": {
                    "policy_rejected_count": retry_alias_replay_summary["policy_rejected_count"],
                    "top_policy_reason": retry_alias_replay_summary["top_policy_reasons"][0]["reason"],
                },
            },
            {
                "surface_id": "oracle_sidecar_branch_split_replay",
                "historical_class": "synthetic_replay_materialization_blocked",
                "relay_status": "needs_live_prevouts",
                "source_artifact": str(branch_split_path),
                "metrics": {
                    "policy_rejected_count": branch_split_replay_summary["policy_rejected_count"],
                    "top_policy_reason": branch_split_replay_summary["top_policy_reasons"][0]["reason"],
                },
            },
        ],
        "modern_isomorphisms": [
            {
                "surface_id": "receipt_rollover_redeem",
                "live_class": "settlement_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "settlement_live",
                "source_artifact": str(receipt_path),
                "metrics": {
                    "short_property_id": receipt_live["short_property_id"],
                    "grant_count": receipt_live["grant_count"],
                    "grant_txids": compact_txids(receipt_live["grant_txids"]),
                    "roll_txids": compact_txids(receipt_live["roll_txids"]),
                    "redeem_txid": receipt_live["redeem_txid"],
                },
            },
            {
                "surface_id": "short_epoch_router",
                "live_class": "settlement_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "settlement_live_with_cache_edges",
                "source_artifact": str(router_path),
                "metrics": {
                    "short_property_id": router_live["short_property_id"],
                    "bucket_sweep_txid": router_live["bucket_sweep_txid"],
                    "excess_route_count": router_live["excess_route_count"],
                    "excess_cache_txids": compact_txids(router_live["excess_cache_txids"]),
                    "excess_payout_txids": compact_txids(router_live["excess_payout_txids"]),
                },
            },
            {
                "surface_id": "short_epoch_router_dispute",
                "live_class": "settlement_and_dispute_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "settlement_live_with_challenge_resolution",
                "source_artifact": str(hybrid_path),
                "metrics": {
                    "short_property_id": hybrid_live["short_property_id"],
                    "contract_ref": hybrid_live["contract_ref"],
                    "prelude_state_hash": hybrid_live["prelude_state_hash"],
                    "prelude_relay_doc_count": hybrid_live["prelude_relay_doc_count"],
                    "transcript_alias_tags": hybrid_live["transcript_alias_tags"],
                    "identifier_blob_refs": hybrid_live["identifier_blob_refs"],
                    "bucket_sweep_txid": hybrid_live["bucket_sweep_txid"],
                    "route_count": hybrid_live["route_count"],
                    "route_labels": hybrid_live["route_labels"],
                    "route_verdicts": hybrid_live["route_verdicts"],
                    "final_statuses": hybrid_live["final_statuses"],
                    "cache_statuses": hybrid_live["cache_statuses"],
                    "cache_txids": compact_txids(hybrid_live["cache_txids"]),
                    "challenge_txids": compact_txids(hybrid_live["challenge_txids"]),
                    "resolve_txids": compact_txids(hybrid_live["resolve_txids"]),
                },
            },
            {
                "surface_id": "plan_a_guardrail",
                "live_class": "dispute_graph_live",
                "relay_status": "relay_compatible_live",
                "settlement_status": "dispute_live",
                "source_artifact": str(tx30_path),
                "metrics": {
                    "uphold_cache_txid": tx30_summary["plan_uphold"]["cache_txid"],
                    "uphold_challenge_txid": tx30_summary["plan_uphold"]["challenge_txid"],
                    "uphold_resolve_txid": tx30_summary["plan_uphold"]["resolve_txid"],
                    "reject_cache_txid": tx30_summary["plan_reject"]["cache_txid"],
                    "reject_challenge_txid": tx30_summary["plan_reject"]["challenge_txid"],
                    "reject_resolve_txid": tx30_summary["plan_reject"]["resolve_txid"],
                    "watchtower_due_event_count": tx30_summary["watchtower"]["due_event_count"],
                    "watchtower_challenge_submission_ids": compact_txids(
                        tx30_summary["watchtower"]["challenge_submission_ids"]
                    ),
                },
            },
        ],
        "verdict": {
            "historical_envelope": "real 2013 mainnet carrier cover exists, but synthetic sidecar replay still stops at missing-inputs",
            "modern_envelope": "clean LTCTEST relay, settlement, dispute, and fused challengeable router graphs already exist as TradeLayer procedural-token flows",
            "usable_today": "yes, on Litecoin for challengeable procedural token routing and dispute edges",
            "blocker": "Bitcoin-side replay still needs funded prevouts; the Litecoin fused graph is now ahead of the Bitcoin replay bench",
        },
    }


def build_flow_rows(report: dict) -> list[dict]:
    rows = []
    for proposal in report["proposals"]:
        for modern in proposal["modern_isomorphisms"]:
            rows.append(
                {
                    "proposal_id": proposal["proposal_id"],
                    "proposal_name": proposal["name"],
                    "surface_id": modern["surface_id"],
                    "live_class": modern["live_class"],
                    "relay_status": modern["relay_status"],
                    "settlement_status": modern["settlement_status"],
                    "source_artifact": modern["source_artifact"],
                }
            )
    return rows


def build_report(
    overlay_summary: dict,
    carrier_report: dict,
    transcript_summary: dict,
    identifier_summary: dict,
    receipt_summary: dict,
    router_summary: dict,
    hybrid_summary: dict,
    tx30_summary: dict,
    retry_alias_replay_summary: dict,
    branch_split_replay_summary: dict,
    args: argparse.Namespace,
) -> dict:
    proposals = [
        build_proposal_one(
            overlay_summary,
            transcript_summary,
            hybrid_summary,
            Path(args.overlay_json).resolve(),
            Path(args.transcript_summary_json).resolve(),
            Path(args.hybrid_summary_json).resolve(),
        ),
        build_proposal_two(
            overlay_summary,
            identifier_summary,
            hybrid_summary,
            Path(args.overlay_json).resolve(),
            Path(args.identifier_summary_json).resolve(),
            Path(args.hybrid_summary_json).resolve(),
        ),
        build_proposal_three(
            carrier_report,
            receipt_summary,
            router_summary,
            hybrid_summary,
            tx30_summary,
            retry_alias_replay_summary,
            branch_split_replay_summary,
            Path(args.carrier_bench_json).resolve(),
            Path(args.receipt_summary_json).resolve(),
            Path(args.router_summary_json).resolve(),
            Path(args.hybrid_summary_json).resolve(),
            Path(args.tx30_summary_json).resolve(),
            Path(args.retry_alias_replay_json).resolve(),
            Path(args.branch_split_replay_json).resolve(),
        ),
    ]
    return {
        "kind": "policy_envelope_mapping",
        "scope": "bitcoin_fossils_to_litecoin_trade_layer",
        "generated_from": {
            "overlay_summary_path": str(Path(args.overlay_json).resolve()),
            "carrier_bench_path": str(Path(args.carrier_bench_json).resolve()),
            "transcript_summary_path": str(Path(args.transcript_summary_json).resolve()),
            "identifier_summary_path": str(Path(args.identifier_summary_json).resolve()),
            "receipt_summary_path": str(Path(args.receipt_summary_json).resolve()),
            "router_summary_path": str(Path(args.router_summary_json).resolve()),
            "hybrid_summary_path": str(Path(args.hybrid_summary_json).resolve()),
            "tx30_summary_path": str(Path(args.tx30_summary_json).resolve()),
            "retry_alias_replay_summary_path": str(Path(args.retry_alias_replay_json).resolve()),
            "branch_split_replay_summary_path": str(Path(args.branch_split_replay_json).resolve()),
        },
        "policy_classes": {
            "policy_rejected_legacy_fossil": "Legacy seam that current policy rejects; useful for replay and measurement, not direct relay use.",
            "ordinary_historical_cover": "Historical mainnet topology that already looked ordinary in its native era.",
            "synthetic_replay_materialization_blocked": "Bench shape is defined, but replay still needs live prevouts or funding materialization.",
            "relay_surface_live": "Modern LTCTEST relay surface already proven live.",
            "settlement_graph_live": "Modern LTCTEST procedural-token settlement path already proven live.",
            "settlement_and_dispute_graph_live": "Modern LTCTEST procedural-token flow that already fuses routing with BitVM challenge and resolution.",
            "dispute_graph_live": "Modern LTCTEST BitVM dispute path already proven live.",
        },
        "proposals": proposals,
        "live_flow_rows": build_flow_rows({"proposals": proposals}),
        "policy_conclusions": {
            "consensus_only_fossils": [
                "findanddelete_context_split",
                "sighash_single_collapse",
                "dummygrind_identifier_bifurcation",
            ],
            "historical_cover_surfaces": [
                "oracle_sidecar_2013",
            ],
            "clean_modern_isomorphisms": [
                "transcript_alias_relay",
                "transcript_alias_router_dispute_graft",
                "identifier_namespace_bifurcation",
                "identifier_namespace_router_dispute_graft",
                "receipt_rollover_redeem",
                "short_epoch_router",
                "short_epoch_router_dispute",
                "plan_a_guardrail",
            ],
            "highest_value_next_graft": (
                "Turn short_epoch_router_dispute into reusable procedural-token templates so relay preludes, "
                "router buckets, and BitVM dispute edges are declared by graph shape instead of one-off live harnesses."
            ),
        },
    }


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Policy Envelope Mapping")
    lines.append("")
    lines.append(
        "This artifact classifies the Jurassic Bitcoin fossils by whether they remain replay-only, "
        "already looked ordinary in their native era, or now have clean LTCTEST isomorphisms inside "
        "TradeLayer procedural-token and BitVM flows."
    )
    lines.append("")
    lines.append("## Proposal Matrix")
    lines.append("")
    lines.append("| proposal | historical envelope | modern isomorphism | usable today | blocker |")
    lines.append("| --- | --- | --- | --- | --- |")
    for proposal in report["proposals"]:
        modern_names = ", ".join(f"`{row['surface_id']}`" for row in proposal["modern_isomorphisms"])
        lines.append(
            f"| `{proposal['proposal_id']}: {proposal['name']}` | {proposal['verdict']['historical_envelope']} | "
            f"{modern_names} | {proposal['verdict']['usable_today']} | {proposal['verdict']['blocker']} |"
        )
    lines.append("")
    lines.append("## Live Modern Surfaces")
    lines.append("")
    lines.append("| surface | proposal | class | relay | settlement/dispute |")
    lines.append("| --- | --- | --- | --- | --- |")
    for row in report["live_flow_rows"]:
        lines.append(
            f"| `{row['surface_id']}` | `{row['proposal_id']}` | `{row['live_class']}` | "
            f"`{row['relay_status']}` | `{row['settlement_status']}` |"
        )
    lines.append("")
    lines.append("## Proposal Details")
    lines.append("")
    for proposal in report["proposals"]:
        lines.append(f"### `{proposal['proposal_id']}: {proposal['name']}`")
        lines.append("")
        lines.append(f"- historical envelope: {proposal['verdict']['historical_envelope']}")
        lines.append(f"- modern envelope: {proposal['verdict']['modern_envelope']}")
        lines.append(f"- usable today: {proposal['verdict']['usable_today']}")
        lines.append(f"- blocker: {proposal['verdict']['blocker']}")
        lines.append("")
        lines.append("| historical surface | class | relay | key metrics |")
        lines.append("| --- | --- | --- | --- |")
        for row in proposal["historical_surfaces"]:
            metrics = ", ".join(f"{key}={value}" for key, value in row["metrics"].items())
            lines.append(
                f"| `{row['surface_id']}` | `{row['historical_class']}` | `{row['relay_status']}` | {metrics} |"
            )
        lines.append("")
        lines.append("| modern surface | class | relay | settlement/dispute | key metrics |")
        lines.append("| --- | --- | --- | --- | --- |")
        for row in proposal["modern_isomorphisms"]:
            metrics = ", ".join(f"{key}={value}" for key, value in row["metrics"].items())
            lines.append(
                f"| `{row['surface_id']}` | `{row['live_class']}` | `{row['relay_status']}` | "
                f"`{row['settlement_status']}` | {metrics} |"
            )
        lines.append("")
    lines.append("## Conclusions")
    lines.append("")
    lines.append(
        "- Consensus-only fossils: "
        + ", ".join(f"`{value}`" for value in report["policy_conclusions"]["consensus_only_fossils"])
    )
    lines.append(
        "- Historical cover surfaces: "
        + ", ".join(f"`{value}`" for value in report["policy_conclusions"]["historical_cover_surfaces"])
    )
    lines.append(
        "- Clean modern isomorphisms: "
        + ", ".join(f"`{value}`" for value in report["policy_conclusions"]["clean_modern_isomorphisms"])
    )
    lines.append(f"- Highest-value next graft: {report['policy_conclusions']['highest_value_next_graft']}")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a policy-envelope mapping report")
    parser.add_argument("--overlay-json", default=str(DEFAULT_OVERLAY_JSON))
    parser.add_argument("--carrier-bench-json", default=str(DEFAULT_CARRIER_BENCH_JSON))
    parser.add_argument("--transcript-summary-json", default=str(DEFAULT_TRANSCRIPT_JSON))
    parser.add_argument("--identifier-summary-json", default=str(DEFAULT_IDENTIFIER_JSON))
    parser.add_argument("--receipt-summary-json", default=str(DEFAULT_RECEIPT_JSON))
    parser.add_argument("--router-summary-json", default=str(DEFAULT_ROUTER_JSON))
    parser.add_argument("--hybrid-summary-json", default=str(DEFAULT_HYBRID_JSON))
    parser.add_argument("--tx30-summary-json", default=str(DEFAULT_TX30_JSON))
    parser.add_argument("--retry-alias-replay-json", default=str(DEFAULT_RETRY_ALIAS_REPLAY_JSON))
    parser.add_argument("--branch-split-replay-json", default=str(DEFAULT_BRANCH_SPLIT_REPLAY_JSON))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        load_json(Path(args.overlay_json).resolve()),
        load_json(Path(args.carrier_bench_json).resolve()),
        load_json(Path(args.transcript_summary_json).resolve()),
        load_json(Path(args.identifier_summary_json).resolve()),
        load_json(Path(args.receipt_summary_json).resolve()),
        load_json(Path(args.router_summary_json).resolve()),
        load_json(Path(args.hybrid_summary_json).resolve()),
        load_json(Path(args.tx30_summary_json).resolve()),
        load_json(Path(args.retry_alias_replay_json).resolve()),
        load_json(Path(args.branch_split_replay_json).resolve()),
        args,
    )

    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
