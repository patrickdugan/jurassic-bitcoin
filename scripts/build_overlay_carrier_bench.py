#!/usr/bin/env python3
"""Build 2013 overlay benchmark specs from seam and carrier artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def index_rows(rows: list[dict], key: str) -> dict[str, dict]:
    return {row[key]: row for row in rows}


def short_hex(value: str | None, width: int = 16) -> str:
    if not value:
        return "unknown"
    return f"{value[:width]}..."


def carrier_index(carriers: dict) -> dict[str, dict]:
    return {record["label"]: record for record in carriers["records"]}


def repeated_decoy_btc(metrics: dict, default_value: float) -> float:
    repeated = metrics.get("top_repeated_amounts") or []
    if repeated:
        value = repeated[0].get("value_btc")
        if isinstance(value, (int, float)):
            return float(value)
    return default_value


def sidecar_density(sidecar_count: int, output_count: int) -> float:
    if output_count <= 0:
        return 0.0
    return round(sidecar_count / output_count, 4)


def commitment_hex(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("ascii")).hexdigest()


def build_publication(
    *,
    case_id: str,
    publication_id: str,
    source_fixture_id: str,
    role: str,
    statement_tag: str,
    variant_tag: str,
    carrier: dict,
    digest_hex: str,
    context_tag_hex: str,
    publication_seq: int,
    op_return_bytes: int,
    change_decoy_btc: float,
    placement_mode: str,
) -> dict:
    payload_fields = {
        "domain_tag": "jbos1",
        "statement_tag": statement_tag,
        "carrier_txid": carrier["txid"],
        "carrier_height": str(carrier["metrics"]["height"]),
        "transcript_digest_hex": digest_hex,
        "context_tag_hex": context_tag_hex,
        "variant_tag": variant_tag,
        "publication_seq": str(publication_seq),
    }
    payload_commitment_hex = commitment_hex(
        [
            case_id,
            statement_tag,
            carrier["txid"],
            digest_hex,
            context_tag_hex,
            variant_tag,
            str(publication_seq),
        ]
    )
    return {
        "publication_id": publication_id,
        "source_fixture_id": source_fixture_id,
        "role": role,
        "tx_shape": "op_return_plus_p2pkh_change",
        "op_return_bytes": op_return_bytes,
        "change_decoy_btc": change_decoy_btc,
        "placement_mode": placement_mode,
        "payload_fields": payload_fields,
        "payload_commitment_hex": payload_commitment_hex,
    }


def choose_rows(summary: dict) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    transcript = summary["transcript_multiplicity"]["subsurfaces"]
    finddelete = index_rows(transcript[0]["rows"], "fixture_id")
    sighash_single = index_rows(transcript[1]["rows"], "fixture_id")
    dummygrind = index_rows(summary["identifier_bifurcation"]["subsurfaces"][0]["rows"], "fixture_id")
    return finddelete, sighash_single, dummygrind


def metric_block(record: dict) -> dict:
    return {
        "height": record["height"],
        "input_count": record["input_count"],
        "output_count": record["output_count"],
        "largest_output_share": record["largest_output_share"],
        "output_type_hist": record["output_type_hist"],
        "top_repeated_amounts": record["top_repeated_amounts"][:3],
    }


def build_oracle_sidecar_casebook(
    primary: dict,
    regimented: dict,
    references: list[dict],
    finddelete: dict[str, dict],
    sighash_single: dict[str, dict],
) -> tuple[dict, list[dict], list[dict]]:
    primary_metrics = primary["metrics"]
    regimented_metrics = regimented["metrics"]
    primary_decoy_btc = repeated_decoy_btc(primary_metrics, 0.01)
    regimented_decoy_btc = repeated_decoy_btc(regimented_metrics, 0.5)
    retry_alias_case_id = "spray202_retry_alias_attestation"
    branch_split_case_id = "exact100_branch_split_settlement"
    retry_statement_tag = "oracle_attest_round_a"
    branch_statement_tag = "oracle_settle_round_b"
    baseline_row = finddelete["findanddelete_core_aa"]
    retry_row = finddelete["findanddelete_core_aaaa"]
    branch_row = finddelete["findanddelete_core_aabb"]
    bug_row = sighash_single["sighash_single_bug"]
    bug_acp_row = sighash_single["sighash_single_bug_anyonecanpay"]

    shared_constraints = {
        "preferred_sidecar_shape": "op_return_plus_p2pkh_change",
        "hazard_filter": "sighash_single_collapse",
        "accepted_carrier_labels": [primary["label"], regimented["label"]],
        "reference_only_carrier_labels": [record["label"] for record in references],
        "no_carrier_mutation": True,
        "max_publications_per_carrier": 2,
        "allowed_op_return_bytes": [40, 48],
    }

    synthetic_cases = [
        {
            "case_id": retry_alias_case_id,
            "status": "accepted",
            "objective": "Publish the same oracle statement twice under retry-equivalent transcript aliases beside the 202-output payout spray.",
            "carrier": {
                "label": primary["label"],
                "txid": primary["txid"],
                "height": primary_metrics["height"],
                "output_count": primary_metrics["output_count"],
                "dominant_decoy_btc": primary_decoy_btc,
            },
            "placement": {
                "mode": "same_height_adjacent_after",
                "synthetic_sidecar_count": 2,
                "sidecar_density": sidecar_density(2, primary_metrics["output_count"]),
                "topology_reference_labels": [record["label"] for record in references],
            },
            "seam_fixture_ids": ["findanddelete_core_aa", "findanddelete_core_aaaa"],
            "expected_property": "same transcript digest survives alias-level retry publication while the carrier remains an ordinary payout spray.",
            "synthetic_publications": [
                build_publication(
                    case_id=retry_alias_case_id,
                    publication_id="oracle_attest_alias_aa",
                    source_fixture_id="findanddelete_core_aa",
                    role="oracle_attestation",
                    statement_tag=retry_statement_tag,
                    variant_tag="aa",
                    carrier=primary,
                    digest_hex=baseline_row["sighash_digest_hex"],
                    context_tag_hex=baseline_row["sighash_context_tag"],
                    publication_seq=1,
                    op_return_bytes=40,
                    change_decoy_btc=primary_decoy_btc,
                    placement_mode="same_height_adjacent_after",
                ),
                build_publication(
                    case_id=retry_alias_case_id,
                    publication_id="oracle_attest_alias_aaaa",
                    source_fixture_id="findanddelete_core_aaaa",
                    role="oracle_attestation_retry",
                    statement_tag=retry_statement_tag,
                    variant_tag="aaaa",
                    carrier=primary,
                    digest_hex=retry_row["sighash_digest_hex"],
                    context_tag_hex=retry_row["sighash_context_tag"],
                    publication_seq=2,
                    op_return_bytes=40,
                    change_decoy_btc=primary_decoy_btc,
                    placement_mode="same_height_adjacent_after",
                ),
            ],
            "success_criteria": [
                "two sidecars stay below a 1% publication density against the payout spray output count",
                "both publications bind to the same transcript digest while preserving distinct alias tags",
                "the carrier remains pure p2pkh batch cover rather than a mixed-script bridge",
            ],
        },
        {
            "case_id": branch_split_case_id,
            "status": "accepted",
            "objective": "Bracket the exact-denomination payout ladder with control and branch-specific oracle settlement publications.",
            "carrier": {
                "label": regimented["label"],
                "txid": regimented["txid"],
                "height": regimented_metrics["height"],
                "output_count": regimented_metrics["output_count"],
                "dominant_decoy_btc": regimented_decoy_btc,
            },
            "placement": {
                "mode": "same_height_straddle",
                "synthetic_sidecar_count": 2,
                "sidecar_density": sidecar_density(2, regimented_metrics["output_count"]),
                "topology_reference_labels": [record["label"] for record in references],
            },
            "seam_fixture_ids": ["findanddelete_core_aa", "findanddelete_core_aabb"],
            "expected_property": "the regimented batch can host a baseline oracle path and an alternate branch transcript without losing payout-shaped cadence.",
            "synthetic_publications": [
                build_publication(
                    case_id=branch_split_case_id,
                    publication_id="oracle_settle_control_path",
                    source_fixture_id="findanddelete_core_aa",
                    role="oracle_settlement_control",
                    statement_tag=branch_statement_tag,
                    variant_tag="control_path",
                    carrier=regimented,
                    digest_hex=baseline_row["sighash_digest_hex"],
                    context_tag_hex=baseline_row["sighash_context_tag"],
                    publication_seq=1,
                    op_return_bytes=48,
                    change_decoy_btc=regimented_decoy_btc,
                    placement_mode="same_height_before_carrier",
                ),
                build_publication(
                    case_id=branch_split_case_id,
                    publication_id="oracle_settle_branch_path",
                    source_fixture_id="findanddelete_core_aabb",
                    role="oracle_settlement_branch",
                    statement_tag=branch_statement_tag,
                    variant_tag="branch_path",
                    carrier=regimented,
                    digest_hex=branch_row["sighash_digest_hex"],
                    context_tag_hex=branch_row["sighash_context_tag"],
                    publication_seq=2,
                    op_return_bytes=48,
                    change_decoy_btc=regimented_decoy_btc,
                    placement_mode="same_height_after_carrier",
                ),
            ],
            "success_criteria": [
                "the control and branch publications produce distinct commitment digests for the same regimented carrier family",
                "two sidecars stay below a 2% publication density against the 101-output payout ladder",
                "the dominant visible rhythm stays anchored to the historical 1.0 and 0.5 BTC denomination ladder",
            ],
        },
    ]

    negative_controls = [
        {
            "case_id": "spray202_constant_one_guardrail",
            "status": "rejected",
            "objective": "Block degenerate SIGHASH_SINGLE bug transcripts from sidecar admission before publication planning.",
            "carrier_label": primary["label"],
            "carrier_txid": primary["txid"],
            "rejected_seam_fixture_ids": ["sighash_single_bug", "sighash_single_bug_anyonecanpay"],
            "rejection_reason": "collapsed constant-one digest fails the oracle-sidecar hazard filter",
            "would_be_publications": [
                {
                    "publication_id": "oracle_bug_single",
                    "source_fixture_id": "sighash_single_bug",
                    "variant_tag": "sighash_single_bug",
                    "collapsed_digest_hex": bug_row["sighash_digest_hex"],
                    "payload_commitment_hex": commitment_hex(
                        [
                            "spray202_constant_one_guardrail",
                            primary["txid"],
                            bug_row["sighash_digest_hex"],
                            "single_bug",
                        ]
                    ),
                },
                {
                    "publication_id": "oracle_bug_single_anyonecanpay",
                    "source_fixture_id": "sighash_single_bug_anyonecanpay",
                    "variant_tag": "sighash_single_bug_anyonecanpay",
                    "collapsed_digest_hex": bug_acp_row["sighash_digest_hex"],
                    "payload_commitment_hex": commitment_hex(
                        [
                            "spray202_constant_one_guardrail",
                            primary["txid"],
                            bug_acp_row["sighash_digest_hex"],
                            "single_bug_anyonecanpay",
                        ]
                    ),
                },
            ],
            "success_criteria": [
                "no sidecar tx is admitted when the transcript digest collapses to the constant-one value",
                "guardrail rejects both plain and ANYONECANPAY bug variants with the same rule",
            ],
        }
    ]

    return shared_constraints, synthetic_cases, negative_controls


def build_oracle_sidecar_bench(carriers: dict, summary: dict) -> dict:
    records = carrier_index(carriers)
    finddelete, sighash_single, _dummygrind = choose_rows(summary)
    primary = records["payout2013-spray-202"]
    regimented = records["payout2013-exact100-101out"]
    references = [records["coinbase-279192"], records["coinbase-279217"], records["coinbase-279289"]]
    shared_constraints, synthetic_cases, negative_controls = build_oracle_sidecar_casebook(
        {
            "label": primary["label"],
            "txid": primary["txid"],
            "metrics": metric_block(primary),
        },
        {
            "label": regimented["label"],
            "txid": regimented["txid"],
            "metrics": metric_block(regimented),
        },
        [
            {
                "label": record["label"],
                "txid": record["txid"],
                "metrics": metric_block(record),
            }
            for record in references
        ],
        finddelete,
        sighash_single,
    )
    return {
        "id": "oracle_sidecar_2013",
        "title": "2013 Oracle Sidecar Batch Cover",
        "objective": "Test whether transcript-family variants can ride beside ordinary high-fanout payout batches without using the miner fanouts themselves as carriers.",
        "overlay_targets": [
            "OP_RETURN oracle publication",
            "DLC settlement sidecar",
            "BitVM watcher publication cadence"
        ],
        "carrier_family": "high_fanout_batch_carrier",
        "primary_carriers": [
            {
                "label": primary["label"],
                "txid": primary["txid"],
                "why": "highest ordinary fanout in the window with repeated low-denomination rhythm",
                "metrics": metric_block(primary),
            },
            {
                "label": regimented["label"],
                "txid": regimented["txid"],
                "why": "exact 1.0 / 0.5 BTC denomination ladder for regimented cadence experiments",
                "metrics": metric_block(regimented),
            },
        ],
        "topology_references": [
            {
                "label": record["label"],
                "txid": record["txid"],
                "why": "reference-only miner payout topology for baseline detectability thresholds",
                "metrics": metric_block(record),
            }
            for record in references
        ],
        "graft_surface": {
            "primary": "findanddelete_context_split",
            "hazard_filter": "sighash_single_collapse",
        },
        "shared_constraints": shared_constraints,
        "cases": [
            {
                "case_id": "retry_alias_pair",
                "carrier_label": primary["label"],
                "seam_fixture_ids": ["findanddelete_core_aa", "findanddelete_core_aaaa"],
                "expected_property": "same digest under retry-equivalent transcript family",
                "evidence": {
                    "digest_hex": finddelete["findanddelete_core_aa"]["sighash_digest_hex"],
                    "context_tag_hex": finddelete["findanddelete_core_aa"]["sighash_context_tag"],
                },
            },
            {
                "case_id": "branch_split",
                "carrier_label": regimented["label"],
                "seam_fixture_ids": ["findanddelete_core_aabb"],
                "expected_property": "distinct transcript branch under same broad spend family",
                "evidence": {
                    "digest_hex": finddelete["findanddelete_core_aabb"]["sighash_digest_hex"],
                    "context_tag_hex": finddelete["findanddelete_core_aabb"]["sighash_context_tag"],
                },
            },
            {
                "case_id": "constant_one_reject",
                "carrier_label": primary["label"],
                "seam_fixture_ids": ["sighash_single_bug", "sighash_single_bug_anyonecanpay"],
                "expected_property": "reject degenerate constant-one transcripts from sidecar selection",
                "evidence": {
                    "collapsed_digest_hex": sighash_single["sighash_single_bug"]["sighash_digest_hex"],
                },
            },
        ],
        "synthetic_cases": synthetic_cases,
        "negative_controls": negative_controls,
        "readiness": {
            "status": "ready_now",
            "why": "carrier fixtures are cached and the transcript surfaces are already measured in the seam reports",
        },
    }


def build_identifier_bifurcation_bench(carriers: dict, summary: dict) -> dict:
    records = carrier_index(carriers)
    _finddelete, _sighash_single, dummygrind = choose_rows(summary)
    aggregator = records["payout2013-aggregator-27in"]
    return {
        "id": "identifier_bifurcation_2013",
        "title": "2013 Anchor Bifurcation Under Aggregation Cover",
        "objective": "Test txid-like namespace freedom under a redistribution cluster where input consolidation dominates the visible topology.",
        "overlay_targets": [
            "Lightning rendezvous or namespace rotation",
            "BitVM anchor/session identifier search",
            "Taproot Asset proof-anchor search"
        ],
        "carrier_family": "aggregation_cover",
        "primary_carrier": {
            "label": aggregator["label"],
            "txid": aggregator["txid"],
            "why": "27-input redistribution cluster hides anchor-level namespace churn under consolidation semantics",
            "metrics": metric_block(aggregator),
        },
        "graft_surface": {
            "primary": "dummygrind_identifier_bifurcation",
        },
        "cases": [
            {
                "case_id": "dummy_zero_anchor",
                "seam_fixture_id": "dummygrind_zero",
                "expected_property": "stable sighash core with one txid-like anchor identifier",
                "evidence": {
                    "txid_hex": dummygrind["dummygrind_zero"]["txid_hex"],
                    "sighash_digest_hex": dummygrind["dummygrind_zero"]["sighash_digest_hex"],
                },
            },
            {
                "case_id": "dummy_32_anchor",
                "seam_fixture_id": "dummygrind_32",
                "expected_property": "stable sighash core with alternate txid-like anchor identifier",
                "evidence": {
                    "txid_hex": dummygrind["dummygrind_32"]["txid_hex"],
                    "sighash_digest_hex": dummygrind["dummygrind_32"]["sighash_digest_hex"],
                },
            },
        ],
        "readiness": {
            "status": "ready_now",
            "why": "the carrier specimen is cached and the txid-axis seam already proves digest stability across identifier variants",
        },
    }


def build_mixed_script_transition_bench(carriers: dict, summary: dict) -> dict:
    records = carrier_index(carriers)
    finddelete, _sighash_single, dummygrind = choose_rows(summary)
    bridge = records["payout2013-early-p2sh-mix"]
    control = records["payout2013-spray-202"]
    return {
        "id": "mixed_script_transition_2013",
        "title": "2013 Mixed-Script Transition Bridge",
        "objective": "Test a staged migration story where a small mixed p2pkh/p2sh envelope carries overlay commitments before the flow graduates into larger batch cover.",
        "overlay_targets": [
            "DLC or oracle migration into P2SH-era envelope",
            "BitVM bridge namespace staging",
            "mixed-script detection baseline"
        ],
        "carrier_family": "mixed_script_transition",
        "primary_carrier": {
            "label": bridge["label"],
            "txid": bridge["txid"],
            "why": "small mixed-script envelope is the first realistic migration bridge, not the final high-fanout carrier",
            "metrics": metric_block(bridge),
        },
        "contrast_carrier": {
            "label": control["label"],
            "txid": control["txid"],
            "why": "pure p2pkh payout spray for comparing detectability against the mixed-script bridge",
            "metrics": metric_block(control),
        },
        "graft_surfaces": [
            "findanddelete_context_split",
            "dummygrind_identifier_bifurcation"
        ],
        "cases": [
            {
                "case_id": "bridge_transcript_split",
                "seam_fixture_id": "findanddelete_core_aabb",
                "expected_property": "staged bridge can still host a non-colliding branch transcript",
                "evidence": {
                    "sighash_digest_hex": finddelete["findanddelete_core_aabb"]["sighash_digest_hex"],
                    "context_tag_hex": finddelete["findanddelete_core_aabb"]["sighash_context_tag"],
                },
            },
            {
                "case_id": "bridge_anchor_variant",
                "seam_fixture_id": "dummygrind_32",
                "expected_property": "bridge can rotate an external identifier without changing the core digest",
                "evidence": {
                    "txid_hex": dummygrind["dummygrind_32"]["txid_hex"],
                    "sighash_digest_hex": dummygrind["dummygrind_32"]["sighash_digest_hex"],
                },
            },
        ],
        "readiness": {
            "status": "ready_now",
            "why": "the bridge carrier and comparison control are cached, and both required seam families are already measured",
        },
    }


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append("# 2013 Overlay Carrier Bench")
    lines.append("")
    lines.append("This bundle composes the measured seam surfaces with the 2013 historical carrier families.")
    lines.append("")
    for bench in report["benchmarks"]:
        lines.append(f"## {bench['title']}")
        lines.append("")
        lines.append(f"- id: `{bench['id']}`")
        lines.append(f"- objective: {bench['objective']}")
        lines.append(f"- carrier family: `{bench['carrier_family']}`")
        lines.append(f"- readiness: `{bench['readiness']['status']}`")
        lines.append(f"- why ready: {bench['readiness']['why']}")
        lines.append(f"- overlay targets: `{', '.join(bench['overlay_targets'])}`")
        if bench.get("primary_carrier"):
            primary = bench["primary_carrier"]
            lines.append(
                f"- primary carrier: `{primary['label']}` / `{primary['txid']}` at height `{primary['metrics']['height']}`"
            )
        else:
            lines.append(
                "- primary carriers: " + ", ".join(
                    f"`{carrier['label']}`/{carrier['txid']}" for carrier in bench["primary_carriers"]
                )
            )
        lines.append("")
        lines.append("### Cases")
        lines.append("")
        lines.append("| case | seam fixtures | expected property | evidence |")
        lines.append("| --- | --- | --- | --- |")
        for case in bench["cases"]:
            seam_ids = ", ".join(f"`{item}`" for item in case.get("seam_fixture_ids", [case.get("seam_fixture_id")]))
            evidence = ", ".join(
                f"{key}={short_hex(str(value))}" for key, value in case["evidence"].items()
            )
            lines.append(f"| `{case['case_id']}` | {seam_ids} | {case['expected_property']} | {evidence} |")
        lines.append("")
        synthetic_cases = bench.get("synthetic_cases") or []
        if synthetic_cases:
            constraints = bench.get("shared_constraints") or {}
            lines.append("### Synthetic Oracle Sidecars")
            lines.append("")
            lines.append(f"- preferred shape: `{constraints.get('preferred_sidecar_shape', 'unknown')}`")
            lines.append(f"- hazard filter: `{constraints.get('hazard_filter', 'unknown')}`")
            lines.append(
                "- accepted carriers: "
                + ", ".join(f"`{label}`" for label in constraints.get("accepted_carrier_labels", []))
            )
            lines.append(
                "- reference-only carriers: "
                + ", ".join(f"`{label}`" for label in constraints.get("reference_only_carrier_labels", []))
            )
            lines.append("")
            lines.append("| synthetic case | carrier | placement | publications | density | decoy_btc |")
            lines.append("| --- | --- | --- | ---: | ---: | ---: |")
            for case in synthetic_cases:
                placement = case["placement"]
                carrier = case["carrier"]
                lines.append(
                    f"| `{case['case_id']}` | `{carrier['label']}` | `{placement['mode']}` | "
                    f"{placement['synthetic_sidecar_count']} | {placement['sidecar_density']:.4f} | "
                    f"{carrier['dominant_decoy_btc']:.8f} |"
                )
            lines.append("")
            for case in synthetic_cases:
                carrier = case["carrier"]
                placement = case["placement"]
                lines.append(f"#### `{case['case_id']}`")
                lines.append("")
                lines.append(f"- objective: {case['objective']}")
                lines.append(
                    f"- carrier: `{carrier['label']}` / `{carrier['txid']}` at height `{carrier['height']}`"
                )
                lines.append(
                    f"- placement: `{placement['mode']}` with {placement['synthetic_sidecar_count']} sidecars"
                )
                lines.append(f"- seam fixtures: `{', '.join(case['seam_fixture_ids'])}`")
                lines.append(f"- expected property: {case['expected_property']}")
                lines.append("")
                lines.append("| publication | role | placement | bytes | decoy_btc | commitment | digest |")
                lines.append("| --- | --- | --- | ---: | ---: | --- | --- |")
                for publication in case["synthetic_publications"]:
                    digest_hex = publication["payload_fields"]["transcript_digest_hex"]
                    lines.append(
                        f"| `{publication['publication_id']}` | `{publication['role']}` | "
                        f"`{publication['placement_mode']}` | {publication['op_return_bytes']} | "
                        f"{publication['change_decoy_btc']:.8f} | "
                        f"`{short_hex(publication['payload_commitment_hex'])}` | "
                        f"`{short_hex(digest_hex)}` |"
                    )
                lines.append("")
        negative_controls = bench.get("negative_controls") or []
        if negative_controls:
            lines.append("### Negative Controls")
            lines.append("")
            lines.append("| case | carrier | reason | rejected fixtures |")
            lines.append("| --- | --- | --- | --- |")
            for case in negative_controls:
                lines.append(
                    f"| `{case['case_id']}` | `{case['carrier_label']}` | {case['rejection_reason']} | "
                    f"`{', '.join(case['rejected_seam_fixture_ids'])}` |"
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build overlay benchmark specs from carrier and seam artifacts")
    parser.add_argument("--overlay-summary", required=True, help="Path to overlay_hook_summary.json")
    parser.add_argument("--carrier-report", required=True, help="Path to payout_2013_carrier_camouflage.json")
    parser.add_argument("--out-json", required=True, help="Path for JSON output")
    parser.add_argument("--out-md", required=True, help="Path for Markdown output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    overlay_summary = load_json(Path(args.overlay_summary).resolve())
    carrier_report = load_json(Path(args.carrier_report).resolve())
    report = {
        "kind": "overlay_carrier_bench_2013",
        "overlay_summary_path": str(Path(args.overlay_summary).resolve()),
        "carrier_report_path": str(Path(args.carrier_report).resolve()),
        "benchmarks": [
            build_oracle_sidecar_bench(carrier_report, overlay_summary),
            build_identifier_bifurcation_bench(carrier_report, overlay_summary),
            build_mixed_script_transition_bench(carrier_report, overlay_summary),
        ],
    }
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
