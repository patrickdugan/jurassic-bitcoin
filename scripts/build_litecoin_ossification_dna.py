#!/usr/bin/env python3
"""Build Litecoin historical carrier/ossification extrapolation reports."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from scan_coinbase_corpus import ascii_fragments, detect_output_type, parse_tx, sats_to_btc


def load_records(label: str, corpus_dir: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(corpus_dir.glob("*.json")):
        if path.name.startswith("_"):
            continue
        testcase = json.loads(path.read_text(encoding="utf-8"))
        tx = parse_tx(testcase["tx_hex"])
        output_hist = Counter(detect_output_type(o["script_pubkey"]) for o in tx["outputs"])
        total_sats = sum(o["value_sats"] for o in tx["outputs"])
        largest_sats = max((o["value_sats"] for o in tx["outputs"]), default=0)
        repeated = Counter(o["value_sats"] for o in tx["outputs"])
        record = {
            "window": label,
            "id": testcase["id"],
            "path": str(path),
            "height": testcase.get("context", {}).get("height"),
            "txid": testcase.get("metadata", {}).get("txid"),
            "block_hash": testcase.get("metadata", {}).get("block_hash"),
            "block_version": testcase.get("metadata", {}).get("block_version"),
            "block_version_hex": testcase.get("metadata", {}).get("block_version_hex"),
            "version": tx["version"],
            "lock_time": tx["lock_time"],
            "has_witness": tx["has_witness"],
            "serialization_flags": tx.get("serialization_flags", 0),
            "has_mweb_extension": tx.get("has_mweb_extension", False),
            "extension_payload_len": tx.get("extension_payload_len", 0),
            "is_coinbase": tx["is_coinbase"],
            "input_count": len(tx["inputs"]),
            "output_count": len(tx["outputs"]),
            "total_ltc": sats_to_btc(total_sats),
            "largest_output_share": round((largest_sats / total_sats) if total_sats else 0.0, 4),
            "output_type_hist": dict(sorted(output_hist.items())),
            "coinbase_tags": ascii_fragments(tx["inputs"][0]["script_sig"]) if tx["is_coinbase"] else [],
            "top_repeated_amounts": [
                {
                    "value_ltc": sats_to_btc(value_sats),
                    "count": count,
                }
                for value_sats, count in sorted(
                    repeated.items(),
                    key=lambda item: (item[1], item[0]),
                    reverse=True,
                )
                if count >= 2
            ][:8],
        }
        record["lanes"] = classify_lanes(record)
        records.append(record)
    return records


def classify_lanes(record: dict) -> list[str]:
    lanes: list[str] = []
    types = record["output_type_hist"]
    if record["is_coinbase"]:
        lanes.append("coinbase_miner_surface")
    if record.get("has_mweb_extension") or types.get("mweb_witness_v8", 0):
        lanes.append("mweb_extension_boundary")
    if record["output_count"] >= 50 and record["input_count"] == 1 and not record["is_coinbase"]:
        lanes.append("high_fanout_batch_carrier")
    elif record["output_count"] >= 20 and not record["is_coinbase"]:
        lanes.append("medium_fanout_batch_carrier")
    if record["input_count"] >= 25:
        lanes.append("large_input_aggregator")
    elif record["input_count"] >= 10:
        lanes.append("input_aggregator")
    if types.get("op_return", 0):
        lanes.append("op_return_anchor")
    if types.get("p2sh", 0):
        lanes.append("p2sh_transition")
    if types.get("p2pk", 0) and types.get("p2pkh", 0):
        lanes.append("p2pk_to_p2pkh_transition")
    if any(name.startswith("witness_") or name == "taproot" for name in types):
        lanes.append("witness_program_output")
    if types.get("taproot", 0):
        lanes.append("taproot_output_namespace")
    if record["has_witness"]:
        lanes.append("witness_envelope")
    if len(types) > 1 and not record["is_coinbase"]:
        lanes.append("mixed_output_envelope")
    if record["lock_time"] != 0:
        lanes.append("locktime_surface")
    if record["top_repeated_amounts"]:
        lanes.append("repeated_denomination_rhythm")
    if not lanes:
        lanes.append("plain_transfer_control")
    return lanes


def pick_top(records: list[dict], lane: str, limit: int = 5) -> list[dict]:
    matched = [record for record in records if lane in record["lanes"]]
    return sorted(
        matched,
        key=lambda item: (
            item["output_count"],
            item["input_count"],
            item["total_ltc"],
            item["height"] or 0,
        ),
        reverse=True,
    )[:limit]


def summarize_window(label: str, records: list[dict]) -> dict:
    heights = [r["height"] for r in records if r["height"] is not None]
    lane_counts = Counter(lane for record in records for lane in record["lanes"])
    type_hist = Counter()
    version_hist = Counter()
    block_version_hist = Counter()
    for record in records:
        type_hist.update(record["output_type_hist"])
        version_hist[record["version"]] += 1
        if record["block_version"] is not None:
            block_version_hist[str(record["block_version"])] += 1
    lanes = [
        "high_fanout_batch_carrier",
        "medium_fanout_batch_carrier",
        "large_input_aggregator",
        "input_aggregator",
        "op_return_anchor",
        "p2sh_transition",
        "p2pk_to_p2pkh_transition",
        "mweb_extension_boundary",
        "witness_program_output",
        "taproot_output_namespace",
        "witness_envelope",
        "mixed_output_envelope",
        "coinbase_miner_surface",
        "repeated_denomination_rhythm",
    ]
    return {
        "label": label,
        "record_count": len(records),
        "height_min": min(heights) if heights else None,
        "height_max": max(heights) if heights else None,
        "lane_counts": dict(sorted(lane_counts.items())),
        "output_type_hist": dict(sorted(type_hist.items())),
        "version_hist": dict(sorted((str(k), v) for k, v in version_hist.items())),
        "block_version_hist": dict(sorted(block_version_hist.items())),
        "top_by_lane": {lane: pick_top(records, lane) for lane in lanes},
    }


def compact_record(record: dict) -> dict:
    return {
        "window": record["window"],
        "height": record["height"],
        "txid": record["txid"],
        "lanes": record["lanes"],
        "input_count": record["input_count"],
        "output_count": record["output_count"],
        "total_ltc": record["total_ltc"],
        "largest_output_share": record["largest_output_share"],
        "serialization_flags": record["serialization_flags"],
        "extension_payload_len": record["extension_payload_len"],
        "output_type_hist": record["output_type_hist"],
        "top_repeated_amounts": record["top_repeated_amounts"][:3],
    }


def candidate_threads(summaries: list[dict]) -> list[dict]:
    by_label = {summary["label"]: summary for summary in summaries}

    def examples(label: str, lane: str, count: int = 3) -> list[dict]:
        return [compact_record(record) for record in by_label[label]["top_by_lane"].get(lane, [])[:count]]

    threads = []
    if "mweb" in by_label:
        threads.append(
            {
                "id": "mweb_extension_block_sidecar",
                "source_window": "mweb",
                "manipulable_surface": "extension-block boundary plus ordinary-chain carrier selection",
                "extrapolation": "Use Litecoin MWEB history as a DNA sample for overlay state that is real but deliberately not visible as ordinary UTXO graph detail.",
                "carrier_dna": [
                    "watch for ordinary-chain txs near extension activation that still look like plain payment or consolidation traffic",
                    "use OP_RETURN and mixed-output specimens as explicit sidecar/control cases",
                    "treat hidden-state transitions as a detectability problem, not only as a consensus-feature problem",
                ],
                "examples": examples("mweb", "mweb_extension_boundary")
                + examples("mweb", "op_return_anchor")
                + examples("mweb", "input_aggregator"),
            }
        )
    if "taproot" in by_label:
        threads.append(
            {
                "id": "taproot_witness_namespace_rotation",
                "source_window": "taproot",
                "manipulable_surface": "witness envelope and script-path opacity around activation",
                "extrapolation": "Taproot-like activation windows are useful for studying how branchiness moves out of the visible script surface and into commitment/identifier policy.",
                "carrier_dna": [
                    "compare witness-heavy records against plain transfer controls",
                    "use aggregators as namespace-rotation covers",
                    "use mixed-output envelopes as staged bridge controls",
                ],
                "examples": examples("taproot", "taproot_output_namespace")
                + examples("taproot", "witness_envelope")
                + examples("taproot", "large_input_aggregator"),
            }
        )
    if "segwit" in by_label:
        threads.append(
            {
                "id": "segwit_witness_osmosis",
                "source_window": "segwit",
                "manipulable_surface": "early witness envelope adoption and P2SH/script transition controls",
                "extrapolation": "SegWit-era Litecoin history gives a cleaner early-warning surface for witness shape, script migration, and policy normalization than a purely synthetic regtest.",
                "carrier_dna": [
                    "use first witness records as envelope transition specimens",
                    "treat P2SH and OP_RETURN as sidecar boundary controls",
                    "measure when wallet-visible transaction shape stops looking exotic",
                ],
                "examples": examples("segwit", "witness_envelope") + examples("segwit", "p2sh_transition"),
            }
        )
    if "recent-vbit2" in by_label:
        threads.append(
            {
                "id": "unknown_versionbit_pressure",
                "source_window": "recent-vbit2",
                "manipulable_surface": "active unknown versionbit warning plus normalized transaction traffic",
                "extrapolation": "The current warning state is a useful live-control window for testing monitors that distinguish consensus-signaling churn from ordinary carrier camouflage.",
                "carrier_dna": [
                    "anchor reports to block version histograms as well as transaction shape",
                    "separate versionbit signaling from spend-level overlay behavior",
                    "use recent high-fanout or aggregator specimens as false-positive controls",
                ],
                "examples": examples("recent-vbit2", "medium_fanout_batch_carrier") + examples("recent-vbit2", "input_aggregator"),
            }
        )
    if "early" in by_label:
        threads.append(
            {
                "id": "early_coinbase_tag_rhythm",
                "source_window": "early",
                "manipulable_surface": "miner tag, coinbase payload, and payout-rhythm conventions before later script ossification",
                "extrapolation": "Early Litecoin testnet blocks are weak as direct carriers but useful as a baseline for how miner/pool conventions become de facto parsing assumptions.",
                "carrier_dna": [
                    "use coinbase tags as metadata-camouflage controls",
                    "separate miner convention from spend-script consensus behavior",
                    "treat repeated payout rhythm as a social-layer ossification signal",
                ],
                "examples": examples("early", "coinbase_miner_surface"),
            }
        )
    return threads


def render_record(record: dict) -> str:
    return (
        f"`{record['txid']}`@{record['height']} "
        f"({record['input_count']}in/{record['output_count']}out, "
        f"{json.dumps(record['output_type_hist'], sort_keys=True)})"
    )


def render_markdown(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Litecoin Historical Ossification DNA")
    lines.append("")
    lines.append("This report applies the Jurassic carrier scanner to local Litecoin RPC history.")
    lines.append("")
    lines.append(f"- scope: `{report['scope']}`")
    lines.append(f"- note: {report['scope_note']}")
    lines.append("")
    lines.append("## Window Summary")
    lines.append("")
    lines.append("| window | heights | records | strongest lanes | output types |")
    lines.append("| --- | --- | ---: | --- | --- |")
    for summary in report["windows"]:
        lane_counts = sorted(summary["lane_counts"].items(), key=lambda item: item[1], reverse=True)
        lanes = ", ".join(f"`{name}`={count}" for name, count in lane_counts[:5])
        lines.append(
            f"| `{summary['label']}` | {summary['height_min']}..{summary['height_max']} | "
            f"{summary['record_count']} | {lanes} | `{json.dumps(summary['output_type_hist'], sort_keys=True)}` |"
        )
    lines.append("")
    lines.append("## Candidate DNA Threads")
    lines.append("")
    for thread in report["threads"]:
        lines.append(f"### `{thread['id']}`")
        lines.append("")
        lines.append(f"- source window: `{thread['source_window']}`")
        lines.append(f"- manipulable surface: {thread['manipulable_surface']}")
        lines.append(f"- extrapolation: {thread['extrapolation']}")
        for item in thread["carrier_dna"]:
            lines.append(f"- DNA: {item}")
        if thread["examples"]:
            lines.append("- examples: " + "; ".join(render_record(item) for item in thread["examples"][:5]))
        lines.append("")
    lines.append("## Top Specimens By Window")
    lines.append("")
    for summary in report["windows"]:
        lines.append(f"### `{summary['label']}`")
        lines.append("")
        for lane in (
            "high_fanout_batch_carrier",
            "medium_fanout_batch_carrier",
            "large_input_aggregator",
            "op_return_anchor",
            "p2sh_transition",
            "mweb_extension_boundary",
            "witness_program_output",
            "taproot_output_namespace",
            "witness_envelope",
            "coinbase_miner_surface",
        ):
            top = summary["top_by_lane"].get(lane) or []
            if not top:
                continue
            lines.append(f"- {lane}: " + "; ".join(render_record(compact_record(record)) for record in top[:3]))
        lines.append("")
    lines.append("## Guardrails")
    lines.append("")
    lines.append("- These are historical-carrier extrapolations, not claims that a historical transaction was an overlay protocol.")
    lines.append("- The current local node is LTCTEST. Treat the output as Litecoin-testnet DNA unless a mainnet node is supplied.")
    lines.append("- The strongest next step is to rerun the same windows on Litecoin mainnet once a mainnet datadir/RPC is available.")
    lines.append("")
    return "\n".join(lines)


def parse_corpus_specs(specs: list[str]) -> list[tuple[str, Path]]:
    parsed = []
    for spec in specs:
        if "=" not in spec:
            raise SystemExit(f"invalid --corpus spec: {spec}")
        label, path = spec.split("=", 1)
        parsed.append((label, Path(path).resolve()))
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Litecoin ossification DNA report")
    parser.add_argument("--corpus", action="append", required=True, help="label=path; may repeat")
    parser.add_argument("--scope", default="litecoin-testnet")
    parser.add_argument(
        "--scope-note",
        default="Generated from the local Litecoin node; this machine currently exposes LTCTEST RPC history.",
    )
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summaries = []
    for label, path in parse_corpus_specs(args.corpus):
        summaries.append(summarize_window(label, load_records(label, path)))
    report = {
        "kind": "litecoin_ossification_dna",
        "scope": args.scope,
        "scope_note": args.scope_note,
        "windows": summaries,
        "threads": candidate_threads(summaries),
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
