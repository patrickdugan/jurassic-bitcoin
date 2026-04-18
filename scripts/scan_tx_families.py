#!/usr/bin/env python3
"""Scan extracted corpora for reusable ordinary-transaction families."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from scan_coinbase_corpus import detect_output_type, parse_tx, sats_to_btc


def load_records(corpus_dir: Path) -> list[dict]:
    records = []
    for path in sorted(corpus_dir.glob("*.json")):
        testcase = json.loads(path.read_text(encoding="utf-8"))
        if path.name.startswith("_") or "tx_hex" not in testcase:
            continue
        tx = parse_tx(testcase["tx_hex"])
        if tx["is_coinbase"]:
            continue
        output_hist = Counter(detect_output_type(o["script_pubkey"]) for o in tx["outputs"])
        total_value_sats = sum(o["value_sats"] for o in tx["outputs"])
        records.append(
            {
                "id": testcase["id"],
                "path": str(path),
                "height": testcase.get("context", {}).get("height"),
                "txid": testcase.get("metadata", {}).get("txid"),
                "input_count": len(tx["inputs"]),
                "output_count": len(tx["outputs"]),
                "lock_time": tx["lock_time"],
                "version": tx["version"],
                "total_value_btc": sats_to_btc(total_value_sats),
                "output_type_hist": dict(sorted(output_hist.items())),
            }
        )
    return records


def family_matches(record: dict) -> dict[str, bool]:
    output_types = set(record["output_type_hist"])
    return {
        "single_input_payout_spray": record["input_count"] == 1 and record["output_count"] >= 50,
        "large_input_aggregator": record["input_count"] >= 10,
        "mixed_p2pk_p2pkh": "p2pk" in output_types and "p2pkh" in output_types,
        "non_coinbase_p2sh": "p2sh" in output_types,
    }


def top_records(records: list[dict], family: str) -> list[dict]:
    matched = [r for r in records if family_matches(r)[family]]
    return sorted(
        matched,
        key=lambda item: (
            item["output_count"],
            item["input_count"],
            item["total_value_btc"],
            item["height"] or 0,
        ),
        reverse=True,
    )[:10]


def summarize(label: str, corpus_dir: Path) -> dict:
    records = load_records(corpus_dir)
    family_counts = Counter()
    for record in records:
        for family, matched in family_matches(record).items():
            if matched:
                family_counts[family] += 1

    families = {}
    for family in (
        "single_input_payout_spray",
        "large_input_aggregator",
        "mixed_p2pk_p2pkh",
        "non_coinbase_p2sh",
    ):
        families[family] = {
            "count": family_counts[family],
            "top_records": top_records(records, family),
        }

    heights = [r["height"] for r in records if r["height"] is not None]
    return {
        "label": label,
        "corpus": str(corpus_dir),
        "record_count": len(records),
        "height_min": min(heights) if heights else None,
        "height_max": max(heights) if heights else None,
        "families": families,
    }


def render_markdown(summaries: list[dict]) -> str:
    lines: list[str] = []
    lines.append("# Transaction Family Scan")
    lines.append("")
    lines.append("This report compares ordinary-transaction families across extracted historical windows.")
    lines.append("")
    for summary in summaries:
        lines.append(f"## {summary['label']}")
        lines.append("")
        lines.append(f"- corpus: `{summary['corpus']}`")
        lines.append(f"- records: {summary['record_count']}")
        lines.append(f"- height range: {summary['height_min']}..{summary['height_max']}")
        lines.append("")
        lines.append("| family | count | strongest examples |")
        lines.append("| --- | ---: | --- |")
        for family_name, family in summary["families"].items():
            examples = ", ".join(
                f"`{item['txid']}`@{item['height']}"
                for item in family["top_records"][:3]
            )
            lines.append(f"| {family_name} | {family['count']} | {examples} |")
        lines.append("")
        for family_name, family in summary["families"].items():
            lines.append(f"### {family_name}")
            lines.append("")
            lines.append("| height | txid | in | out | total_btc | output_types |")
            lines.append("| ---: | --- | ---: | ---: | ---: | --- |")
            for item in family["top_records"][:5]:
                lines.append(
                    "| {height} | `{txid}` | {input_count} | {output_count} | "
                    "{total_value_btc:.8f} | `{output_type_hist}` |".format(
                        height=item["height"],
                        txid=item["txid"],
                        input_count=item["input_count"],
                        output_count=item["output_count"],
                        total_value_btc=item["total_value_btc"],
                        output_type_hist=json.dumps(item["output_type_hist"], sort_keys=True),
                    )
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare reusable tx families across corpora")
    parser.add_argument(
        "--corpus",
        action="append",
        required=True,
        help="Corpus spec in label=path form; may be repeated",
    )
    parser.add_argument("--out-json", required=True, help="Path for JSON output")
    parser.add_argument("--out-md", required=True, help="Path for Markdown output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summaries = []
    for spec in args.corpus:
        if "=" not in spec:
            raise SystemExit(f"invalid corpus spec: {spec}")
        label, path_str = spec.split("=", 1)
        summaries.append(summarize(label, Path(path_str).resolve()))
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    payload = {"windows": summaries}
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(summaries), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
