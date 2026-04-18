#!/usr/bin/env python3
"""Scan extracted mainnet testcase corpus for structurally interesting transactions.

This is intentionally offline. It only needs the testcase JSON files emitted by
`extract-era`, not a running node or blk*.dat access.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

COINBASE_TAG_RE = re.compile(r"^[A-Za-z0-9 ./,:+_-]{4,}$")


def read_varint(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        raise ValueError("varint out of bounds")
    first = buf[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    if first == 0xFD:
        return int.from_bytes(buf[offset : offset + 2], "little"), offset + 2
    if first == 0xFE:
        return int.from_bytes(buf[offset : offset + 4], "little"), offset + 4
    return int.from_bytes(buf[offset : offset + 8], "little"), offset + 8


def parse_tx(tx_hex: str) -> dict:
    buf = bytes.fromhex(tx_hex)
    offset = 0

    if len(buf) < 10:
        raise ValueError("transaction too short")

    version = int.from_bytes(buf[offset : offset + 4], "little")
    offset += 4

    serialization_flags = 0
    has_extended_marker = offset + 1 < len(buf) and buf[offset] == 0 and buf[offset + 1] != 0
    if has_extended_marker:
        serialization_flags = buf[offset + 1]
        offset += 2
    has_witness = bool(serialization_flags & 0x01)
    has_mweb_extension = bool(serialization_flags & 0x08)

    input_count, offset = read_varint(buf, offset)
    inputs = []
    for _ in range(input_count):
        prev_txid = buf[offset : offset + 32]
        offset += 32
        prev_vout = int.from_bytes(buf[offset : offset + 4], "little")
        offset += 4
        script_len, offset = read_varint(buf, offset)
        script_sig = buf[offset : offset + script_len]
        offset += script_len
        sequence = int.from_bytes(buf[offset : offset + 4], "little")
        offset += 4
        inputs.append(
            {
                "prev_txid": prev_txid,
                "prev_vout": prev_vout,
                "script_sig": script_sig,
                "sequence": sequence,
            }
        )

    output_count, offset = read_varint(buf, offset)
    outputs = []
    for _ in range(output_count):
        value_sats = int.from_bytes(buf[offset : offset + 8], "little")
        offset += 8
        script_len, offset = read_varint(buf, offset)
        script_pubkey = buf[offset : offset + script_len]
        offset += script_len
        outputs.append({"value_sats": value_sats, "script_pubkey": script_pubkey})

    if has_witness:
        for txin in inputs:
            item_count, offset = read_varint(buf, offset)
            witness_items = []
            for _ in range(item_count):
                item_len, offset = read_varint(buf, offset)
                witness_items.append(buf[offset : offset + item_len])
                offset += item_len
            txin["witness"] = witness_items

    if offset + 4 > len(buf):
        raise ValueError("lock_time out of bounds")
    lock_time = int.from_bytes(buf[offset : offset + 4], "little")
    offset += 4
    extension_payload = b""
    if has_extended_marker and offset < len(buf):
        extension_payload = buf[offset:]
        offset = len(buf)
    if offset != len(buf):
        raise ValueError("transaction parse did not consume full buffer")

    is_coinbase = (
        len(inputs) == 1
        and inputs[0]["prev_txid"] == (b"\x00" * 32)
        and inputs[0]["prev_vout"] == 0xFFFFFFFF
    )
    return {
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "lock_time": lock_time,
        "has_witness": has_witness,
        "serialization_flags": serialization_flags,
        "has_mweb_extension": has_mweb_extension,
        "extension_payload_len": len(extension_payload),
        "extension_payload_hex": extension_payload.hex(),
        "is_coinbase": is_coinbase,
    }


def detect_output_type(script: bytes) -> str:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return "p2pkh"
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return "p2sh"
    if len(script) in (35, 67) and script[-1:] == b"\xac" and script[0] in (33, 65):
        return "p2pk"
    if script[:1] == b"\x6a":
        return "op_return"
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return "witness_v0_keyhash"
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return "witness_v0_scripthash"
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return "taproot"
    if len(script) == 34 and script[:2] == b"\x58\x20":
        return "mweb_witness_v8"
    if (
        4 <= len(script) <= 42
        and (script[0] == 0 or 0x51 <= script[0] <= 0x60)
        and script[1] == len(script) - 2
    ):
        version = 0 if script[0] == 0 else script[0] - 0x50
        return f"witness_v{version}"
    if script[-1:] == b"\xae":
        return "multisig_like"
    return "unknown"


def ascii_fragments(blob: bytes) -> list[str]:
    text = "".join(chr(b) if 32 <= b <= 126 else " " for b in blob)
    parts = []
    for part in re.split(r"\s+", text):
        if len(part) < 4:
            continue
        if not re.search(r"[A-Za-z]", part):
            continue
        if part not in parts:
            parts.append(part)
    return parts


def looks_like_coinbase_tag(fragment: str) -> bool:
    if not COINBASE_TAG_RE.fullmatch(fragment):
        return False
    return sum(ch.isalpha() for ch in fragment) >= 2


def parse_bip34_height(script_sig: bytes) -> int | None:
    if not script_sig:
        return None
    push_len = script_sig[0]
    if push_len < 1 or push_len > 5:
        return None
    if len(script_sig) < 1 + push_len:
        return None
    return int.from_bytes(script_sig[1 : 1 + push_len], "little")


def sats_to_btc(sats: int) -> float:
    return sats / 100_000_000.0


def interestingness(record: dict) -> int:
    score = 0
    coinbase_script_len = record["coinbase_script_len"] or 0
    if record["is_coinbase"]:
        score += 1
    if record["output_count"] >= 10:
        score += 1
    if record["output_count"] >= 25:
        score += 2
    if record["output_count"] >= 50:
        score += 2
    if record["is_coinbase"] and coinbase_script_len >= 60:
        score += 1
    if record["is_coinbase"] and coinbase_script_len >= 90:
        score += 1
    if record["is_coinbase"] and record["ascii_fragments"]:
        score += 1
    if record["version"] != 1:
        score += 2
    if record["lock_time"] != 0:
        score += 1
    if record["is_coinbase"]:
        if record["bip34_height"] is None:
            score += 1
        elif record["bip34_height"] != record["height"]:
            score += 2
    elif record["input_count"] >= 2:
        score += 1
    if len(record["output_type_hist"]) > 1:
        score += 2
    if any(t in record["output_type_hist"] for t in ("p2sh", "multisig_like", "op_return", "unknown")):
        score += 2
    if record["largest_output_share"] < 0.50:
        score += 1
    return score


def load_records(corpus_dir: Path) -> list[dict]:
    records = []
    for path in sorted(corpus_dir.glob("*.json")):
        testcase = json.loads(path.read_text(encoding="utf-8"))
        if path.name.startswith("_") or "tx_hex" not in testcase:
            continue
        tx = parse_tx(testcase["tx_hex"])
        first_input = tx["inputs"][0] if tx["inputs"] else None
        script_sig = first_input["script_sig"] if first_input else b""
        output_types = Counter(detect_output_type(o["script_pubkey"]) for o in tx["outputs"])
        total_value_sats = sum(o["value_sats"] for o in tx["outputs"])
        largest_output_sats = max((o["value_sats"] for o in tx["outputs"]), default=0)
        is_coinbase = tx["is_coinbase"]
        coinbase_fragments = ascii_fragments(script_sig) if is_coinbase else []
        record = {
            "id": testcase["id"],
            "path": str(path),
            "height": testcase.get("context", {}).get("height"),
            "txid": testcase.get("metadata", {}).get("txid"),
            "block_hash": testcase.get("metadata", {}).get("block_hash"),
            "version": tx["version"],
            "lock_time": tx["lock_time"],
            "has_witness": tx["has_witness"],
            "serialization_flags": tx.get("serialization_flags", 0),
            "has_mweb_extension": tx.get("has_mweb_extension", False),
            "extension_payload_len": tx.get("extension_payload_len", 0),
            "is_coinbase": is_coinbase,
            "input_count": len(tx["inputs"]),
            "output_count": len(tx["outputs"]),
            "first_input_script_len": len(script_sig),
            "coinbase_script_len": len(script_sig) if is_coinbase else None,
            "coinbase_script_hex": script_sig.hex() if is_coinbase else None,
            "ascii_fragments": coinbase_fragments,
            "bip34_height": parse_bip34_height(script_sig) if is_coinbase else None,
            "total_value_sats": total_value_sats,
            "total_value_btc": sats_to_btc(total_value_sats),
            "largest_output_sats": largest_output_sats,
            "largest_output_btc": sats_to_btc(largest_output_sats),
            "largest_output_share": round(
                (largest_output_sats / total_value_sats) if total_value_sats else 0.0, 4
            ),
            "output_type_hist": dict(sorted(output_types.items())),
        }
        record["interestingness"] = interestingness(record)
        records.append(record)
    return records


def first_seen_tags(records: list[dict]) -> list[dict]:
    seen = {}
    for record in sorted(records, key=lambda item: item["height"]):
        if not record["is_coinbase"]:
            continue
        for fragment in record["ascii_fragments"]:
            if fragment not in seen:
                seen[fragment] = {
                    "tag": fragment,
                    "first_height": record["height"],
                    "first_txid": record["txid"],
                    "count": 0,
                }
            seen[fragment]["count"] += 1
    filtered = [
        item
        for item in seen.values()
        if item["count"] >= 2 and looks_like_coinbase_tag(item["tag"])
    ]
    return sorted(filtered, key=lambda item: (item["first_height"], item["tag"]))


def summarize(records: list[dict]) -> dict:
    heights = [r["height"] for r in records if r["height"] is not None]
    versions = Counter(r["version"] for r in records)
    output_counts = [r["output_count"] for r in records]
    coinbase_records = [r for r in records if r["is_coinbase"]]
    non_coinbase_records = [r for r in records if not r["is_coinbase"]]
    script_lengths = [r["coinbase_script_len"] for r in coinbase_records if r["coinbase_script_len"] is not None]
    type_hist = Counter()
    for record in records:
        type_hist.update(record["output_type_hist"])

    interesting_coinbase = sorted(
        coinbase_records,
        key=lambda item: (
            item["interestingness"],
            item["output_count"],
            item["coinbase_script_len"] or 0,
            item["height"],
        ),
        reverse=True,
    )
    interesting_non_coinbase = sorted(
        non_coinbase_records,
        key=lambda item: (
            item["interestingness"],
            item["output_count"],
            item["input_count"],
            item["height"],
        ),
        reverse=True,
    )

    return {
        "record_count": len(records),
        "height_min": min(heights) if heights else None,
        "height_max": max(heights) if heights else None,
        "coinbase_records": len(coinbase_records),
        "non_coinbase_records": len(non_coinbase_records),
        "version_hist": dict(sorted(versions.items())),
        "output_count_min": min(output_counts) if output_counts else None,
        "output_count_max": max(output_counts) if output_counts else None,
        "coinbase_script_len_min": min(script_lengths) if script_lengths else None,
        "coinbase_script_len_max": max(script_lengths) if script_lengths else None,
        "output_type_hist": dict(sorted(type_hist.items())),
        "first_seen_tags": first_seen_tags(records),
        "top_output_count": [
            {
                "height": r["height"],
                "txid": r["txid"],
                "is_coinbase": r["is_coinbase"],
                "output_count": r["output_count"],
                "output_type_hist": r["output_type_hist"],
                "ascii_fragments": r["ascii_fragments"],
                "largest_output_share": r["largest_output_share"],
            }
            for r in sorted(records, key=lambda item: (item["output_count"], item["height"]), reverse=True)[:15]
        ],
        "top_coinbase_script_len": [
            {
                "height": r["height"],
                "txid": r["txid"],
                "coinbase_script_len": r["coinbase_script_len"],
                "ascii_fragments": r["ascii_fragments"],
            }
            for r in sorted(
                coinbase_records,
                key=lambda item: ((item["coinbase_script_len"] or 0), item["height"]),
                reverse=True,
            )[:15]
        ],
        "interesting_coinbase_candidates": interesting_coinbase[:25],
        "interesting_non_coinbase_candidates": interesting_non_coinbase[:25],
    }


def render_markdown(corpus_dir: Path, summary: dict) -> str:
    lines = []
    lines.append(f"# Corpus Scan: {corpus_dir.name}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- records: {summary['record_count']}")
    lines.append(f"- height range: {summary['height_min']}..{summary['height_max']}")
    lines.append(
        f"- coinbase vs non-coinbase: {summary['coinbase_records']} / {summary['non_coinbase_records']}"
    )
    lines.append(f"- output count range: {summary['output_count_min']}..{summary['output_count_max']}")
    lines.append(
        f"- coinbase script length range: {summary['coinbase_script_len_min']}..{summary['coinbase_script_len_max']}"
    )
    lines.append(f"- output types: {json.dumps(summary['output_type_hist'], sort_keys=True)}")
    lines.append("")
    lines.append("## First Seen Coinbase Tags")
    lines.append("")
    lines.append("| tag | first_height | count |")
    lines.append("| --- | ---: | ---: |")
    for item in summary["first_seen_tags"][:20]:
        lines.append(f"| `{item['tag']}` | {item['first_height']} | {item['count']} |")
    lines.append("")
    lines.append("## Top Output Count Transactions")
    lines.append("")
    lines.append("| height | outputs | class | largest_share | output_types | tags |")
    lines.append("| ---: | ---: | --- | ---: | --- | --- |")
    for item in summary["top_output_count"][:15]:
        tags = ", ".join(item["ascii_fragments"][:3])
        tx_class = "coinbase" if item["is_coinbase"] else "non-coinbase"
        lines.append(
            "| {height} | {output_count} | {tx_class} | {largest_output_share:.4f} | "
            "`{output_type_hist}` | {tags} |".format(
                height=item["height"],
                output_count=item["output_count"],
                tx_class=tx_class,
                largest_output_share=item["largest_output_share"],
                output_type_hist=json.dumps(item["output_type_hist"], sort_keys=True),
                tags=tags,
            )
        )
    lines.append("")
    lines.append("## Interesting Coinbase Candidates")
    lines.append("")
    lines.append("| height | score | outputs | total_btc | script_len | output_types | tags |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | --- | --- |")
    for item in summary["interesting_coinbase_candidates"][:20]:
        tags = ", ".join(item["ascii_fragments"][:3])
        lines.append(
            "| {height} | {interestingness} | {output_count} | {total_value_btc:.8f} | "
            "{coinbase_script_len} | `{output_type_hist}` | {tags} |".format(
                height=item["height"],
                interestingness=item["interestingness"],
                output_count=item["output_count"],
                total_value_btc=item["total_value_btc"],
                coinbase_script_len=item["coinbase_script_len"],
                output_type_hist=json.dumps(item["output_type_hist"], sort_keys=True),
                tags=tags,
            )
        )
    lines.append("")
    lines.append("## Interesting Non-Coinbase Candidates")
    lines.append("")
    lines.append("| height | txid | score | in | out | total_btc | lock_time | output_types |")
    lines.append("| ---: | --- | ---: | ---: | ---: | ---: | ---: | --- |")
    for item in summary["interesting_non_coinbase_candidates"][:20]:
        lines.append(
            "| {height} | `{txid}` | {interestingness} | {input_count} | {output_count} | "
            "{total_value_btc:.8f} | {lock_time} | `{output_type_hist}` |".format(
                height=item["height"],
                txid=item["txid"],
                interestingness=item["interestingness"],
                input_count=item["input_count"],
                output_count=item["output_count"],
                total_value_btc=item["total_value_btc"],
                lock_time=item["lock_time"],
                output_type_hist=json.dumps(item["output_type_hist"], sort_keys=True),
            )
        )
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- This scan is offline and only uses testcase JSON emitted by `extract-era`.")
    lines.append("- Coinbase-tag analysis is limited to actual coinbase transactions to avoid random scriptSig noise from ordinary spends.")
    lines.append("- If this corpus is `tx0000`-only, it is a coinbase/miner-behavior slice, not a general transaction slice.")
    lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Offline scan of extracted mainnet testcase corpus")
    parser.add_argument("--corpus", required=True, help="Directory containing extracted testcase JSON files")
    parser.add_argument("--out-json", required=True, help="Path for JSON summary output")
    parser.add_argument("--out-md", required=True, help="Path for Markdown report output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    corpus_dir = Path(args.corpus).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    records = load_records(corpus_dir)
    summary = summarize(records)
    payload = {"corpus": str(corpus_dir), "summary": summary}

    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(corpus_dir, summary), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
