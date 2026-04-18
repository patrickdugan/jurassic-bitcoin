#!/usr/bin/env python3
"""Analyze fetched fixture txids and selected coinbase heights for carrier camouflage."""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
import urllib.request
from collections import Counter
from pathlib import Path

from scan_coinbase_corpus import ascii_fragments, detect_output_type, parse_tx, sats_to_btc


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def manifest_title(manifest: dict) -> str:
    name = str(manifest.get("name") or "").strip()
    titles = {
        "payout_2013_carrier_camouflage": "2013 Carrier Camouflage Trial",
        "overlay_oracle_sidecar_2013_poc": "2013 Oracle Sidecar Trial",
        "overlay_identifier_bifurcation_2013_poc": "2013 Identifier Bifurcation Trial",
        "overlay_mixed_script_transition_2013_poc": "2013 Mixed-Script Transition Trial",
    }
    if name in titles:
        return titles[name]
    if not name:
        return "Fixture Carrier Trial"
    return name.replace("_", " ").title()


def manifest_takeaways(manifest: dict) -> list[str]:
    name = str(manifest.get("name") or "").strip()
    if name == "overlay_oracle_sidecar_2013_poc":
        return [
            "The usable sidecar carriers are the ordinary payout sprays, not the coinbase fanouts.",
            "The `/P2SH/` coinbase specimens are still valuable because they set topology and detectability baselines for adjacent oracle or DLC publication.",
            "The `202`-output spray is the strongest broad cover because its repeated low-denomination rhythm already looks like a normal payout batch.",
        ]
    if name == "overlay_identifier_bifurcation_2013_poc":
        return [
            "The `27`-input aggregator is the right carrier for identifier churn because consolidation dominates the visible transaction shape.",
            "This lane is about anchor or namespace movement, not payout camouflage.",
            "The historical carrier is already sufficient; the limiting surface is the txid-axis seam, not missing chain data.",
        ]
    if name == "overlay_mixed_script_transition_2013_poc":
        return [
            "The mixed `p2sh` specimen matters as a migration bridge, not as the final large-batch carrier.",
            "The pure payout spray is a useful control because it isolates the detectability cost of mixed-script staging.",
            "This lane is strongest when framed as staged overlay migration rather than generic payout camouflage.",
        ]
    return [
        "The strongest ordinary carrier family in this window is the single-input payout spray, not the mixed-script specimen.",
        "The mixed `p2sh` specimen is still important because it gives an early transition envelope rather than pure fanout.",
        "The `/P2SH/` coinbase fanouts are better as topology references and detection baselines than as direct carrier candidates.",
    ]


def find_local_coinbase_case(height: int) -> Path | None:
    corpus_root = Path(__file__).resolve().parent.parent / "corpus"
    pattern = f"mainnet-h{height}-tx0000.json"
    matches = list(corpus_root.glob(f"**/{pattern}"))
    if not matches:
        return None
    matches.sort()
    return matches[0]


def load_cached_tx_hex(cache_dir: Path, txid: str) -> str | None:
    cache_path = cache_dir / f"{txid}.json"
    if not cache_path.exists():
        return None
    cached = json.loads(cache_path.read_text(encoding="utf-8"))
    return cached.get("tx_hex")


def parse_height(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value))
    except Exception:
        return None


class RpcClient:
    def __init__(self, url: str, user: str, password: str, timeout_sec: int = 120, retries: int = 2) -> None:
        token = base64.b64encode(f"{user}:{password}".encode("ascii")).decode("ascii")
        self._url = url
        self._headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "text/plain",
        }
        self._timeout_sec = timeout_sec
        self._retries = retries

    def call(self, method: str, params: list[object]) -> object:
        body = json.dumps(
            {
                "jsonrpc": "1.0",
                "id": "jb-carrier",
                "method": method,
                "params": params,
            }
        ).encode("utf-8")
        req = urllib.request.Request(self._url, data=body, headers=self._headers, method="POST")
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self._timeout_sec) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                if payload.get("error") is not None:
                    raise RuntimeError(f"{method} failed: {payload['error']}")
                return payload["result"]
            except Exception as err:  # pragma: no cover - exercised against slow live RPC
                last_error = err
                if attempt >= self._retries:
                    break
                time.sleep(2)
        raise RuntimeError(f"{method} failed after retries: {last_error}")


def build_rpc_from_env() -> RpcClient:
    url = os.environ.get("BITCOIND_RPC_URL")
    user = os.environ.get("BITCOIND_RPC_USER")
    password = os.environ.get("BITCOIND_RPC_PASS")
    timeout_sec = int(os.environ.get("JB_RPC_TIMEOUT_SECS", "120"))
    if not url or not user or not password:
        raise RuntimeError("BITCOIND_RPC_URL, BITCOIND_RPC_USER, and BITCOIND_RPC_PASS are required")
    return RpcClient(url=url, user=user, password=password, timeout_sec=timeout_sec)


def repeated_output_amounts(outputs: list[dict]) -> list[dict]:
    amount_hist = Counter(output["value_sats"] for output in outputs)
    ranked = [
        {
            "value_sats": value_sats,
            "value_btc": sats_to_btc(value_sats),
            "count": count,
        }
        for value_sats, count in amount_hist.items()
        if count >= 2
    ]
    ranked.sort(key=lambda item: (item["count"], item["value_sats"]), reverse=True)
    return ranked[:10]


def classify_lane(record: dict) -> tuple[str, list[str]]:
    output_types = record["output_type_hist"]
    p2pkh_count = output_types.get("p2pkh", 0)
    output_count = record["output_count"]
    repeated = record["top_repeated_amounts"]
    is_coinbase = record["is_coinbase"]

    if is_coinbase and output_count >= 300:
        return (
            "miner_fanout_cover",
            [
                "Reference miner payout topology as a camouflage template for overlay batch sizing.",
                "Prefer paired or adjacent oracle/DLC publications rather than claiming direct spendability.",
                "Use the payout rhythm as a detection baseline for unusual sidecar behavior."
            ],
        )

    if output_count >= 100 and p2pkh_count >= output_count - 2:
        return (
            "high_fanout_batch_carrier",
            [
                "Strong cover family for OP_RETURN oracle or DLC settlement sidecars near payout-shaped batches.",
                "Usable as a Taproot Asset distribution-shadow template because the fanout is already normalized.",
                "Good candidate for BitVM watcher benchmarks that need ordinary-looking many-recipient flows."
            ],
        )

    if record["input_count"] >= 10:
        return (
            "aggregation_cover",
            [
                "Good cover family for anchor rotation or Lightning-adjacent namespace churn because input consolidation dominates the visual signature.",
                "Useful for testing whether txid-like overlay identifiers can hide inside redistribution clusters.",
                "Best treated as a structural cover specimen, not a payout broadcast analogue."
            ],
        )

    if output_types.get("p2sh", 0) >= 1:
        return (
            "mixed_script_transition",
            [
                "Best candidate for early OP_RETURN / DLC / P2SH coexistence experiments.",
                "Small mixed-script envelopes are useful for staged migration ideas where the overlay does not control the whole carrier transaction.",
                "Good baseline for 'first script transition' detectors."
            ],
        )

    if repeated:
        return (
            "rhythmic_distribution",
            [
                "Repeated output denominations give a natural place to benchmark commitment camouflage against payout rhythm.",
                "Useful for Taproot Asset or DLC batch-shape experiments where denomination regularity matters."
            ],
        )

    return (
        "misc_structural_cover",
        [
            "Structurally interesting, but weaker as a first carrier family than the high-fanout or mixed-script specimens."
        ],
    )


def summarize_tx(tx_hex: str, *, txid: str, label: str, height: int | None, metadata: dict, is_coinbase: bool) -> dict:
    tx = parse_tx(tx_hex)
    outputs = tx["outputs"]
    total_value_sats = sum(output["value_sats"] for output in outputs)
    largest_output_sats = max((output["value_sats"] for output in outputs), default=0)
    output_type_hist = Counter(detect_output_type(output["script_pubkey"]) for output in outputs)
    top_repeated = repeated_output_amounts(outputs)
    record = {
        "label": label,
        "txid": txid,
        "height": height,
        "is_coinbase": is_coinbase or tx["is_coinbase"],
        "metadata": metadata,
        "input_count": len(tx["inputs"]),
        "output_count": len(outputs),
        "total_value_sats": total_value_sats,
        "total_value_btc": sats_to_btc(total_value_sats),
        "largest_output_sats": largest_output_sats,
        "largest_output_btc": sats_to_btc(largest_output_sats),
        "largest_output_share": round((largest_output_sats / total_value_sats) if total_value_sats else 0.0, 4),
        "output_type_hist": dict(sorted(output_type_hist.items())),
        "top_repeated_amounts": top_repeated,
        "has_op_return": output_type_hist.get("op_return", 0) > 0,
        "p2sh_outputs": output_type_hist.get("p2sh", 0),
        "p2pk_outputs": output_type_hist.get("p2pk", 0),
        "coinbase_tags": ascii_fragments(tx["inputs"][0]["script_sig"]) if tx["is_coinbase"] else [],
    }
    lane, notes = classify_lane(record)
    record["carrier_lane"] = lane
    record["overlay_notes"] = notes
    return record


def fetch_coinbase_record(rpc: RpcClient, height: int) -> dict:
    block_hash = rpc.call("getblockhash", [height])
    block = rpc.call("getblock", [block_hash, 1])
    tx = block["tx"][0]
    txid = tx if isinstance(tx, str) else tx["txid"]
    tx_hex = rpc.call("getrawtransaction", [txid, False])
    return summarize_tx(
        tx_hex,
        txid=txid,
        label=f"coinbase-{height}",
        height=height,
        metadata={"family": "coinbase_fanout", "source": "rpc-height"},
        is_coinbase=True,
    )


def load_local_coinbase_record(height: int) -> dict | None:
    case_path = find_local_coinbase_case(height)
    if case_path is None:
        return None
    testcase = json.loads(case_path.read_text(encoding="utf-8"))
    return summarize_tx(
        testcase["tx_hex"],
        txid=testcase.get("metadata", {}).get("txid", f"coinbase-{height}"),
        label=f"coinbase-{height}",
        height=testcase.get("context", {}).get("height", height),
        metadata={"family": "coinbase_fanout", "source": str(case_path)},
        is_coinbase=True,
    )


def summarize_manifest_blob(manifest_path: Path, fixture: dict) -> dict:
    blob_ref = fixture.get("tx_hex_blob")
    if not blob_ref:
        raise RuntimeError(f"fixture {fixture.get('id')} is missing tx_hex_blob")
    blob_path = (manifest_path.parent / blob_ref).resolve()
    testcase = json.loads(blob_path.read_text(encoding="utf-8"))
    tx_hex_field = str(fixture.get("tx_hex_field") or "tx_hex")
    tx_hex = testcase.get(tx_hex_field)
    if not isinstance(tx_hex, str) or not tx_hex:
        raise RuntimeError(f"fixture {fixture.get('id')} blob {blob_path} is missing field {tx_hex_field}")
    metadata = dict(fixture.get("metadata", {}))
    metadata.setdefault("source_blob", str(blob_path))
    height = (
        parse_height(metadata.get("height"))
        or parse_height(metadata.get("carrier_height"))
        or parse_height((testcase.get("context") or {}).get("height"))
    )
    txid = (
        fixture.get("txid")
        or (testcase.get("metadata") or {}).get("txid")
        or testcase.get("id")
        or fixture.get("id")
    )
    return summarize_tx(
        tx_hex,
        txid=str(txid),
        label=fixture["id"],
        height=height,
        metadata=metadata,
        is_coinbase=False,
    )


def fetch_manifest_records(manifest_path: Path, manifest: dict, cache_dir: Path) -> list[dict]:
    records = []
    windows = {window["name"]: window for window in manifest.get("windows", [])}
    for fixture in manifest.get("fixtures", []):
        txid = fixture.get("txid")
        if txid:
            tx_hex = load_cached_tx_hex(cache_dir, txid)
            if tx_hex is None:
                raise RuntimeError(f"cache miss for txid {txid}; fetch fixtures first")
            window = windows.get(fixture["window"], {})
            reps = window.get("representative_heights") or []
            metadata = dict(fixture.get("metadata", {}))
            height = (
                parse_height(metadata.get("height"))
                or parse_height(metadata.get("carrier_height"))
                or (reps[0] if len(reps) == 1 else None)
            )
            records.append(
                summarize_tx(
                    tx_hex,
                    txid=txid,
                    label=fixture["id"],
                    height=height,
                    metadata=metadata,
                    is_coinbase=False,
                )
            )
            continue
        if fixture.get("tx_hex_blob"):
            records.append(summarize_manifest_blob(manifest_path, fixture))
            continue
        raise RuntimeError(f"fixture {fixture.get('id')} has neither txid nor tx_hex_blob")
    return records


def render_markdown(manifest: dict, manifest_path: Path, records: list[dict], coinbase_heights: list[int]) -> str:
    lines: list[str] = []
    lines.append(f"# {manifest_title(manifest)}")
    lines.append("")
    lines.append(f"- manifest: `{manifest_path}`")
    if manifest.get("name"):
        lines.append(f"- manifest name: `{manifest['name']}`")
    lines.append(f"- specimen count: {len(records)}")
    if coinbase_heights:
        lines.append(f"- coinbase heights: `{', '.join(str(height) for height in coinbase_heights)}`")
    lines.append("")
    lines.append("## Carrier Summary")
    lines.append("")
    lines.append("| label | height | lane | in | out | total_btc | largest_share | output_types |")
    lines.append("| --- | ---: | --- | ---: | ---: | ---: | ---: | --- |")
    for record in sorted(records, key=lambda item: (item["output_count"], item["height"] or 0), reverse=True):
        lines.append(
            "| {label} | {height} | {carrier_lane} | {input_count} | {output_count} | "
            "{total_value_btc:.8f} | {largest_output_share:.4f} | `{output_type_hist}` |".format(
                **record
            )
        )
    lines.append("")
    lines.append("## Specimen Notes")
    lines.append("")
    for record in sorted(records, key=lambda item: (item["is_coinbase"], item["output_count"]), reverse=True):
        lines.append(f"### {record['label']}")
        lines.append("")
        lines.append(f"- txid: `{record['txid']}`")
        lines.append(f"- lane: `{record['carrier_lane']}`")
        lines.append(f"- height: {record['height']}")
        lines.append(f"- inputs / outputs: {record['input_count']} / {record['output_count']}")
        lines.append(f"- total value: {record['total_value_btc']:.8f} BTC")
        lines.append(f"- largest output share: {record['largest_output_share']:.4f}")
        lines.append(f"- output types: `{json.dumps(record['output_type_hist'], sort_keys=True)}`")
        if record["coinbase_tags"]:
            lines.append(f"- coinbase tags: `{', '.join(record['coinbase_tags'][:4])}`")
        if record["top_repeated_amounts"]:
            repeated = ", ".join(
                f"{item['count']}x {item['value_btc']:.8f} BTC"
                for item in record["top_repeated_amounts"][:5]
            )
            lines.append(f"- repeated denominations: {repeated}")
        for note in record["overlay_notes"]:
            lines.append(f"- note: {note}")
    lines.append("")
    lines.append("## Takeaways")
    lines.append("")
    for takeaway in manifest_takeaways(manifest):
        lines.append(f"- {takeaway}")
    lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze fetched tx fixtures for carrier camouflage")
    parser.add_argument("--manifest", required=True, help="Manifest file containing txid fixtures")
    parser.add_argument("--cache-dir", default="fixtures/cache", help="Fixture cache directory")
    parser.add_argument("--out-json", required=True, help="Path for JSON output")
    parser.add_argument("--out-md", required=True, help="Path for Markdown output")
    parser.add_argument(
        "--coinbase-height",
        action="append",
        type=int,
        default=[],
        help="Coinbase block height to include via RPC; may be repeated",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    cache_dir = Path(args.cache_dir).resolve()
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    manifest = load_manifest(manifest_path)
    records = fetch_manifest_records(manifest_path, manifest, cache_dir)
    rpc = None
    for height in args.coinbase_height:
        local_record = load_local_coinbase_record(height)
        if local_record is not None:
            records.append(local_record)
            continue
        if rpc is None:
            rpc = build_rpc_from_env()
        records.append(fetch_coinbase_record(rpc, height))
    payload = {
        "manifest": str(manifest_path),
        "coinbase_heights": args.coinbase_height,
        "records": sorted(records, key=lambda item: (item["output_count"], item["height"] or 0), reverse=True),
    }
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(manifest, manifest_path, payload["records"], args.coinbase_height), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
