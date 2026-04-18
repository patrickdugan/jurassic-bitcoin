#!/usr/bin/env python3
"""Build payload, mock-tx, and replay-manifest assets for the 2013 oracle sidecar bench."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCH = ROOT / "artifacts" / "grants" / "overlay_carrier_bench_2013.json"
DEFAULT_PAYLOAD_JSON = ROOT / "artifacts" / "grants" / "oracle_sidecar_payloads_2013.json"
DEFAULT_PAYLOAD_MD = ROOT / "artifacts" / "grants" / "oracle_sidecar_payloads_2013.md"
DEFAULT_BLOB_JSON = ROOT / "fixtures" / "blobs" / "oracle-sidecar-2013-mocks.json"
DEFAULT_MANIFEST_JSON = ROOT / "fixtures" / "manifests" / "oracle_sidecar_2013_replay_poc.json"
SOURCE_MANIFESTS = [
    ROOT / "fixtures" / "manifests" / "p2sh_findanddelete_core_seam_poc.json",
    ROOT / "fixtures" / "manifests" / "sighash_single_core_seam_poc.json",
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def safe_slug(value: str) -> str:
    out = []
    for ch in value.lower():
        if ch.isalnum():
            out.append(ch)
        else:
            out.append("-")
    slug = "".join(out).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug


def format_btc(value: float | None) -> str | None:
    if value is None:
        return None
    return f"{value:.8f}"


def is_hex_string(value: str) -> bool:
    if len(value) % 2 != 0:
        return False
    try:
        bytes.fromhex(value)
        return True
    except ValueError:
        return False


def load_source_catalog() -> dict[str, dict]:
    catalog: dict[str, dict] = {}
    for manifest_path in SOURCE_MANIFESTS:
        manifest = load_json(manifest_path)
        windows = {window["name"]: window for window in manifest.get("windows", [])}
        for fixture in manifest.get("fixtures", []):
            fixture_id = fixture["id"]
            if fixture_id in catalog:
                raise RuntimeError(f"duplicate source fixture id {fixture_id}")
            window = windows.get(fixture["window"], {})
            catalog[fixture_id] = {
                "manifest_path": str(manifest_path),
                "window_name": fixture["window"],
                "epoch": window.get("epoch") or "post-bip34",
                "fixture": fixture,
            }
    return catalog


def resolve_source_tx_hex(source_entry: dict) -> tuple[str, Path]:
    fixture = source_entry["fixture"]
    manifest_path = Path(source_entry["manifest_path"])
    blob_ref = fixture.get("tx_hex_blob")
    blob_field = fixture.get("tx_hex_field")
    if not blob_ref or not blob_field:
        raise RuntimeError(f"fixture {fixture['id']} is missing tx_hex_blob or tx_hex_field")
    blob_path = (manifest_path.parent / blob_ref).resolve()
    blob = load_json(blob_path)
    tx_hex = blob.get(blob_field)
    if not isinstance(tx_hex, str) or not tx_hex:
        raise RuntimeError(f"blob {blob_path} missing field {blob_field}")
    if not is_hex_string(tx_hex):
        raise RuntimeError(f"blob field {blob_field} in {blob_path} is not valid hex")
    return tx_hex, blob_path


def build_carrier_lookup(oracle_bench: dict) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    for carrier in oracle_bench.get("primary_carriers", []):
        lookup[carrier["label"]] = carrier
    for carrier in oracle_bench.get("topology_references", []):
        lookup[carrier["label"]] = carrier
    return lookup


def accepted_publication_rows(oracle_bench: dict) -> list[dict]:
    rows: list[dict] = []
    for case in oracle_bench.get("synthetic_cases", []):
        carrier = case["carrier"]
        placement = case["placement"]
        for publication in case.get("synthetic_publications", []):
            payload_fields = publication["payload_fields"]
            rows.append(
                {
                    "status": case["status"],
                    "case_id": case["case_id"],
                    "objective": case["objective"],
                    "publication_id": publication["publication_id"],
                    "source_fixture_id": publication["source_fixture_id"],
                    "carrier_label": carrier["label"],
                    "carrier_txid": carrier["txid"],
                    "carrier_height": carrier["height"],
                    "carrier_output_count": carrier["output_count"],
                    "placement_mode": publication["placement_mode"],
                    "synthetic_sidecar_count": placement["synthetic_sidecar_count"],
                    "sidecar_density": placement["sidecar_density"],
                    "role": publication["role"],
                    "statement_tag": payload_fields["statement_tag"],
                    "variant_tag": payload_fields["variant_tag"],
                    "transcript_digest_hex": payload_fields["transcript_digest_hex"],
                    "context_tag_hex": payload_fields["context_tag_hex"],
                    "payload_commitment_hex": publication["payload_commitment_hex"],
                    "change_decoy_btc": publication["change_decoy_btc"],
                    "op_return_bytes": publication["op_return_bytes"],
                    "expected_property": case["expected_property"],
                }
            )
    return rows


def rejected_publication_rows(oracle_bench: dict, carrier_lookup: dict[str, dict]) -> list[dict]:
    rows: list[dict] = []
    for case in oracle_bench.get("negative_controls", []):
        carrier = carrier_lookup.get(case["carrier_label"])
        if carrier is None:
            raise RuntimeError(f"negative control carrier {case['carrier_label']} not found")
        dominant_decoy_btc = None
        repeated = carrier.get("metrics", {}).get("top_repeated_amounts") or []
        if repeated:
            value = repeated[0].get("value_btc")
            if isinstance(value, (int, float)):
                dominant_decoy_btc = float(value)
        for publication in case.get("would_be_publications", []):
            rows.append(
                {
                    "status": case["status"],
                    "case_id": case["case_id"],
                    "objective": case["objective"],
                    "publication_id": publication["publication_id"],
                    "source_fixture_id": publication["source_fixture_id"],
                    "carrier_label": case["carrier_label"],
                    "carrier_txid": case["carrier_txid"],
                    "carrier_height": carrier["metrics"]["height"],
                    "carrier_output_count": carrier["metrics"]["output_count"],
                    "placement_mode": "rejected_before_planning",
                    "synthetic_sidecar_count": 0,
                    "sidecar_density": 0.0,
                    "role": "rejected_candidate",
                    "statement_tag": case["case_id"],
                    "variant_tag": publication["variant_tag"],
                    "transcript_digest_hex": publication["collapsed_digest_hex"],
                    "context_tag_hex": "",
                    "payload_commitment_hex": publication["payload_commitment_hex"],
                    "change_decoy_btc": dominant_decoy_btc,
                    "op_return_bytes": None,
                    "expected_property": case["rejection_reason"],
                    "rejection_reason": case["rejection_reason"],
                }
            )
    return rows


def window_name_for_row(row: dict) -> str:
    prefix = "oracle-sidecar"
    case_slug = safe_slug(row["case_id"])
    return f"{prefix}-{case_slug}-h{row['carrier_height']}"


def mock_field_name(publication_id: str) -> str:
    return f"{safe_slug(publication_id).replace('-', '_')}_tx_hex"


def build_payload_artifact(
    bench_path: Path,
    oracle_bench: dict,
    accepted_rows: list[dict],
    rejected_rows: list[dict],
    blob_path: Path,
    manifest_path: Path,
) -> dict:
    windows = []
    seen_windows: set[str] = set()
    for row in accepted_rows + rejected_rows:
        window_name = window_name_for_row(row)
        if window_name in seen_windows:
            continue
        seen_windows.add(window_name)
        windows.append(
            {
                "name": window_name,
                "height": row["carrier_height"],
                "epoch": "post-bip34",
                "carrier_label": row["carrier_label"],
                "status": row["status"],
            }
        )
    return {
        "kind": "oracle_sidecar_2013_payloads",
        "source_bench_path": str(bench_path),
        "mock_blob_path": str(blob_path),
        "replay_manifest_path": str(manifest_path),
        "shared_constraints": oracle_bench.get("shared_constraints", {}),
        "accepted_publications": accepted_rows,
        "rejected_candidates": rejected_rows,
        "windows": windows,
    }


def build_mock_blob(payload_artifact: dict, source_catalog: dict[str, dict]) -> dict:
    publications = payload_artifact["accepted_publications"] + payload_artifact["rejected_candidates"]
    mock_fields: dict[str, str] = {}
    source_blobs: dict[str, str] = {}
    payload_rows: list[dict] = []
    for row in publications:
        source_entry = source_catalog[row["source_fixture_id"]]
        tx_hex, blob_path = resolve_source_tx_hex(source_entry)
        field_name = mock_field_name(row["publication_id"])
        if field_name in mock_fields and mock_fields[field_name] != tx_hex:
            raise RuntimeError(f"conflicting tx hex for {field_name}")
        mock_fields[field_name] = tx_hex
        source_blobs[row["publication_id"]] = str(blob_path)
        payload_rows.append(
            {
                "publication_id": row["publication_id"],
                "mock_tx_field": field_name,
                "source_fixture_id": row["source_fixture_id"],
                "carrier_label": row["carrier_label"],
                "carrier_height": row["carrier_height"],
                "status": row["status"],
                "placement_mode": row["placement_mode"],
                "payload_commitment_hex": row["payload_commitment_hex"],
            }
        )
    payload = {
        "name": "oracle_sidecar_2013_mocks",
        "network": "regtest",
        "source_bench_path": payload_artifact["source_bench_path"],
        "source_manifests": [str(path) for path in SOURCE_MANIFESTS],
        "publications": payload_rows,
        "source_blobs": source_blobs,
    }
    payload.update(mock_fields)
    return payload


def metadata_without_nones(values: dict[str, str | None]) -> dict[str, str]:
    return {key: value for key, value in values.items() if value not in (None, "")}


def build_replay_manifest(
    oracle_bench: dict,
    payload_artifact: dict,
    source_catalog: dict[str, dict],
    blob_path: Path,
    manifest_path: Path,
) -> dict:
    blob_ref = Path(
        Path(blob_path).relative_to(manifest_path.parent).as_posix()
        if blob_path.is_relative_to(manifest_path.parent)
        else Path("../blobs") / blob_path.name
    )
    fixtures = []
    windows: dict[str, dict] = {}
    for row in payload_artifact["accepted_publications"] + payload_artifact["rejected_candidates"]:
        source_entry = source_catalog[row["source_fixture_id"]]
        source_fixture = source_entry["fixture"]
        window_name = window_name_for_row(row)
        windows[window_name] = {
            "name": window_name,
            "start_height": row["carrier_height"],
            "end_height": row["carrier_height"],
            "representative_heights": [row["carrier_height"]],
            "epoch": "post-bip34",
        }
        fixture_description = (
            f"Synthetic oracle sidecar {row['publication_id']} on {row['carrier_label']} "
            f"using {row['source_fixture_id']}"
        )
        metadata = dict(source_fixture.get("metadata", {}))
        metadata.update(
            metadata_without_nones(
                {
                    "benchmark_id": oracle_bench["id"],
                    "synthetic_status": row["status"],
                    "sidecar_case_id": row["case_id"],
                    "publication_id": row["publication_id"],
                    "source_fixture_id": row["source_fixture_id"],
                    "carrier_family": oracle_bench["carrier_family"],
                    "carrier_label": row["carrier_label"],
                    "carrier_txid": row["carrier_txid"],
                    "carrier_height": str(row["carrier_height"]),
                    "carrier_output_count": str(row["carrier_output_count"]),
                    "placement_mode": row["placement_mode"],
                    "oracle_role": row["role"],
                    "statement_tag": row["statement_tag"],
                    "variant_tag": row["variant_tag"],
                    "payload_commitment_hex": row["payload_commitment_hex"],
                    "transcript_digest_hex": row["transcript_digest_hex"],
                    "context_tag_hex": row["context_tag_hex"],
                    "change_decoy_btc": format_btc(row["change_decoy_btc"]),
                    "op_return_bytes": (
                        str(row["op_return_bytes"]) if row["op_return_bytes"] is not None else None
                    ),
                    "expected_property": row["expected_property"],
                    "oracle_overlay_target": "oracle_sidecar_2013",
                    "guardrail_rejected": "true" if row["status"] == "rejected" else "false",
                    "rejection_reason": row.get("rejection_reason"),
                    "mock_tx_field": mock_field_name(row["publication_id"]),
                    "historical_epoch": "post-bip34",
                }
            )
        )
        fixtures.append(
            {
                "id": row["publication_id"],
                "description": fixture_description,
                "window": window_name,
                "tx_hex_blob": blob_ref.as_posix(),
                "tx_hex_field": mock_field_name(row["publication_id"]),
                "spend_type": source_fixture["spend_type"],
                "metadata": metadata,
            }
        )
    fixtures.sort(key=lambda item: item["id"])
    return {
        "name": "oracle_sidecar_2013_replay_poc",
        "windows": [windows[name] for name in sorted(windows)],
        "fixtures": fixtures,
    }


def validate_outputs(payload_artifact: dict, mock_blob: dict, manifest: dict) -> dict:
    mock_fields_present = True
    spend_types = set()
    fixture_count = len(manifest.get("fixtures", []))
    for fixture in manifest.get("fixtures", []):
        spend_types.add(fixture["spend_type"])
        field_name = fixture["tx_hex_field"]
        tx_hex = mock_blob.get(field_name)
        if not isinstance(tx_hex, str) or not is_hex_string(tx_hex):
            raise RuntimeError(f"mock blob missing valid tx hex field {field_name}")
        if fixture["metadata"].get("source_fixture_id") not in {
            row["source_fixture_id"]
            for row in payload_artifact["accepted_publications"] + payload_artifact["rejected_candidates"]
        }:
            raise RuntimeError(f"unknown source fixture id in manifest fixture {fixture['id']}")
    return {
        "all_mock_fields_present": mock_fields_present,
        "fixture_count": fixture_count,
        "spend_types": sorted(spend_types),
    }


def render_markdown(payload_artifact: dict, validation: dict) -> str:
    accepted = payload_artifact["accepted_publications"]
    rejected = payload_artifact["rejected_candidates"]
    lines: list[str] = []
    lines.append("# 2013 Oracle Sidecar Payloads")
    lines.append("")
    lines.append(f"- source bench: `{payload_artifact['source_bench_path']}`")
    lines.append(f"- mock blob: `{payload_artifact['mock_blob_path']}`")
    lines.append(f"- replay manifest: `{payload_artifact['replay_manifest_path']}`")
    lines.append(f"- validation spend types: `{', '.join(validation['spend_types'])}`")
    lines.append("")
    lines.append("## Accepted Publications")
    lines.append("")
    lines.append("| publication | source fixture | carrier | placement | bytes | decoy_btc | commitment |")
    lines.append("| --- | --- | --- | --- | ---: | ---: | --- |")
    for row in accepted:
        lines.append(
            f"| `{row['publication_id']}` | `{row['source_fixture_id']}` | `{row['carrier_label']}` | "
            f"`{row['placement_mode']}` | {row['op_return_bytes']} | "
            f"{format_btc(row['change_decoy_btc']) or ''} | `{row['payload_commitment_hex'][:16]}...` |"
        )
    lines.append("")
    lines.append("## Rejected Candidates")
    lines.append("")
    lines.append("| publication | source fixture | carrier | reason |")
    lines.append("| --- | --- | --- | --- |")
    for row in rejected:
        lines.append(
            f"| `{row['publication_id']}` | `{row['source_fixture_id']}` | `{row['carrier_label']}` | {row['rejection_reason']} |"
        )
    lines.append("")
    lines.append("## Replay Windows")
    lines.append("")
    lines.append("| window | height | status | carrier |")
    lines.append("| --- | ---: | --- | --- |")
    for window in payload_artifact["windows"]:
        lines.append(
            f"| `{window['name']}` | {window['height']} | `{window['status']}` | `{window['carrier_label']}` |"
        )
    lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build oracle-sidecar payload, mock-tx, and replay assets")
    parser.add_argument("--bench-json", default=str(DEFAULT_BENCH))
    parser.add_argument("--payload-json", default=str(DEFAULT_PAYLOAD_JSON))
    parser.add_argument("--payload-md", default=str(DEFAULT_PAYLOAD_MD))
    parser.add_argument("--blob-json", default=str(DEFAULT_BLOB_JSON))
    parser.add_argument("--manifest-json", default=str(DEFAULT_MANIFEST_JSON))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    bench_path = Path(args.bench_json).resolve()
    payload_json = Path(args.payload_json).resolve()
    payload_md = Path(args.payload_md).resolve()
    blob_json = Path(args.blob_json).resolve()
    manifest_json = Path(args.manifest_json).resolve()

    bench_report = load_json(bench_path)
    oracle_bench = next(
        (bench for bench in bench_report.get("benchmarks", []) if bench.get("id") == "oracle_sidecar_2013"),
        None,
    )
    if oracle_bench is None:
        raise RuntimeError(f"oracle_sidecar_2013 bench not found in {bench_path}")

    source_catalog = load_source_catalog()
    carrier_lookup = build_carrier_lookup(oracle_bench)
    accepted_rows = accepted_publication_rows(oracle_bench)
    rejected_rows = rejected_publication_rows(oracle_bench, carrier_lookup)
    payload_artifact = build_payload_artifact(
        bench_path,
        oracle_bench,
        accepted_rows,
        rejected_rows,
        blob_json,
        manifest_json,
    )
    mock_blob = build_mock_blob(payload_artifact, source_catalog)
    replay_manifest = build_replay_manifest(
        oracle_bench,
        payload_artifact,
        source_catalog,
        blob_json,
        manifest_json,
    )
    validation = validate_outputs(payload_artifact, mock_blob, replay_manifest)
    payload_artifact["validation"] = validation

    dump_json(payload_json, payload_artifact)
    dump_json(blob_json, mock_blob)
    dump_json(manifest_json, replay_manifest)
    payload_md.parent.mkdir(parents=True, exist_ok=True)
    payload_md.write_text(render_markdown(payload_artifact, validation), encoding="utf-8")

    print(str(payload_json))
    print(str(payload_md))
    print(str(blob_json))
    print(str(manifest_json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
