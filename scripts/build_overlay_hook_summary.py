#!/usr/bin/env python3
"""Summarize overlay-oriented hook surfaces from existing seam artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_events(artifact_dir: Path) -> list[dict]:
    events: list[dict] = []
    for path in sorted(artifact_dir.rglob("*-event.json")):
        events.append(json.loads(path.read_text(encoding="utf-8")))
    if not events:
        raise SystemExit(f"no event files found under {artifact_dir}")
    return events


def short_hex(value: str | None, keep: int = 16) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return value
    return value[:keep] + "..."


def summarize_findanddelete(events: list[dict], artifact_dir: Path) -> dict:
    rows = []
    for event in events:
        details = event["rust"]["details"]
        rows.append(
            {
                "fixture_id": event["testcase_id"].split("-h", 1)[0],
                "core_reason": event.get("core_reason"),
                "fd_removed_total": int(details["findanddelete_removed_total"]),
                "signature_count": int(details["findanddelete_signature_count"]),
                "sighash_context_tag": details["sighash_context_tag"],
                "sighash_digest_hex": details["sighash_digest_hex"],
            }
        )
    rows.sort(key=lambda item: item["fixture_id"])
    return {
        "surface": "findanddelete_context_split",
        "artifact_dir": str(artifact_dir),
        "variant_count": len(rows),
        "shared_core_reason": len({row["core_reason"] for row in rows}) == 1,
        "distinct_sighash_context_tags": len({row["sighash_context_tag"] for row in rows}),
        "distinct_sighash_digests": len({row["sighash_digest_hex"] for row in rows}),
        "rows": rows,
    }


def summarize_sighash_single(events: list[dict], artifact_dir: Path) -> dict:
    rows = []
    for event in events:
        details = event["rust"]["details"]
        rows.append(
            {
                "fixture_id": event["testcase_id"].split("-h", 1)[0],
                "core_reason": event.get("core_reason"),
                "sighash_type": details["sighash_type"],
                "sighash_single_bug": details["sighash_single_bug"].lower() == "true",
                "sighash_digest_hex": details["sighash_digest_hex"],
            }
        )
    rows.sort(key=lambda item: item["fixture_id"])
    bug_rows = [row for row in rows if row["sighash_single_bug"]]
    control_rows = [row for row in rows if not row["sighash_single_bug"]]
    constant_one_hex = "01" + ("00" * 31)
    return {
        "surface": "sighash_single_collapse",
        "artifact_dir": str(artifact_dir),
        "variant_count": len(rows),
        "shared_core_reason": len({row["core_reason"] for row in rows}) == 1,
        "bug_variant_count": len(bug_rows),
        "control_variant_count": len(control_rows),
        "bug_digests_constant_one": all(row["sighash_digest_hex"] == constant_one_hex for row in bug_rows),
        "distinct_bug_digests": len({row["sighash_digest_hex"] for row in bug_rows}),
        "distinct_control_digests": len({row["sighash_digest_hex"] for row in control_rows}),
        "rows": rows,
    }


def summarize_dummygrind(events: list[dict], artifact_dir: Path) -> dict:
    rows = []
    for event in events:
        details = event["rust"]["details"]
        rows.append(
            {
                "fixture_id": event["testcase_id"].split("-h", 1)[0],
                "core_reason": event.get("core_reason"),
                "dummy_len": int(details["dummy_len"]),
                "txid_hex": details["txid_hex"],
                "sighash_digest_hex": details["sighash_digest_hex"],
                "dummy_affects_sighash": details["dummy_affects_sighash"].lower() == "true",
            }
        )
    rows.sort(key=lambda item: item["dummy_len"])
    return {
        "surface": "dummygrind_identifier_bifurcation",
        "artifact_dir": str(artifact_dir),
        "variant_count": len(rows),
        "shared_core_reason": len({row["core_reason"] for row in rows}) == 1,
        "distinct_txids": len({row["txid_hex"] for row in rows}),
        "distinct_sighash_digests": len({row["sighash_digest_hex"] for row in rows}),
        "dummy_affects_sighash_any": any(row["dummy_affects_sighash"] for row in rows),
        "rows": rows,
    }


def build_payload(repo_root: Path) -> dict:
    finddelete_dir = repo_root / "artifacts" / "p2sh-findanddelete-core-seam"
    sighash_single_dir = repo_root / "artifacts" / "sighash-single-core-seam"
    dummygrind_dir = repo_root / "artifacts" / "p2sh-dummygrind-core-seam"

    finddelete = summarize_findanddelete(load_events(finddelete_dir), finddelete_dir)
    sighash_single = summarize_sighash_single(load_events(sighash_single_dir), sighash_single_dir)
    dummygrind = summarize_dummygrind(load_events(dummygrind_dir), dummygrind_dir)

    return {
        "transcript_multiplicity": {
            "name": "Transcript Multiplicity",
            "thesis": "Hold the broad spend skeleton constant while shifting the effective signing transcript.",
            "overlay_targets": [
                "BitVM branch transcript steering",
                "DLC/oracle outcome-set compression",
                "Lightning adaptor transcript selection",
            ],
            "subsurfaces": [finddelete, sighash_single],
        },
        "identifier_bifurcation": {
            "name": "Identifier Bifurcation",
            "thesis": "Hold the core contract digest constant while shifting externally visible transaction identifiers.",
            "overlay_targets": [
                "Lightning commitment / rendezvous identifier search",
                "OP_RETURN namespace and carrier selection",
                "Taproot Asset anchor and proof-surface search",
            ],
            "subsurfaces": [dummygrind],
        },
    }


def render_markdown(payload: dict) -> str:
    lines: list[str] = []
    lines.append("# Overlay Hook Summary")
    lines.append("")
    lines.append("This note reframes the existing seam artifacts as overlay-oriented search manifolds rather than legacy quirks.")
    lines.append("")

    transcript = payload["transcript_multiplicity"]
    lines.append("## Surface I: Transcript Multiplicity")
    lines.append("")
    lines.append(transcript["thesis"])
    lines.append("")
    lines.append("Potential grafts:")
    for target in transcript["overlay_targets"]:
        lines.append(f"- {target}")
    lines.append("")

    finddelete = transcript["subsurfaces"][0]
    lines.append("### FindAndDelete Context Split")
    lines.append("")
    lines.append(
        f"- variants: {finddelete['variant_count']}; shared core reason: {str(finddelete['shared_core_reason']).lower()}; distinct context tags: {finddelete['distinct_sighash_context_tags']}; distinct digests: {finddelete['distinct_sighash_digests']}"
    )
    lines.append(f"- source: `{finddelete['artifact_dir']}`")
    lines.append("")
    lines.append("| fixture | fd_removed | sigs | context_tag | sighash_digest |")
    lines.append("| --- | ---: | ---: | --- | --- |")
    for row in finddelete["rows"]:
        lines.append(
            f"| `{row['fixture_id']}` | {row['fd_removed_total']} | {row['signature_count']} | `{short_hex(row['sighash_context_tag'])}` | `{short_hex(row['sighash_digest_hex'])}` |"
        )
    lines.append("")
    lines.append("Interpretation:")
    lines.append("- `aa` and `aaaa` share a digest, while `aabb` shifts both removal count and digest under the same Core policy envelope.")
    lines.append("- That is the minimal measurable form of transcript steering without changing the broad spend family.")
    lines.append("")

    sighash_single = transcript["subsurfaces"][1]
    lines.append("### SIGHASH_SINGLE Collapse")
    lines.append("")
    lines.append(
        f"- variants: {sighash_single['variant_count']}; shared core reason: {str(sighash_single['shared_core_reason']).lower()}; bug variants constant-one: {str(sighash_single['bug_digests_constant_one']).lower()}; distinct control digests: {sighash_single['distinct_control_digests']}"
    )
    lines.append(f"- source: `{sighash_single['artifact_dir']}`")
    lines.append("")
    lines.append("| fixture | sighash_type | bug | sighash_digest |")
    lines.append("| --- | --- | --- | --- |")
    for row in sighash_single["rows"]:
        lines.append(
            f"| `{row['fixture_id']}` | `{row['sighash_type']}` | `{str(row['sighash_single_bug']).lower()}` | `{short_hex(row['sighash_digest_hex'])}` |"
        )
    lines.append("")
    lines.append("Interpretation:")
    lines.append("- The bug specimens collapse to the constant-one digest while the controls diverge.")
    lines.append("- That gives a second transcript surface independent of FindAndDelete.")
    lines.append("")

    identifier = payload["identifier_bifurcation"]
    lines.append("## Surface II: Identifier Bifurcation")
    lines.append("")
    lines.append(identifier["thesis"])
    lines.append("")
    lines.append("Potential grafts:")
    for target in identifier["overlay_targets"]:
        lines.append(f"- {target}")
    lines.append("")

    dummygrind = identifier["subsurfaces"][0]
    lines.append("### DUMMYGRIND")
    lines.append("")
    lines.append(
        f"- variants: {dummygrind['variant_count']}; shared core reason: {str(dummygrind['shared_core_reason']).lower()}; distinct txids: {dummygrind['distinct_txids']}; distinct digests: {dummygrind['distinct_sighash_digests']}"
    )
    lines.append(f"- source: `{dummygrind['artifact_dir']}`")
    lines.append("")
    lines.append("| fixture | dummy_len | txid | sighash_digest |")
    lines.append("| --- | ---: | --- | --- |")
    for row in dummygrind["rows"]:
        lines.append(
            f"| `{row['fixture_id']}` | {row['dummy_len']} | `{short_hex(row['txid_hex'])}` | `{short_hex(row['sighash_digest_hex'])}` |"
        )
    lines.append("")
    lines.append("Interpretation:")
    lines.append("- The dummy element changes `txid_hex` while preserving the same legacy sighash digest.")
    lines.append("- That is the cleanest current example in the repo of identifier-level freedom decoupled from the signing core.")
    lines.append("")

    lines.append("## Immediate Next Experiments")
    lines.append("")
    lines.append("- Lift FindAndDelete transcript multiplicity into a named overlay bench with explicit `BitVM`, `DLC`, and `Lightning` hypotheses.")
    lines.append("- Add a second identifier-bifurcation family beyond DUMMYGRIND so the txid-axis claim is not single-family.")
    lines.append("- Once the historical archive finishes indexing, test whether ordinary historical payout carriers can host the same commitment surfaces under less conspicuous transaction topology.")
    lines.append("")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an overlay-oriented seam summary")
    parser.add_argument("--repo-root", default=".", help="Repository root")
    parser.add_argument("--out-json", required=True, help="Path for JSON summary")
    parser.add_argument("--out-md", required=True, help="Path for Markdown summary")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    payload = build_payload(repo_root)
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(payload), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
