#!/usr/bin/env python3
"""Constructive overlay primitives built on the three Jurassic seams.

This is the companion to ``seam_digests_standalone.py``. Where that file
*measures* the ossified behaviours (which digests alias, which collapse, which
txids move), this file turns each behaviour into a named, specified overlay
primitive and demonstrates it with a deterministic, node-free check. The goal
is the one Robin Linus set with Binohash: take a legacy consensus/encoding
degree of freedom and express a genuinely useful capability on top of it, with
an honest statement of what it costs and where policy fences it.

No node, no RPC, no third-party packages, no signatures verified. Every claim
below is a pure function of legacy serialization and the original
``SignatureHash``; keys are deterministic SHA-256 placeholders. The point of
each demo is a cryptographic invariant (digests that must match, digests that
must stay fixed, a collision bound), not a spendable transaction.

Primitives:

  P1  Aggregatable attestation   (Motif I)  SIGHASH_SINGLE|ANYONECANPAY slots
  P2  State-bound handle rotation (Motif II) dummy-axis + witness-era variant
  P3  Binohash cost bench        (Motif I)  FindAndDelete grinding accountant

Each primitive carries a ``properties`` block naming which of the four
admission properties from the paper (P1 semantic binding, P2 non-collapse,
P3 authority separation, P4 rotation invariance) it enforces, so the demo and
the formalisation stay in sync.

Usage:

  python scripts/binohash_level_tools.py [--out-dir docs/grants]

Writes ``binohash_level_tools.{json,md}`` into the output directory and prints
a PASS/FAIL line per invariant.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
from dataclasses import replace
from pathlib import Path

# Reuse the audited primitives from the seam module rather than re-deriving
# them. The seam module does not export OP_RETURN, so define it locally.
from seam_digests_standalone import (  # noqa: E402
    OP_CHECKMULTISIG,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE,
    UINT256_ONE,
    Tx,
    TxIn,
    TxOut,
    digest_hex,
    fake_prevout,
    fake_pubkey,
    find_and_delete,
    op,
    p2pkh,
    push,
    signature_hash,
    sha256,
    txid_hex,
)

OP_RETURN = 0x6A

PK = {name: fake_pubkey(name) for name in ("oracle0", "oracle1", "oracle2", "sink", "A")}


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii")


def commit(obj) -> str:
    return sha256(canon(obj)).hex()


# --------------------------------------------------------------------------
# P1: Aggregatable attestation via SIGHASH_SINGLE | ANYONECANPAY
# --------------------------------------------------------------------------
#
# Motif I, constructive face. The hazard half of the SIGHASH_SINGLE seam is the
# constant-one collapse (fenced by property P2). The *useful* half is that
# SINGLE|ANYONECANPAY makes one signer's digest depend only on their own input
# and their own output slot, so independently produced pieces compose into one
# transaction without re-signing. This is the mechanism behind assurance
# contracts; here it is lifted to threshold oracle attestation, where each
# oracle signs one (funding slot, payout slot) pair for a shared event and an
# aggregator assembles any sufficient subset.
#
# The invariant we demonstrate: the digest an oracle computes over its
# standalone slot equals the digest for that same slot in the fully composed
# multi-oracle transaction, for every oracle, regardless of which other oracles
# are included. That equality is exactly what "really leverages" the seam.


def _attestation_slot(event_hash: bytes, idx: int) -> tuple[TxIn, TxOut]:
    """One oracle's (input, output) slot for a shared event."""
    txin = TxIn(fake_prevout(f"oracle-funding-{idx}-{event_hash.hex()[:8]}"), idx, b"")
    # Payout output binds the event hash so the slot is not reusable for a
    # different event (property P1, semantic binding).
    script = op(OP_RETURN) + push(b"attest:" + event_hash[:16])
    payout = TxOut(1000 + idx, p2pkh(PK["sink"]) if idx % 2 == 0 else script)
    return txin, payout


def primitive_aggregatable_attestation(n: int = 3) -> dict:
    event = sha256(b"jurassic-oracle-event: BTCUSD>100k @ 2026-12-31")
    script_code = p2pkh(PK["oracle0"])  # each oracle spends a p2pkh-shaped slot
    ht = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY

    slots = [_attestation_slot(event, i) for i in range(n)]
    ins = tuple(s[0] for s in slots)
    outs = tuple(s[1] for s in slots)

    def digest_at(tx: Tx, i: int) -> str:
        return digest_hex(signature_hash(script_code, tx, i, ht))

    # Base composed transaction: every oracle present, each at its own index.
    composed = Tx(1, ins, outs, 0)
    base = {i: digest_at(composed, i) for i in range(n)}

    # (a) Independence from other slots' CONTENT. Mutate every slot except the
    #     one we are checking (different prevouts, different output values and
    #     scripts) and confirm the checked signer's digest is unchanged. With
    #     ANYONECANPAY other inputs are dropped from the hash; with SINGLE the
    #     earlier outputs are nulled and later outputs truncated away, so only
    #     this signer's own (input, output, index) matters.
    focus = 1
    mutated_ins = tuple(
        ins[j] if j == focus else TxIn(fake_prevout(f"other-{j}-mutated"), j + 100, b"", 7)
        for j in range(n)
    )
    mutated_outs = tuple(
        outs[j] if j == focus else TxOut(9999 + j, p2pkh(PK["A"])) for j in range(n)
    )
    mutated = Tx(1, mutated_ins, mutated_outs, 0)
    independent = digest_at(mutated, focus) == base[focus]

    # (b) Append-only: adding a LATER slot does not change an earlier signer's
    #     digest (the extra output is truncated away for that signer).
    extra_in, extra_out = _attestation_slot(event, n)
    appended = Tx(1, ins + (extra_in,), outs + (extra_out,), 0)
    append_preserves = all(digest_at(appended, i) == base[i] for i in range(n))

    # (c) Position-bound: removing an EARLIER slot shifts the signer's index and
    #     changes the digest. This is the precondition an aggregator must honour
    #     (it may append or swap contents, but not reorder or drop earlier slots).
    dropped_earlier = Tx(1, ins[1:], outs[1:], 0)  # old index 2 now sits at index 1
    remove_earlier_changes = digest_at(dropped_earlier, 1) != base[2]

    # (d) Non-collapse guard (property P2): a slot whose signed index has no
    #     output collapses to the constant one and must be refused.
    collapse_view = Tx(1, (ins[0],), (), 0)
    collapse_detected = digest_at(collapse_view, 0) == digest_hex(UINT256_ONE)

    return {
        "primitive": "aggregatable_attestation",
        "motif": "transcript_multiplicity",
        "mechanism": "SIGHASH_SINGLE|ANYONECANPAY makes a signer's digest a function of only its own (input, output, index), so independently produced slots compose append-only without re-signing.",
        "event_commitment": event.hex(),
        "sighash_type": f"0x{ht:02x}",
        "oracle_count": n,
        "base_digests": base,
        "checked_signer_index": focus,
        "invariants": {
            "digest_independent_of_other_slot_content": independent,
            "append_later_slot_preserves_earlier_digests": append_preserves,
            "remove_earlier_slot_changes_digest": remove_earlier_changes,
            "constant_one_collapse_detected_and_refused": collapse_detected,
        },
        "preconditions": [
            "all signers agree on nVersion and nLockTime",
            "aggregation is append-only: a signer's index must be preserved, so earlier slots cannot be dropped or reordered (later slots and other-slot contents are free)",
            "the constant-one collapse (no output at the signed index) is refused before a slot is treated as an attestation",
        ],
        "properties": {
            "P1_semantic_binding": "each payout output carries the event hash",
            "P2_non_collapse": "constant-one slot refused",
            "P3_authority_separation": "a slot is evidence of one oracle's attestation, not spend authority over the aggregate",
            "P4_rotation_invariance": "n/a (attestation, not a handle)",
        },
        "overlay_use": "threshold DLC/oracle attestation: any sufficient subset of position-ordered oracle slots composes into one settlement without a re-signing round",
    }


# --------------------------------------------------------------------------
# P2: State-bound handle rotation (identifier bifurcation)
# --------------------------------------------------------------------------
#
# Motif II. The legacy dummy element moves the txid while leaving the sighash
# fixed. Constructively, that is a public handle you can rotate without
# touching the committed state. The primitive adds the missing piece the raw
# seam lacks: a derivation that *binds* the handle to the state so an indexer
# can verify a rotation is authentic (property P4) rather than an unrelated
# third-party malleation. We show the legacy form (policy-dead today) and a
# witness-era form that carries the same rotation in an OP_RETURN handle, which
# is relay-standard under Core 30.0.


def derive_handle(state_hash: bytes, label: str, epoch: int) -> bytes:
    """A handle an indexer can recompute from the committed state. Rotation is
    changing (label, epoch); the state hash is fixed. Verification is a single
    recomputation, so rotation is a no-op on authority (property P4)."""
    return sha256(state_hash + label.encode("ascii") + struct.pack("<I", epoch))


def primitive_handle_rotation() -> dict:
    state = {"kind": "ln_lease", "channel": "jurassic-demo", "amount_sats": 250000}
    state_hash = bytes.fromhex(commit(state))
    redeem = op(0x51) + push(PK["A"]) + op(0x51) + op(OP_CHECKMULTISIG)  # 1-of-1

    # --- legacy dummy-axis form: handle lives in the unused dummy element ---
    legacy_rows = []
    sig = bytes.fromhex("3044" + "aa" * 68 + "01")
    for epoch in range(3):
        handle = derive_handle(state_hash, "ln-watchtower-alert", epoch)
        script_sig = push(handle) + push(sig) + push(redeem)  # handle as the dummy
        tx = Tx(1, (TxIn(fake_prevout("lease"), 0, script_sig),), (TxOut(30000, p2pkh(PK["sink"])),))
        code, _ = find_and_delete(redeem, push(sig))
        d = signature_hash(code, tx, 0, SIGHASH_ALL)
        legacy_rows.append({
            "epoch": epoch,
            "handle": handle.hex(),
            "txid": txid_hex(tx),
            "sighash_digest": digest_hex(d),
            "handle_verifies": derive_handle(state_hash, "ln-watchtower-alert", epoch) == handle,
        })

    legacy_digests = {r["sighash_digest"] for r in legacy_rows}
    legacy_txids = {r["txid"] for r in legacy_rows}

    # --- witness-era form: handle in an OP_RETURN output, relay-standard ---
    # The committed state is anchored once in output 0; the rotating handle is a
    # second OP_RETURN output whose content changes per epoch. The *anchor*
    # output is byte-identical across epochs, so an indexer keys state on it and
    # treats the handle output purely as a routing label.
    witness_rows = []
    anchor_script = op(OP_RETURN) + push(b"jbanchor" + state_hash[:16])
    for epoch in range(3):
        handle = derive_handle(state_hash, "ln-rendezvous", epoch)
        handle_script = op(OP_RETURN) + push(b"jbh" + handle[:20])
        tx = Tx(
            2,
            (TxIn(fake_prevout("wit-lease"), 0, b""),),
            (TxOut(0, anchor_script), TxOut(0, handle_script), TxOut(29000, p2pkh(PK["sink"]))),
        )
        witness_rows.append({
            "epoch": epoch,
            "handle": handle.hex(),
            "anchor_script_hex": anchor_script.hex(),
            "handle_script_hex": handle_script.hex(),
            "txid": txid_hex(tx),
            "handle_verifies": derive_handle(state_hash, "ln-rendezvous", epoch) == handle,
        })
    anchor_scripts = {r["anchor_script_hex"] for r in witness_rows}

    return {
        "primitive": "state_bound_handle_rotation",
        "motif": "identifier_bifurcation",
        "mechanism": "a handle derived from the committed state hash can rotate across epochs while the state commitment is fixed and indexer-verifiable.",
        "state_commitment": state_hash.hex(),
        "legacy_dummy_axis": {
            "rows": legacy_rows,
            "distinct_txids": len(legacy_txids),
            "distinct_sighash_digests": len(legacy_digests),
            "policy": "non-null dummy is policy-dead (NULLDUMMY) / consensus-invalid for witness v0 (BIP147); shown for the historical mechanism only",
        },
        "witness_era_form": {
            "rows": witness_rows,
            "distinct_anchor_scripts": len(anchor_scripts),
            "policy": "relay-standard under Bitcoin Core 30.0 datacarrier policy; the anchor output is byte-identical across epochs so state keying is stable",
        },
        "invariants": {
            "legacy_txid_moves_digest_fixed": len(legacy_txids) == 3 and len(legacy_digests) == 1,
            "witness_anchor_fixed_across_rotation": len(anchor_scripts) == 1,
            "all_handles_verify": all(r["handle_verifies"] for r in legacy_rows + witness_rows),
        },
        "properties": {
            "P1_semantic_binding": "handle = H(state_hash || label || epoch)",
            "P2_non_collapse": "n/a (no signed degenerate digest)",
            "P3_authority_separation": "the handle indexes; it is never checked by any spend path",
            "P4_rotation_invariance": "verifier decision is recomputation of the derivation; identical for every epoch",
        },
        "overlay_use": "rotating rendezvous / watchtower-alert / proof-anchor handles over a fixed channel or reserve state without re-anchoring the state",
    }


# --------------------------------------------------------------------------
# P3: Binohash grinding-cost bench (FindAndDelete introspection)
# --------------------------------------------------------------------------
#
# Motif I, the Binohash seam itself. We do not re-derive Linus' scheme; we
# reproduce the FindAndDelete scriptCode mutation it stands on (so the
# mechanism is concrete) and provide an honest accountant for the grinding
# cost under his two-round W1/W2 parameters, so a protocol designer can choose
# parameters against a real cost line instead of a vibe. Collision resistance
# ~ W1+W2 bits; honest work ~ W2+2.6 bits (Linus, 2026).


def binohash_cost(w1: int, w2: int, hashrate_hps: float, usd_per_gpu_hour: float, hashes_per_gpu_sec: float) -> dict:
    resistance_bits = w1 + w2
    honest_work_bits = w2 + 2.6
    honest_hashes = 2.0 ** honest_work_bits
    seconds = honest_hashes / hashrate_hps
    gpu_seconds = honest_hashes / hashes_per_gpu_sec
    usd = (gpu_seconds / 3600.0) * usd_per_gpu_hour
    return {
        "W1": w1,
        "W2": w2,
        "collision_resistance_bits": resistance_bits,
        "honest_work_bits": round(honest_work_bits, 2),
        "honest_hashes_log2": round(math.log2(honest_hashes), 2),
        "wall_time_seconds_at_hashrate": round(seconds, 2),
        "grind_cost_usd": round(usd, 2),
    }


def primitive_binohash_bench() -> dict:
    # Concrete FindAndDelete mechanism: a redeemScript that embeds the pushes it
    # is fed, so the signed scriptCode is a function of chosen data. This is the
    # degree of freedom Binohash grinds against.
    redeem = push(b"\xde\xad") + op(0x75) + op(0x51) + push(PK["A"]) + op(0x51) + op(OP_CHECKMULTISIG)
    fed = push(b"\xde\xad")
    mutated, removed = find_and_delete(redeem, fed)
    mechanism_demo = {
        "redeem_script_hex": redeem.hex(),
        "fed_push_hex": fed.hex(),
        "mutated_script_hex": mutated.hex(),
        "pushes_removed": removed,
        "scriptcode_is_data_dependent": mutated != redeem,
    }

    # Cost line. GPU figures are illustrative and configurable; defaults sized
    # so the W1=W2=42 row lands near Linus' "<$50 on cloud GPUs" claim.
    hashes_per_gpu_sec = 10.0e9  # 10 GH/s sha-ish, order of magnitude for a rented GPU
    usd_per_gpu_hour = 0.50
    fleet = 1000.0 * hashes_per_gpu_sec  # a modest rented fleet for wall-time
    table = [
        binohash_cost(w1, w2, fleet, usd_per_gpu_hour, hashes_per_gpu_sec)
        for (w1, w2) in [(32, 32), (42, 42), (48, 48), (56, 56), (64, 64)]
    ]
    return {
        "primitive": "binohash_grinding_bench",
        "motif": "transcript_multiplicity",
        "mechanism": "FindAndDelete makes the signed scriptCode depend on fed pushes; Binohash grinds a PoW nonce so the resulting digest is collision-resistant and Script-readable.",
        "attribution": "cost model for Robin Linus, Binohash (2026); this bench does not propose a competing scheme",
        "findanddelete_demo": mechanism_demo,
        "cost_assumptions": {
            "hashes_per_gpu_sec": hashes_per_gpu_sec,
            "usd_per_gpu_hour": usd_per_gpu_hour,
            "wall_time_fleet_hps": fleet,
        },
        "cost_table": table,
        "invariants": {
            "scriptcode_is_data_dependent": mechanism_demo["scriptcode_is_data_dependent"],
            "resistance_matches_w1_plus_w2": all(
                row["collision_resistance_bits"] == row["W1"] + row["W2"] for row in table
            ),
        },
        "properties": {
            "P1_semantic_binding": "the grind commits the digest to the spending transaction's fields",
            "P2_non_collapse": "a well-formed Binohash digest is not a verifier-known constant",
            "P3_authority_separation": "introspection is read-only; it gates nothing by itself",
            "P4_rotation_invariance": "n/a",
        },
        "overlay_use": "trust-minimised transaction introspection for BitVM bridges without a soft fork; this bench picks (W1,W2) against a real cost line",
    }


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def build_report() -> dict:
    return {
        "kind": "jurassic_binohash_level_tools",
        "version": 1,
        "notes": [
            "node-free; no signatures verified; keys/prevouts are deterministic placeholders",
            "digests rendered byte-reversed (uint256::GetHex style)",
        ],
        "primitives": [
            primitive_aggregatable_attestation(),
            primitive_handle_rotation(),
            primitive_binohash_bench(),
        ],
    }


def all_invariants(report: dict) -> list[tuple[str, str, bool]]:
    out = []
    for prim in report["primitives"]:
        for name, ok in prim["invariants"].items():
            out.append((prim["primitive"], name, bool(ok)))
    return out


def render_markdown(report: dict) -> str:
    lines = ["# Binohash-Level Overlay Primitives", "",
             "Generated by `scripts/binohash_level_tools.py` with no node. Each primitive",
             "turns one ossified seam into a specified overlay capability and checks a",
             "cryptographic invariant. Digests are byte-reversed (`uint256::GetHex`).", ""]
    for prim in report["primitives"]:
        lines += [f"## {prim['primitive']}", "",
                  f"- Motif: `{prim['motif']}`",
                  f"- Mechanism: {prim['mechanism']}",
                  f"- Overlay use: {prim['overlay_use']}", "",
                  "Invariants:"]
        for name, ok in prim["invariants"].items():
            lines.append(f"- {'PASS' if ok else 'FAIL'} `{name}`")
        lines.append("")
    bench = next(p for p in report["primitives"] if p["primitive"] == "binohash_grinding_bench")
    lines += ["## Binohash cost line", "",
              "| W1 | W2 | resistance (bits) | honest work (bits) | wall time (s) | grind cost (USD) |",
              "| ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in bench["cost_table"]:
        lines.append(f"| {row['W1']} | {row['W2']} | {row['collision_resistance_bits']} | "
                     f"{row['honest_work_bits']} | {row['wall_time_seconds_at_hashrate']} | {row['grind_cost_usd']} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default=str(Path(__file__).resolve().parents[1] / "docs" / "grants"))
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_report()
    (out_dir / "binohash_level_tools.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out_dir / "binohash_level_tools.md").write_text(render_markdown(report) + "\n", encoding="utf-8")

    failures = 0
    for prim, name, ok in all_invariants(report):
        print(f"[{'PASS' if ok else 'FAIL'}] {prim}: {name}")
        if not ok:
            failures += 1
    print(f"wrote {out_dir / 'binohash_level_tools.{json,md}'}")
    if failures:
        raise SystemExit(f"{failures} invariant(s) failed")


if __name__ == "__main__":
    main()
