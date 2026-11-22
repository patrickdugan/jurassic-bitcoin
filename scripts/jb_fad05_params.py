#!/usr/bin/env python3
"""JB-FAD05 parameter budget: how far the HORS-attested Binohash round scales
under legacy Script limits, and what the measured attacks cost.

Script sizes come from calling the real jb_fad05.round_script for (n, t)
with placeholder 73-byte pool-signature pushes (a 72-byte DER signature plus
flag, the upper end of what the fixture pool produces) and 20-byte HASH160
commitments. Opcode counts include Core's CHECKMULTISIG key charge.

Work model (stated, not measured beyond the toy run):
  w      puzzle difficulty per nonce round, bits (a random fixed-R ECDSA
         signature meets the size gate with probability 2^-w)
  R      rounds; F sighash flag bytes an attacker may try per signature
  honest ~ R * 2^w nonce sighashes (+ pins)
  front-run with leaked preimages for FIXED subsets:
         candidates ~ 2^(R*w) / F^R, each re-solving the last pin (2^p)
Legacy Script cannot read a signature's final byte, so F = 240 ALL-like
flags is the consensus-relevant value; F = 1 is what the off-chain referee
enforces and what Bitcoin cannot.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

MAX_OPS = 201
MAX_SCRIPT = 10_000
FLAGS_LEGACY = 240


PLACEHOLDER_SIG = bytes(72)        # 71-72 byte DER + flag; pushed as 73 bytes
PLACEHOLDER_HASH = bytes(20)
PLACEHOLDER_KEY = bytes([2]) + bytes(32)


def plain_round_script(n: int, t: int, above: int = 0) -> bytes:
    """Binohash selection without HORS, same leftover-tolerant layout."""
    from jb_fad05 import (snum, op, push, OP_ROLL, OP_SIZE, OP_LESSTHANOREQUAL,
                          OP_VERIFY, OP_TOALTSTACK, OP_PICK, OP_DUP, OP_WITHIN, OP_0,
                          OP_FROMALTSTACK, OP_CHECKMULTISIG)
    s = (snum(t + above) + op(OP_ROLL) + op(OP_SIZE) + snum(59) +
         op(OP_LESSTHANOREQUAL) + op(OP_VERIFY) + op(OP_TOALTSTACK))
    s += push(PLACEHOLDER_SIG) * n
    for i in range(t):
        rem = n - i
        sel = rem + above + (t - 1 - i)
        s += snum(sel) + op(OP_PICK) + op(OP_DUP)
        s += snum(0) if i == 0 else snum(sel + 3) + op(OP_PICK)
        s += snum(rem) + op(OP_WITHIN) + op(OP_VERIFY) + op(OP_ROLL) + op(OP_TOALTSTACK)
    s += op(OP_0) + op(OP_FROMALTSTACK) * (t + 1)
    s += snum(t + 1) + push(PLACEHOLDER_KEY) * (t + 1) + snum(t + 1) + op(OP_CHECKMULTISIG)
    return s


def build_script(n: int, t: int, *, rounds_in_script: int, hors: bool = True) -> bytes:
    from jb_fad05 import (pin_prefix, round_script, round_leftover, op,
                          OP_VERIFY, OP_CODESEPARATOR)
    from jb_fad03_pinning import FLAGS
    script = pin_prefix({name: PLACEHOLDER_KEY for name, _ in FLAGS})
    above = 0
    for k in range(rounds_in_script):
        if k:
            script += op(OP_VERIFY) + op(OP_CODESEPARATOR)
        if hors:
            script += round_script((PLACEHOLDER_SIG,) * n, PLACEHOLDER_KEY, PLACEHOLDER_KEY,
                                   (PLACEHOLDER_HASH,) * n, t=t, above=above)
            above += round_leftover(n, t)
        else:
            script += plain_round_script(n, t, above)
            above += (n - t) + t
    return script


def shape(n: int, t: int, *, rounds_in_script: int, hors: bool = True) -> dict:
    from jb_fad05 import static_counts
    if t + 1 > 20:
        return {"n": n, "t": t, "rounds_in_script": rounds_in_script, "hors": hors,
                "fits": False, "reason": "CHECKMULTISIG allows at most 20 keys"}
    c = static_counts(build_script(n, t, rounds_in_script=rounds_in_script, hors=hors))
    return {"n": n, "t": t, "rounds_in_script": rounds_in_script, "hors": hors,
            "script_bytes": c["script_bytes"], "core_op_count": c["core_op_count"],
            "fits": c["within_201"] and c["within_10000_bytes"],
            "subset_bits_per_round": round(math.log2(math.comb(n, t)), 2)}


def max_n(t: int, rounds_in_script: int, hors: bool = True) -> int | None:
    """Largest pool size that fits (fit is monotone in n: ops do not depend on n)."""
    lo, hi = t + 1, 400
    if not shape(lo, t, rounds_in_script=rounds_in_script, hors=hors)["fits"]:
        return None
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if shape(mid, t, rounds_in_script=rounds_in_script, hors=hors)["fits"]:
            lo = mid
        else:
            hi = mid - 1
    return lo


def frontier(rounds_in_script: int) -> dict:
    best = None
    for t in range(1, 20):
        n = max_n(t, rounds_in_script)
        if n is None:
            continue
        bits = math.log2(math.comb(n, t))
        if best is None or bits > best["subset_bits_per_round"]:
            best = shape(n, t, rounds_in_script=rounds_in_script) | {"subset_bits_per_round": round(bits, 2)}
    return best


def attack_costs(w: float, rounds: int, pin_bits: float = 8.0) -> dict:
    honest = math.log2(rounds) + w
    out = {"w_bits_per_round": w, "rounds": rounds,
           "honest_nonce_sighashes_log2": round(honest, 2)}
    for label, f in (("flags_unenforced_F240", FLAGS_LEGACY), ("flags_enforced_F1", 1)):
        cand = rounds * w - rounds * math.log2(f)
        cand = max(cand, 0.0)
        out[label] = {"candidates_log2": round(cand, 2),
                      "total_sig_work_log2": round(cand + pin_bits, 2)}
    return out


def build(measured: dict | None = None) -> dict:
    rows = []
    for n, t, k in ((10, 5, 2), (10, 5, 1), (50, 5, 2), (103, 10, 1), (120, 8, 1), (120, 8, 2)):
        rows.append(shape(n, t, rounds_in_script=k))
    rows.append(shape(120, 8, rounds_in_script=1, hors=False))
    rows.append(shape(120, 8, rounds_in_script=2, hors=False))
    report = {
        "limits": {"max_ops": MAX_OPS, "max_script_bytes": MAX_SCRIPT,
                   "checkmultisig_max_keys": 20,
                   "findanddelete_contexts": "legacy (bare) scripts only; P2SH redeem <= 520 bytes; "
                                             "BIP143/BIP341 sighash omit FindAndDelete"},
        "shapes": rows,
        "frontier_single_script_two_rounds": frontier(2),
        "frontier_one_round_per_input": frontier(1),
        "attack_models": {
            "toy_10C5_w8": attack_costs(8.0, 2),
            "binohash_120C8_w_eq_log2C": attack_costs(math.log2(math.comb(120, 8)), 2),
            "max_single_script_hors": attack_costs(frontier(2)["subset_bits_per_round"], 2),
        },
        "notes": [
            "raw subset space at 10C5 x2 is 15.95 bits; this is not a security level",
            "front-run cost assumes the ten revealed preimages are public (they are: scriptSig)",
            "F=240 because legacy consensus accepts every flag byte and 240 of 256 are ALL-like",
            "one-round-per-input shapes have no consensus-enforced cross-input dependency (native scenario G)",
        ],
    }
    if measured:
        report["measured_toy"] = measured
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--native-receipt")
    ap.add_argument("--output", default="docs/JB-FAD05-params.json")
    args = ap.parse_args()
    measured = None
    if args.native_receipt:
        r = json.loads(Path(args.native_receipt).read_text(encoding="utf-8"))
        measured = {"honest_attempts": r["honest"]["attempts"],
                    "front_run_attempts": r["D_reorg_front_run"]["front_run"]["attempts"],
                    "front_run_flags": r["D_reorg_front_run"]["front_run"]["nonce_flags"]}
    rep = build(measured)
    Path(args.output).write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"frontier_two_rounds": rep["frontier_single_script_two_rounds"],
                      "frontier_split": rep["frontier_one_round_per_input"],
                      "attack_models": rep["attack_models"]}, indent=2))


if __name__ == "__main__":
    main()
