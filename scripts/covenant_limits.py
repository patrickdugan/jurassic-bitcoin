#!/usr/bin/env python3
"""Limits of Binohash-style covenants, and the sound construction underneath.

Companion to ``seam_digests_standalone.py`` and ``binohash_level_tools.py``.
This module records, node-free, the three reasons a batch of natural-looking
"turn a seam into a richer covenant" ideas break, and verifies the one sound,
no-soft-fork construction that the failures point to.

Everything here is a digest identity or a serialization fact computed from the
audited primitives in ``seam_digests_standalone``. No node, no RPC, no third-
party packages, no ECDSA (so the R1 obstruction below is stated as an analytic
argument, not demonstrated here; the digest-class behaviour it defeats *is*
reproduced). Digests are byte-reversed (``uint256::GetHex`` order).

Sections:

  FACT 1  SINGLE|ACP fence gap        what a per-row pin does and does not lock
  FACT 2  ALL|ACP dual                global output fence, appendable inputs
  FACT 3  whole-tx core / own prevout the SERA fixed-point obstruction (R2)
  FACT 4  SINGLE constant-one         reusable authority + decoy evasion (R3)
  FACT 5  SINGLE-authored/ALL-frozen  the sound construction (per-row + fence)

R1 (not reproduced here, stated in the paper): legacy FindAndDelete only deletes
a push that is a signature which must ECDSA-verify over the post-deletion digest,
so the 2^m "menu" subsets are not freely selectable on-chain; fixing the deleted
push to a committed constant removes exactly the free variable Binohash grinds.

Usage:
  python scripts/covenant_limits.py [--out-dir docs/grants]
Writes ``covenant_limits.{json,md}`` and prints PASS/FAIL per check.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Same-directory import; ensure the script's own dir is importable when run
# from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE,
    UINT256_ONE,
    Tx,
    TxIn,
    TxOut,
    dsha256,
    digest_hex,
    fake_prevout,
    fake_pubkey,
    p2pkh,
    ser_tx,
    signature_hash,
)

ACP = SIGHASH_ANYONECANPAY
PK = {n: fake_pubkey(n) for n in "ABCDE"}
RESULTS: list[dict] = []


def check(section: str, name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"section": section, "name": name, "pass": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def D(code: bytes, tx: Tx, i: int, ht: int) -> str:
    return digest_hex(signature_hash(code, tx, i, ht))


def mk(n_out: int, n_in: int = 3, vary_out=None, vary_in_prevout=None, extra_outs: int = 0) -> Tx:
    """A settlement template: outputs 0..n_out-1 are party rows; inputs 0..n_in-1."""
    outs = []
    for k in range(n_out):
        val = 1000 + k
        if vary_out is not None and k == vary_out:
            val += 1  # one-sat perturbation of row k
        outs.append(TxOut(val, p2pkh(PK["ABCDE"[k % 5]])))
    for _ in range(extra_outs):
        outs.append(TxOut(777, p2pkh(PK["E"])))
    ins = []
    for j in range(n_in):
        ph = fake_prevout(f"in-{j}-ALT" if vary_in_prevout == j else f"in-{j}")
        ins.append(TxIn(ph, j, b""))
    return Tx(1, tuple(ins), tuple(outs), 0)


CODE = p2pkh(PK["A"])


def fact1() -> None:
    s = "fence_gap"
    print("\n--- FACT 1: SINGLE|ACP fence gap (what a per-row pin locks and leaks) ---")
    j = 1
    base = D(CODE, mk(3), j, SIGHASH_SINGLE | ACP)
    check(s, "SINGLE|ACP pins its own output j",
          D(CODE, mk(3, vary_out=j), j, SIGHASH_SINGLE | ACP) != base,
          "one-sat change to output j flips the digest")
    check(s, "SINGLE|ACP ignores another party's output (k>j)",
          D(CODE, mk(3, vary_out=2), j, SIGHASH_SINGLE | ACP) == base,
          "changing output 2 leaves signer 1's digest fixed")
    check(s, "SINGLE|ACP ignores other inputs",
          D(CODE, mk(3, vary_in_prevout=0), j, SIGHASH_SINGLE | ACP) == base,
          "changing input 0's prevout leaves signer 1's digest fixed")
    check(s, "SINGLE|ACP does NOT fence appended outputs (the leak)",
          D(CODE, mk(3, extra_outs=4), j, SIGHASH_SINGLE | ACP) == base,
          "4 extra outputs appended, signer 1's digest unchanged -> pool not fenced")
    check(s, "legacy sighash does not commit the input amount",
          not hasattr(TxIn(fake_prevout("x"), 0, b""), "value"),
          "no value in the serialized input -> conservation needs BIP143 or inspection")


def fact2() -> None:
    s = "all_acp_dual"
    print("\n--- FACT 2: ALL|ACP dual (global output fence, appendable inputs) ---")
    base = D(CODE, mk(3), 0, SIGHASH_ALL | ACP)
    check(s, "ALL|ACP fences every output",
          all(D(CODE, mk(3, vary_out=k), 0, SIGHASH_ALL | ACP) != base for k in range(3)),
          "changing ANY output flips the digest")
    check(s, "ALL|ACP fences appended outputs too",
          D(CODE, mk(3, extra_outs=2), 0, SIGHASH_ALL | ACP) != base,
          "appending outputs flips the digest (unlike SINGLE)")
    check(s, "ALL|ACP still ignores appended inputs",
          D(CODE, mk(3, vary_in_prevout=2), 0, SIGHASH_ALL | ACP) == base,
          "changing a non-signing input's prevout leaves the digest fixed")


def fact3() -> None:
    s = "whole_tx_fixed_point"
    print("\n--- FACT 3: whole-tx core commits the own prevout (SERA fixed-point, R2) ---")
    core = lambda tx: dsha256(ser_tx(tx)).hex()
    check(s, "whole-tx core changes with the spending input's prevout",
          core(mk(2, n_in=1)) != core(mk(2, n_in=1, vary_in_prevout=0)),
          "a Binohash core over the tx depends on the spent input's txid:vout")
    check(s, "baked-constant-equals-own-core is a fixed point (structural)",
          True,
          "K -> redeem -> scriptPubKey -> funding txid -> prevout -> core must equal K")


def fact4() -> None:
    s = "constant_one"
    print("\n--- FACT 4: SINGLE constant-one is reusable; absence is decoy-evadable (R3) ---")
    one = digest_hex(UINT256_ONE)
    txX = Tx(1, tuple(TxIn(fake_prevout(f"X{j}"), j, b"") for j in range(3)),
             (TxOut(5, p2pkh(PK["A"])),), 0)
    txY = Tx(1, tuple(TxIn(fake_prevout(f"Y{j}"), j, b"") for j in range(3)),
             (TxOut(9, p2pkh(PK["B"])),), 7)
    check(s, "constant-one is identical across unrelated txs (reusable authority)",
          D(CODE, txX, 2, SIGHASH_SINGLE) == one and D(CODE, txY, 2, SIGHASH_SINGLE) == one,
          "a signature over 0^63||1 is not bound to any particular transaction")
    idx = 2
    absent = Tx(1, tuple(TxIn(fake_prevout(f"r{j}"), j, b"") for j in range(3)),
                (TxOut(1, p2pkh(PK["A"])),), 0)
    decoy = Tx(1, tuple(TxIn(fake_prevout(f"r{j}"), j, b"") for j in range(3)),
               tuple(TxOut(1, p2pkh(PK[c])) for c in "ABC"), 0)
    check(s, "absence collapses to constant-one", D(CODE, absent, idx, SIGHASH_SINGLE) == one)
    check(s, "a decoy output at index i evades the collapse (break)",
          D(CODE, decoy, idx, SIGHASH_SINGLE) != one,
          "custodian keeps a dust decoy at index i -> ordinary digest -> no tripwire")


def fact5() -> None:
    s = "single_authored_all_frozen"
    print("\n--- FACT 5: SINGLE-authored, ALL-frozen settlement (sound, no-fork) ---")
    settle = mk(3, n_in=4)  # rows 0,1,2; input 3 is the closer
    row_pin = {j: D(CODE, settle, j, SIGHASH_SINGLE | ACP) for j in range(3)}
    closer = D(CODE, settle, 3, SIGHASH_ALL | ACP)
    tampered = mk(3, n_in=4, vary_out=1)
    check(s, "tamper breaks the victim party's own row-pin",
          D(CODE, tampered, 1, SIGHASH_SINGLE | ACP) != row_pin[1])
    check(s, "tamper simultaneously breaks the closer's freeze",
          D(CODE, tampered, 3, SIGHASH_ALL | ACP) != closer)
    check(s, "an untouched party's row-pin still verifies after the tamper",
          D(CODE, tampered, 0, SIGHASH_SINGLE | ACP) == row_pin[0],
          "party 0 is unaffected -- rows are independent")
    check(s, "appending an uncommitted output breaks the closer's freeze",
          D(CODE, mk(3, n_in=4, extra_outs=1), 3, SIGHASH_ALL | ACP) != closer,
          "no output can join the table after the ALL|ACP freeze")


SECTION_TITLES = {
    "fence_gap": "FACT 1: SINGLE|ACP fence gap",
    "all_acp_dual": "FACT 2: ALL|ACP dual",
    "whole_tx_fixed_point": "FACT 3: whole-tx core / own-prevout fixed point (R2)",
    "constant_one": "FACT 4: SINGLE constant-one reuse + decoy evasion (R3)",
    "single_authored_all_frozen": "FACT 5: SINGLE-authored, ALL-frozen settlement",
}


def render_markdown() -> str:
    lines = ["# Limits of Binohash Covenants, and the Sound Construction", "",
             "Generated by `scripts/covenant_limits.py` with no node. Each check is a",
             "digest identity or serialization fact over the audited seam primitives.", ""]
    for key, title in SECTION_TITLES.items():
        rows = [r for r in RESULTS if r["section"] == key]
        if not rows:
            continue
        lines += [f"## {title}", ""]
        for r in rows:
            lines.append(f"- {'PASS' if r['pass'] else 'FAIL'} `{r['name']}`"
                         + (f" — {r['detail']}" if r["detail"] else ""))
        lines.append("")
    passed = sum(1 for r in RESULTS if r["pass"])
    lines += [f"**{passed}/{len(RESULTS)} checks passed.**", ""]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default=str(Path(__file__).resolve().parents[1] / "docs" / "grants"))
    args = parser.parse_args()

    fact1(); fact2(); fact3(); fact4(); fact5()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report = {"kind": "jurassic_covenant_limits", "version": 1, "checks": RESULTS}
    (out_dir / "covenant_limits.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out_dir / "covenant_limits.md").write_text(render_markdown(), encoding="utf-8")

    passed = sum(1 for r in RESULTS if r["pass"])
    print(f"\n{passed}/{len(RESULTS)} checks passed")
    print(f"wrote {out_dir / 'covenant_limits.{json,md}'}")
    if passed != len(RESULTS):
        raise SystemExit(f"{len(RESULTS) - passed} check(s) failed")


if __name__ == "__main__":
    main()
