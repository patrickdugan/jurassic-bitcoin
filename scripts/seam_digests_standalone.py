#!/usr/bin/env python3
"""Standalone analytic reproduction of the three Jurassic seam surfaces.

No Bitcoin node, no RPC, no third-party packages. Every value below is a pure
function of legacy (pre-SegWit) transaction serialization and the original
``SignatureHash`` algorithm from Bitcoin Core ``src/script/interpreter.cpp``,
including ``FindAndDelete`` and the ``SIGHASH_SINGLE`` out-of-range return of
``uint256::ONE``. A reader can therefore verify every digest quoted in
``docs/grants/jurassic_design_motifs.tex`` by running this file.

The regtest-minted seams in ``fixtures/manifests/*_core_seam_poc.json`` remain
the funded, Core-oracle-stamped versions of the same surfaces; this script is
the node-free companion so the *cryptographic* claim (which digests alias,
which collapse, which txids move) can be checked without a node.

Seams reproduced:

  A. FindAndDelete context split   (motif I: transcript multiplicity)
  B. SIGHASH_SINGLE degeneracy     (motif I hazard, the constant-one tripwire)
  C. DUMMYGRIND txid axis          (motif II: identifier bifurcation)

Usage:

  python scripts/seam_digests_standalone.py [--out-dir docs/grants]

Writes ``seam_digests_standalone.{json,md,tex}`` into the output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass, replace
from pathlib import Path

# --------------------------------------------------------------------------
# Opcodes and sighash flags (only what the seams need)
# --------------------------------------------------------------------------

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_DROP = 0x75
OP_DUP = 0x76
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_HASH160 = 0xA9
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

MASK32 = 0xFFFFFFFF


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def dsha256(data: bytes) -> bytes:
    return sha256(sha256(data))


def _rol(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def ripemd160_py(msg: bytes) -> bytes:
    """Pure-Python RIPEMD-160 (OpenSSL 3 builds often lack it in hashlib)."""
    r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    r2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    s1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    s2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    k1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    k2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]

    def f(j: int, x: int, y: int, z: int) -> int:
        if j < 16:
            return x ^ y ^ z
        if j < 32:
            return (x & y) | ((~x) & z)
        if j < 48:
            return (x | (~y)) ^ z
        if j < 64:
            return (x & z) | (y & (~z))
        return x ^ (y | (~z))

    bit_len = len(msg) * 8
    padded = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + struct.pack("<Q", bit_len)
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(padded), 64):
        x = list(struct.unpack("<16I", padded[off:off + 64]))
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            t = (_rol((al + f(j, bl, cl, dl) + x[r1[j]] + k1[j // 16]) & MASK32, s1[j]) + el) & MASK32
            al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
            t = (_rol((ar + f(79 - j, br, cr, dr) + x[r2[j]] + k2[j // 16]) & MASK32, s2[j]) + er) & MASK32
            ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        t = (h[1] + cl + dr) & MASK32
        h[1] = (h[2] + dl + er) & MASK32
        h[2] = (h[3] + el + ar) & MASK32
        h[3] = (h[4] + al + br) & MASK32
        h[4] = (h[0] + bl + cr) & MASK32
        h[0] = t
    return struct.pack("<5I", *h)


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except (ValueError, TypeError):
        return ripemd160_py(data)


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def _self_test_ripemd160() -> None:
    assert ripemd160_py(b"").hex() == "9c1185a5c5e9fc54612808977ee8f548b2258d31"
    assert ripemd160_py(b"abc").hex() == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"


# --------------------------------------------------------------------------
# Script helpers (mirroring CScript semantics that matter here)
# --------------------------------------------------------------------------


def varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def push(data: bytes) -> bytes:
    """``CScript << std::vector<unsigned char>``: size-based push encoding.

    Note that a one-byte vector is encoded as ``01 xx`` (never OP_1..OP_16),
    and the empty vector is ``00`` (OP_0). This is exactly what makes the
    empty-dummy and one-byte-zero-dummy variants in seam C serialize
    differently.
    """
    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def op(code: int) -> bytes:
    return bytes([code])


def get_op(script: bytes, pc: int) -> tuple[int, int, bytes]:
    opcode = script[pc]
    pc += 1
    if opcode <= 0x4B:
        n = opcode
    elif opcode == OP_PUSHDATA1:
        n = script[pc]
        pc += 1
    elif opcode == OP_PUSHDATA2:
        n = struct.unpack("<H", script[pc:pc + 2])[0]
        pc += 2
    elif opcode == OP_PUSHDATA4:
        n = struct.unpack("<I", script[pc:pc + 4])[0]
        pc += 4
    else:
        n = 0
    data = script[pc:pc + n]
    pc += n
    return pc, opcode, data


def find_and_delete(script: bytes, pattern: bytes) -> tuple[bytes, int]:
    """Port of ``CScript::FindAndDelete``: delete ``pattern`` wherever it
    occurs *at an opcode boundary* of ``script``."""
    if not pattern:
        return script, 0
    out = bytearray()
    pc = 0
    pc2 = 0
    found = 0
    end = len(script)
    while True:
        out += script[pc2:pc]
        while end - pc >= len(pattern) and script[pc:pc + len(pattern)] == pattern:
            pc += len(pattern)
            found += 1
        pc2 = pc
        if pc >= end:
            break
        pc, _, _ = get_op(script, pc)
    out += script[pc2:end]
    return bytes(out), found


# --------------------------------------------------------------------------
# Legacy transaction model and the original SignatureHash
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class TxIn:
    prevout_hash: bytes  # internal byte order
    prevout_n: int
    script_sig: bytes
    sequence: int = 0xFFFFFFFF


@dataclass(frozen=True)
class TxOut:
    value: int  # satoshis; -1 encodes the "null" output used by SIGHASH_SINGLE
    script_pubkey: bytes


@dataclass(frozen=True)
class Tx:
    version: int
    vin: tuple[TxIn, ...]
    vout: tuple[TxOut, ...]
    locktime: int = 0


def ser_tx(tx: Tx) -> bytes:
    out = struct.pack("<i", tx.version)
    out += varint(len(tx.vin))
    for txin in tx.vin:
        out += txin.prevout_hash + struct.pack("<I", txin.prevout_n)
        out += varint(len(txin.script_sig)) + txin.script_sig
        out += struct.pack("<I", txin.sequence)
    out += varint(len(tx.vout))
    for txout in tx.vout:
        out += struct.pack("<q", txout.value)
        out += varint(len(txout.script_pubkey)) + txout.script_pubkey
    out += struct.pack("<I", tx.locktime)
    return out


def txid_hex(tx: Tx) -> str:
    return dsha256(ser_tx(tx))[::-1].hex()


UINT256_ONE = (1).to_bytes(32, "little")  # GetHex() renders as 000...0001


def signature_hash(script_code: bytes, tx: Tx, n_in: int, hash_type: int) -> bytes:
    """The pre-BIP143 ``SignatureHash`` (``interpreter.cpp``), verbatim in
    behaviour: returns ``uint256::ONE`` for an out-of-range input index or an
    out-of-range ``SIGHASH_SINGLE`` output index instead of a real digest."""
    if n_in >= len(tx.vin):
        return UINT256_ONE
    base = hash_type & 0x1F
    if base == SIGHASH_SINGLE and n_in >= len(tx.vout):
        return UINT256_ONE

    code, _ = find_and_delete(script_code, op(OP_CODESEPARATOR))
    vin = [replace(txin, script_sig=(code if i == n_in else b"")) for i, txin in enumerate(tx.vin)]
    vout = list(tx.vout)

    if base == SIGHASH_NONE:
        vout = []
        vin = [replace(txin, sequence=(txin.sequence if i == n_in else 0)) for i, txin in enumerate(vin)]
    elif base == SIGHASH_SINGLE:
        vout = vout[:n_in + 1]
        for i in range(n_in):
            vout[i] = TxOut(-1, b"")
        vin = [replace(txin, sequence=(txin.sequence if i == n_in else 0)) for i, txin in enumerate(vin)]

    if hash_type & SIGHASH_ANYONECANPAY:
        vin = [vin[n_in]]

    tmp = Tx(tx.version, tuple(vin), tuple(vout), tx.locktime)
    return dsha256(ser_tx(tmp) + struct.pack("<I", hash_type))


def digest_hex(d: bytes) -> str:
    """Render like ``uint256::GetHex()`` (byte-reversed), so the constant-one
    digest prints as 63 zeros followed by ``1`` exactly as the UTXORef
    ``rejectionTripwireDigest`` does."""
    return d[::-1].hex()


# --------------------------------------------------------------------------
# Deterministic specimen material (no real keys are needed for hashing)
# --------------------------------------------------------------------------


def fake_pubkey(label: str) -> bytes:
    return b"\x02" + sha256(f"jurassic-key-{label}".encode())


def fake_prevout(label: str) -> bytes:
    return sha256(f"jurassic-prevout-{label}".encode())


def p2pkh(pubkey: bytes) -> bytes:
    return op(OP_DUP) + op(OP_HASH160) + push(hash160(pubkey)) + op(OP_EQUALVERIFY) + op(OP_CHECKSIG)


def p2sh(redeem: bytes) -> bytes:
    return op(OP_HASH160) + push(hash160(redeem)) + op(OP_EQUAL)


PK_A, PK_B, PK_C, PK_D = (fake_pubkey(x) for x in "ABCD")


# --------------------------------------------------------------------------
# Seam A: FindAndDelete context split
# --------------------------------------------------------------------------


def seam_findanddelete() -> dict:
    # A redeemScript that *contains* the signature pushes it will be fed. Only
    # such a script can make legacy FindAndDelete change the scriptCode; it is
    # a crafted, legacy-only degree of freedom, which is the point.
    redeem = (
        push(b"\xaa") + op(OP_DROP) + push(b"\xbb") + op(OP_DROP)
        + op(OP_2) + push(PK_A) + push(PK_B) + push(PK_C) + op(OP_3) + op(OP_CHECKMULTISIG)
    )
    variants = [
        ("baseline_cc", [b"\xcc"], "signature absent from scriptCode: nothing deleted"),
        ("subset_aa", [b"\xaa"], "one aa signature: both aa pushes deleted"),
        ("subset_aaaa", [b"\xaa", b"\xaa"], "two aa signatures: same scriptCode as subset_aa"),
        ("subset_aabb", [b"\xaa", b"\xbb"], "aa and bb: a second push class is deleted"),
    ]
    rows = []
    for vid, sigs, note in variants:
        script_sig = op(OP_0) + b"".join(push(s) for s in sigs) + push(redeem)
        tx = Tx(
            version=1,
            vin=(TxIn(fake_prevout("fad"), 0, script_sig),),
            vout=(TxOut(50_000, p2pkh(PK_D)),),
        )
        code = redeem
        removed = 0
        for s in sigs:
            code, n = find_and_delete(code, push(s))
            removed += n
        digest = signature_hash(code, tx, 0, SIGHASH_ALL)
        rows.append({
            "variant": vid,
            "signatures": [s.hex() for s in sigs],
            "note": note,
            "pushes_removed": removed,
            "script_code_hex": code.hex(),
            "script_code_sha256": sha256(code).hex(),
            "txid": txid_hex(tx),
            "sighash_digest": digest_hex(digest),
        })
    classes: dict[str, list[str]] = {}
    for r in rows:
        classes.setdefault(r["sighash_digest"], []).append(r["variant"])
    return {
        "seam": "findanddelete_context_split",
        "motif": "transcript_multiplicity",
        "redeem_script_hex": redeem.hex(),
        "script_pubkey_hex": p2sh(redeem).hex(),
        "sighash_type": "0x01",
        "rows": rows,
        "digest_classes": classes,
        "claims": [
            "subset_aa and subset_aaaa share one sighash digest (FindAndDelete is idempotent per push class)",
            "subset_aabb has a distinct digest under the same spend family and the same policy envelope",
            "every variant has a distinct txid because the scriptSig differs; the digest classes are what the motif is about",
        ],
    }


# --------------------------------------------------------------------------
# Seam B: SIGHASH_SINGLE degeneracy
# --------------------------------------------------------------------------


def seam_sighash_single() -> dict:
    script_code = p2pkh(PK_A)
    vin = (
        TxIn(fake_prevout("single-0"), 0, b""),
        TxIn(fake_prevout("single-1"), 1, b""),
    )
    bug_tx = Tx(1, vin, (TxOut(40_000, p2pkh(PK_D)),))
    control_tx = Tx(1, vin, (TxOut(40_000, p2pkh(PK_D)), TxOut(9_000, p2pkh(PK_B))))
    variants = [
        ("sighash_single_bug", bug_tx, SIGHASH_SINGLE, "2-in/1-out, sign input 1 with SINGLE"),
        ("sighash_single_bug_anyonecanpay", bug_tx, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, "2-in/1-out, SINGLE|ANYONECANPAY"),
        ("sighash_single_control", control_tx, SIGHASH_SINGLE, "2-in/2-out, sign input 1 with SINGLE"),
        ("sighash_single_control_anyonecanpay", control_tx, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY, "2-in/2-out, SINGLE|ANYONECANPAY"),
    ]
    rows = []
    for vid, tx, ht, note in variants:
        d = signature_hash(script_code, tx, 1, ht)
        rows.append({
            "variant": vid,
            "sighash_type": f"0x{ht:02x}",
            "inputs": len(tx.vin),
            "outputs": len(tx.vout),
            "input_index": 1,
            "note": note,
            "txid_unsigned_template": txid_hex(tx),
            "sighash_digest": digest_hex(d),
            "constant_one": d == UINT256_ONE,
        })
    return {
        "seam": "sighash_single_degeneracy",
        "motif": "transcript_multiplicity_hazard",
        "script_code_hex": script_code.hex(),
        "constant_one_digest": digest_hex(UINT256_ONE),
        "rows": rows,
        "claims": [
            "both bug specimens collapse to the constant-one digest regardless of ANYONECANPAY",
            "both controls produce ordinary, distinct digests",
            "a signature over the constant-one digest is valid for any transaction that reaches the same out-of-range branch, which is why overlays must treat it as a rejection tripwire, never as an identifier",
        ],
    }


# --------------------------------------------------------------------------
# Seam C: DUMMYGRIND txid axis
# --------------------------------------------------------------------------


def seam_dummygrind() -> dict:
    redeem = op(OP_1) + push(PK_A) + op(OP_1) + op(OP_CHECKMULTISIG)
    sig = bytes.fromhex("3044" + "aa" * 68 + "01")  # DER-shaped placeholder + SIGHASH_ALL byte
    variants = [
        ("dummygrind_empty", b"", "empty vector dummy (OP_0): the NULLDUMMY-clean form"),
        ("dummygrind_zero", b"\x00", "one-byte zero push (01 00): same numeric value, different bytes"),
        ("dummygrind_32", b"\x00" * 32, "32-byte dummy: a 256-bit free field in the unlocking data"),
    ]
    rows = []
    for vid, dummy, note in variants:
        script_sig = push(dummy) + push(sig) + push(redeem)
        tx = Tx(1, (TxIn(fake_prevout("dummy"), 0, script_sig),), (TxOut(30_000, p2pkh(PK_D)),))
        code, _ = find_and_delete(redeem, push(sig))
        d = signature_hash(code, tx, 0, SIGHASH_ALL)
        rows.append({
            "variant": vid,
            "dummy_hex": dummy.hex(),
            "dummy_push_hex": push(dummy).hex(),
            "note": note,
            "txid": txid_hex(tx),
            "sighash_digest": digest_hex(d),
            "policy_note": "non-empty dummy violates SCRIPT_VERIFY_NULLDUMMY (standardness for legacy, consensus for witness v0 since BIP147)",
        })
    digests = {r["sighash_digest"] for r in rows}
    txids = {r["txid"] for r in rows}
    return {
        "seam": "dummygrind_txid_axis",
        "motif": "identifier_bifurcation",
        "redeem_script_hex": redeem.hex(),
        "script_pubkey_hex": p2sh(redeem).hex(),
        "rows": rows,
        "distinct_txids": len(txids),
        "distinct_sighash_digests": len(digests),
        "claims": [
            "three distinct txids over one unchanged sighash digest: the public identifier moves while the committed core is fixed",
            "no re-signing is needed because the legacy digest blanks every scriptSig and substitutes the redeemScript",
        ],
    }


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def short(h: str, n: int = 16) -> str:
    return h[:n] + "…"


def short_tex(h: str, n: int = 16) -> str:
    """LaTeX-safe prefix (inputenc/T1 cannot render U+2026)."""
    return h[:n] + "\\ldots"


def render_markdown(report: dict) -> str:
    a, b, c = report["seams"]
    lines = ["# Standalone Seam Digests", "",
             "Generated by `scripts/seam_digests_standalone.py` with no node. Digests are",
             "rendered like `uint256::GetHex()` (byte-reversed hex).", ""]
    lines += ["## Seam A: FindAndDelete context split", "",
              f"redeemScript: `{a['redeem_script_hex']}`", "",
              "| variant | sigs | pushes removed | scriptCode sha256 | sighash digest | txid |",
              "| --- | --- | ---: | --- | --- | --- |"]
    for r in a["rows"]:
        lines.append(f"| `{r['variant']}` | `{','.join(r['signatures'])}` | {r['pushes_removed']} | `{short(r['script_code_sha256'])}` | `{r['sighash_digest']}` | `{short(r['txid'])}` |")
    lines += ["", "Digest classes:", ""]
    for d, vs in a["digest_classes"].items():
        lines.append(f"- `{short(d)}`: {', '.join(vs)}")
    lines += ["", "## Seam B: SIGHASH_SINGLE degeneracy", "",
              "| variant | type | in/out | sighash digest | constant one |",
              "| --- | --- | --- | --- | --- |"]
    for r in b["rows"]:
        lines.append(f"| `{r['variant']}` | `{r['sighash_type']}` | {r['inputs']}/{r['outputs']} | `{r['sighash_digest']}` | {r['constant_one']} |")
    lines += ["", "## Seam C: DUMMYGRIND txid axis", "",
              f"redeemScript: `{c['redeem_script_hex']}`", "",
              "| variant | dummy push | txid | sighash digest |",
              "| --- | --- | --- | --- |"]
    for r in c["rows"]:
        lines.append(f"| `{r['variant']}` | `{r['dummy_push_hex'] or '(none)'}` | `{r['txid']}` | `{short(r['sighash_digest'])}` |")
    lines += ["", f"distinct txids: {c['distinct_txids']}; distinct sighash digests: {c['distinct_sighash_digests']}", ""]
    return "\n".join(lines)


def tex_escape(s: str) -> str:
    return s.replace("_", "\\_")


def render_latex(report: dict) -> str:
    short = short_tex  # noqa: F841 - shadow the markdown helper with the LaTeX-safe one
    a, b, c = report["seams"]
    out = ["% Generated by scripts/seam_digests_standalone.py; do not edit by hand.", ""]
    out += ["\\begin{tabular}{llrll}", "\\toprule",
            "Variant & Signatures & Removed & scriptCode (sha256) & Legacy sighash digest \\\\", "\\midrule"]
    for r in a["rows"]:
        out.append(f"\\texttt{{{tex_escape(r['variant'])}}} & \\texttt{{{','.join(r['signatures'])}}} & {r['pushes_removed']} & \\texttt{{{short(r['script_code_sha256'])}}} & \\texttt{{{short(r['sighash_digest'])}}} \\\\")
    out += ["\\bottomrule", "\\end{tabular}", ""]
    out += ["\\begin{tabular}{llcl}", "\\toprule",
            "Variant & Type & In/Out & Legacy sighash digest \\\\", "\\midrule"]
    for r in b["rows"]:
        d = r["sighash_digest"]
        shown = "$0^{63}1$ (constant one)" if r["constant_one"] else f"\\texttt{{{short(d)}}}"
        out.append(f"\\texttt{{{tex_escape(r['variant'])}}} & \\texttt{{{r['sighash_type']}}} & {r['inputs']}/{r['outputs']} & {shown} \\\\")
    out += ["\\bottomrule", "\\end{tabular}", ""]
    out += ["\\begin{tabular}{llll}", "\\toprule",
            "Variant & Dummy push & txid & Legacy sighash digest \\\\", "\\midrule"]
    for r in c["rows"]:
        out.append(f"\\texttt{{{tex_escape(r['variant'])}}} & \\texttt{{{r['dummy_push_hex'][:8] + ('\\ldots' if len(r['dummy_push_hex']) > 8 else '')}}} & \\texttt{{{short(r['txid'])}}} & \\texttt{{{short(r['sighash_digest'])}}} \\\\")
    out += ["\\bottomrule", "\\end{tabular}", ""]
    return "\n".join(out)


def build_report() -> dict:
    _self_test_ripemd160()
    return {
        "kind": "jurassic_seam_digests_standalone",
        "version": 1,
        "notes": [
            "pure-function reproduction; no node, no RPC, no signatures verified",
            "digest hex is byte-reversed (uint256::GetHex style)",
            "keys and prevouts are deterministic sha256 placeholders",
        ],
        "seams": [seam_findanddelete(), seam_sighash_single(), seam_dummygrind()],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", default=str(Path(__file__).resolve().parents[1] / "docs" / "grants"))
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    report = build_report()
    (out_dir / "seam_digests_standalone.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (out_dir / "seam_digests_standalone.md").write_text(render_markdown(report) + "\n", encoding="utf-8")
    (out_dir / "seam_digests_standalone.tex").write_text(render_latex(report) + "\n", encoding="utf-8")

    a, b, c = report["seams"]
    print("seam A digest classes:")
    for d, vs in a["digest_classes"].items():
        print(f"  {d}  <- {', '.join(vs)}")
    print("seam B:")
    for r in b["rows"]:
        print(f"  {r['variant']:38s} {r['sighash_type']} {r['inputs']}/{r['outputs']} {r['sighash_digest']} one={r['constant_one']}")
    print("seam C:")
    for r in c["rows"]:
        print(f"  {r['variant']:18s} txid={r['txid']} digest={r['sighash_digest']}")
    print(f"  distinct txids={c['distinct_txids']} distinct digests={c['distinct_sighash_digests']}")
    print(f"wrote {out_dir / 'seam_digests_standalone.{json,md,tex}'}")


if __name__ == "__main__":
    main()
