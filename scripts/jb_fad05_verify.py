#!/usr/bin/env python3
"""JB-FAD05 byte-exact settlement referee and canonical BitVM statement.

Inputs are separated by trust class:

  policy   (authenticated)   registered before funding by a channel the
                             adversary cannot edit: vault outpoint, vault
                             script hash, HORS root, recipient, payout, fee,
                             verified program id, previous state root.
  witness  (adversary data)  raw funding tx, raw settlement tx, payout witness
                             script opening, block header, Merkle branch.
  anchor   (trusted)         a block hash taken from a validated header chain.

The referee re-parses the vault locking script from the raw funding output,
rebuilds it from the extracted parameters with its own layout code, and then
checks the settlement against it. Each check is labelled with the mechanism
that would enforce it on Bitcoin. Only checks labelled `bitcoin-consensus`
are guaranteed by the chain; the rest hold only where this referee (or a
BitVM circuit implementing it) is actually consulted.

This is an off-chain reference implementation. Its acceptance is never an
on-chain authorization condition.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from jb_fad02 import POOL_N, POOL_T, TARGET_SIG_BYTES
from jb_fad03_pinning import FLAGS
from jb_fad04_verify import (
    ProofRejected, build_merkle_branch, need, parse_canonical_pushes,
    parse_funding_tx, parse_legacy_tx, verify_block_inclusion,
    verify_ecdsa_pubkey, _depths_to_subset,
)
from jb_fad05_interp import ecdsa_ok
from seam_digests_standalone import (
    SIGHASH_ALL, SIGHASH_SINGLE, UINT256_ONE, find_and_delete, get_op,
    hash160, push, ser_tx, sha256, signature_hash, txid_hex,
)

STATEMENT_VERSION = 1
STATEMENT_TAG = b"JB-FAD05/BITVM-SETTLEMENT/v1"
PROGRAM_SPEC = (
    b"JB-FAD05/toy-settlement-transition/v1:"
    b" successor = TaggedHash('JB-FAD05/state', previous_root || vault_txid_le"
    b" || vault_vout_le32 || len(recipient_body) || recipient_body"
    b" || payout_le64 || fee_le64)"
)
CANONICAL_PIN_FLAGS = {"acp_none": 0x82, "none": 0x02, "acp_all": 0x81, "all": 0x01}

CONSENSUS = "bitcoin-consensus"
REFEREE = "referee-only"
POLICY = "external-policy"
ANCHOR = "trusted-anchor"


def th(tag: bytes, data: bytes) -> bytes:
    t = sha256(tag)
    return sha256(t + t + data)


def ser_bytes(b: bytes) -> bytes:
    n = len(b)
    if n < 0xFD:
        return bytes([n]) + b
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n) + b
    return b"\xfe" + struct.pack("<I", n) + b


def num(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    return bytes([1, n])


# ---------------------------------------------------------------------------
# independent layout of the vault script
# ---------------------------------------------------------------------------

# opcode bytes used by the independent layout
PICK, ROLL, DUP, SIZE, LTE, VERIFY = b"\x79", b"\x7a", b"\x76", b"\x82", b"\xa1", b"\x69"
TOALT, FROMALT, WITHIN, ADD = b"\x6b", b"\x6c", b"\xa5", b"\x93"
HASH160_OP, EQUALVERIFY, CHECKMULTISIG = b"\xa9", b"\x88", b"\xae"
CHECKSIGVERIFY, CODESEPARATOR, OP0 = b"\xad", b"\xab", b"\x00"


def _round_layout(table, pool, pool_pub, puzzle_pub, above) -> bytes:
    """Re-implementation of the FAD05 round from the spec, op by op
    (n = 10, t = 5; `above` = items left by the previous round)."""
    L = above
    b = bytearray()
    b += num(10 + L) + ROLL + SIZE + num(TARGET_SIG_BYTES) + LTE + VERIFY + TOALT
    for h in table:
        b += push(h)
    for sig in pool:
        b += push(sig)
    for i in range(5):
        b += num(24 - 3 * i + L) + PICK + DUP
        b += num(0) if i == 0 else num(27 - 3 * i + L) + PICK
        b += num(10 - i) + WITHIN + VERIFY + ROLL + TOALT
        b += num(23 - 3 * i + L) + PICK + num(9 - i) + ADD + ROLL
        b += num(28 - 3 * i + L) + ROLL + HASH160_OP + EQUALVERIFY
    b += OP0 + FROMALT * 6
    b += num(6) + push(pool_pub) * 5 + push(puzzle_pub) + num(6) + CHECKMULTISIG
    return bytes(b)


def parse_vault_script(script: bytes) -> dict:
    ops = []
    pc = 0
    while pc < len(script):
        start = pc
        pc, opcode, data = get_op(script, pc)
        ops.append((opcode, data, start, pc))
    need(len(ops) > 24, "vault script too short")
    pins = []
    for k in range(4):
        row = ops[6 * k:6 * k + 6]
        need([o for o, _, _, _ in row][0] == 0x82 and row[5][0] == 0xAD,
             "pin prefix layout")
        pins.append(row[4][1])
    rounds = []
    cursor = 24
    codesep_end = None
    for r in range(2):
        head = ops[cursor:cursor + 7]
        need(len(head) == 7 and head[1][0] == 0x7A and head[6][0] == 0x6B, "round head layout")
        table = [ops[cursor + 7 + k][1] for k in range(POOL_N)]
        pool = [ops[cursor + 17 + k][1] for k in range(POOL_N)]
        need(all(len(h) == 20 for h in table), "HORS commitments are HASH160 values")
        # locate the CHECKMULTISIG that ends this round
        end = next(i for i in range(cursor, len(ops)) if ops[i][0] == 0xAE)
        pool_pub = ops[end - 7][1]
        puzzle_pub = ops[end - 2][1]
        rounds.append({"table": table, "pool": pool, "puzzle_pub": puzzle_pub,
                       "pool_pub": pool_pub})
        cursor = end + 1
        if r == 0:
            need(ops[cursor][0] == 0x69 and ops[cursor + 1][0] == 0xAB,
                 "round boundary must be VERIFY CODESEPARATOR")
            codesep_end = ops[cursor + 1][3]
            cursor += 2
    need(cursor == len(ops), "trailing opcodes after round 2")
    rebuilt = b"".join(SIZE + num(TARGET_SIG_BYTES) + LTE + VERIFY + push(p) + CHECKSIGVERIFY
                       for p in pins)
    rebuilt += (_round_layout(**_kw(rounds[0]), above=0) + VERIFY + CODESEPARATOR +
                _round_layout(**_kw(rounds[1]), above=15))
    need(rebuilt == script, "vault script differs from the FAD05 layout")
    return {"pins": dict(zip((n for n, _ in FLAGS), pins)), "rounds": rounds,
            "round2_source_offset": codesep_end}


def _kw(r):
    return {"table": r["table"], "pool": r["pool"], "pool_pub": r["pool_pub"],
            "puzzle_pub": r["puzzle_pub"]}


def hors_root(rounds) -> bytes:
    return th(b"JB-FAD05/hors-root", b"".join(h for r in rounds for h in r["table"]))


def successor_root(previous_root: bytes, vault_txid: str, vault_vout: int,
                   body: bytes, payout: int, fee: int) -> bytes:
    return th(b"JB-FAD05/state", previous_root + bytes.fromhex(vault_txid)[::-1] +
              struct.pack("<I", vault_vout) + bytes([len(body)]) + body +
              struct.pack("<q", payout) + struct.pack("<q", fee))


def parse_payout_witness(ws: bytes) -> tuple[bytes, int, bytes]:
    need(len(ws) >= 33 + 5 + 1 and ws[0] == 32, "payout witness script must start with a 32-byte root")
    succ = ws[1:33]
    need(ws[33] == 4, "payout witness script needs a 4-byte salt push")
    salt = struct.unpack("<I", ws[34:38])[0]
    need(ws[38] == 0x6D, "payout witness script needs OP_2DROP")
    return succ, salt, ws[39:]


# ---------------------------------------------------------------------------
# referee
# ---------------------------------------------------------------------------

def verify_settlement(policy: dict, witness: dict, trusted_block_hash: str) -> dict:
    checks = []

    def ok(name, cond, msg, enforced_by):
        need(cond, msg)
        checks.append({"check": name, "enforced_by": enforced_by})

    need(policy.get("schema") == "jb-fad05-policy-v1", "unknown policy schema")
    funding = parse_funding_tx(bytes.fromhex(witness["raw_funding_hex"]))
    spend_raw = bytes.fromhex(witness["raw_spend_hex"])
    tx = parse_legacy_tx(spend_raw)
    ftxid = txid_hex(funding)
    ok("funding_txid_matches_policy", ftxid == policy["vault_txid"],
       "funding transaction is not the registered vault funding", POLICY)
    vout = policy["vault_vout"]
    need(0 <= vout < len(funding.vout), "vault vout outside funding tx")
    script = funding.vout[vout].script_pubkey
    ok("vault_script_hash_matches_policy", sha256(script).hex() == policy["funding_script_sha256"],
       "vault script hash differs from registration", POLICY)
    layout = parse_vault_script(script)
    rounds = layout["rounds"]
    ok("hors_root_matches_policy", hors_root(rounds).hex() == policy["hors_root"],
       "HORS commitment root differs from registration", POLICY)

    ok("two_inputs_one_output", len(tx.vin) == 2 and len(tx.vout) == 1,
       "settlement must have exactly two inputs and one output", REFEREE)
    ok("spends_registered_vault_outpoint",
       tx.vin[1].prevout_hash[::-1].hex() == ftxid and tx.vin[1].prevout_n == vout,
       "input 1 does not spend the registered vault outpoint", CONSENSUS)
    aux_in = tx.vin[0]
    need(aux_in.prevout_hash[::-1].hex() == ftxid and aux_in.prevout_n < len(funding.vout),
         "auxiliary input value cannot be authenticated from the funding tx")

    items = parse_canonical_pushes(tx.vin[1].script_sig)
    ok("scriptsig_shape", len(items) == 26, "expected 2 x 11 round items + 4 pins", REFEREE)
    groups = {2: items[0:11], 1: items[11:22]}
    pins = {name: sig for (name, _), sig in zip(reversed(FLAGS), items[22:26])}
    subsets = {}
    preimages = {}
    for r in (1, 2):
        g = groups[r]
        need(all(len(x) <= 1 for x in g[6:11]), "selector numbers must be small")
        depths = tuple(x[0] if x else 0 for x in g[6:11])
        subset = _depths_to_subset(depths)
        picks = [POOL_N - 1 - i - d for i, d in enumerate(depths)]
        table = rounds[r - 1]["table"]
        for i, p in enumerate(picks):
            need(hash160(g[1 + i]) == table[p], f"round {r} preimage {i} does not open index {p}")
        subsets[r] = subset
        preimages[r] = tuple(g[1:6])
        checks.append({"check": f"round{r}_hors_preimages_open_selected_indices", "enforced_by": CONSENSUS})
        checks.append({"check": f"round{r}_canonical_subset_encoding", "enforced_by": CONSENSUS})

    for name, flag in FLAGS:
        need(pins[name][-1] == CANONICAL_PIN_FLAGS[name], f"pin {name} uses noncanonical sighash byte")
        digest = signature_hash(script, tx, 1, flag)
        verify_ecdsa_pubkey(layout["pins"][name], digest, pins[name], flag)
    checks.append({"check": "four_pin_signatures_valid", "enforced_by": CONSENSUS})
    checks.append({"check": "pin_sighash_bytes_canonical", "enforced_by": REFEREE})

    for r in (1, 2):
        rd = rounds[r - 1]
        source = script if r == 1 else script[layout["round2_source_offset"]:]
        code = source
        removed = 0
        for idx in subsets[r]:
            code, n = find_and_delete(code, push(rd["pool"][idx]))
            removed += n
        need(removed == POOL_T, "FindAndDelete count")
        nonce = groups[r][0]
        need(nonce[-1] == SIGHASH_ALL, f"round {r} nonce uses noncanonical sighash byte")
        verify_ecdsa_pubkey(rd["puzzle_pub"], signature_hash(code, tx, 1, SIGHASH_ALL), nonce, SIGHASH_ALL)
        need(signature_hash(code, tx, 1, SIGHASH_SINGLE) == UINT256_ONE, "SINGLE bug precondition")
        for idx in subsets[r]:
            need(ecdsa_ok(rd["pool_pub"], UINT256_ONE, rd["pool"][idx][:-1]), "pool signature")
    checks.append({"check": "nonce_puzzles_valid", "enforced_by": CONSENSUS})
    checks.append({"check": "nonce_sighash_bytes_canonical", "enforced_by": REFEREE})

    ws = bytes.fromhex(witness["payout_witness_script_hex"])
    out = tx.vout[0]
    ok("payout_script_opens_witness", out.script_pubkey == b"\x00\x20" + sha256(ws),
       "payout output is not P2WSH of the supplied witness script", REFEREE)
    succ, salt, body = parse_payout_witness(ws)
    ok("recipient_matches_policy", body.hex() == policy["recipient_body_hex"],
       "payout recipient differs from registered policy", REFEREE)
    ok("payout_matches_policy", out.value == policy["payout_sats"],
       "payout amount differs from registered policy", REFEREE)
    fee = funding.vout[aux_in.prevout_n].value + funding.vout[vout].value - out.value
    ok("fee_matches_policy", fee == policy["fee_sats"], "fee differs from registered policy", REFEREE)
    ok("program_id_matches_policy", sha256(PROGRAM_SPEC).hex() == policy["verified_program_id"],
       "verifier implements a different program than registered", POLICY)
    prev = bytes.fromhex(policy["previous_state_root"])
    expect = successor_root(prev, ftxid, vout, body, out.value, fee)
    ok("state_transition_valid", succ == expect, "successor state root is not the program output", REFEREE)

    header = bytes.fromhex(witness["block_header_hex"])
    inclusion = verify_block_inclusion(
        txid=txid_hex(tx), header_hex=witness["block_header_hex"],
        claimed_block_hash=witness["claimed_block_hash"],
        trusted_block_hash=trusted_block_hash, merkle=witness["merkle"])
    checks.append({"check": "tx_in_trusted_block", "enforced_by": ANCHOR})

    root = hors_root(rounds)
    proof_commitment = th(b"JB-FAD05/hors-attestation",
                          root + b"".join(preimages[1]) + b"".join(preimages[2]))
    fields = [
        ("vault_outpoint", bytes.fromhex(ftxid)[::-1] + struct.pack("<I", vout)),
        ("funding_script_hash", sha256(script)),
        ("transaction_bytes", spend_raw),
        ("block_header_anchor", header),
        ("binohash_round_1_indices", bytes(subsets[1])),
        ("binohash_round_2_indices", bytes(subsets[2])),
        ("verified_program_id", sha256(PROGRAM_SPEC)),
        ("previous_state_root", prev),
        ("successor_state_root", succ),
        ("recipient_script", out.script_pubkey),
        ("payout_amount", struct.pack("<q", out.value)),
        ("fee", struct.pack("<q", fee)),
        ("proof_commitment", proof_commitment),
    ]
    ser = bytes([STATEMENT_VERSION]) + b"".join(ser_bytes(v) for _, v in fields)
    return {
        "valid": True,
        "statement_version": STATEMENT_VERSION,
        "statement_domain": STATEMENT_TAG.decode(),
        "statement": {k: v.hex() for k, v in fields},
        "statement_serialization": ser.hex(),
        "statement_hash": th(STATEMENT_TAG, ser).hex(),
        "txid": txid_hex(tx),
        "indices": list(subsets[1] + subsets[2]),
        "inclusion": inclusion,
        "checks": checks,
        "input_classes": {"policy": "authenticated registration",
                          "witness": "adversary-supplied bytes",
                          "anchor": "trusted block hash"},
    }


def witness_from_receipt(receipt: dict, which: str) -> dict:
    rec = {"honest": receipt["honest"],
           "front_run": receipt["D_reorg_front_run"]["front_run"] | {"block_evidence": receipt["D_reorg_front_run"]["block_evidence"]},
           "unauthorized": receipt["E_retained_key"]["unauthorized"] | {"block_evidence": receipt["E_retained_key"]["block_evidence"]},
           }[which]
    ev = rec["block_evidence"]
    return {
        "raw_funding_hex": receipt["funding"]["raw_tx"],
        "raw_spend_hex": rec["raw_tx"],
        "payout_witness_script_hex": rec["payout_witness_script"],
        "block_header_hex": ev["header_hex"],
        "claimed_block_hash": ev["block_hash"],
        "merkle": build_merkle_branch(ev["txids"], ev["position"]),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--native-receipt", required=True)
    ap.add_argument("--policy", required=True, help="separately authenticated jb-fad05-policy-v1 JSON")
    ap.add_argument("--trusted-blockhash", required=True)
    ap.add_argument("--which", choices=("honest", "front_run", "unauthorized"), default="honest")
    ap.add_argument("--expect", choices=("accept", "reject"), default="accept")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    receipt = json.loads(Path(args.native_receipt).read_text(encoding="utf-8"))
    policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    witness = witness_from_receipt(receipt, args.which)
    try:
        result = verify_settlement(policy, witness, args.trusted_blockhash)
    except (ProofRejected, ValueError, KeyError) as exc:
        result = {"valid": False, "rejection": str(exc)}
    result["which"] = args.which
    result["expected"] = args.expect
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: result.get(k) for k in ("which", "valid", "rejection", "statement_hash", "txid")}, indent=2))
    if result["valid"] != (args.expect == "accept"):
        sys.exit(1)


if __name__ == "__main__":
    main()
