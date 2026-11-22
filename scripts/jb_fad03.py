#!/usr/bin/env python3
"""JB-FAD03A: native 256-byte sighash matrix and FindAndDelete payout bypass.

The FAD02 locking script checks the byte LENGTH of a signature, not the
appended legacy sighash type. This experiment freshly grinds real Rmin ECDSA
signatures under every byte value and tests them against Bitcoin Core's
consensus validator using direct regtest blocks. It then demonstrates that
ANYONECANPAY|NONE can pay different recipients while preserving identical
nonce selectors, scriptCode, and the exact same witness/scriptSig.

Scope is a counterexample to FAD02, not a fully pinned Binohash protocol.
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import utils

from jb_fad01 import (
    AUX_REDEEM,
    CoreRPC,
    RPCFailure,
    SECP256K1_ORDER,
    satoshis,
    verifies,
    wallet_rpc,
)
from jb_fad02 import (
    AUX_SATS,
    FUNDING_FEE_SATS,
    POOL_SATS,
    POOL_T,
    PAYOUT_SATS,
    TARGET_SIG_BYTES,
    compact_rmin,
    make_setup,
    model_stack,
    selection_depths,
    unlocking_script,
)
from seam_digests_standalone import (
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    UINT256_ONE,
    Tx,
    TxIn,
    TxOut,
    find_and_delete,
    get_op,
    op,
    p2sh,
    push,
    ser_tx,
    sha256,
    signature_hash,
    txid_hex,
)

ATTACK_FLAG = SIGHASH_ANYONECANPAY | SIGHASH_NONE
FOCUS_SUBSET = (0, 1, 2, 3, 4)
MAX_FLAG_TRIALS = 4096
RMIN = compact_rmin()
RMIN_SECRET = pow(RMIN, -1, SECP256K1_ORDER)
DUMMY = b""


@dataclass(frozen=True)
class FlagCandidate:
    flag: int
    tx: Tx
    sig: bytes
    digest: bytes
    trials: int
    script_code: bytes

    @property
    def txid(self) -> str:
        return txid_hex(self.tx)


def flag_family(flag: int) -> str:
    base = flag & 31
    if base == SIGHASH_SINGLE:
        return "SINGLE_BUG"
    if base == SIGHASH_NONE:
        return "NONE"
    if base == SIGHASH_ALL:
        return "ALL"
    return "ALL_FALLBACK"


def code_for_subset(setup, subset: tuple[int, ...]) -> tuple[bytes, int]:
    selected = model_stack(setup, selection_depths(subset))
    code = setup.script_pubkey
    removed = 0
    for sig in selected:
        code, count = find_and_delete(code, push(sig))
        removed += count
    if removed != POOL_T:
        raise AssertionError("wrong number of FindAndDelete removed pushes")
    return code, removed


def fixed_rmin_sig(digest: bytes, flag: int) -> bytes:
    z = int.from_bytes(digest, "big")
    s = 2 * (z + 1) % SECP256K1_ORDER
    if not s:
        raise RuntimeError("zero-S Rmin signing exception")
    s = min(s, SECP256K1_ORDER - s)
    return utils.encode_dss_signature(RMIN, s) + bytes([flag])


def tx_template(funding_txid: str, payout_script: bytes, *,
                sequence: int = 0xFFFFFFFD, locktime: int = 0) -> Tx:
    outpoint = bytes.fromhex(funding_txid)[::-1]
    if len(outpoint) != 32:
        raise ValueError("requires 32-byte funding TXID")
    return Tx(
        2,
        (TxIn(outpoint, 0, push(AUX_REDEEM), 0xFFFFFFFD),
         TxIn(outpoint, 1, b"", sequence)),
        (TxOut(PAYOUT_SATS, payout_script),),
        locktime,
    )


def candidate_for_flag(setup, base: Tx, flag: int,
                       subset: tuple[int, ...] = FOCUS_SUBSET,
                       max_trials: int = MAX_FLAG_TRIALS) -> FlagCandidate | None:
    """Search over the experimental input's sequence only, keeping outputs fixed.

    A successful witness uses the target Rmin public key and a signature
    below the FAD02 length threshold. This is a fresh signature per flag:
    merely changing the last byte of an existing signature would fail ECDSA.
    """
    code, _ = code_for_subset(setup, subset)
    depths = selection_depths(subset)
    for attempt in range(max_trials):
        # High bit set disables relative locktime; zero nLockTime is final.
        seq = 0xF0000000 + attempt
        unsigned = replace(base, vin=(
            base.vin[0], replace(base.vin[1], sequence=seq, script_sig=b""),
        ))
        digest = signature_hash(code, unsigned, 1, flag)
        sig = fixed_rmin_sig(digest, flag)
        if len(sig) <= TARGET_SIG_BYTES:
            if not verifies(RMIN_SECRET, digest, sig):
                raise AssertionError("Rmin ECDSA mismatch for flag %02x" % flag)
            signed = replace(unsigned, vin=(
                unsigned.vin[0],
                replace(unsigned.vin[1], script_sig=unlocking_script(sig, depths)),
            ))
            return FlagCandidate(flag, signed, sig, digest, attempt + 1, code)
        if (flag & 31) == SIGHASH_SINGLE:
            # The historical constant-one digest is independent of sequence.
            break
    return None


def create_matrix(setup, base: Tx, max_trials: int = MAX_FLAG_TRIALS
                  ) -> tuple[list[dict], dict[int, FlagCandidate]]:
    rows = []
    candidates = {}
    code, _ = code_for_subset(setup, FOCUS_SUBSET)
    for flag in range(256):
        candidate = candidate_for_flag(setup, base, flag, max_trials=max_trials)
        probe = signature_hash(code, base, 1, flag)
        trial_sig = fixed_rmin_sig(probe, flag)
        row = {
            "flag": flag,
            "hex": "0x%02x" % flag,
            "mode": flag_family(flag),
            "anyonecanpay": bool(flag & SIGHASH_ANYONECANPAY),
            "raw_hash_type_appended": flag,
            "initial_signature_bytes": len(trial_sig),
            "short_witness_found": candidate is not None,
            "signature_bytes": len(candidate.sig) if candidate else None,
            "trials": candidate.trials if candidate else 1 if flag_family(flag) == "SINGLE_BUG" else max_trials,
            "selected_subset": list(FOCUS_SUBSET),
            "txid": candidate.txid if candidate else None,
            "signature": candidate.sig.hex() if candidate else None,
            "scriptcode_sha256": sha256(code).hex(),
            "digest": candidate.digest.hex() if candidate else probe.hex(),
            "native_block": None,
        }
        candidates[flag] = candidate
        rows.append(row)
    return rows, candidates


def build_payout_collision(setup, funding_txid: str,
                           honest_script: bytes, altered_script: bytes
                           ) -> tuple[FlagCandidate, Tx]:
    if honest_script == altered_script:
        raise ValueError("counterexample needs two different recipients")
    honest_base = tx_template(funding_txid, honest_script)
    c = candidate_for_flag(setup, honest_base, ATTACK_FLAG)
    if c is None:
        raise AssertionError("ACP|NONE puzzle did not grind within work budget")
    altered = replace(c.tx, vout=(replace(c.tx.vout[0], script_pubkey=altered_script),))
    if c.tx == altered or c.txid == txid_hex(altered):
        raise AssertionError("modified recipient did not alter TXID")
    if c.tx.vin != altered.vin:
        raise AssertionError("spend must reuse exactly the same inputs and scriptSig")
    actual_digest = signature_hash(c.script_code, altered, 1, ATTACK_FLAG)
    if actual_digest != c.digest:
        raise AssertionError("ANYONECANPAY|NONE unexpectedly binds payout")
    if not verifies(RMIN_SECRET, actual_digest, c.sig):
        raise AssertionError("reused signature is invalid")
    if signature_hash(c.script_code, altered, 1, SIGHASH_ALL) == (
            signature_hash(c.script_code, c.tx, 1, SIGHASH_ALL)):
        raise AssertionError("ALL digest failed to bind changed payout")
    if signature_hash(c.script_code, c.tx, 1, SIGHASH_SINGLE) != UINT256_ONE:
        raise AssertionError("selected pool signatures lost SINGLE bug")
    if len(c.sig) > TARGET_SIG_BYTES:
        raise AssertionError("signature violates on-chain length gate")
    return c, altered


def script_resources(script: bytes) -> dict:
    nonpush = 0
    script_opcodes = 0
    pc = 0
    while pc < len(script):
        pc, opcode, _ = get_op(script, pc)
        script_opcodes += 1
        if opcode > 0x60:
            nonpush += 1
    return {
        "locking_script_bytes": len(script),
        "total_script_opcodes": script_opcodes,
        "nonpush_opcodes": nonpush,
        "bare_CHECKMULTISIG_sigops": 6,
        "bare_script_exceeds_P2SH_520": len(script) > 520,
        "within_201_nonpush_limit": nonpush <= 201,
        "within_10000_script_size": len(script) <= 10_000,
    }


def report(setup, funding_txid: str, honest_script: bytes,
           altered_script: bytes, *, max_trials: int = MAX_FLAG_TRIALS
           ) -> tuple[dict, dict[int, FlagCandidate], FlagCandidate, Tx]:
    base = tx_template(funding_txid, honest_script)
    rows, candidates = create_matrix(setup, base, max_trials=max_trials)
    a, b = build_payout_collision(setup, funding_txid, honest_script, altered_script)
    if len(rows) != 256:
        raise AssertionError("incomplete hash-type matrix")
    family_counts = {
        family: sum(row["mode"] == family for row in rows)
        for family in ("ALL", "ALL_FALLBACK", "NONE", "SINGLE_BUG")
    }
    valid_count = sum(row["short_witness_found"] for row in rows)
    short_single = [row["hex"] for row in rows
                    if row["mode"] == "SINGLE_BUG" and row["short_witness_found"]]
    result = {
        "experiment": "JB-FAD03A",
        "source": "Jurassic Bitcoin / bare legacy FindAndDelete consensus",
        "scope": "offline ECDSA verification; native results require --live-regtest",
        "funding_txid": funding_txid,
        "resource_bounds": script_resources(setup.script_pubkey),
        "flag_matrix": rows,
        "matrix_summary": {
            "flags_total": len(rows),
            "mode_counts": family_counts,
            "short_candidates_found": valid_count,
            "single_bug_short_flags": short_single,
            "unknown_type_fallback_flags": family_counts["ALL_FALLBACK"],
        },
        "counterexample": {
            "flag": "0x82",
            "nonce_subset": list(FOCUS_SUBSET),
            "selected_scriptcode_hash": sha256(a.script_code).hex(),
            "identical_scriptSig": a.tx.vin[1].script_sig == b.vin[1].script_sig,
            "identical_signature": True,
            "identical_selected_nonce": True,
            "identical_ACP_NONE_sighash": (
                signature_hash(a.script_code, a.tx, 1, ATTACK_FLAG) ==
                signature_hash(a.script_code, b, 1, ATTACK_FLAG)),
            "different_ALL_sighash": (
                signature_hash(a.script_code, a.tx, 1, SIGHASH_ALL) !=
                signature_hash(a.script_code, b, 1, SIGHASH_ALL)),
            "same_input_prevouts": a.tx.vin == b.vin,
            "honest_txid": a.txid,
            "altered_txid": txid_hex(b),
            "honest_raw": ser_tx(a.tx).hex(),
            "altered_raw": ser_tx(b).hex(),
            "payout_A_script": honest_script.hex(),
            "payout_B_script": altered_script.hex(),
            "puzzle_signature": a.sig.hex(),
            "puzzle_sig_length": len(a.sig),
            "grind_attempts": a.trials,
            "native": None,
        },
        "warnings": [
            "All 256 hash-type bytes are distinct signed-message domain values.",
            "Unknown hash base types fall through to ALL-like semantics under legacy hash algorithm.",
            "The default Script policy is stricter than consensus for unknown sighash bytes.",
            "This is a direct demonstration of JB-FAD02's missing signature-hash binding.",
            "Nonce selected by scriptSig is approximately eight bits; this does not implement two-round Binohash.",
            "Four-puzzle transaction pinning and BitVM enforcement remain separate pending milestones.",
        ],
    }
    return result, candidates, a, b


def mine(node: CoreRPC, miner: str, tx: Tx) -> str:
    block = node("generateblock", miner, [ser_tx(tx).hex()])
    txid = txid_hex(tx)
    if txid not in node("getblock", block["hash"], 1)["tx"]:
        raise AssertionError("direct block did not include expected tx " + txid)
    return block["hash"]


def rollback(node: CoreRPC, new_tip: str, parent_tip: str, funding_txid: str):
    node("invalidateblock", new_tip)
    if node("getbestblockhash") != parent_tip:
        raise AssertionError("explicit rollback did not restore parent block")
    if node("gettxout", funding_txid, 1, False) is None:
        raise AssertionError("pool outpoint remained spent after rollback")


def native_matrix(node: CoreRPC, miner: str, funding_txid: str, rows: list[dict],
                  candidates: dict[int, FlagCandidate], *, all_flags: bool) -> dict:
    """Classify every flag natively using direct block inclusion and rollback.

    If all_flags is false, still include selected representative flags with
    accepted/size-failure probes. The offline matrix always covers 256 values.
    """
    parent = node("getbestblockhash")
    selected = range(256) if all_flags else (0, 1, 2, 3, 0x41, 0x81, 0x82, 0x83, 0xff)
    accepted, rejected = 0, 0
    for flag in selected:
        row = rows[flag]
        c = candidates[flag]
        if c is None:
            # Explicit negative: send a correctly signed but overlong Rmin
            # signature. Its OP_SIZE gate must reject in native validation.
            base = tx_template(funding_txid, bytes.fromhex(rows[1]["payout_script"]))
            digest = signature_hash(code_for_subset(make_setup(), FOCUS_SUBSET)[0],
                                    base, 1, flag)
            sig = fixed_rmin_sig(digest, flag)
            candidate = replace(base, vin=(
                base.vin[0],
                replace(base.vin[1], script_sig=unlocking_script(
                    sig, selection_depths(FOCUS_SUBSET))),
            ))
            if len(sig) <= TARGET_SIG_BYTES:
                raise AssertionError("unexpected short ungrindable SINGLE signature")
            try:
                mine(node, miner, candidate)
            except RPCFailure as exc:
                if node("getbestblockhash") != parent:
                    raise AssertionError("native refusal advanced tip")
                row["native_block"] = {
                    "accepted": False, "reason": str(exc),
                    "candidate_signature_length": len(sig),
                    "cause": "length_gate",
                }
                rejected += 1
            else:
                raise AssertionError("overlong signature accepted for 0x%02x" % flag)
        else:
            tip = mine(node, miner, c.tx)
            row["native_block"] = {"accepted": True, "block": tip}
            rollback(node, tip, parent, funding_txid)
            accepted += 1
    return {
        "tested": accepted + rejected,
        "accepted": accepted,
        "rejected": rejected,
        "exhaustive": all_flags,
        "parent_tip_unchanged": node("getbestblockhash") == parent,
    }


def run_native(node: CoreRPC, all_flags: bool) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("JB-FAD03 refuses non-regtest network")
    wallet = wallet_rpc(node, "jb_fad03")
    miner = wallet("getnewaddress", "jb-fad03-miner", "bech32")
    coins = [x for x in wallet("listunspent")
             if x["spendable"] and x["confirmations"] >= 101
             and satoshis(x["amount"]) > 1_000_000]
    if not coins:
        node("generatetoaddress", 102, miner)
        coins = [x for x in wallet("listunspent")
                 if x["spendable"] and x["confirmations"] >= 101
                 and satoshis(x["amount"]) > 1_000_000]
    if not coins:
        raise RuntimeError("could not mine mature funding coin")
    coin = coins[0]
    setup = make_setup()
    addr_honest = wallet("getnewaddress", "jb-fad03-honest", "bech32")
    addr_altered = wallet("getnewaddress", "jb-fad03-altered", "bech32")
    change_addr = wallet("getnewaddress", "jb-fad03-change", "bech32")
    p1 = bytes.fromhex(wallet("getaddressinfo", addr_honest)["scriptPubKey"])
    p2 = bytes.fromhex(wallet("getaddressinfo", addr_altered)["scriptPubKey"])
    change_script = bytes.fromhex(wallet("getaddressinfo", change_addr)["scriptPubKey"])
    change_value = satoshis(coin["amount"]) - AUX_SATS - POOL_SATS - FUNDING_FEE_SATS
    if change_value <= 0:
        raise RuntimeError("insufficient coinbase for fund")
    funding = Tx(
        2, (TxIn(bytes.fromhex(coin["txid"])[::-1], coin["vout"], b"", 0xFFFFFFFD),),
        (TxOut(AUX_SATS, p2sh(AUX_REDEEM)),
         TxOut(POOL_SATS, setup.script_pubkey),
         TxOut(change_value, change_script)),
        0,
    )
    signed = wallet("signrawtransactionwithwallet", ser_tx(funding).hex())
    if not signed["complete"]:
        raise RuntimeError("failed wallet signature for funding")
    raw_funding = signed["hex"]
    funding_txid = node("decoderawtransaction", raw_funding)["txid"]
    funding_policy = node("testmempoolaccept", [raw_funding])[0]
    funded_block = node("generateblock", miner, [raw_funding])
    if funding_txid not in node("getblock", funded_block["hash"], 1)["tx"]:
        raise AssertionError("bare funding absent from block")
    if node("gettxout", funding_txid, 1, False) is None:
        raise AssertionError("pool output missing after funding")

    data, candidates, a, b = report(setup, funding_txid, p1, p2)
    for row in data["flag_matrix"]:
        row["payout_script"] = p1.hex()
    data["scope"] = "Bitcoin Core 30.2 regtest native block oracle"
    data["funding"] = {
        "txid": funding_txid,
        "block": funded_block["hash"],
        "raw": raw_funding,
        "policy": funding_policy,
    }
    data["native_matrix"] = native_matrix(
        node, miner, funding_txid, data["flag_matrix"], candidates,
        all_flags=all_flags,
    )

    parent = node("getbestblockhash")
    same_sig = a.tx.vin[1].script_sig == b.vin[1].script_sig
    if not same_sig:
        raise AssertionError("counterexample must reuse identical witness")
    data["counterexample"]["native"] = {
        "policy_honest": node("testmempoolaccept", [ser_tx(a.tx).hex()])[0],
        "policy_altered": node("testmempoolaccept", [ser_tx(b).hex()])[0],
    }
    honest_tip = mine(node, miner, a.tx)
    rollback(node, honest_tip, parent, funding_txid)
    altered_tip = mine(node, miner, b)
    if txid_hex(a.tx) == txid_hex(b):
        raise AssertionError("identical txids after output mutation")
    if node("gettxout", funding_txid, 1, False) is not None:
        raise AssertionError("altered spend failed to consume funding output")
    data["counterexample"]["native"].update({
        "honest_spend_accepted": True,
        "honest_block": honest_tip,
        "controlled_rollback": True,
        "altered_spend_accepted": True,
        "altered_block": altered_tip,
        "same_funding_outpoint": True,
    })
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="artifacts/jb-fad03/receipt.json")
    parser.add_argument("--live-regtest", action="store_true")
    parser.add_argument("--all-native-flags", action="store_true")
    parser.add_argument("--rpc-url", default=os.getenv("BITCOIND_RPC_URL", "http://127.0.0.1:18443"))
    parser.add_argument("--rpc-user", default=os.getenv("BITCOIND_RPC_USER", "user"))
    parser.add_argument("--rpc-password", default=os.getenv("BITCOIND_RPC_PASS", "pass"))
    args = parser.parse_args()
    if args.all_native_flags and not args.live_regtest:
        parser.error("--all-native-flags requires --live-regtest")
    if args.live_regtest:
        data = run_native(CoreRPC(args.rpc_url, args.rpc_user, args.rpc_password),
                          args.all_native_flags)
    else:
        setup = make_setup()
        data, _, _, _ = report(setup, "12" * 32,
                                p2sh(AUX_REDEEM), p2sh(op(0x52)))
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "experiment": data["experiment"],
        "matrix": data["matrix_summary"],
        "counterexample": {
            k: v for k, v in data["counterexample"].items()
            if k not in ("honest_raw", "altered_raw")
        },
        "native_matrix": data.get("native_matrix"),
        "receipt": str(out),
    }, indent=2))


if __name__ == "__main__":
    main()
