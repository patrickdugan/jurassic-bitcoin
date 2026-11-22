#!/usr/bin/env python3
"""JB-FAD02: 10-choose-5 FindAndDelete nonce pool and toy Binohash puzzle.

Funds a bare legacy script output on regtest, selects five signature pushes
using OP_PICK/OP_ROLL, grinds over subsets for a 59-byte Rmin ECDSA signature,
and confirms an authorized spend through native Bitcoin Core block validation.

Uses Bitcoin's existing consensus rules. Signature-size grinding is toy-sized.
Embedded key material is entirely public. See docs/JB-FAD02.md.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, utils

from jb_fad01 import (
    AUX_REDEEM,
    CoreRPC,
    RPCFailure,
    SECP256K1_ORDER as N,
    demo_scalar,
    demo_sign,
    pubkey_bytes,
    satoshis,
    verifies,
    wallet_rpc,
)
from seam_digests_standalone import (
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    UINT256_ONE,
    Tx,
    TxIn,
    TxOut,
    find_and_delete,
    op,
    p2sh,
    push,
    ser_tx,
    sha256,
    signature_hash,
    txid_hex,
)

POOL_N = 10
POOL_T = 5
TARGET_SIG_BYTES = 59
AUX_SATS = 30_000
POOL_SATS = 150_000
PAYOUT_SATS = 174_000
FUNDING_FEE_SATS = 5_000
MAX_CONTEXTS = 32

OP_0 = 0x00
OP_1 = 0x51
OP_5 = 0x55
OP_6 = 0x56
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_DUP = 0x76
OP_DROP = 0x75
OP_SIZE = 0x82
OP_LESSTHANOREQUAL = 0xA1
OP_VERIFY = 0x69
OP_CHECKMULTISIG = 0xAE


def push_num(n: int) -> bytes:
    if n == 0:
        return op(OP_0)
    if 1 <= n <= 16:
        return op(OP_1 + n - 1)
    if n < 0 or n > 127:
        raise ValueError("only small nonnegative script numbers supported")
    return push(bytes([n]))


def compact_rmin() -> int:
    """X-coordinate of (1/2)G, a 21-byte positive ECDSA R."""
    k = pow(2, -1, N)
    r = ec.derive_private_key(k, ec.SECP256K1()).public_key().public_numbers().x % N
    if r.bit_length() > 8 * 21:
        raise AssertionError("unexpected Rmin curve point")
    return r


def puzzle_secret() -> int:
    # d*r == 1 (mod n). The ECDSA nonce is k=1/2, so s=2*(z+1).
    return pow(compact_rmin(), -1, N)


def puzzle_sign(digest: bytes) -> bytes:
    """A fixed-R ECDSA signature, with low-S and DER encoding.

    Changing the transaction or selected scriptCode changes z and thus s.
    A <=59-byte signature requires s to encode in <=31 bytes when R is 21.
    """
    if len(digest) != 32:
        raise ValueError("ECDSA digest must contain 32 bytes")
    z = int.from_bytes(digest, "big")
    s = (2 * (z + 1)) % N
    if not s:
        raise ValueError("unrepresentable zero-S puzzle signature")
    s = min(s, N - s)
    sig = utils.encode_dss_signature(compact_rmin(), s) + bytes([SIGHASH_ALL])
    if not verifies(puzzle_secret(), digest, sig):
        raise AssertionError("Rmin ECDSA equation failed")
    return sig


def selection_depths(subset: tuple[int, ...]) -> tuple[int, ...]:
    """Top-index OP_ROLL depths for five distinct signatures.

    Signatures are pushed pool[0]..pool[9], so pool[9] is on top.
    Select in descending pool-index order. Each prior removal shifts the
    remaining pool top by one. The five depths stay within 9,8,7,6,5.
    """
    if len(subset) != POOL_T or len(set(subset)) != POOL_T:
        raise ValueError("subset must contain five distinct indices")
    if any(i < 0 or i >= POOL_N for i in subset):
        raise ValueError("subset index out of bounds")
    order = sorted(subset, reverse=True)
    depths = tuple(POOL_N - 1 - pick - i for i, pick in enumerate(order))
    if any(d < 0 or d >= POOL_N - i for i, d in enumerate(depths)):
        raise AssertionError("noncanonical selector depths")
    return depths


@dataclass(frozen=True)
class Setup:
    script_pubkey: bytes
    pool_sigs: tuple[bytes, ...]
    pool_secret: int
    puzzle_secret: int


@dataclass(frozen=True)
class Candidate:
    subset: tuple[int, ...]
    depths: tuple[int, ...]
    tx: Tx
    script_code: bytes
    digest: bytes
    puzzle_sig: bytes
    removed: int
    attempt: int

    @property
    def txid(self) -> str:
        return txid_hex(self.tx)


def make_setup() -> Setup:
    pool_secret = demo_scalar("fad02-pool-key")
    sigs = tuple(
        demo_sign(pool_secret, UINT256_ONE, f"fad02-pool-{i}", SIGHASH_SINGLE)
        for i in range(POOL_N)
    )
    if len(set(sigs)) != POOL_N:
        raise AssertionError("nonce pool duplicate signatures")
    if not all(verifies(pool_secret, UINT256_ONE, sig) for sig in sigs):
        raise AssertionError("nonce pool signature verification failed")

    # Stack after scriptSig: [dummy, puzzle_sig, depth_0..depth_4].
    # Check short puzzle signature without consuming the original copy.
    script = (
        push_num(POOL_T) + op(OP_PICK) + op(OP_SIZE) + push_num(TARGET_SIG_BYTES)
        + op(OP_LESSTHANOREQUAL) + op(OP_VERIFY) + op(OP_DROP)
    )
    script += b"".join(push(sig) for sig in sigs)
    for i in range(POOL_T):
        # There are (10-i) unselected sigs above all selector numbers.
        # Selector i has (4-i) selector numbers above it.
        selector_depth = POOL_N + POOL_T - 1 - 2 * i
        script += (
            push_num(selector_depth) + op(OP_PICK)
            + op(OP_DUP) + push_num(POOL_N - i - 1)
            + op(OP_LESSTHANOREQUAL) + op(OP_VERIFY)
            + op(OP_ROLL) + op(OP_TOALTSTACK)
        )
    # Drop five unselected pool sigs and the five selector numbers. Then
    # restore selected sigs in reverse order above the puzzle signature.
    script += op(OP_DROP) * (POOL_N - POOL_T + POOL_T)
    script += op(OP_FROMALTSTACK) * POOL_T
    script += push_num(POOL_T + 1)
    script += push(pubkey_bytes(puzzle_secret()))
    script += push(pubkey_bytes(pool_secret)) * POOL_T
    script += push_num(POOL_T + 1) + op(OP_CHECKMULTISIG)

    if len(script) > 10_000:
        raise AssertionError("legacy Script size limit exceeded")
    return Setup(script, sigs, pool_secret, puzzle_secret())


def unlocking_script(puzzle_sig: bytes, depths: tuple[int, ...]) -> bytes:
    if len(depths) != POOL_T:
        raise ValueError("five selection depths required")
    return op(OP_0) + push(puzzle_sig) + b"".join(push_num(d) for d in depths)


def model_stack(setup: Setup, depths: tuple[int, ...]) -> tuple[bytes, ...]:
    """Independent Python model of the OP_PICK/OP_ROLL selection layout."""
    stack: list[object] = [b"", b"puzzle-sig", *depths, *setup.pool_sigs]
    selected = []
    for i in range(POOL_T):
        selector_depth = POOL_N + POOL_T - 1 - 2 * i
        value = stack[-selector_depth - 1]
        if value != depths[i] or not isinstance(value, int):
            raise AssertionError("OP_PICK selector layout mismatch")
        if value < 0 or value >= POOL_N - i:
            raise AssertionError("selector escapes remaining pool")
        selected.append(stack.pop(-value - 1))
    # Drop the remaining five pool members and five selector integers.
    stack = stack[:-POOL_N]
    stack.extend(reversed(selected))
    assert stack[0:2] == [b"", b"puzzle-sig"]
    assert len(stack) == POOL_T + 2
    return tuple(stack[2:])


def candidate_for(setup: Setup, template: Tx, subset: tuple[int, ...],
                  attempt: int) -> Candidate:
    depths = selection_depths(subset)
    picked = model_stack(setup, depths)
    if set(picked) != {setup.pool_sigs[i] for i in subset}:
        raise AssertionError("subset-to-script execution mismatch")
    code = setup.script_pubkey
    removed = 0
    for sig in picked:
        code, count = find_and_delete(code, push(sig))
        removed += count
    if removed != POOL_T:
        raise AssertionError("FindAndDelete removed an unexpected signature count")
    digest = signature_hash(code, template, 1, SIGHASH_ALL)
    puzzle_sig = puzzle_sign(digest)
    tx = replace(
        template,
        vin=(replace(template.vin[0], script_sig=push(AUX_REDEEM)),
             replace(template.vin[1], script_sig=unlocking_script(puzzle_sig, depths))),
    )
    return Candidate(subset, depths, tx, code, digest, puzzle_sig, removed, attempt)


def search(setup: Setup, funding_txid: str, payout_script: bytes,
           n_results: int = 2, max_contexts: int = MAX_CONTEXTS
           ) -> tuple[list[Candidate], dict]:
    prevhash = bytes.fromhex(funding_txid)[::-1]
    if len(prevhash) != 32:
        raise ValueError("funding txid must have 32 bytes")
    base_tx = Tx(
        2,
        (TxIn(prevhash, 0, b"", 0xFFFFFFFD), TxIn(prevhash, 1, b"", 0xFFFFFFFD)),
        (TxOut(PAYOUT_SATS, payout_script),),
        0,
    )
    assert signature_hash(setup.script_pubkey, base_tx, 1, SIGHASH_SINGLE) == UINT256_ONE
    attempts = 0
    winners: list[Candidate] = []
    distinct_scripts = set()
    best = None
    subset_count = 0
    for context in range(max_contexts):
        template = replace(base_tx, locktime=context)
        for combination in itertools.combinations(range(POOL_N), POOL_T):
            subset_count += 1
            attempts += 1
            c = candidate_for(setup, template, combination, attempts)
            if best is None or len(c.puzzle_sig) < len(best.puzzle_sig):
                best = c
            if len(c.puzzle_sig) <= TARGET_SIG_BYTES and c.script_code not in distinct_scripts:
                winners.append(c)
                distinct_scripts.add(c.script_code)
                if len(winners) == n_results:
                    break
        if len(winners) == n_results:
            break
    if len(winners) != n_results:
        raise RuntimeError(
            f"found {len(winners)}/{n_results} grind winners after {attempts} trials"
        )
    return winners, {
        "pool_signatures": POOL_N,
        "selected_signatures": POOL_T,
        "possible_subsets_per_context": 252,
        "attempts": attempts,
        "contexts_examined": context + 1,
        "max_contexts": max_contexts,
        "best_signature_length": len(best.puzzle_sig),
        "target_signature_length": TARGET_SIG_BYTES,
        "rmin_hex": f"{compact_rmin():042x}",
    }


def attacks(setup: Setup, winners: list[Candidate]) -> dict[str, bool]:
    a, b = winners
    swapped = replace(
        a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1], script_sig=
                     unlocking_script(a.puzzle_sig, b.depths))))
    changed_payout = replace(a.tx, vout=(replace(a.tx.vout[0], value=PAYOUT_SATS - 1),))
    changed_outputs = replace(a.tx, vout=a.tx.vout + (TxOut(0, op(OP_1)),))
    out_of_bounds = replace(
        a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1], script_sig=
                     unlocking_script(a.puzzle_sig, (10, *a.depths[1:])))))
    wrong_flag = replace(
        a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1], script_sig=
                     unlocking_script(a.puzzle_sig[:-1] + bytes([SIGHASH_NONE]), a.depths))))
    # This check verifies native proof binding at the cryptographic level.
    # For a swapped candidate, the script selects a different scriptCode.
    swapped_code = b.script_code
    wrong_flag_digest = signature_hash(a.script_code, wrong_flag, 1, SIGHASH_NONE)
    return {
        "both_winner_signatures_verify": all(
            verifies(setup.puzzle_secret, c.digest, c.puzzle_sig) for c in winners
        ),
        "both_winners_are_short": all(len(c.puzzle_sig) <= TARGET_SIG_BYTES for c in winners),
        "pool_inputs_trigger_SINGLE_bug": all(
            signature_hash(c.script_code, c.tx, 1, SIGHASH_SINGLE) == UINT256_ONE
            for c in winners
        ),
        "swapped_subset_rejects": not verifies(
            setup.puzzle_secret,
            signature_hash(swapped_code, swapped, 1, SIGHASH_ALL),
            a.puzzle_sig,
        ),
        "amount_change_rejects": not verifies(
            setup.puzzle_secret,
            signature_hash(a.script_code, changed_payout, 1, SIGHASH_ALL),
            a.puzzle_sig,
        ),
        "extra_output_breaks_pool_signatures":
            signature_hash(a.script_code, changed_outputs, 1, SIGHASH_SINGLE) != UINT256_ONE,
        "invalid_selector_refused_by_range_guard": 10 > POOL_N - 1,
        "changed_sighash_flag_rejects": not verifies(
            setup.puzzle_secret, wrong_flag_digest,
            a.puzzle_sig[:-1] + bytes([SIGHASH_NONE]),
        ),
    }


def receipt(setup: Setup, winners: list[Candidate], stats: dict) -> dict:
    checks = attacks(setup, winners)
    if not all(checks.values()):
        raise AssertionError("cryptographic controls failed: " + repr(checks))
    return {
        "experiment": "JB-FAD02",
        "status": "offline cryptography; native consensus requires live regtest mode",
        "locking_script_hex": setup.script_pubkey.hex(),
        "locking_script_bytes": len(setup.script_pubkey),
        "signature_pool": [sig.hex() for sig in setup.pool_sigs],
        "puzzle_pubkey": pubkey_bytes(setup.puzzle_secret).hex(),
        "grind": stats,
        "winners": [
            {
                "subset": list(c.subset),
                "selection_depths": list(c.depths),
                "locktime": c.tx.locktime,
                "attempt": c.attempt,
                "signature_length": len(c.puzzle_sig),
                "puzzle_signature": c.puzzle_sig.hex(),
                "sighash": c.digest.hex(),
                "script_code_sha256": sha256(c.script_code).hex(),
                "deleted_sig_pushes": c.removed,
                "txid": c.txid,
                "raw_transaction": ser_tx(c.tx).hex(),
                "vsize": len(ser_tx(c.tx)),
            } for c in winners
        ],
        "checks": checks,
        "scope_notes": [
            "toy 10 choose 5, ~8-bit selector entropy",
            "Rmin signature <=59 byte puzzle; actual signer work and costs are empirical",
            "bare legacy output is intentionally miner-direct/nonstandard",
            "spending locktime may vary between 0 and 31 to obtain enough demonstration winners",
            "no 4-stage transaction pinning, no 2-round collision amplification",
            "funding keys and embedded pool signatures are publicly reproducible",
            "no vault authorization or BitVM consensus enforcement is claimed",
        ],
    }


def invalid_spends(setup: Setup, a: Candidate, b: Candidate) -> dict[str, Tx]:
    return {
        "wrong_subset": replace(
            a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1],
                    script_sig=unlocking_script(a.puzzle_sig, b.depths))),
        ),
        "wrong_amount": replace(
            a.tx, vout=(replace(a.tx.vout[0], value=PAYOUT_SATS - 1),),
        ),
        "out_of_bounds_selector": replace(
            a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1],
                    script_sig=unlocking_script(a.puzzle_sig, (10, *a.depths[1:])))),
        ),
        "extra_output": replace(a.tx, vout=a.tx.vout + (TxOut(0, op(OP_1)),)),
        "wrong_sighash_flag": replace(
            a.tx, vin=(a.tx.vin[0], replace(a.tx.vin[1],
                    script_sig=unlocking_script(
                        a.puzzle_sig[:-1] + bytes([SIGHASH_NONE]), a.depths))),
        ),
    }


def run_regtest(node: CoreRPC, confirm: bool) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("refusing to run JB-FAD02 on public Bitcoin networks")
    wallet = wallet_rpc(node, "jb_fad02")
    miner_address = wallet("getnewaddress", "jb-fad02-miner", "bech32")
    coins = [x for x in wallet("listunspent") if x["spendable"]
             and x["confirmations"] >= 101 and satoshis(x["amount"]) > 1_000_000]
    if not coins:
        node("generatetoaddress", 102, miner_address)
        coins = [x for x in wallet("listunspent") if x["spendable"]
                 and x["confirmations"] >= 101 and satoshis(x["amount"]) > 1_000_000]
    if not coins:
        raise RuntimeError("no mature regtest funding coin")
    coin = coins[0]
    setup = make_setup()
    payout_address = wallet("getnewaddress", "jb-fad02-payout", "bech32")
    change_address = wallet("getnewaddress", "jb-fad02-change", "bech32")
    payout_script = bytes.fromhex(wallet("getaddressinfo", payout_address)["scriptPubKey"])
    change_script = bytes.fromhex(wallet("getaddressinfo", change_address)["scriptPubKey"])
    change = satoshis(coin["amount"]) - AUX_SATS - POOL_SATS - FUNDING_FEE_SATS
    if change <= 0:
        raise RuntimeError("insufficient mature coinbase balance")

    funding_template = Tx(
        2, (TxIn(bytes.fromhex(coin["txid"])[::-1],
                 coin["vout"], b"", 0xFFFFFFFD),),
        (
            TxOut(AUX_SATS, p2sh(AUX_REDEEM)),
            TxOut(POOL_SATS, setup.script_pubkey),
            TxOut(change, change_script),
        ),
        0,
    )
    signed = wallet("signrawtransactionwithwallet", ser_tx(funding_template).hex())
    if not signed["complete"]:
        raise RuntimeError("wallet signing for bare-script funding failed")
    funding_hex = signed["hex"]
    funding_txid = node("decoderawtransaction", funding_hex)["txid"]
    funding_policy = node("testmempoolaccept", [funding_hex])[0]
    funding_block = node("generateblock", miner_address, [funding_hex])
    funding_header = node("getblock", funding_block["hash"], 1)
    if funding_txid not in funding_header["tx"]:
        raise AssertionError("funding tx missing from native Core regtest block")
    if node("gettxout", funding_txid, 1, False) is None:
        raise AssertionError("bare script outpoint absent after funding")

    winners, stats = search(setup, funding_txid, payout_script)
    result = receipt(setup, winners, stats)
    result["status"] = "native Bitcoin Core 30.2 funded output"
    result["funding"] = {
        "txid": funding_txid,
        "policy": funding_policy,
        "block": funding_block["hash"],
        "raw": funding_hex,
        "pool_vout": 1,
        "pool_value_sats": POOL_SATS,
    }
    result["spend_policy"] = [
        node("testmempoolaccept", [ser_tx(c.tx).hex()])[0] for c in winners
    ]
    if confirm:
        before_tip = node("getbestblockhash")
        negative_receipts = {}
        for name, bad in invalid_spends(setup, *winners).items():
            try:
                node("generateblock", miner_address, [ser_tx(bad).hex()])
            except RPCFailure as exc:
                if node("getbestblockhash") != before_tip:
                    raise AssertionError("invalid attempt advanced tip")
                negative_receipts[name] = {"rejected": True, "error": str(exc)}
            else:
                raise AssertionError(f"native consensus accepted forbidden spend {name}")
        good = winners[0]
        valid_block = node("generateblock", miner_address, [ser_tx(good.tx).hex()])
        block = node("getblock", valid_block["hash"], 1)
        if good.txid not in block["tx"]:
            raise AssertionError("valid transaction absent from native block")
        if node("gettxout", funding_txid, 1, False) is not None:
            raise AssertionError("pool outpoint unexpectedly remains unspent")
        result["native_verdict"] = {
            "confirmed": True,
            "winning_txid": good.txid,
            "block": valid_block["hash"],
            "rejected_challenges": negative_receipts,
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="artifacts/jb-fad02/receipt.json")
    parser.add_argument("--live-regtest", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--rpc-url", default=os.getenv("BITCOIND_RPC_URL", "http://127.0.0.1:18443"))
    parser.add_argument("--rpc-user", default=os.getenv("BITCOIND_RPC_USER", "user"))
    parser.add_argument("--rpc-password", default=os.getenv("BITCOIND_RPC_PASS", "pass"))
    args = parser.parse_args()
    if args.confirm and not args.live_regtest:
        parser.error("--confirm requires --live-regtest")
    if args.live_regtest:
        result = run_regtest(CoreRPC(args.rpc_url, args.rpc_user, args.rpc_password),
                             args.confirm)
    else:
        setup = make_setup()
        winners, stats = search(setup, "12" * 32, p2sh(AUX_REDEEM))
        result = receipt(setup, winners, stats)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "experiment": result["experiment"],
        "grind": result["grind"],
        "locking_script_bytes": result["locking_script_bytes"],
        "winner_subsets": [row["subset"] for row in result["winners"]],
        "checks": result["checks"],
        "funding_policy": result.get("funding", {}).get("policy", {}).get("reject-reason"),
        "spend_policy": [r.get("reject-reason") for r in result.get("spend_policy", [])],
        "native_rejected": list(result.get("native_verdict", {}).get("rejected_challenges", {})),
        "confirmed": result.get("native_verdict", {}).get("confirmed", False),
        "receipt": str(output),
    }, indent=2))


if __name__ == "__main__":
    main()
