#!/usr/bin/env python3
"""JB-FAD04: two sequential native FindAndDelete nonce rounds.

Both 10-choose-5 pools and the four transaction-pinning ECDSA puzzles run
in the *same* legacy bare Script spend. An OP_CODESEPARATOR between the
rounds gives the second round its own scriptCode. The actual Binohash
witness is the concatenation of the two selected index tuples.

The work factor here is deliberately tiny. This module supplies signed
transactions and a native regtest harness; see jb_fad04_verify.py for
byte-exact independent public-key and block-merkle verification.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import os
from dataclasses import dataclass, replace
from pathlib import Path

from jb_fad01 import (
    AUX_REDEEM, CoreRPC, RPCFailure, UINT256_ONE, demo_scalar, demo_sign,
    pubkey_bytes, satoshis, verifies, wallet_rpc,
)
from jb_fad02 import (
    AUX_SATS, POOL_T, POOL_N, POOL_SATS, TARGET_SIG_BYTES,
    Setup as BaseSetup, make_setup, model_stack, push_num,
    selection_depths, unlocking_script,
)
from jb_fad03_pinning import (
    AUX_COUNT, AUX_VALUE_SATS, FUNDING_FEE_SATS, OUTPUT_VARIANTS,
    PAYOUT_BASE_SATS, SEQ0_LIMIT, SEQ1_LIMIT, FLAGS, PinnedSetup,
    pin_signature, pin_digest, raw_template, rmin_sign,
)
from seam_digests_standalone import (
    OP_CODESEPARATOR, SIGHASH_ALL, SIGHASH_SINGLE, Tx, TxIn, TxOut,
    find_and_delete, op, p2sh, push, ser_tx, sha256,
    signature_hash, txid_hex,
)

OP_VERIFY = 0x69
OP_SIZE = 0x82
OP_LESSTHANOREQUAL = 0xA1
OP_CHECKSIGVERIFY = 0xAD
RESEARCH_ID = "JB-FAD04"
DEFAULT_FUNDING_TXID = "12" * 32


@dataclass(frozen=True)
class DualSetup:
    first: BaseSetup
    second: BaseSetup
    script: bytes
    second_offset: int
    pin_secrets: dict[str, int]
    pin_pubkeys: dict[str, bytes]


@dataclass(frozen=True)
class DualCandidate:
    tx: Tx
    first_subset: tuple[int, ...]
    second_subset: tuple[int, ...]
    first_nonce_sig: bytes
    second_nonce_sig: bytes
    first_nonce_digest: bytes
    second_nonce_digest: bytes
    pin_signatures: dict[str, bytes]
    pin_digests: dict[str, bytes]
    pin_attempts: dict[str, int]
    nonce_attempts: dict[str, int]

    @property
    def txid(self) -> str:
        return txid_hex(self.tx)

    @property
    def index_digest(self) -> tuple[int, ...]:
        return self.first_subset + self.second_subset


def _replace_exact_once(script: bytes, before: bytes, after: bytes,
                        n: int = 1) -> bytes:
    if script.count(before) != n:
        raise AssertionError("pool template replacement matched unexpected count")
    return script.replace(before, after)


def make_dual_setup() -> DualSetup:
    first = make_setup()
    pool_secret = demo_scalar("JB-FAD04/second-pool")
    nonce_secret = demo_scalar("JB-FAD04/second-nonce")
    pool2 = tuple(
        demo_sign(pool_secret, UINT256_ONE, f"JB-FAD04/second-pool/{i}", SIGHASH_SINGLE)
        for i in range(POOL_N)
    )
    if len(set(pool2)) != POOL_N:
        raise AssertionError("second pool contains duplicate ECDSA signatures")
    if set(pool2).intersection(first.pool_sigs):
        raise AssertionError("both signature pools must be disjoint")
    if not all(verifies(pool_secret, UINT256_ONE, x) for x in pool2):
        raise AssertionError("second pool signatures fail ECDSA")

    body2 = first.script_pubkey
    for old, new in zip(first.pool_sigs, pool2):
        body2 = _replace_exact_once(body2, push(old), push(new))
    body2 = _replace_exact_once(
        body2, push(pubkey_bytes(first.puzzle_secret)),
        push(pubkey_bytes(nonce_secret)),
    )
    body2 = _replace_exact_once(
        body2, push(pubkey_bytes(first.pool_secret)),
        push(pubkey_bytes(pool_secret)), n=POOL_T,
    )
    second = BaseSetup(body2, pool2, pool_secret, nonce_secret)

    secrets = {name: demo_scalar("JB-FAD04/pin/" + name) for name, _ in FLAGS}
    pubkeys = {name: pubkey_bytes(secret) for name, secret in secrets.items()}
    # Four size-limited ECDSA checks consume pins from the top first.
    pin_prefix = b"".join(
        op(OP_SIZE) + push_num(TARGET_SIG_BYTES) +
        op(OP_LESSTHANOREQUAL) + op(OP_VERIFY) +
        push(pubkeys[name]) + op(OP_CHECKSIGVERIFY)
        for name, _ in FLAGS
    )

    # The first CHECKMULTISIG produces a bool; VERIFY consumes it so the
    # lower round-2 unlocking stack becomes the active stack.
    # Executing CODESEPARATOR then changes the second check's scriptCode.
    head = pin_prefix + first.script_pubkey + op(OP_VERIFY) + op(OP_CODESEPARATOR)
    script = head + second.script_pubkey
    if len(script) > 10_000:
        raise AssertionError("bare Script exceeds consensus 10KB bound")
    if script[ len(head) - 1 ] != OP_CODESEPARATOR:
        raise AssertionError("round boundary must be an opcode separator")
    return DualSetup(first, second, script, len(head), secrets, pubkeys)


def nonce_script_code(setup: DualSetup, which: int,
                      subset: tuple[int, ...]) -> tuple[bytes, int]:
    if which == 1:
        source = setup.script
        pool = setup.first
    elif which == 2:
        source = setup.script[setup.second_offset:]
        pool = setup.second
    else:
        raise ValueError("which must be 1 or 2")
    selected = model_stack(pool, selection_depths(subset))
    code = source
    removed = 0
    for sig in selected:
        code, count = find_and_delete(code, push(sig))
        removed += count
    if removed != POOL_T:
        raise AssertionError("wrong number of FindAndDelete removals")
    return code, removed


def build_script_sig(pin_signatures: dict[str, bytes],
                     nonce1: bytes, indices1: tuple[int, ...],
                     nonce2: bytes, indices2: tuple[int, ...]) -> bytes:
    # Stack, from bottom to top: round2 stack, round1 stack, pins reversed.
    script_sig = (
        unlocking_script(nonce2, selection_depths(indices2)) +
        unlocking_script(nonce1, selection_depths(indices1))
    )
    for name, _ in reversed(FLAGS):
        script_sig += push(pin_signatures[name])
    return script_sig


def canonical_checks(setup: DualSetup, candidate: DualCandidate) -> dict[str, bool]:
    tx = candidate.tx
    result: dict[str, bool] = {}
    for name, flag in FLAGS:
        sig = candidate.pin_signatures[name]
        digest = signature_hash(setup.script, tx, 1, flag)
        result["pin_" + name] = (
            sig[-1] == flag and len(sig) <= TARGET_SIG_BYTES and
            digest == candidate.pin_digests[name] and
            verifies(setup.pin_secrets[name], digest, sig)
        )
    for round_no, subset, sig, claimed in (
        (1, candidate.first_subset, candidate.first_nonce_sig,
         candidate.first_nonce_digest),
        (2, candidate.second_subset, candidate.second_nonce_sig,
         candidate.second_nonce_digest),
    ):
        code, removed = nonce_script_code(setup, round_no, subset)
        digest = signature_hash(code, tx, 1, SIGHASH_ALL)
        secret = setup.first.puzzle_secret if round_no == 1 else setup.second.puzzle_secret
        result[f"nonce_{round_no}"] = (
            removed == POOL_T and sig[-1] == SIGHASH_ALL and
            len(sig) <= TARGET_SIG_BYTES and digest == claimed and
            verifies(secret, digest, sig)
        )
        result[f"pool_bug_{round_no}"] = (
            signature_hash(code, tx, 1, SIGHASH_SINGLE) == UINT256_ONE
        )
    result["single_output"] = len(tx.vout) == 1
    result["two_inputs"] = len(tx.vin) == 2
    result["pool_index_one"] = tx.vin[1].prevout_n == AUX_COUNT
    result["fixed_locktime"] = tx.locktime == 0
    result["canonical_script_sig"] = tx.vin[1].script_sig == build_script_sig(
        candidate.pin_signatures, candidate.first_nonce_sig,
        candidate.first_subset, candidate.second_nonce_sig,
        candidate.second_subset,
    )
    result["distinct_nonce_rounds"] = (
        candidate.first_subset != candidate.second_subset or
        setup.first.pool_sigs != setup.second.pool_sigs
    )
    return result


def grind(setup: DualSetup, funding_txid: str, payout_script: bytes,
          *, aux_count: int = AUX_COUNT) -> DualCandidate:
    """Four staged signature puzzles then two separate subset searches.

    Stage 1 grinds input-1 sequence with ACP|NONE.
    Stage 2 grinds the auxiliary input-0 outpoint with NONE.
    Stage 3 grinds output amount with ACP|ALL.
    Stage 4 grinds input-0 sequence with ALL.
    Two nonce-round searches run only after all four pin signatures pass.
    When either nonce search fails, we backtrack to the next stage-4 candidate.
    """
    if aux_count < 1:
        raise ValueError("auxiliary pool must contain real funded outputs")
    base = raw_template(funding_txid, aux_count, payout_script)
    attempts = {name: 0 for name, _ in FLAGS}
    nonce_attempts = {"round_1": 0, "round_2": 0}
    for s1trial in range(SEQ1_LIMIT):
        first = replace(base, vin=(
            base.vin[0], replace(base.vin[1], sequence=0xF0000000+s1trial),
        ))
        sig1, digest1 = pin_signature(setup, first, *FLAGS[0])
        attempts["acp_none"] += 1
        if len(sig1) > TARGET_SIG_BYTES:
            continue
        for aux_vout in range(aux_count):
            second = replace(first, vin=(
                replace(first.vin[0], prevout_n=aux_vout), first.vin[1],
            ))
            sig2, digest2 = pin_signature(setup, second, *FLAGS[1])
            attempts["none"] += 1
            if len(sig2) > TARGET_SIG_BYTES:
                continue
            if pin_digest(setup, second, FLAGS[0][1]) != digest1:
                raise AssertionError("stage 2 broke stage 1")
            for delta in range(OUTPUT_VARIANTS):
                third = replace(second, vout=(
                    replace(second.vout[0], value=PAYOUT_BASE_SATS + delta),
                ))
                sig3, digest3 = pin_signature(setup, third, *FLAGS[2])
                attempts["acp_all"] += 1
                if len(sig3) > TARGET_SIG_BYTES:
                    continue
                if pin_digest(setup, third, FLAGS[1][1]) != digest2:
                    raise AssertionError("stage 3 broke stage 2")
                for s0trial in range(SEQ0_LIMIT):
                    fourth = replace(third, vin=(
                        replace(third.vin[0], sequence=0xF0000000 + s0trial),
                        third.vin[1],
                    ))
                    sig4, digest4 = pin_signature(setup, fourth, *FLAGS[3])
                    attempts["all"] += 1
                    if len(sig4) > TARGET_SIG_BYTES:
                        continue
                    if pin_digest(setup, fourth, FLAGS[2][1]) != digest3:
                        raise AssertionError("stage 4 broke stage 3")
                    pins = dict(
                        zip((name for name, _ in FLAGS), (sig1, sig2, sig3, sig4))
                    )
                    pin_digests = dict(
                        zip((name for name, _ in FLAGS), (digest1,digest2,digest3,digest4))
                    )
                    winners = []
                    for which, pool in ((1,setup.first), (2,setup.second)):
                        winner = None
                        for subset in itertools.combinations(range(POOL_N), POOL_T):
                            nonce_attempts[f"round_{which}"] += 1
                            code, _ = nonce_script_code(setup, which, subset)
                            d = signature_hash(code, fourth, 1, SIGHASH_ALL)
                            sig = rmin_sign(d, pool.puzzle_secret, SIGHASH_ALL)
                            if len(sig) <= TARGET_SIG_BYTES:
                                winner = (subset, sig, d)
                                break
                        if winner is None:
                            break
                        winners.append(winner)
                    if len(winners) != 2:
                        continue
                    (subset1, nonce1, d1), (subset2, nonce2, d2) = winners
                    tx = replace(fourth, vin=(
                        fourth.vin[0],
                        replace(fourth.vin[1], script_sig=build_script_sig(
                            pins, nonce1, subset1, nonce2, subset2
                        )),
                    ))
                    c = DualCandidate(
                        tx, subset1, subset2, nonce1, nonce2,
                        d1, d2, pins, pin_digests, dict(attempts), dict(nonce_attempts)
                    )
                    checks = canonical_checks(setup, c)
                    if not all(checks.values()):
                        raise AssertionError("dual signing self-verification failed: "+str(checks))
                    return c
    raise RuntimeError("no four-pin two-round candidate within registered work budget")


def script_resources(setup: DualSetup, candidate: DualCandidate) -> dict:
    from jb_fad03 import script_resources as count
    rows = count(setup.script)
    rows["sigops_accurate"] = 4 + (POOL_T + 1)*2
    rows["script_sig_bytes"] = len(candidate.tx.vin[1].script_sig)
    rows["tx_weight"] = 4*len(ser_tx(candidate.tx))
    rows["nonwitness_tx_bytes"] = len(ser_tx(candidate.tx))
    rows["combinations_per_round"] = math.comb(POOL_N, POOL_T)
    rows["raw_entropy_bits"] = 2*math.log2(math.comb(POOL_N,POOL_T))
    if not rows["within_201_nonpush_limit"]:
        raise AssertionError("two-round script exceeds nonpush limit")
    if not rows["within_10000_script_size"]:
        raise AssertionError("two-round script exceeds length limit")
    return rows


def receipt(setup: DualSetup, c: DualCandidate) -> dict:
    checks = canonical_checks(setup,c)
    if not all(checks.values()):
        raise AssertionError("failed dual-receipt self-verification")
    resources = script_resources(setup,c)
    return {
        "experiment":RESEARCH_ID,
        "scope":"offline ECDSA, native Core verification is independent",
        "funding_txid":c.tx.vin[1].prevout_hash[::-1].hex(),
        "locking_script_hex":setup.script.hex(),
        "txid":c.txid, "raw_spend_tx":ser_tx(c.tx).hex(),
        "two_round_binohash":{
            "round1_indices":list(c.first_subset),
            "round2_indices":list(c.second_subset),
            "concatenated_indices":list(c.index_digest),
            "round1_signature":c.first_nonce_sig.hex(),
            "round2_signature":c.second_nonce_sig.hex(),
            "round1_sighash":c.first_nonce_digest.hex(),
            "round2_sighash":c.second_nonce_digest.hex(),
            "round1_scriptcode_hash":sha256(nonce_script_code(setup,1,c.first_subset)[0]).hex(),
            "round2_scriptcode_hash":sha256(nonce_script_code(setup,2,c.second_subset)[0]).hex(),
            "attempts":c.nonce_attempts,
        },
        "pins":{
            name:{
                "flag":f"0x{flag:02x}",
                "signature":c.pin_signatures[name].hex(),
                "sighash":c.pin_digests[name].hex(),
            } for name,flag in FLAGS
        },
        "pin_attempts":c.pin_attempts,
        "resources":resources,
        "checks":checks,
        "warnings":[
            "10-choose-5 per round is a tiny research parameter; ~16 bits raw index space",
            "scriptSig selects indices but bare Bitcoin Script does not emit a SHA256 digest",
            "canonical sighash bytes are enforced by independent verifier, not consensus here",
            "miner-direct inclusion needed for nonstandard bare script and FindAndDelete",
            "no BitVM covenant or generalized ZK verification is implemented",
            "keys are public deterministic fixture scalars",
        ],
    }


def _direct_block(node: CoreRPC, miner: str, tx: Tx) -> str:
    block = node("generateblock", miner, [ser_tx(tx).hex()])
    if txid_hex(tx) not in node("getblock", block["hash"], 1)["tx"]:
        raise AssertionError("native direct block omitted expected transaction")
    return block["hash"]


def run_native(node: CoreRPC) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("JB-FAD04 refuses non-regtest network")
    wallet = wallet_rpc(node, "jb_fad04")
    miner = wallet("getnewaddress", "jb-fad04-miner", "bech32")
    coins = [x for x in wallet("listunspent")
             if x["spendable"] and x["confirmations"] >= 101
             and satoshis(x["amount"]) > 10_000_000]
    if not coins:
        node("generatetoaddress", 102, miner)
        coins = [x for x in wallet("listunspent") if x["spendable"]
                 and x["confirmations"] >= 101
                 and satoshis(x["amount"]) > 10_000_000]
    if not coins:
        raise RuntimeError("no mature fixture coin")
    coin = coins[0]
    setup = make_dual_setup()
    payout = wallet("getnewaddress", "jb-fad04-payout", "bech32")
    change = wallet("getnewaddress", "jb-fad04-change", "bech32")
    payout_script = bytes.fromhex(wallet("getaddressinfo", payout)["scriptPubKey"])
    change_script = bytes.fromhex(wallet("getaddressinfo", change)["scriptPubKey"])
    change_amount = (
        satoshis(coin["amount"]) - AUX_COUNT*AUX_VALUE_SATS -
        POOL_SATS - FUNDING_FEE_SATS
    )
    if change_amount <= 0:
        raise RuntimeError("funding amount insufficient")
    outputs = (
        [TxOut(AUX_VALUE_SATS,p2sh(AUX_REDEEM)) for _ in range(AUX_COUNT)] +
        [TxOut(POOL_SATS,setup.script), TxOut(change_amount,change_script)]
    )
    funding_tx = Tx(
        2,(TxIn(bytes.fromhex(coin["txid"])[::-1],
                coin["vout"],b"",0xFFFFFFFD),),
        tuple(outputs),0
    )
    signed = wallet("signrawtransactionwithwallet",ser_tx(funding_tx).hex())
    if not signed["complete"]:
        raise AssertionError("wallet funding signature incomplete")
    funding_raw = signed["hex"]
    funding_txid=node("decoderawtransaction",funding_raw)["txid"]
    funding_policy=node("testmempoolaccept",[funding_raw])[0]
    funding_block=node("generateblock",miner,[funding_raw])["hash"]
    if funding_txid not in node("getblock",funding_block,1)["tx"]:
        raise AssertionError("funding not in native block")
    if node("gettxout",funding_txid,AUX_COUNT,False) is None:
        raise AssertionError("pool outpoint missing")
    c=grind(setup,funding_txid,payout_script)
    result=receipt(setup,c)
    result["scope"]="native Bitcoin Core 30.2 funded transactions"
    result["funding"]={
        "txid":funding_txid,"raw_tx":funding_raw,
        "block":funding_block,"pool_vout":AUX_COUNT,
        "pool_value_sats":POOL_SATS,"aux_value_sats":AUX_VALUE_SATS,
        "policy":funding_policy,
    }
    result["spend_policy"]=node("testmempoolaccept",[ser_tx(c.tx).hex()])[0]
    old_tip=node("getbestblockhash")
    attacks={}
    wrong_payout=replace(c.tx,vout=(replace(
        c.tx.vout[0],script_pubkey=p2sh(op(0x52))
    ),))
    altered_second=list(c.second_subset)
    for subset in itertools.combinations(range(POOL_N),POOL_T):
        if subset != c.second_subset:
            altered_second=list(subset)
            break
    wrong_round=replace(c.tx,vin=(
        c.tx.vin[0],replace(c.tx.vin[1],script_sig=build_script_sig(
            c.pin_signatures,c.first_nonce_sig,c.first_subset,
            c.second_nonce_sig,tuple(altered_second),
        ))
    ))
    extra_output=replace(c.tx,vout=c.tx.vout+(TxOut(0,op(0x51)),))
    for label,bad in (
        ("altered_payout",wrong_payout),
        ("round2_selector",wrong_round),
        ("extra_output",extra_output),
    ):
        try:
            _direct_block(node,miner,bad)
        except RPCFailure as exc:
            if node("getbestblockhash")!=old_tip:
                raise AssertionError("invalid "+label+" modified tip") from exc
            attacks[label]={"rejected":True,"reason":str(exc)}
        else:
            raise AssertionError("native consensus accepted mutated "+label)
    block_hash=_direct_block(node,miner,c.tx)
    if node("gettxout",funding_txid,AUX_COUNT,False) is not None:
        raise AssertionError("pool coin remains available after confirmed spend")

    # Export a live block header and complete transaction list. The verifier
    # independently builds/verifies a transaction Merkle branch from these.
    txids=node("getblock",block_hash,1)["tx"]
    result["block_evidence"]={
        "block_hash":block_hash,
        "header_hex":node("getblockheader",block_hash,False),
        "txids":txids,
        "position":txids.index(c.txid),
    }
    result["native"]={
        "confirmed":True,"block":block_hash,"txid":c.txid,
        "rejected_challenges":attacks,
        "tip_was_preserved_on_every_negative":True,
    }
    return result


def main():
    ap=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--output",default="artifacts/jb-fad04/receipt.json")
    ap.add_argument("--live-regtest",action="store_true")
    ap.add_argument("--rpc-url",default=os.getenv("BITCOIND_RPC_URL","http://127.0.0.1:18443"))
    ap.add_argument("--rpc-user",default=os.getenv("BITCOIND_RPC_USER","user"))
    ap.add_argument("--rpc-password",default=os.getenv("BITCOIND_RPC_PASS","pass"))
    args=ap.parse_args()
    if args.live_regtest:
        result=run_native(CoreRPC(args.rpc_url,args.rpc_user,args.rpc_password))
    else:
        setup=make_dual_setup()
        c=grind(setup,DEFAULT_FUNDING_TXID,p2sh(op(0x51)))
        result=receipt(setup,c)
    out=Path(args.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({
        "experiment":result["experiment"],
        "txid":result["txid"],
        "indices":result["two_round_binohash"]["concatenated_indices"],
        "round_attempts":result["two_round_binohash"]["attempts"],
        "pin_attempts":result["pin_attempts"],
        "resources":result["resources"],
        "native":result.get("native"),
        "receipt":str(out),
    },indent=2))

if __name__=="__main__":
    main()
