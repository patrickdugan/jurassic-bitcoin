#!/usr/bin/env python3
"""JB-FAD03B: four-mode transaction pinning, then FindAndDelete nonce extraction.

The experiment adds four real ECDSA signature-size puzzles ahead of the
FAD02 10-choose-5 script. They use canonical sighash modes 0x82, 0x02, 0x81
and 0x01, successively grinding distinct transaction fields. Separate,
publicly reproducible Rmin signing keys avoid trivial signature reuse.

Bitcoin Script checks ECDSA and signature lengths. Exact flag-byte
canonicality is checked by the separate BitVM-policy model, since legacy
Script cannot inspect the last signature byte. This is a small-work pilot,
not a proof of production collision resistance.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import utils

from jb_fad01 import (
    AUX_REDEEM, CoreRPC, RPCFailure, SECP256K1_ORDER as N, demo_scalar,
    pubkey_bytes, satoshis, verifies, wallet_rpc,
)
from jb_fad02 import (
    POOL_SATS, POOL_T, TARGET_SIG_BYTES, Setup as BaseSetup,
    make_setup, model_stack, push_num, selection_depths, unlocking_script,
)
from jb_fad03 import RMIN, code_for_subset, script_resources
from seam_digests_standalone import (
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_NONE, SIGHASH_SINGLE,
    UINT256_ONE, Tx, TxIn, TxOut, op, p2sh, push, ser_tx, sha256,
    signature_hash, txid_hex,
)

FLAGS = (
    ("acp_none", SIGHASH_ANYONECANPAY | SIGHASH_NONE),
    ("none", SIGHASH_NONE),
    ("acp_all", SIGHASH_ANYONECANPAY | SIGHASH_ALL),
    ("all", SIGHASH_ALL),
)
AUX_COUNT = 2048
AUX_VALUE_SATS = 30_000
PAYOUT_BASE_SATS = 170_000
FUNDING_FEE_SATS = 14_000
OUTPUT_VARIANTS = 4096
SEQ1_LIMIT = 4096
SEQ0_LIMIT = 4096
OP_SIZE = 0x82
OP_LESSTHANOREQUAL = 0xA1
OP_VERIFY = 0x69
OP_CHECKSIGVERIFY = 0xAD
OP_0 = 0x00


@dataclass(frozen=True)
class PinnedSetup:
    base: BaseSetup
    script: bytes
    pin_secrets: dict[str, int]
    pin_pubkeys: dict[str, bytes]


@dataclass(frozen=True)
class PinnedCandidate:
    tx: Tx
    nonce_subset: tuple[int, ...]
    nonce_signature: bytes
    nonce_digest: bytes
    pin_signatures: dict[str, bytes]
    pin_digests: dict[str, bytes]
    pin_attempts: dict[str, int]
    nonce_attempts: int

    @property
    def txid(self) -> str:
        return txid_hex(self.tx)


def rmin_sign(digest: bytes, scalar: int, hash_type: int) -> bytes:
    z = int.from_bytes(digest, "big")
    s = (2 * (z + scalar * RMIN)) % N
    if not s:
        raise ValueError("ECDSA zero-S in fixed nonce pilot")
    s = min(s, N - s)
    return utils.encode_dss_signature(RMIN, s) + bytes([hash_type])


def make_pinned_setup() -> PinnedSetup:
    base = make_setup()
    secrets = {name: demo_scalar("JB-FAD03B/" + name) for name, _ in FLAGS}
    pubkeys = {name: pubkey_bytes(secret) for name, secret in secrets.items()}
    # The last unlocking push is acp_none, which executes first. Each CHECKSIG
    # consumes one signature and leaves the original FAD02 stack intact.
    prefix = b"".join(
        op(OP_SIZE) + push_num(TARGET_SIG_BYTES) +
        op(OP_LESSTHANOREQUAL) + op(OP_VERIFY) +
        push(pubkeys[name]) + op(OP_CHECKSIGVERIFY)
        for name, _ in FLAGS
    )
    return PinnedSetup(
        base=base, script=prefix + base.script_pubkey,
        pin_secrets=secrets, pin_pubkeys=pubkeys,
    )


def raw_template(funding_txid: str, pool_vout: int, payout_script: bytes) -> Tx:
    outpoint = bytes.fromhex(funding_txid)[::-1]
    if len(outpoint) != 32:
        raise ValueError("32-byte funding txid required")
    return Tx(
        2,
        (
            TxIn(outpoint, 0, push(AUX_REDEEM), 0xF0000000),
            TxIn(outpoint, pool_vout, b"", 0xF0000000),
        ),
        (TxOut(PAYOUT_BASE_SATS, payout_script),),
        0,
    )


def pin_digest(setup: PinnedSetup, tx: Tx, flag: int) -> bytes:
    return signature_hash(setup.script, tx, 1, flag)


def pin_signature(setup: PinnedSetup, tx: Tx, name: str, flag: int) -> tuple[bytes, bytes]:
    digest = pin_digest(setup, tx, flag)
    sig = rmin_sign(digest, setup.pin_secrets[name], flag)
    return sig, digest


def build_pinned_script_sig(pin_signatures: dict[str, bytes],
                            nonce_sig: bytes, subset: tuple[int, ...]) -> bytes:
    depths = selection_depths(subset)
    code = unlocking_script(nonce_sig, depths)
    # Push last-to-first, so acp_none is checked first.
    for name, _ in reversed(FLAGS):
        code += push(pin_signatures[name])
    return code


def verify_canonical_flags(candidate: PinnedCandidate, setup: PinnedSetup) -> dict:
    """Off-chain BitVM policy: strict hash types and replayed signatures.

    This verifies the full signed transaction against the known policy
    construction. The real BitVM light-client and refutation path are separate.
    """
    outcome = {}
    for name, flag in FLAGS:
        sig = candidate.pin_signatures[name]
        digest = pin_digest(setup, candidate.tx, flag)
        outcome[name] = (
            sig[-1] == flag and len(sig) <= TARGET_SIG_BYTES and
            digest == candidate.pin_digests[name] and
            verifies(setup.pin_secrets[name], digest, sig)
        )
    nonce_code, deleted = code_for_subset(
        replace(setup.base, script_pubkey=setup.script), candidate.nonce_subset
    )
    digest = signature_hash(nonce_code, candidate.tx, 1, SIGHASH_ALL)
    outcome["nonce"] = (
        deleted == POOL_T and
        candidate.nonce_signature[-1] == SIGHASH_ALL and
        len(candidate.nonce_signature) <= TARGET_SIG_BYTES and
        digest == candidate.nonce_digest and
        verifies(setup.base.puzzle_secret, digest, candidate.nonce_signature)
    )
    outcome["constant_one_pool"] = (
        signature_hash(nonce_code, candidate.tx, 1, SIGHASH_SINGLE) == UINT256_ONE
    )
    outcome["locktime_zero"] = candidate.tx.locktime == 0
    outcome["single_output"] = len(candidate.tx.vout) == 1
    outcome["pool_input_at_index_one"] = candidate.tx.vin[1].prevout_n >= AUX_COUNT
    return outcome


def grind(setup: PinnedSetup, funding_txid: str, payout_script: bytes,
          *, aux_count: int = AUX_COUNT) -> PinnedCandidate:
    """Sequential 4-mode pinning with real ECDSA, followed by 252-subset search.

    Stage 1 (ACP|NONE) grinds input-1 sequence.
    Stage 2 (NONE) grinds independently funded input-0 outpoint.
    Stage 3 (ACP|ALL) grinds the output value.
    Stage 4 (ALL) grinds input-0 sequence.
    The 10-choose-5 FAD nonce is solved after all four pins are fixed.
    """
    if aux_count < 1:
        raise ValueError("auxiliary output set must be nonempty")
    base = raw_template(funding_txid, aux_count, payout_script)
    script_setup = replace(setup.base, script_pubkey=setup.script)
    pin_attempts = {name: 0 for name, _ in FLAGS}
    nonce_attempts = 0
    for s1trial in range(SEQ1_LIMIT):
        first = replace(base, vin=(
            base.vin[0], replace(base.vin[1], sequence=0xF0000000 + s1trial),
        ))
        first_sig, first_digest = pin_signature(setup, first, *FLAGS[0])
        pin_attempts["acp_none"] += 1
        if len(first_sig) > TARGET_SIG_BYTES:
            continue

        for aux_vout in range(aux_count):
            second = replace(first, vin=(
                replace(first.vin[0], prevout_n=aux_vout), first.vin[1],
            ))
            second_sig, second_digest = pin_signature(setup, second, *FLAGS[1])
            pin_attempts["none"] += 1
            if len(second_sig) > TARGET_SIG_BYTES:
                continue
            if pin_digest(setup, second, FLAGS[0][1]) != first_digest:
                raise AssertionError("NONE stage altered earlier ACP|NONE digest")

            for value_off in range(OUTPUT_VARIANTS):
                third = replace(second, vout=(replace(
                    second.vout[0], value=PAYOUT_BASE_SATS + value_off,
                ),))
                third_sig, third_digest = pin_signature(setup, third, *FLAGS[2])
                pin_attempts["acp_all"] += 1
                if len(third_sig) > TARGET_SIG_BYTES:
                    continue
                if pin_digest(setup, third, FLAGS[1][1]) != second_digest:
                    raise AssertionError("ACP|ALL stage altered NONE digest")

                for s0trial in range(SEQ0_LIMIT):
                    fourth = replace(third, vin=(
                        replace(third.vin[0], sequence=0xF0000000 + s0trial),
                        third.vin[1],
                    ))
                    fourth_sig, fourth_digest = pin_signature(setup, fourth, *FLAGS[3])
                    pin_attempts["all"] += 1
                    if len(fourth_sig) > TARGET_SIG_BYTES:
                        continue
                    if pin_digest(setup, fourth, FLAGS[2][1]) != third_digest:
                        raise AssertionError("ALL stage altered ACP|ALL digest")
                    pins = {
                        "acp_none": first_sig, "none": second_sig,
                        "acp_all": third_sig, "all": fourth_sig,
                    }
                    digests = {
                        "acp_none": first_digest, "none": second_digest,
                        "acp_all": third_digest, "all": fourth_digest,
                    }
                    for subset in itertools.combinations(range(10), 5):
                        nonce_attempts += 1
                        code, deleted = code_for_subset(script_setup, subset)
                        if deleted != POOL_T:
                            raise AssertionError("unexpected nonce signature removal")
                        nonce_digest = signature_hash(code, fourth, 1, SIGHASH_ALL)
                        nonce_sig = rmin_sign(
                            nonce_digest, script_setup.puzzle_secret, SIGHASH_ALL
                        )
                        if len(nonce_sig) > TARGET_SIG_BYTES:
                            continue
                        final = replace(fourth, vin=(
                            fourth.vin[0], replace(
                                fourth.vin[1], script_sig=build_pinned_script_sig(
                                    pins, nonce_sig, subset,
                                ),
                            ),
                        ))
                        result = PinnedCandidate(
                            tx=final, nonce_subset=subset,
                            nonce_signature=nonce_sig, nonce_digest=nonce_digest,
                            pin_signatures=pins, pin_digests=digests,
                            pin_attempts=dict(pin_attempts),
                            nonce_attempts=nonce_attempts,
                        )
                        checks = verify_canonical_flags(result, setup)
                        if not all(checks.values()):
                            raise AssertionError("pinning candidate self-check: " + str(checks))
                        if len(final.vin[1].script_sig) > 10_000:
                            raise AssertionError("unlocking script too long")
                        return result
    raise RuntimeError("exhausted staged pinning search without finding witness")


def build_receipt(setup: PinnedSetup, candidate: PinnedCandidate) -> dict:
    checks = verify_canonical_flags(candidate, setup)
    if not all(checks.values()):
        raise AssertionError("invalid pinned receipt")
    altered_output = replace(candidate.tx, vout=(replace(
        candidate.tx.vout[0],
        script_pubkey=p2sh(op(0x52)),
    ),))
    if altered_output.vout == candidate.tx.vout:
        raise AssertionError("payout mutant accidentally identical")
    pin_sighashes = {
        name: {
            "sighash_flag": "0x%02x" % flag,
            "signature": candidate.pin_signatures[name].hex(),
            "signature_bytes": len(candidate.pin_signatures[name]),
            "digest": candidate.pin_digests[name].hex(),
            "altered_digest_matches": (
                candidate.pin_digests[name] ==
                pin_digest(setup, altered_output, flag)
            ),
        } for name, flag in FLAGS
    }
    if (pin_sighashes["all"]["altered_digest_matches"] or
            pin_sighashes["acp_all"]["altered_digest_matches"]):
        raise AssertionError("output change preserved ALL-mode pin hashes")
    if (not pin_sighashes["none"]["altered_digest_matches"] or
            not pin_sighashes["acp_none"]["altered_digest_matches"]):
        raise AssertionError("output changed NONE-mode pin hash")
    resources = script_resources(setup.script)
    resources["bare_total_sigops"] = resources["bare_CHECKMULTISIG_sigops"] + 4
    resources["signed_spend_size_bytes"] = len(ser_tx(candidate.tx))
    resources["spend_nonwitness_weight"] = 4 * len(ser_tx(candidate.tx))
    resources["spend_scriptSig_bytes"] = len(candidate.tx.vin[1].script_sig)
    return {
        "experiment": "JB-FAD03B",
        "status": "offline cryptography unless native Core receipt is present",
        "scriptpubkey_hex": setup.script.hex(),
        "resource_bounds": resources,
        "txid": candidate.txid,
        "raw_tx": ser_tx(candidate.tx).hex(),
        "nonce_subset": list(candidate.nonce_subset),
        "nonce_signature": candidate.nonce_signature.hex(),
        "nonce_sighash": candidate.nonce_digest.hex(),
        "nonce_grind_attempts": candidate.nonce_attempts,
        "four_pin_grind_attempts": candidate.pin_attempts,
        "four_pins": pin_sighashes,
        "canonical_offchain_checks": checks,
        "altered_output_raw": ser_tx(altered_output).hex(),
        "altered_output_txid": txid_hex(altered_output),
        "expected_output_substitution": "consensus rejection with original pins",
        "warnings": [
            "Public deterministic keys: only a proof-of-work accounting model",
            "Signature flag canonicality requires BitVM/off-chain validation",
            "Four independent toy-size 59-byte pins use W1 much lower than production target",
            "No full two-round Binohash commitment, vault covenant or ZK proof integration",
            "Nonstandard bare script needs miner-direct block inclusion",
        ],
    }


def run_native(node: CoreRPC) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("native JB-FAD03B is regtest-only")
    wallet = wallet_rpc(node, "jb_fad03b")
    miner = wallet("getnewaddress", "jb-fad03b-miner", "bech32")
    coins = [x for x in wallet("listunspent") if x["spendable"]
             and x["confirmations"] >= 101 and satoshis(x["amount"]) > 10_000_000]
    if not coins:
        node("generatetoaddress", 102, miner)
        coins = [x for x in wallet("listunspent") if x["spendable"]
                 and x["confirmations"] >= 101 and satoshis(x["amount"]) > 10_000_000]
    if not coins:
        raise RuntimeError("native funding coin missing")
    coin = coins[0]
    setup = make_pinned_setup()
    payout_addr = wallet("getnewaddress", "jb-fad03b-payout", "bech32")
    change_addr = wallet("getnewaddress", "jb-fad03b-change", "bech32")
    payout_script = bytes.fromhex(wallet("getaddressinfo", payout_addr)["scriptPubKey"])
    change_script = bytes.fromhex(wallet("getaddressinfo", change_addr)["scriptPubKey"])
    change = satoshis(coin["amount"]) - AUX_COUNT * AUX_VALUE_SATS - POOL_SATS - FUNDING_FEE_SATS
    if change <= 0:
        raise RuntimeError("insufficient coinbase balance")
    # Many OP_TRUE auxiliary outputs offer an input-0 prevout search axis for
    # SIGHASH_NONE without requiring a fresh funding transaction per attempt.
    outputs = [TxOut(AUX_VALUE_SATS, p2sh(AUX_REDEEM)) for _ in range(AUX_COUNT)]
    outputs.append(TxOut(POOL_SATS, setup.script))
    outputs.append(TxOut(change, change_script))
    funding = Tx(
        2, (TxIn(bytes.fromhex(coin["txid"])[::-1],
                 coin["vout"], b"", 0xFFFFFFFD),),
        tuple(outputs),
        0,
    )
    signed = wallet("signrawtransactionwithwallet", ser_tx(funding).hex())
    if not signed["complete"]:
        raise RuntimeError("wallet rejected native signed funding template")
    raw = signed["hex"]
    txid = node("decoderawtransaction", raw)["txid"]
    funding_policy = node("testmempoolaccept", [raw])[0]
    funded = node("generateblock", miner, [raw])
    if txid not in node("getblock", funded["hash"], 1)["tx"]:
        raise AssertionError("funding tx not in generated block")
    if node("gettxout", txid, AUX_COUNT, False) is None:
        raise AssertionError("pinned pool output absent")

    candidate = grind(setup, txid, payout_script)
    result = build_receipt(setup, candidate)
    result["status"] = "native Bitcoin Core 30.2 funded pinning test"
    result["funding"] = {
        "txid": txid, "block": funded["hash"], "raw": raw,
        "pool_vout": AUX_COUNT, "aux_vout": candidate.tx.vin[0].prevout_n,
        "aux_count": AUX_COUNT, "funding_policy": funding_policy,
    }
    result["spend_policy"] = node("testmempoolaccept", [result["raw_tx"]])[0]

    # Identical signatures, altered destination: the ALL and ACP|ALL pins now
    # bind the change, so native block validation must reject it.
    previous = node("getbestblockhash")
    try:
        node("generateblock", miner, [result["altered_output_raw"]])
    except RPCFailure as exc:
        if node("getbestblockhash") != previous:
            raise AssertionError("invalid payout advanced best-chain tip") from exc
        result["altered_output_native"] = {
            "accepted": False, "native_error": str(exc),
            "best_tip_preserved": True,
        }
    else:
        raise AssertionError("native Core accepted altered payout with stale pins")

    block = node("generateblock", miner, [result["raw_tx"]])
    if candidate.txid not in node("getblock", block["hash"], 1)["tx"]:
        raise AssertionError("pinned valid spend absent from block")
    if node("gettxout", txid, AUX_COUNT, False) is not None:
        raise AssertionError("pinned pool outpoint remains unspent")
    result["native_verdict"] = {
        "valid_pins_confirmed": True,
        "block": block["hash"], "txid": candidate.txid,
        "modified_payout_rejected": True,
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="artifacts/jb-fad03b/receipt.json")
    parser.add_argument("--live-regtest", action="store_true")
    parser.add_argument("--rpc-url", default=os.getenv("BITCOIND_RPC_URL", "http://127.0.0.1:18443"))
    parser.add_argument("--rpc-user", default=os.getenv("BITCOIND_RPC_USER", "user"))
    parser.add_argument("--rpc-password", default=os.getenv("BITCOIND_RPC_PASS", "pass"))
    args = parser.parse_args()
    if args.live_regtest:
        r = run_native(CoreRPC(args.rpc_url, args.rpc_user, args.rpc_password))
    else:
        setup = make_pinned_setup()
        candidate = grind(setup, "12" * 32, p2sh(op(0x51)))
        r = build_receipt(setup, candidate)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(r, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "experiment": r["experiment"],
        "pinning": r["four_pin_grind_attempts"],
        "nonce_attempts": r["nonce_grind_attempts"],
        "nonce_subset": r["nonce_subset"],
        "resource_bounds": r["resource_bounds"],
        "offchain_checks": r["canonical_offchain_checks"],
        "native": r.get("native_verdict"),
        "receipt": str(path),
    }, indent=2))


if __name__ == "__main__":
    main()
