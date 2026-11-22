#!/usr/bin/env python3
"""Stage the JB-FAD05 vault and its honest settlement on Bitcoin testnet4.

Builds a funding transaction with `--aux-count` P2SH(OP_TRUE) auxiliary
coins and the 2,695-byte bare FAD05 vault script, funds and signs it from a
Core wallet, then grinds the honest settlement (four pins, two HORS-attested
nonce rounds) against the funding txid. The payout goes to
P2WSH(<successor> <salt> 2DROP <wallet pubkey> CHECKSIG).

Both transactions are nonstandard (bare-script output, bare-script spend).
The node must run with -acceptnonstdtxn=1 (allowed on test networks only) to
hold them in its mempool; peers with default policy drop them, so
confirmation needs a testnet4 miner that accepts nonstandard transactions.

Without --broadcast the script only builds, signs and runs testmempoolaccept.
Refuses any chain other than testnet4.
"""

from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

from jb_fad01 import AUX_REDEEM, CoreRPC, RPCFailure, satoshis, wallet_rpc
from jb_fad05 import (
    PREVIOUS_STATE_ROOT, PROGRAM_ID, grind_settlement, make_setup, resources,
    settlement_record, successor_root,
)
from jb_fad05_interp import verify_input
from seam_digests_standalone import Tx, TxOut, op, p2sh, push, ser_tx, sha256, txid_hex

SETTLEMENT_VBYTES_BOUND = 730   # measured 719 bytes; DER lengths vary by a byte or two


def cookie_rpc(url: str, cookie: Path) -> CoreRPC:
    user, password = cookie.read_text(encoding="utf-8").strip().split(":", 1)
    return CoreRPC(url, user, password)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rpc-url", default="http://127.0.0.1:48342")
    ap.add_argument("--cookie", type=Path, required=True)
    ap.add_argument("--wallet", required=True)
    ap.add_argument("--aux-count", type=int, default=4)
    ap.add_argument("--aux-sats", type=int, default=546)
    ap.add_argument("--vault-sats", type=int, default=1000)
    ap.add_argument("--fee-rate", type=float, default=1.0, help="sat/vB for both transactions")
    ap.add_argument("--broadcast", action="store_true")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    node = cookie_rpc(args.rpc_url, args.cookie)
    info = node("getblockchaininfo")
    if info["chain"] != "testnet4":
        raise SystemExit(f"refusing chain {info['chain']!r}; this stager is testnet4-only")
    if info["blocks"] != info["headers"] or info["initialblockdownload"]:
        raise SystemExit("node is not synced to its best header")
    wallet = wallet_rpc(node, args.wallet)

    setup = make_setup()
    payee = wallet("getnewaddress", "jb-fad05-testnet4-payee", "bech32")
    pubkey = bytes.fromhex(wallet("getaddressinfo", payee)["pubkey"])
    body = push(pubkey) + op(0xAC)

    k = args.aux_count
    outputs = [TxOut(args.aux_sats, p2sh(AUX_REDEEM)) for _ in range(k)]
    outputs.append(TxOut(args.vault_sats, setup.script))
    # Manual coin selection: the wallet's funding RPCs apply the relay dust
    # rule to every output, and a 2,695-byte bare output has a dust threshold
    # near 8.6k sats. Dust is policy; -acceptnonstdtxn skips it.
    coins = sorted((u for u in wallet("listunspent", 1) if u["spendable"] and u["safe"]),
                   key=lambda u: -satoshis(u["amount"]))
    change_addr = wallet("getrawchangeaddress", "bech32")
    change_script = bytes.fromhex(wallet("getaddressinfo", change_addr)["scriptPubKey"])
    need = sum(o.value for o in outputs)
    chosen, total = [], 0
    for u in coins:
        chosen.append(u)
        total += satoshis(u["amount"])
        if total >= need + 4000:
            break
    if total < need + 1000:
        raise SystemExit(f"wallet holds {total} sats spendable; staging needs about {need + 4000}")

    def build(change_value: int) -> tuple[str, dict]:
        from seam_digests_standalone import TxIn
        vin = tuple(TxIn(bytes.fromhex(u["txid"])[::-1], u["vout"], b"", 0xFFFFFFFD) for u in chosen)
        tx = Tx(2, vin, tuple(outputs) + (TxOut(change_value, change_script),), 0)
        signed = wallet("signrawtransactionwithwallet", ser_tx(tx).hex())
        if not signed["complete"]:
            raise SystemExit("wallet could not sign the funding transaction")
        return signed["hex"], node("decoderawtransaction", signed["hex"])

    _, probe = build(total - need)
    wallet_fee = math.ceil(probe["vsize"] * args.fee_rate) + 2
    change_value = total - need - wallet_fee
    if change_value < 546:
        raise SystemExit("selected coins leave no change above dust")
    funding_hex, funding = build(change_value)
    funded = {"fee": (total - need - change_value) / 1e8}
    ftxid = funding["txid"]
    vault_vout = k
    if bytes.fromhex(funding["vout"][vault_vout]["scriptPubKey"]["hex"]) != setup.script:
        raise SystemExit("funding output order changed; vault not at the expected index")

    in_sats = args.vault_sats + args.aux_sats
    fee = math.ceil(SETTLEMENT_VBYTES_BOUND * args.fee_rate)
    payout = in_sats - fee
    if payout <= 0:
        raise SystemExit("vault + aux value does not cover the settlement fee")
    succ = successor_root(PREVIOUS_STATE_ROOT, ftxid, vault_vout, body, payout, fee)
    t0 = time.monotonic()
    s = grind_settlement(setup, ftxid, vault_vout, list(range(k)), body, succ,
                         payout_sats=payout, seq1_limit=1 << 22)
    grind_seconds = round(time.monotonic() - t0, 2)

    # The spent vault output is the funding output; the model checks the
    # exact script before anything leaves this machine.
    ok, why, trace = verify_input(s.tx.vin[1].script_sig, setup.script, s.tx, 1)
    if not ok:
        raise SystemExit("settlement fails the offline Script model: " + why)

    settlement_hex = ser_tx(s.tx).hex()
    package = node("testmempoolaccept", [funding_hex, settlement_hex])
    receipt = {
        "experiment": "JB-FAD05 testnet4 staging",
        "chain": info["chain"],
        "tip_at_build": {"height": info["blocks"], "hash": info["bestblockhash"]},
        "core_version": node("getnetworkinfo")["subversion"],
        "node_policy": "acceptnonstdtxn=1 (test networks only)",
        "funding": {"txid": ftxid, "raw_tx": funding_hex, "vault_vout": vault_vout,
                    "aux_vouts": list(range(k)), "aux_sats": args.aux_sats,
                    "vault_sats": args.vault_sats, "fee_rate_sat_vb": args.fee_rate,
                    "wallet_fee_sats": satoshis(funded["fee"]),
                    "vsize": funding["vsize"]},
        "settlement": settlement_record(s) | {
            "payout_sats": payout, "fee_sats": fee, "recipient_body": body.hex(),
            "payee_address": payee, "grind_seconds": grind_seconds,
            "offline_model": {"ok": ok, "core_op_count": trace.op_count}},
        "policy_registration": {
            "vault_txid": ftxid, "vault_vout": vault_vout,
            "funding_script_sha256": sha256(setup.script).hex(),
            "hors_root": setup.hors.root.hex(), "recipient_body_hex": body.hex(),
            "payout_sats": payout, "fee_sats": fee,
            "verified_program_id": PROGRAM_ID.hex(),
            "previous_state_root": PREVIOUS_STATE_ROOT.hex()},
        "resources": resources(setup, s),
        "testmempoolaccept_package": package,
        "broadcast": None,
    }
    if args.broadcast:
        # The funding must be locally acceptable. The settlement is attempted
        # and its refusal recorded: Core applies SCRIPT_VERIFY_CONST_SCRIPTCODE
        # to every mempool spend, and -acceptnonstdtxn does not lift it, so a
        # FindAndDelete spend reaches a block only through a miner.
        if not package[0].get("allowed"):
            raise SystemExit("local node refuses the funding; not broadcasting: " + json.dumps(package[0]))
        sent = {}
        for name, raw in (("funding", funding_hex), ("settlement", settlement_hex)):
            try:
                sent[name] = {"txid": node("sendrawtransaction", raw)}
            except RPCFailure as exc:
                sent[name] = {"error": str(exc)}
        mempool = set(node("getrawmempool"))
        sent["in_local_mempool"] = {"funding": ftxid in mempool, "settlement": s.txid in mempool}
        sent["peers"] = len(node("getpeerinfo"))
        sent["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        receipt["broadcast"] = sent
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"funding_txid": ftxid, "settlement_txid": s.txid,
                      "indices": list(s.indices), "package": package,
                      "broadcast": receipt["broadcast"], "receipt": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
