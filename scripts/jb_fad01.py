#!/usr/bin/env python3
"""JB-FAD01: funded P2SH FindAndDelete experiment.

Build two competing, fully signed legacy spends of the same outpoints. The
selected embedded SIGHASH_SINGLE signature is removed from the CHECKMULTISIG
scriptCode, changing the SIGHASH_ALL digest signed by a second key.

Offline mode generates reproducible transactions against a synthetic prevout
and verifies the ECDSA equations. --live-regtest creates real funded P2SH UTXOs
and probes Bitcoin Core policy. --confirm-branch A|B additionally submits that
variant directly to a regtest block with generateblock.

Research only. Deterministic demonstration keys are publicly reproducible.
Requires: pip install cryptography
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import struct
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from seam_digests_standalone import (
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    UINT256_ONE,
    Tx,
    TxIn,
    TxOut,
    dsha256,
    find_and_delete,
    op,
    p2sh,
    push,
    ser_tx,
    sha256,
    signature_hash,
    txid_hex,
)

OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_CHECKMULTISIG = 0xAE
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
COIN = Decimal(100_000_000)
AUX_SATS = 30_000
NONCE_SATS = 100_000
PAYOUT_SATS = 125_000
FUNDING_FEE_SATS = 3_000
AUX_REDEEM = op(OP_1)


def demo_scalar(label: str) -> int:
    return int.from_bytes(sha256(("JB-FAD01/" + label).encode()), "big") % (SECP256K1_ORDER - 1) + 1


def public_key(secret: int) -> ec.EllipticCurvePublicKey:
    return ec.derive_private_key(secret, ec.SECP256K1()).public_key()


def pubkey_bytes(secret: int) -> bytes:
    return public_key(secret).public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )


def demo_sign(secret: int, digest: bytes, nonce_label: str, sighash_flag: int) -> bytes:
    """Deterministic research ECDSA, with low S and canonical DER."""
    assert len(digest) == 32
    nonce = demo_scalar("nonce/" + nonce_label)
    r = public_key(nonce).public_numbers().x % SECP256K1_ORDER
    s = (pow(nonce, -1, SECP256K1_ORDER) *
         (int.from_bytes(digest, "big") + r * secret)) % SECP256K1_ORDER
    if r == 0 or s == 0:
        raise ValueError("degenerate ECDSA demonstration nonce")
    s = min(s, SECP256K1_ORDER - s)
    return utils.encode_dss_signature(r, s) + bytes([sighash_flag])


def verifies(secret: int, digest: bytes, signature: bytes) -> bool:
    try:
        public_key(secret).verify(
            signature[:-1],
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return True
    except InvalidSignature:
        return False


@dataclass(frozen=True)
class Setup:
    redeem_script: bytes
    single_signatures: dict[str, bytes]
    puzzle_secret: int
    single_secret: int


@dataclass(frozen=True)
class Variant:
    branch: str
    tx: Tx
    script_code: bytes
    sighash: bytes
    puzzle_signature: bytes
    removed_pushes: int


def make_setup() -> Setup:
    single = demo_scalar("single-key")
    puzzle = demo_scalar("puzzle-key")
    signatures = {
        name: demo_sign(single, UINT256_ONE, "single-" + name, SIGHASH_SINGLE)
        for name in ("A", "B")
    }
    assert signatures["A"] != signatures["B"]
    assert all(verifies(single, UINT256_ONE, sig) for sig in signatures.values())
    redeem = (
        op(OP_IF) + push(signatures["A"]) +
        op(OP_ELSE) + push(signatures["B"]) + op(OP_ENDIF) +
        op(OP_2) + push(pubkey_bytes(puzzle)) +
        push(pubkey_bytes(single)) + op(OP_2) + op(OP_CHECKMULTISIG)
    )
    if len(redeem) > 520:
        raise ValueError("P2SH redeem script exceeds consensus push limit")
    return Setup(redeem, signatures, puzzle, single)


def script_sig(setup: Setup, puzzle_signature: bytes, branch: str) -> bytes:
    if branch not in ("A", "B"):
        raise ValueError("branch must be A or B")
    # P2SH scriptSig is push-only. The first OP_0 is CHECKMULTISIG's NULLDUMMY.
    return (
        op(OP_0) + push(puzzle_signature) +
        op(OP_1 if branch == "A" else OP_0) + push(setup.redeem_script)
    )


def build_variants(setup: Setup, funding_txid: str, payout_script: bytes) -> dict[str, Variant]:
    if len(bytes.fromhex(funding_txid)) != 32:
        raise ValueError("funding_txid must contain exactly 32 bytes")
    prevhash = bytes.fromhex(funding_txid)[::-1]
    template = Tx(
        version=2,
        vin=(TxIn(prevhash, 0, b"", 0xFFFFFFFD),
             TxIn(prevhash, 1, b"", 0xFFFFFFFD)),
        vout=(TxOut(PAYOUT_SATS, payout_script),),
        locktime=0,
    )
    # With one output, input index 1 invokes Bitcoin's historical SINGLE bug.
    assert signature_hash(setup.redeem_script, template, 1, SIGHASH_SINGLE) == UINT256_ONE

    variants = {}
    for name, selected in setup.single_signatures.items():
        code, removed = find_and_delete(setup.redeem_script, push(selected))
        if removed != 1:
            raise ValueError("expected exactly one selected signature removal")
        sighash = signature_hash(code, template, 1, SIGHASH_ALL)
        puzzle_sig = demo_sign(setup.puzzle_secret, sighash, "puzzle-" + name, SIGHASH_ALL)
        if not verifies(setup.puzzle_secret, sighash, puzzle_sig):
            raise AssertionError("puzzle signature self-verification failed")
        tx = replace(
            template,
            vin=(replace(template.vin[0], script_sig=push(AUX_REDEEM)),
                 replace(template.vin[1], script_sig=script_sig(setup, puzzle_sig, name))),
        )
        variants[name] = Variant(name, tx, code, sighash, puzzle_sig, removed)

    if variants["A"].sighash == variants["B"].sighash:
        raise AssertionError("FindAndDelete failed to split sighash contexts")
    return variants


def attack_cases(setup: Setup, variants: dict[str, Variant]) -> dict[str, bool]:
    a, b = variants["A"], variants["B"]
    wrong_branch = replace(
        a.tx, vin=(a.tx.vin[0],
                   replace(a.tx.vin[1], script_sig=script_sig(setup, a.puzzle_signature, "B"))),
    )
    changed_amount = replace(a.tx, vout=(replace(a.tx.vout[0], value=PAYOUT_SATS - 1),))
    added_output = replace(a.tx, vout=a.tx.vout + (TxOut(0, op(OP_1)),))
    # Both the actual ECDSA signature and the current Script context matter.
    return {
        "A_verified": verifies(setup.puzzle_secret, a.sighash, a.puzzle_signature),
        "B_verified": verifies(setup.puzzle_secret, b.sighash, b.puzzle_signature),
        "A_rejects_unmodified_scriptcode": not verifies(
            setup.puzzle_secret, signature_hash(setup.redeem_script, a.tx, 1, SIGHASH_ALL),
            a.puzzle_signature),
        "A_rejects_branch_flip": not verifies(
            setup.puzzle_secret, signature_hash(b.script_code, wrong_branch, 1, SIGHASH_ALL),
            a.puzzle_signature),
        "A_rejects_changed_amount": not verifies(
            setup.puzzle_secret, signature_hash(a.script_code, changed_amount, 1, SIGHASH_ALL),
            a.puzzle_signature),
        "SINGLE_pool_rejects_second_output": not verifies(
            setup.single_secret,
            signature_hash(a.script_code, added_output, 1, SIGHASH_SINGLE),
            setup.single_signatures["A"]),
        "A_rejects_wrong_sighash_flag": not verifies(
            setup.puzzle_secret,
            signature_hash(a.script_code, a.tx, 1, 0x82),
            a.puzzle_signature),
    }


def audit(setup: Setup, variants: dict[str, Variant]) -> dict:
    checks = attack_cases(setup, variants)
    if not all(checks.values()):
        raise AssertionError("JB-FAD01 cryptographic self-test failed: " + str(checks))
    return {
        "experiment": "JB-FAD01",
        "scope": "offline cryptography; Core consensus requires --live-regtest",
        "redeem_script_hex": setup.redeem_script.hex(),
        "p2sh_script_pubkey_hex": p2sh(setup.redeem_script).hex(),
        "redeem_size_bytes": len(setup.redeem_script),
        "single_bug_digest_hex_raw_bytes": UINT256_ONE.hex(),
        "variants": {
            name: {
                "txid": txid_hex(v.tx),
                "raw_transaction_hex": ser_tx(v.tx).hex(),
                "script_code_hex": v.script_code.hex(),
                "script_code_sha256": sha256(v.script_code).hex(),
                "sighash_hex_raw_bytes": v.sighash.hex(),
                "selected_single_signature": setup.single_signatures[name].hex(),
                "puzzle_signature": v.puzzle_signature.hex(),
                "removed_pushes": v.removed_pushes,
                "vsize_legacy": len(ser_tx(v.tx)),
            }
            for name, v in variants.items()
        },
        "checks": checks,
        "warnings": [
            "synthetic prevout in offline mode: raw transactions are not broadcastable",
            "this is not a vault covenant or a keyless authorization mechanism",
            "selected nonce pool signature is SINGLE-bug-based; one output and index 1 are mandatory",
            "P2SH scriptCode mutation is nonstandard under CONST_SCRIPTCODE policy",
            "key scalars and signatures are deterministic public research fixtures",
        ],
    }


class RPCFailure(RuntimeError):
    pass


class CoreRPC:
    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode((username + ":" + password).encode()).decode()

    def __call__(self, method: str, *params):
        payload = json.dumps({"jsonrpc": "1.0", "id": "jb-fad01", "method": method,
                              "params": params}).encode()
        req = Request(self.url, payload, {"Content-Type": "application/json",
                                           "Authorization": self.auth})
        try:
            with urlopen(req, timeout=120) as resp:
                body = resp.read()
        except HTTPError as e:
            body = e.read()
        try:
            data = json.loads(body)
        except (ValueError, UnboundLocalError):
            raise RPCFailure(method + ": invalid RPC response") from None
        if data.get("error"):
            raise RPCFailure(method + ": " + str(data["error"]))
        return data["result"]


def wallet_rpc(node: CoreRPC, name: str) -> CoreRPC:
    loaded = node("listwallets")
    if name not in loaded:
        names = [row["name"] for row in node("listwalletdir")["wallets"]]
        node("loadwallet", name) if name in names else node("createwallet", name)
    # Inherit the same Authorization header without reinterpreting credentials.
    wallet = CoreRPC.__new__(CoreRPC)
    wallet.url = node.url + "/wallet/" + name
    wallet.auth = node.auth
    return wallet


def satoshis(btc) -> int:
    result = Decimal(str(btc)) * COIN
    if result != int(result):
        raise ValueError("fractional satoshi in Core RPC")
    return int(result)


def run_regtest(node: CoreRPC, confirm_branch: str | None) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("JB-FAD01 refuses to use a non-regtest node")
    wallet = wallet_rpc(node, "jb_fad01")
    miner_addr = wallet("getnewaddress", "jb-fad01-miner", "bech32")
    coins = [coin for coin in wallet("listunspent")
             if coin["spendable"] and coin["confirmations"] >= 101
             and satoshis(coin["amount"]) > 1_000_000]
    if not coins:
        node("generatetoaddress", 102, miner_addr)
        coins = [coin for coin in wallet("listunspent")
                 if coin["spendable"] and coin["confirmations"] >= 101
                 and satoshis(coin["amount"]) > 1_000_000]
    if not coins:
        raise RuntimeError("wallet has no mature funding coin after mining")

    coin = coins[0]
    setup = make_setup()
    change_addr = wallet("getnewaddress", "jb-fad01-change", "bech32")
    payout_addr = wallet("getnewaddress", "jb-fad01-payout", "bech32")
    change_script = bytes.fromhex(wallet("getaddressinfo", change_addr)["scriptPubKey"])
    payout_script = bytes.fromhex(wallet("getaddressinfo", payout_addr)["scriptPubKey"])
    change = satoshis(coin["amount"]) - AUX_SATS - NONCE_SATS - FUNDING_FEE_SATS
    if change <= 0:
        raise RuntimeError("insufficient funds for a regtest fixture")
    funding = Tx(2, (TxIn(bytes.fromhex(coin["txid"])[::-1], coin["vout"], b"", 0xFFFFFFFD),),
                 (TxOut(AUX_SATS, p2sh(AUX_REDEEM)),
                  TxOut(NONCE_SATS, p2sh(setup.redeem_script)),
                  TxOut(change, change_script)))
    signed = wallet("signrawtransactionwithwallet", ser_tx(funding).hex())
    if not signed["complete"]:
        raise RuntimeError("wallet could not sign fixture funding transaction")
    funding_txid = node("sendrawtransaction", signed["hex"])
    node("generatetoaddress", 1, miner_addr)

    if node("gettxout", funding_txid, 0, False) is None or node("gettxout", funding_txid, 1, False) is None:
        raise RuntimeError("funding outpoints are not confirmed and unspent")
    variants = build_variants(setup, funding_txid, payout_script)
    result = audit(setup, variants)
    result["scope"] = "Bitcoin Core regtest-funded signed spends"
    result["funding_txid"] = funding_txid
    result["mempool_policy"] = {
        name: node("testmempoolaccept", [ser_tx(v.tx).hex()])[0]
        for name, v in variants.items()
    }
    if confirm_branch:
        selected = variants[confirm_branch]
        before = node("getbestblockhash")
        swapped = "B" if confirm_branch == "A" else "A"
        invalid = replace(
            selected.tx,
            vin=(selected.tx.vin[0],
                 replace(selected.tx.vin[1],
                         script_sig=script_sig(setup, selected.puzzle_signature, swapped))),
        )
        # Consensus-level rejection, independent of standard mempool policy.
        try:
            node("generateblock", miner_addr, [ser_tx(invalid).hex()])
        except RPCFailure as exc:
            if node("getbestblockhash") != before:
                raise AssertionError("rejected challenge advanced regtest tip") from exc
            result["native_negative"] = {
                "kind": "cross_branch_puzzle_signature",
                "invalid_txid": txid_hex(invalid),
                "rejected": True,
                "reason": str(exc),
            }
        else:
            raise AssertionError("cross-branch invalid puzzle signature mined")

        mined = node("generateblock", miner_addr, [ser_tx(selected.tx).hex()])
        block = node("getblock", mined["hash"], 1)
        if txid_hex(selected.tx) not in block["tx"]:
            raise AssertionError("generateblock did not include selected spend")
        if before == mined["hash"]:
            raise AssertionError("regtest block did not advance")
        result["confirmed_branch"] = confirm_branch
        result["confirmed_block"] = mined["hash"]
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", default="artifacts/jb-fad01/receipt.json")
    parser.add_argument("--live-regtest", action="store_true",
                        help="fund P2SH outputs and test candidates on a local regtest Core node")
    parser.add_argument("--confirm-branch", choices=("A", "B"),
                        help="mine one branch through Bitcoin Core generateblock")
    parser.add_argument("--rpc-url", default=os.getenv("BITCOIND_RPC_URL", "http://127.0.0.1:18443"))
    parser.add_argument("--rpc-user", default=os.getenv("BITCOIND_RPC_USER", "user"))
    parser.add_argument("--rpc-password", default=os.getenv("BITCOIND_RPC_PASS", "pass"))
    args = parser.parse_args()
    if args.confirm_branch and not args.live_regtest:
        parser.error("--confirm-branch requires --live-regtest")
    if args.live_regtest:
        result = run_regtest(CoreRPC(args.rpc_url, args.rpc_user, args.rpc_password),
                             args.confirm_branch)
    else:
        setup = make_setup()
        variants = build_variants(setup, "12" * 32, p2sh(AUX_REDEEM))
        result = audit(setup, variants)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"experiment": result["experiment"], "checks": result["checks"],
                      "txids": {k: v["txid"] for k, v in result["variants"].items()},
                      "receipt": str(output), "confirmed": result.get("confirmed_branch"),
                      "native_negative": result.get("native_negative"),
                      "mempool_policy": {
                          k: {"allowed": v.get("allowed"), "reason": v.get("reject-reason")}
                          for k, v in result.get("mempool_policy", {}).items()
                      }},
                     indent=2))


if __name__ == "__main__":
    main()
