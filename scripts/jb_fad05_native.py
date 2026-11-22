#!/usr/bin/env python3
"""JB-FAD05 native campaign on an isolated Bitcoin Core regtest node.

Every claim in the receipt is a Bitcoin Core block-validation decision made
through `generateblock` (miner-direct inclusion), recorded next to the
default relay-policy decision from `testmempoolaccept`. Rejected blocks
must leave the best-block hash unchanged and the watched coins unspent.
Accepted *alternative* histories are rolled back with `invalidateblock`
and checked the same way.

Scenarios:
  A  HORS subset attestation: honest settlement and 13 rejected mutations.
  B  All 256 legacy sighash bytes on the round-2 nonce signature.
  C  Third-party txid malleation of the confirmed settlement.
  D  Controlled reorg + front-run that re-uses the revealed HORS preimages.
  E  Retained HORS key: unauthorized operator payout, then equivocation slash;
     a single unauthorized attestation cannot be slashed.
  F  Bond timeout: early release rejected, challenger censored until CSV
     expiry, late slash rejected.
  G  Split-UTXO arrangement: round-1 UTXO spends without round-2 UTXO.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
from dataclasses import replace
from pathlib import Path

from jb_fad01 import AUX_REDEEM, CoreRPC, RPCFailure, pubkey_bytes, satoshis, wallet_rpc
from cryptography.hazmat.primitives.asymmetric import utils

from jb_fad01 import SECP256K1_ORDER
from jb_fad02 import POOL_N, POOL_T, TARGET_SIG_BYTES, push_num, selection_depths
from jb_fad03_pinning import FLAGS, rmin_sign
from jb_fad05 import (
    ATTACKER_SECRET, AUX_VALUE_SATS, BOND_CSV_BLOCKS, BOND_SATS, EQUIV_T,
    OPERATOR_SECRET, PAYOUT_SATS, PREVIOUS_STATE_ROOT, PROGRAM_ID,
    RECIPIENT_SECRET, ROUNDS, SETTLEMENT_FEE_SATS, UNAUTHORIZED_SECRET,
    VAULT_SATS, Settlement, bond_script, build_script_sig,
    canonical_round_unlock, equivocation_unlock, front_run, grind_settlement,
    key_body, make_setup, nonce_script_code, p2wsh, payout_witness_script,
    release_unlock, resources, round_specs, round_unlock, settlement_record,
    split_scripts, successor_root, RoundSpec,
)
from seam_digests_standalone import (
    Tx, TxIn, TxOut, op, p2sh, push, ser_tx, sha256, signature_hash, txid_hex,
)

AUX_COUNT = 2048
FUNDING_FEE_SATS = 30_000


class Campaign:
    def __init__(self, node: CoreRPC, miner: str):
        self.node = node
        self.miner = miner

    def tip(self) -> str:
        return self.node("getbestblockhash")

    def policy(self, tx: Tx) -> dict:
        row = self.node("testmempoolaccept", [ser_tx(tx).hex()])[0]
        return {"allowed": row.get("allowed", False),
                "reject_reason": row.get("reject-reason")}

    def unspent(self, outpoints) -> bool:
        return all(self.node("gettxout", t, v, False) is not None for t, v in outpoints)

    def mine(self, tx: Tx) -> str:
        block = self.node("generateblock", self.miner, [ser_tx(tx).hex()])["hash"]
        if txid_hex(tx) not in self.node("getblock", block, 1)["tx"]:
            raise AssertionError("direct block omitted the transaction")
        return block

    def reject(self, label: str, tx: Tx, watch) -> dict:
        tip = self.tip()
        try:
            block = self.mine(tx)
        except RPCFailure as exc:
            if self.tip() != tip:
                raise AssertionError(label + ": rejected block moved the tip") from exc
            if not self.unspent(watch):
                raise AssertionError(label + ": watched coin spent after rejection")
            return {"consensus": "rejected", "reason": str(exc), "tip_preserved": tip,
                    "relay_policy": self.policy(tx), "txid": txid_hex(tx)}
        raise AssertionError(f"{label}: Core accepted block {block}")

    def accept_alternative(self, label: str, tx: Tx, watch) -> dict:
        tip = self.tip()
        pol = self.policy(tx)
        block = self.mine(tx)
        spent = not self.unspent(watch)
        self.node("invalidateblock", block)
        if self.tip() != tip or not self.unspent(watch):
            raise AssertionError(label + ": rollback did not restore the chain")
        return {"consensus": "accepted", "block": block, "txid": txid_hex(tx),
                "spent_watched_coins": spent, "rolled_back_to": tip,
                "relay_policy": pol}


def block_evidence(node: CoreRPC, block: str, txid: str) -> dict:
    txids = node("getblock", block, 1)["tx"]
    return {"block_hash": block, "header_hex": node("getblockheader", block, False),
            "txids": txids, "position": txids.index(txid)}


def ordered_unlock(nonce_sig: bytes, picks: list[int], row) -> bytes:
    """Selector encoding for an ARBITRARY pick order (canonical or not)."""
    remaining = list(range(POOL_N))  # remaining[-1] is the top of the region
    depths = []
    for p in picks:
        d = len(remaining) - 1 - remaining.index(p)
        depths.append(d)
        remaining.remove(p)
    return round_unlock(nonce_sig, tuple(depths), tuple(row[p] for p in picks))


def with_round(s: Settlement, rows, *, r1: bytes | None = None, r2: bytes | None = None,
               pins: dict | None = None) -> Tx:
    g1 = r1 if r1 is not None else canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], rows[0])
    g2 = r2 if r2 is not None else canonical_round_unlock(s.nonce_sigs[1], s.subsets[1], rows[1])
    sig = build_script_sig(pins or s.pins, g1, g2)
    return replace(s.tx, vin=(s.tx.vin[0], replace(s.tx.vin[1], script_sig=sig)))


def scenario_a(c: Campaign, setup, s: Settlement, funding_txid: str, vault_vout: int,
               twin_vout: int, body: bytes) -> dict:
    rows = setup.hors.preimages
    vault = [(funding_txid, vault_vout)]
    out = {}
    tx = s.tx
    out["payout_plus_one_sat"] = c.reject("payout+1", replace(tx, vout=(replace(tx.vout[0], value=tx.vout[0].value + 1),)), vault)
    out["fee_plus_1000_sats"] = c.reject("fee+1000", replace(tx, vout=(replace(tx.vout[0], value=tx.vout[0].value - 1000),)), vault)
    altered_succ = payout_witness_script(sha256(b"altered successor"), s.salt, body)
    out["altered_successor_root"] = c.reject("successor", replace(tx, vout=(TxOut(tx.vout[0].value, p2wsh(altered_succ)),)), vault)
    other = payout_witness_script(s.successor, s.salt, key_body(ATTACKER_SECRET))
    out["altered_recipient"] = c.reject("recipient", replace(tx, vout=(TxOut(tx.vout[0].value, p2wsh(other)),)), vault)
    out["extra_output"] = c.reject("extra output", replace(tx, vout=tx.vout + (TxOut(0, op(0x51)),)), vault)
    out["substituted_vault_outpoint"] = c.reject(
        "outpoint", replace(tx, vin=(tx.vin[0], replace(tx.vin[1], prevout_n=twin_vout))),
        vault + [(funding_txid, twin_vout)])
    picks1 = sorted(s.subsets[0], reverse=True)
    bad_row = list(rows[0]); bad_row[picks1[2]] = bytes([rows[0][picks1[2]][0] ^ 1]) + rows[0][picks1[2]][1:]
    out["round1_corrupted_preimage"] = c.reject("bad preimage", with_round(s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], tuple(bad_row))), vault)
    out["cross_round_preimages"] = c.reject("cross round", with_round(
        s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], rows[1]),
        r2=canonical_round_unlock(s.nonce_sigs[1], s.subsets[1], rows[0])), vault)
    dup = list(rows[0]); dup[picks1[1]] = rows[0][picks1[0]]
    out["duplicated_preimage"] = c.reject("duplicate", with_round(s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], tuple(dup))), vault)
    reordered = [picks1[1], picks1[0]] + picks1[2:]
    out["reordered_same_subset"] = c.reject("reordered", with_round(s, rows, r1=ordered_unlock(s.nonce_sigs[0], reordered, rows[0])), vault)
    ascending = sorted(s.subsets[1])
    out["ascending_encoding_same_subset"] = c.reject("ascending", with_round(s, rows, r2=ordered_unlock(s.nonce_sigs[1], ascending, rows[1])), vault)
    alt = next(x for x in itertools.combinations(range(POOL_N), POOL_T) if x != s.subsets[1])
    out["substituted_round2_subset_with_real_preimages"] = c.reject(
        "subset", with_round(s, rows, r2=canonical_round_unlock(s.nonce_sigs[1], alt, rows[1])), vault)
    depths = list(selection_depths(s.subsets[0])); depths[0] = POOL_N
    out["out_of_range_selector"] = c.reject("range", with_round(s, rows, r1=round_unlock(
        s.nonce_sigs[0], tuple(depths), tuple(rows[0][p] for p in picks1))), vault)
    r_, s_ = utils.decode_dss_signature(s.nonce_sigs[1][:-1])
    high = utils.encode_dss_signature(r_, SECP256K1_ORDER - s_) + s.nonce_sigs[1][-1:]
    out["high_s_nonce_twin"] = c.reject("high-S", with_round(s, rows, r2=canonical_round_unlock(high, s.subsets[1], rows[1])), vault)
    out["_note"] = "every mutation keeps all other signatures and preimages from the honest settlement"
    return out


def scenario_b(c: Campaign, setup, s: Settlement, funding_txid: str, vault_vout: int) -> dict:
    """Re-sign ONLY the round-2 nonce signature under each of 256 flag bytes."""
    rows = setup.hors.preimages
    code = nonce_script_code(setup, 2, s.subsets[1])
    vault = [(funding_txid, vault_vout)]
    matrix = []
    for flag in range(256):
        digest = signature_hash(code, s.tx, 1, flag)
        sig = rmin_sign(digest, setup.puzzle_secrets[1], flag)
        tx = with_round(s, rows, r2=canonical_round_unlock(sig, s.subsets[1], rows[1]))
        row = {"flag": f"0x{flag:02x}", "sig_bytes": len(sig),
               "base": ("NONE" if flag & 0x1F == 2 else "SINGLE" if flag & 0x1F == 3 else "ALL-like"),
               "acp": bool(flag & 0x80)}
        if len(sig) <= TARGET_SIG_BYTES:
            res = c.accept_alternative(f"flag {flag:#x}", tx, vault)
        else:
            res = c.reject(f"flag {flag:#x}", tx, vault)
        row["consensus"] = res["consensus"]
        row["block"] = res.get("block")
        row["referee_canonical"] = flag == 0x01
        matrix.append(row)
    accepted = [r["flag"] for r in matrix if r["consensus"] == "accepted"]
    return {"rows": matrix, "accepted_flags": accepted,
            "rejected_count": 256 - len(accepted),
            "note": "acceptance is exactly the 59-byte size gate; Core ignores which flag byte was used"}


def scenario_c(c: Campaign, setup, s: Settlement, funding_txid: str, vault_vout: int) -> dict:
    vault = [(funding_txid, vault_vout)]
    sig = s.tx.vin[1].script_sig
    out = {}
    # Prepend OP_NOP: consensus-valid for a bare scriptPubKey spend.
    nop = replace(s.tx, vin=(s.tx.vin[0], replace(s.tx.vin[1], script_sig=op(0x61) + sig)))
    out["prepended_op_nop"] = c.accept_alternative("nop twin", nop, vault)
    # Prepend arbitrary data: it lands below every group, all depths are
    # measured from the top, and only the top element is checked at the end.
    junk = replace(s.tx, vin=(s.tx.vin[0], replace(s.tx.vin[1], script_sig=push(b"third-party") + sig)))
    out["prepended_data_push"] = c.accept_alternative("junk twin", junk, vault)
    # Re-encode the first round-2 selector as a one-byte data push instead of
    # the minimal OP_n / OP_0 form. MINIMALDATA is policy, not consensus.
    rows = setup.hors.preimages
    picks = sorted(s.subsets[1], reverse=True)
    depths = selection_depths(s.subsets[1])
    group = (push(s.nonce_sigs[1]) + b"".join(push(rows[1][p]) for p in picks) +
             bytes([1, depths[0]]) + b"".join(push_num(d) for d in depths[1:]))
    nonminimal = with_round(s, rows, r2=group)
    out["nonminimal_selector_push"] = c.accept_alternative("selector twin", nonminimal, vault)
    for k, v in out.items():
        v["txid_differs_from_honest"] = v["txid"] != s.txid
    return out


def run_native(node: CoreRPC) -> dict:
    if node("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("JB-FAD05 refuses non-regtest networks")
    wallet = wallet_rpc(node, "jb_fad05")
    miner = wallet("getnewaddress", "jb-fad05-miner", "bech32")
    if node("getblockcount") < 110:
        node("generatetoaddress", 110, miner)
    coins = sorted((x for x in wallet("listunspent") if x["spendable"] and x["confirmations"] >= 101),
                   key=lambda x: -satoshis(x["amount"]))
    if not coins:
        raise RuntimeError("no mature fixture coin")
    coin = coins[0]
    c = Campaign(node, miner)
    setup = make_setup()
    op_pub = pubkey_bytes(OPERATOR_SECRET)
    bonds = tuple(bond_script(setup.hors.tables[r], op_pub) for r in range(ROUNDS))
    split1, split2 = split_scripts(setup)
    change = wallet("getnewaddress", "jb-fad05-change", "bech32")
    change_script = bytes.fromhex(wallet("getaddressinfo", change)["scriptPubKey"])
    V, VT, B1, B2, S1, S2 = (AUX_COUNT + k for k in range(6))
    outputs = ([TxOut(AUX_VALUE_SATS, p2sh(AUX_REDEEM)) for _ in range(AUX_COUNT)] +
               [TxOut(VAULT_SATS, setup.script), TxOut(VAULT_SATS, setup.script),
                TxOut(BOND_SATS, bonds[0]), TxOut(BOND_SATS, bonds[1]),
                TxOut(VAULT_SATS, split1), TxOut(VAULT_SATS, split2)])
    spent_value = sum(o.value for o in outputs) + FUNDING_FEE_SATS
    outputs.append(TxOut(satoshis(coin["amount"]) - spent_value, change_script))
    funding = Tx(2, (TxIn(bytes.fromhex(coin["txid"])[::-1], coin["vout"], b"", 0xFFFFFFFD),),
                 tuple(outputs), 0)
    signed = wallet("signrawtransactionwithwallet", ser_tx(funding).hex())
    if not signed["complete"]:
        raise AssertionError("funding signature incomplete")
    funding_raw = signed["hex"]
    ftxid = node("decoderawtransaction", funding_raw)["txid"]
    funding_policy = node("testmempoolaccept", [funding_raw])[0]
    funding_block = node("generateblock", miner, [funding_raw])["hash"]
    funding_height = node("getblock", funding_block, 1)["height"]
    aux = list(range(AUX_COUNT))
    receipt = {
        "experiment": "JB-FAD05",
        "scope": "native Bitcoin Core regtest; generateblock = miner-direct inclusion",
        "core_version": node("getnetworkinfo")["subversion"],
        "funding": {"txid": ftxid, "raw_tx": funding_raw, "block": funding_block,
                    "height": funding_height, "vault_vout": V, "twin_vault_vout": VT,
                    "bond_vouts": [B1, B2], "split_vouts": [S1, S2],
                    "aux_count": AUX_COUNT,
                    "relay_policy": {"allowed": funding_policy.get("allowed", False),
                                     "reject_reason": funding_policy.get("reject-reason")}},
        "locking_script_hex": setup.script.hex(),
        "bond_scripts_hex": [b.hex() for b in bonds],
        "split_scripts_hex": [split1.hex(), split2.hex()],
        "hors_root": setup.hors.root.hex(),
        "program_id": PROGRAM_ID.hex(),
        "previous_state_root": PREVIOUS_STATE_ROOT.hex(),
    }

    body = key_body(RECIPIENT_SECRET)
    succ = successor_root(PREVIOUS_STATE_ROOT, ftxid, V, body, PAYOUT_SATS, SETTLEMENT_FEE_SATS)
    honest = grind_settlement(setup, ftxid, V, aux, body, succ)
    receipt["honest"] = settlement_record(honest)
    receipt["honest"]["recipient_body"] = body.hex()
    receipt["honest"]["relay_policy"] = c.policy(honest.tx)
    receipt["resources"] = resources(setup, honest)

    receipt["A_attestation_mutations"] = scenario_a(c, setup, honest, ftxid, V, VT, body)
    receipt["B_sighash_flag_matrix"] = scenario_b(c, setup, honest, ftxid, V)
    receipt["C_txid_malleation"] = scenario_c(c, setup, honest, ftxid, V)

    vault = [(ftxid, V)]
    block_a = c.mine(honest.tx)
    if c.unspent(vault):
        raise AssertionError("vault still unspent after honest settlement")
    receipt["honest"]["block_evidence"] = block_evidence(node, block_a, honest.txid)

    # D: controlled reorg, then front-run with the revealed preimages.
    node("invalidateblock", block_a)
    if not c.unspent(vault):
        raise AssertionError("reorg did not restore the vault coin")
    fr = front_run(setup, honest, ftxid, V, aux, key_body(ATTACKER_SECRET))
    d = {"front_run": settlement_record(fr), "relay_policy": c.policy(fr.tx)}
    d["same_indices_as_honest"] = fr.indices == honest.indices
    d["preimages_used"] = "only the ten revealed in the honest settlement scriptSig"
    block_f = c.mine(fr.tx)
    d["consensus"] = "accepted"
    d["block_evidence"] = block_evidence(node, block_f, fr.txid)
    d["honest_now_conflicts"] = c.reject("honest after front-run", honest.tx, [])
    node("invalidateblock", block_f)
    node("reconsiderblock", block_a)
    if c.tip() != block_a or c.unspent(vault):
        raise AssertionError("could not restore the honest history")
    d["restored_honest_tip"] = block_a
    receipt["D_reorg_front_run"] = d

    # E: retained HORS key; unauthorized payout in an alternative history.
    node("invalidateblock", block_a)
    ubody = key_body(UNAUTHORIZED_SECRET)
    usucc = successor_root(PREVIOUS_STATE_ROOT, ftxid, V, ubody, PAYOUT_SATS, SETTLEMENT_FEE_SATS)
    unauth = grind_settlement(setup, ftxid, V, aux, ubody, usucc)
    e = {"unauthorized": settlement_record(unauth), "relay_policy": c.policy(unauth.tx)}
    e["unauthorized"]["recipient_body"] = ubody.hex()
    block_u = c.mine(unauth.tx)
    e["consensus"] = "accepted"
    e["block_evidence"] = block_evidence(node, block_u, unauth.txid)
    rows = setup.hors.preimages
    slashed = None
    e["union_sizes"] = []
    for r in range(ROUNDS):
        union = set(honest.subsets[r]) | set(unauth.subsets[r])
        e["union_sizes"].append(len(union))
        if len(union) >= EQUIV_T and slashed is None:
            slashed = r
    bond_vouts = (B1, B2)
    challenger = bytes.fromhex(wallet("getaddressinfo", wallet("getnewaddress", "jb-fad05-challenger", "bech32"))["scriptPubKey"])
    single = {idx: rows[0][idx] for idx in unauth.subsets[0]}
    filler = next(i for i in range(POOL_N) if i not in single)
    single[filler] = sha256(b"guess")[:20]
    lone = Tx(2, (TxIn(bytes.fromhex(ftxid)[::-1], B1, equivocation_unlock(single), 0xFFFFFFFF),),
              (TxOut(BOND_SATS - 2_000, challenger),), 0)
    e["slash_with_single_attestation_plus_guess"] = c.reject("single attestation", lone, [(ftxid, B1)])
    if slashed is None:
        raise AssertionError("honest and unauthorized subsets coincide in both rounds")
    known = {idx: rows[slashed][idx] for idx in set(honest.subsets[slashed]) | set(unauth.subsets[slashed])}
    slash = Tx(2, (TxIn(bytes.fromhex(ftxid)[::-1], bond_vouts[slashed], equivocation_unlock(known), 0xFFFFFFFF),),
               (TxOut(BOND_SATS - 2_000, challenger),), 0)
    e["equivocation_round"] = slashed + 1
    e["equivocation_slash"] = c.accept_alternative("slash", slash, [(ftxid, bond_vouts[slashed])])
    receipt["E_retained_key"] = e

    # F: challenger censorship until the bond's CSV delay expires.
    f = {}
    release_tx = Tx(2, (TxIn(bytes.fromhex(ftxid)[::-1], bond_vouts[slashed], b"", BOND_CSV_BLOCKS),),
                    (TxOut(BOND_SATS - 2_000, change_script),), 0)
    release_tx = replace(release_tx, vin=(replace(release_tx.vin[0], script_sig=release_unlock(bonds[slashed], release_tx, 0, "release")),))
    age = node("getblockcount") - funding_height + 1
    f["bond_age_blocks_at_early_attempt"] = age
    if age >= BOND_CSV_BLOCKS:
        raise AssertionError("bond matured before the early-release check")
    f["early_release"] = c.reject("early release", release_tx, [(ftxid, bond_vouts[slashed])])
    node("generatetoaddress", BOND_CSV_BLOCKS, miner)
    f["blocks_mined_without_challenger"] = BOND_CSV_BLOCKS
    f["release_relay_policy"] = c.policy(release_tx)
    f["release_block"] = c.mine(release_tx)
    f["late_slash"] = c.reject("late slash", slash, [])
    receipt["F_bond_timeout"] = f

    # G: split-UTXO arrangement. Spend the round-1 UTXO alone.
    sp = RoundSpec(1, setup.pools[0], setup.puzzle_secrets[0], split1)
    gsucc = successor_root(PREVIOUS_STATE_ROOT, ftxid, S1, body, PAYOUT_SATS, SETTLEMENT_FEE_SATS)
    used_aux = {honest.tx.vin[0].prevout_n, unauth.tx.vin[0].prevout_n}
    g_aux = [a for a in aux if a not in used_aux]
    lone_split = grind_settlement(setup, ftxid, S1, g_aux, body, gsucc,
                                  lock_script=split1, specs=(sp,))
    g = {"split_round1_spend": settlement_record(lone_split),
         "relay_policy": c.policy(lone_split.tx)}
    g["block"] = c.mine(lone_split.tx)
    g["round2_utxo_still_unspent"] = c.unspent([(ftxid, S2)])
    g["consensus_enforced_cross_input_dependency"] = not g["round2_utxo_still_unspent"]
    receipt["G_split_utxo"] = g
    receipt["final_tip"] = c.tip()
    return receipt


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--output", default="artifacts/jb-fad05/native.json")
    ap.add_argument("--rpc-url", default=os.getenv("BITCOIND_RPC_URL", "http://127.0.0.1:18443"))
    ap.add_argument("--rpc-user", default=os.getenv("BITCOIND_RPC_USER", "user"))
    ap.add_argument("--rpc-password", default=os.getenv("BITCOIND_RPC_PASS", "pass"))
    args = ap.parse_args()
    try:
        result = run_native(CoreRPC(args.rpc_url, args.rpc_user, args.rpc_password))
    except Exception:
        # Workflow-command annotations are readable on public repos without
        # authentication, unlike raw job logs.
        import traceback
        for line in traceback.format_exc().splitlines()[-12:]:
            print("::error title=jb-fad05-native::" + line.replace("%", "%25"), flush=True)
        raise
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    summary = {
        "honest_txid": result["honest"]["txid"],
        "indices": result["honest"]["round1_indices"] + result["honest"]["round2_indices"],
        "resources": result["resources"],
        "A_rejected": sorted(k for k, v in result["A_attestation_mutations"].items()
                             if isinstance(v, dict) and v["consensus"] == "rejected"),
        "B_accepted_flags": result["B_sighash_flag_matrix"]["accepted_flags"],
        "C_malleated_twins_accepted": [k for k, v in result["C_txid_malleation"].items() if v["consensus"] == "accepted"],
        "D_front_run_accepted": result["D_reorg_front_run"]["consensus"],
        "D_front_run_flags": result["D_reorg_front_run"]["front_run"]["nonce_flags"],
        "E_unauthorized_accepted": result["E_retained_key"]["consensus"],
        "E_slash": result["E_retained_key"]["equivocation_slash"]["consensus"],
        "E_single_attestation_slash": result["E_retained_key"]["slash_with_single_attestation_plus_guess"]["consensus"],
        "F_early_release": result["F_bond_timeout"]["early_release"]["consensus"],
        "F_late_slash": result["F_bond_timeout"]["late_slash"]["consensus"],
        "G_cross_input_enforced": result["G_split_utxo"]["consensus_enforced_cross_input_dependency"],
        "receipt": str(out),
    }
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
