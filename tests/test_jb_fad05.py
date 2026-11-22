"""JB-FAD05: HORS subset attestation, referee, bond, split and budget tests.

Offline lane. The legacy-Script model in jb_fad05_interp is checked here;
the native Bitcoin Core lane (jb_fad05_native.py) is the consensus oracle.
"""

import itertools
import struct
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric import utils  # noqa: E402

from jb_fad01 import SECP256K1_ORDER  # noqa: E402
from jb_fad02 import POOL_N, POOL_T, selection_depths  # noqa: E402
from jb_fad03_pinning import rmin_sign  # noqa: E402
from jb_fad04_verify import ProofRejected, build_merkle_branch  # noqa: E402
from jb_fad05 import (  # noqa: E402
    ALL_LIKE_FLAGS, ATTACKER_SECRET, BOND_CSV_BLOCKS, BOND_SATS, OPERATOR_SECRET,
    PAYOUT_SATS, PREVIOUS_STATE_ROOT, PROGRAM_ID, RECIPIENT_SECRET, RoundSpec,
    SETTLEMENT_FEE_SATS, UNAUTHORIZED_SECRET, all_family_digests, bond_script,
    canonical_round_unlock, equivocation_unlock, front_run, grind_settlement,
    key_body, make_setup, nonce_script_code, p2wsh, payout_witness_script,
    release_unlock, round_unlock, split_scripts, static_counts, successor_root,
    synthetic_funding,
)
from jb_fad05_interp import verify_input  # noqa: E402
from jb_fad05_native import ordered_unlock, with_round  # noqa: E402
from jb_fad05_params import build as build_params, shape  # noqa: E402
from jb_fad05_verify import (  # noqa: E402
    PROGRAM_SPEC, parse_vault_script, verify_settlement,
)
from jb_fad01 import pubkey_bytes  # noqa: E402
from seam_digests_standalone import (  # noqa: E402
    Tx, TxIn, TxOut, dsha256, get_op, op, push, ser_tx, sha256,
    signature_hash, txid_hex,
)

REGTEST_BITS = 0x207FFFFF


def fake_block(txid: str) -> tuple[str, str]:
    """A header with valid regtest proof-of-work committing to one txid."""
    root = bytes.fromhex(txid)[::-1]
    for nonce in range(1 << 16):
        header = (struct.pack("<i", 0x20000000) + bytes(32) + root +
                  struct.pack("<III", 1_700_000_000, REGTEST_BITS, nonce))
        h = dsha256(header)
        if int.from_bytes(h, "little") <= 0x7FFFFF << (8 * (0x20 - 3)):
            return header.hex(), h[::-1].hex()
    raise AssertionError("no regtest header found")


class Fad05Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = make_setup()
        cls.funding, cls.vault_vout = synthetic_funding(cls.setup)
        cls.ftxid = txid_hex(cls.funding)
        cls.aux = list(range(cls.vault_vout))
        cls.body = key_body(RECIPIENT_SECRET)
        cls.succ = successor_root(PREVIOUS_STATE_ROOT, cls.ftxid, cls.vault_vout,
                                  cls.body, PAYOUT_SATS, SETTLEMENT_FEE_SATS)
        cls.honest = grind_settlement(cls.setup, cls.ftxid, cls.vault_vout, cls.aux,
                                      cls.body, cls.succ)
        cls.rows = cls.setup.hors.preimages

    def run_vault(self, tx: Tx, script: bytes | None = None):
        return verify_input(tx.vin[1].script_sig, script or self.setup.script, tx, 1)

    def accepts(self, tx, script=None):
        ok, why, _ = self.run_vault(tx, script)
        self.assertTrue(ok, why)

    def rejects(self, tx, fragment: str, script=None):
        ok, why, _ = self.run_vault(tx, script)
        self.assertFalse(ok)
        self.assertIn(fragment, why)

    # -- WP-A: script shape and attestation ------------------------------

    def test_budget_and_measured_op_count(self):
        c = static_counts(self.setup.script)
        self.assertEqual(c["core_op_count"], 182)
        self.assertLessEqual(c["core_op_count"], 201)
        self.assertLessEqual(c["script_bytes"], 10_000)
        ok, _, trace = self.run_vault(self.honest.tx)
        self.assertTrue(ok)
        self.assertEqual(trace.op_count, c["core_op_count"])

    def test_honest_settlement_and_indices(self):
        self.accepts(self.honest.tx)
        for subset in self.honest.subsets:
            self.assertEqual(len(set(subset)), POOL_T)
            self.assertEqual(tuple(sorted(subset)), subset)
        self.assertEqual(self.honest.nonce_flags, (0x01, 0x01))

    def test_preimage_mutations_rejected(self):
        s, rows = self.honest, self.rows
        picks = sorted(s.subsets[0], reverse=True)
        bad = list(rows[0]); bad[picks[2]] = bytes(20)
        self.rejects(with_round(s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], tuple(bad))), "EQUALVERIFY")
        self.rejects(with_round(s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], rows[1]),
                                r2=canonical_round_unlock(s.nonce_sigs[1], s.subsets[1], rows[0])), "EQUALVERIFY")
        dup = list(rows[0]); dup[picks[1]] = rows[0][picks[0]]
        self.rejects(with_round(s, rows, r1=canonical_round_unlock(s.nonce_sigs[0], s.subsets[0], tuple(dup))), "EQUALVERIFY")

    def test_noncanonical_encodings_rejected(self):
        s, rows = self.honest, self.rows
        picks = sorted(s.subsets[0], reverse=True)
        for order in itertools.permutations(picks):
            if list(order) == picks:
                continue
            self.rejects(with_round(s, rows, r1=ordered_unlock(s.nonce_sigs[0], list(order), rows[0])), "OP_VERIFY")
        depths = list(selection_depths(s.subsets[0])); depths[0] = POOL_N
        self.rejects(with_round(s, rows, r1=round_unlock(s.nonce_sigs[0], tuple(depths),
                                                         tuple(rows[0][p] for p in picks))), "OP_VERIFY")

    def test_every_canonical_subset_maps_to_its_own_commitments(self):
        """For all 252 subsets, the HORS check passes exactly with the
        matching preimages (the nonce signature then decides)."""
        s, rows = self.honest, self.rows
        for subset in itertools.combinations(range(POOL_N), POOL_T):
            tx = with_round(s, rows, r2=canonical_round_unlock(s.nonce_sigs[1], subset, rows[1]))
            ok, why, _ = self.run_vault(tx)
            if subset == s.subsets[1]:
                self.assertTrue(ok, why)
            else:
                self.assertFalse(ok)
                self.assertIn("false", why)   # reached CHECKMULTISIG, failed there

    def test_payout_and_outpoint_mutations_rejected(self):
        tx = self.honest.tx
        self.rejects(replace(tx, vout=(replace(tx.vout[0], value=tx.vout[0].value + 1),)), "CHECKSIGVERIFY")
        other = payout_witness_script(sha256(b"x"), self.honest.salt, self.body)
        self.rejects(replace(tx, vout=(TxOut(tx.vout[0].value, p2wsh(other)),)), "CHECKSIGVERIFY")
        self.rejects(replace(tx, vin=(tx.vin[0], replace(tx.vin[1], prevout_n=self.vault_vout + 1))), "CHECKSIGVERIFY")

    def test_high_s_and_flag_matrix(self):
        s, rows = self.honest, self.rows
        r_, s_ = utils.decode_dss_signature(s.nonce_sigs[1][:-1])
        high = utils.encode_dss_signature(r_, SECP256K1_ORDER - s_) + b"\x01"
        self.rejects(with_round(s, rows, r2=canonical_round_unlock(high, s.subsets[1], rows[1])), "OP_VERIFY")
        code = nonce_script_code(self.setup, 2, s.subsets[1])
        accepted = []
        for flag in range(256):
            sig = rmin_sign(signature_hash(code, s.tx, 1, flag), self.setup.puzzle_secrets[1], flag)
            ok, _, _ = self.run_vault(with_round(s, rows, r2=canonical_round_unlock(sig, s.subsets[1], rows[1])))
            self.assertEqual(ok, len(sig) <= 59, f"flag {flag:#x}")
            if ok:
                accepted.append(flag)
        self.assertIn(0x01, accepted)

    def test_all_family_digest_fast_path(self):
        code = nonce_script_code(self.setup, 1, self.honest.subsets[0])
        fast = all_family_digests(code, self.honest.tx, 1, ALL_LIKE_FLAGS)
        self.assertEqual(len(fast), 240)
        for f in (0x00, 0x01, 0x21, 0x81, 0xC1, 0xFF, 0x1F, 0x04):
            self.assertEqual(fast[f], signature_hash(code, self.honest.tx, 1, f))

    def test_third_party_malleation_is_consensus_valid(self):
        sig = self.honest.tx.vin[1].script_sig
        for prefix in (op(0x61), push(b"third-party")):
            twin = replace(self.honest.tx, vin=(self.honest.tx.vin[0],
                                                replace(self.honest.tx.vin[1], script_sig=prefix + sig)))
            self.accepts(twin)
            self.assertNotEqual(txid_hex(twin), self.honest.txid)

    # -- counterexamples -------------------------------------------------

    def test_front_run_reuses_revealed_preimages(self):
        fr = front_run(self.setup, self.honest, self.ftxid, self.vault_vout, self.aux,
                       key_body(ATTACKER_SECRET))
        self.accepts(fr.tx)
        self.assertEqual(fr.subsets, self.honest.subsets)
        self.assertNotEqual(fr.tx.vout[0].script_pubkey, self.honest.tx.vout[0].script_pubkey)

    def test_front_run_without_flag_freedom_is_costlier(self):
        with self.assertRaises(RuntimeError):
            grind_settlement(self.setup, self.ftxid, self.vault_vout, self.aux,
                             key_body(ATTACKER_SECRET), sha256(b"s"),
                             required=self.honest.subsets, max_candidates=8)

    def test_retained_key_unauthorized_payout_is_script_valid(self):
        ubody = key_body(UNAUTHORIZED_SECRET)
        usucc = successor_root(PREVIOUS_STATE_ROOT, self.ftxid, self.vault_vout, ubody,
                               PAYOUT_SATS, SETTLEMENT_FEE_SATS)
        un = grind_settlement(self.setup, self.ftxid, self.vault_vout, self.aux, ubody, usucc)
        self.accepts(un.tx)
        policy, witness, anchor = self.referee_inputs(un)
        with self.assertRaisesRegex(ProofRejected, "recipient"):
            verify_settlement(policy, witness, anchor)

    # -- WP-C: bond ------------------------------------------------------

    def bond_tx(self, r, script_sig, sequence=0xFFFFFFFF):
        prev = bytes.fromhex(self.ftxid)[::-1]
        return Tx(2, (TxIn(prev, self.vault_vout + 2 + r, script_sig, sequence),),
                  (TxOut(BOND_SATS - 2000, key_body(ATTACKER_SECRET)),), 0)

    def test_equivocation_slash(self):
        bond = bond_script(self.setup.hors.tables[0], pubkey_bytes(OPERATOR_SECRET))
        self.assertLessEqual(static_counts(bond)["core_op_count"], 201)
        six = {i: self.rows[0][i] for i in range(6)}
        tx = self.bond_tx(0, equivocation_unlock(six))
        ok, why, _ = verify_input(tx.vin[0].script_sig, bond, tx, 0)
        self.assertTrue(ok, why)
        five_and_guess = {i: self.rows[0][i] for i in range(5)} | {7: bytes(20)}
        tx = self.bond_tx(0, equivocation_unlock(five_and_guess))
        ok, why, _ = verify_input(tx.vin[0].script_sig, bond, tx, 0)
        self.assertFalse(ok)
        wrong_round = {i: self.rows[1][i] for i in range(6)}
        tx = self.bond_tx(0, equivocation_unlock(wrong_round))
        self.assertFalse(verify_input(tx.vin[0].script_sig, bond, tx, 0)[0])

    def test_release_needs_csv(self):
        bond = bond_script(self.setup.hors.tables[1], pubkey_bytes(OPERATOR_SECRET))
        for seq, expect in ((BOND_CSV_BLOCKS, True), (BOND_CSV_BLOCKS - 1, False)):
            tx = self.bond_tx(1, b"", seq)
            tx = replace(tx, vin=(replace(tx.vin[0], script_sig=release_unlock(bond, tx, 0, "t")),))
            ok, why, _ = verify_input(tx.vin[0].script_sig, bond, tx, 0)
            self.assertEqual(ok, expect, why)

    # -- WP-A: split arrangement ----------------------------------------

    def test_split_round_spends_alone(self):
        s1, _ = split_scripts(self.setup)
        sp = RoundSpec(1, self.setup.pools[0], self.setup.puzzle_secrets[0], s1)
        lone = grind_settlement(self.setup, self.ftxid, self.vault_vout, self.aux, self.body,
                                self.succ, lock_script=s1, specs=(sp,))
        self.accepts(lone.tx, s1)
        self.assertEqual(len(lone.tx.vin), 2)

    # -- WP-B: referee and statement ------------------------------------

    def referee_inputs(self, s):
        header, bhash = fake_block(s.txid)
        policy = {
            "schema": "jb-fad05-policy-v1", "vault_txid": self.ftxid,
            "vault_vout": self.vault_vout,
            "funding_script_sha256": sha256(self.setup.script).hex(),
            "hors_root": self.setup.hors.root.hex(),
            "recipient_body_hex": self.body.hex(), "payout_sats": PAYOUT_SATS,
            "fee_sats": SETTLEMENT_FEE_SATS, "verified_program_id": PROGRAM_ID.hex(),
            "previous_state_root": PREVIOUS_STATE_ROOT.hex(),
        }
        witness = {
            "raw_funding_hex": ser_tx(self.funding).hex(), "raw_spend_hex": ser_tx(s.tx).hex(),
            "payout_witness_script_hex": s.witness_script.hex(),
            "block_header_hex": header, "claimed_block_hash": bhash,
            "merkle": build_merkle_branch([s.txid], 0),
        }
        return policy, witness, bhash

    def test_referee_accepts_honest_and_labels_enforcement(self):
        policy, witness, anchor = self.referee_inputs(self.honest)
        out = verify_settlement(policy, witness, anchor)
        self.assertTrue(out["valid"])
        self.assertEqual(out["indices"], list(self.honest.indices))
        labels = {c["check"]: c["enforced_by"] for c in out["checks"]}
        self.assertEqual(labels["round1_hors_preimages_open_selected_indices"], "bitcoin-consensus")
        self.assertEqual(labels["recipient_matches_policy"], "referee-only")
        self.assertEqual(labels["state_transition_valid"], "referee-only")
        self.assertEqual(labels["nonce_sighash_bytes_canonical"], "referee-only")
        self.assertEqual(labels["tx_in_trusted_block"], "trusted-anchor")
        self.assertEqual(len(out["statement"]), 13)
        again = verify_settlement(policy, witness, anchor)
        self.assertEqual(out["statement_hash"], again["statement_hash"])

    def test_referee_rejects_policy_and_witness_tampering(self):
        policy, witness, anchor = self.referee_inputs(self.honest)
        for key, value, msg in (
            ("hors_root", "00" * 32, "HORS"),
            # vout+1 is the twin vault: same script hash, different outpoint.
            ("vault_vout", self.vault_vout + 1, "outpoint"),
            ("vault_vout", self.vault_vout + 2, "hash"),
            ("payout_sats", PAYOUT_SATS + 1, "payout"),
            ("fee_sats", SETTLEMENT_FEE_SATS - 1, "fee"),
            ("previous_state_root", "11" * 32, "successor"),
            ("verified_program_id", "22" * 32, "program"),
        ):
            with self.assertRaisesRegex(ProofRejected, msg):
                verify_settlement(policy | {key: value}, witness, anchor)
        with self.assertRaisesRegex(ProofRejected, "trusted"):
            verify_settlement(policy, witness, "00" * 32)
        fr = front_run(self.setup, self.honest, self.ftxid, self.vault_vout, self.aux,
                       key_body(ATTACKER_SECRET))
        p2, w2, a2 = self.referee_inputs(fr)
        with self.assertRaisesRegex(ProofRejected, "noncanonical sighash"):
            verify_settlement(p2, w2, a2)
        twin = replace(self.honest.tx, vin=(self.honest.tx.vin[0], replace(
            self.honest.tx.vin[1], script_sig=op(0x61) + self.honest.tx.vin[1].script_sig)))
        w3 = witness | {"raw_spend_hex": ser_tx(twin).hex()}
        with self.assertRaises(ProofRejected):
            verify_settlement(policy, w3, anchor)

    def test_referee_layout_is_independent_and_exact(self):
        layout = parse_vault_script(self.setup.script)
        self.assertEqual([r["table"] for r in layout["rounds"]],
                         [list(t) for t in self.setup.hors.tables])
        self.assertEqual(sha256(PROGRAM_SPEC), PROGRAM_ID)
        broken = bytearray(self.setup.script)
        broken[-1] = 0xAF   # CHECKMULTISIGVERIFY instead of CHECKMULTISIG
        with self.assertRaises((ProofRejected, StopIteration)):
            parse_vault_script(bytes(broken))

    # -- WP-E: budget model ---------------------------------------------

    def test_budget_model_matches_real_script(self):
        model = shape(10, 5, rounds_in_script=2)
        self.assertEqual(model["core_op_count"], static_counts(self.setup.script)["core_op_count"])
        real_sig_pushes = sum(len(push(sig)) for pool in self.setup.pools for sig in pool)
        self.assertEqual(model["script_bytes"] - (2 * POOL_N * 73 - real_sig_pushes),
                         len(self.setup.script))
        rep = build_params()
        self.assertFalse(shape(120, 8, rounds_in_script=1)["fits"])
        self.assertTrue(shape(120, 8, rounds_in_script=1, hors=False)["fits"])
        self.assertFalse(shape(120, 8, rounds_in_script=2, hors=False)["fits"])
        self.assertLess(rep["frontier_single_script_two_rounds"]["subset_bits_per_round"], 22)


if __name__ == "__main__":
    unittest.main()
