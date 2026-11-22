"""JB-FAD03: 256 legacy sighash flags, regenerated Rmin signatures, payout alias."""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from jb_fad01 import AUX_REDEEM, verifies  # noqa: E402
from jb_fad02 import TARGET_SIG_BYTES, make_setup  # noqa: E402
from jb_fad03 import (  # noqa: E402
    ATTACK_FLAG,
    FOCUS_SUBSET,
    MAX_FLAG_TRIALS,
    RMIN_SECRET,
    build_payout_collision,
    code_for_subset,
    candidate_for_flag,
    fixed_rmin_sig,
    flag_family,
    report,
    script_resources,
    tx_template,
)
from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    UINT256_ONE,
    op,
    p2sh,
    signature_hash,
    txid_hex,
)


class SighashFlagMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = make_setup()
        cls.funding = "12" * 32
        cls.a_script = p2sh(AUX_REDEEM)
        cls.b_script = p2sh(op(0x52))
        cls.result, cls.candidates, cls.honest, cls.altered = report(
            cls.setup, cls.funding, cls.a_script, cls.b_script
        )

    def test_matrix_has_256_exactly_once(self):
        rows = self.result["flag_matrix"]
        self.assertEqual(len(rows), 256)
        self.assertEqual([row["flag"] for row in rows], list(range(256)))
        self.assertEqual(self.result["matrix_summary"]["flags_total"], 256)
        self.assertEqual(sum(self.result["matrix_summary"]["mode_counts"].values()), 256)
        self.assertEqual(self.result["matrix_summary"]["mode_counts"]["SINGLE_BUG"], 8)
        self.assertEqual(self.result["matrix_summary"]["mode_counts"]["NONE"], 8)
        self.assertEqual(self.result["matrix_summary"]["mode_counts"]["ALL"], 8)
        self.assertEqual(self.result["matrix_summary"]["mode_counts"]["ALL_FALLBACK"], 232)

    def test_every_solved_signature_is_a_real_ecdsa_witness(self):
        for flag, candidate in self.candidates.items():
            if candidate is None:
                self.assertEqual(flag_family(flag), "SINGLE_BUG")
                continue
            self.assertEqual(candidate.sig[-1], flag)
            self.assertLessEqual(len(candidate.sig), TARGET_SIG_BYTES)
            self.assertTrue(verifies(RMIN_SECRET, candidate.digest, candidate.sig))
            self.assertTrue(candidate.trials <= MAX_FLAG_TRIALS)
            self.assertEqual(candidate.tx.vin[1].script_sig[0], 0)
            self.assertEqual(
                candidate.digest,
                signature_hash(candidate.script_code, candidate.tx, 1, flag),
            )

    def test_fixed_rmin_single_bug_is_too_large(self):
        code, _ = code_for_subset(self.setup, FOCUS_SUBSET)
        base = tx_template(self.funding, self.a_script)
        for flag in range(256):
            if flag_family(flag) == "SINGLE_BUG":
                self.assertEqual(signature_hash(code, base, 1, flag), UINT256_ONE)
                self.assertGreater(len(fixed_rmin_sig(UINT256_ONE, flag)),
                                   TARGET_SIG_BYTES)
                self.assertIsNone(self.candidates[flag])

    def test_consensus_fallback_hash_type_domain_separation(self):
        code, _ = code_for_subset(self.setup, FOCUS_SUBSET)
        tx = tx_template(self.funding, self.a_script)
        digests = [signature_hash(code, tx, 1, flag) for flag in range(256)]
        # The eight SINGLE-bug flags all map to uint256::ONE by design.
        for flag in range(256):
            if flag_family(flag) == "SINGLE_BUG":
                self.assertEqual(digests[flag], UINT256_ONE)
            else:
                self.assertNotEqual(digests[flag], UINT256_ONE)
        self.assertEqual(len(set(digests)), 249)

    def test_reused_signature_and_subset_authorize_different_payouts(self):
        a, b = self.honest, self.altered
        self.assertEqual(a.flag, ATTACK_FLAG)
        self.assertNotEqual(txid_hex(a.tx), txid_hex(b))
        self.assertEqual(a.tx.vin, b.vin)
        self.assertEqual(a.tx.vin[1].script_sig, b.vin[1].script_sig)
        self.assertEqual(a.tx.vout[0].value, b.vout[0].value)
        self.assertNotEqual(a.tx.vout[0].script_pubkey, b.vout[0].script_pubkey)
        self.assertEqual(
            signature_hash(a.script_code, a.tx, 1, ATTACK_FLAG),
            signature_hash(a.script_code, b, 1, ATTACK_FLAG),
        )
        self.assertNotEqual(
            signature_hash(a.script_code, a.tx, 1, SIGHASH_ALL),
            signature_hash(a.script_code, b, 1, SIGHASH_ALL),
        )
        self.assertTrue(verifies(RMIN_SECRET, a.digest, a.sig))

    def test_sighash_none_also_omits_outputs(self):
        none = self.candidates[SIGHASH_NONE]
        self.assertIsNotNone(none)
        changed = replace(none.tx, vout=(replace(
            none.tx.vout[0], script_pubkey=self.b_script
        ),))
        self.assertEqual(
            signature_hash(none.script_code, none.tx, 1, SIGHASH_NONE),
            signature_hash(none.script_code, changed, 1, SIGHASH_NONE),
        )
        self.assertNotEqual(
            signature_hash(none.script_code, none.tx, 1, SIGHASH_ALL),
            signature_hash(none.script_code, changed, 1, SIGHASH_ALL),
        )

    def test_known_script_bounds(self):
        r = script_resources(self.setup.script_pubkey)
        self.assertEqual(r["locking_script_bytes"], 996)
        self.assertTrue(r["within_201_nonpush_limit"])
        self.assertTrue(r["within_10000_script_size"])
        self.assertTrue(r["bare_script_exceeds_P2SH_520"])
        self.assertEqual(r["bare_CHECKMULTISIG_sigops"], 6)

    def test_counterexample_receipt_preserves_raw_and_cryptographic_claim(self):
        c = self.result["counterexample"]
        self.assertEqual(c["flag"], "0x82")
        self.assertTrue(c["identical_scriptSig"])
        self.assertTrue(c["identical_ACP_NONE_sighash"])
        self.assertTrue(c["different_ALL_sighash"])
        self.assertTrue(c["same_input_prevouts"])
        self.assertEqual(c["honest_txid"], self.honest.txid)
        self.assertEqual(c["altered_txid"], txid_hex(self.altered))
        self.assertEqual(c["nonce_subset"], list(FOCUS_SUBSET))


if __name__ == "__main__":
    unittest.main()
