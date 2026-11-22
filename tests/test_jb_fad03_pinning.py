"""JB-FAD03B: ECDSA four-mode pinning and legacy nonce extraction."""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from jb_fad01 import verifies  # noqa: E402
from jb_fad02 import TARGET_SIG_BYTES  # noqa: E402
from jb_fad03 import code_for_subset  # noqa: E402
from jb_fad03_pinning import (  # noqa: E402
    AUX_COUNT,
    FLAGS,
    build_pinned_script_sig,
    build_receipt,
    grind,
    make_pinned_setup,
    pin_digest,
    script_resources,
    verify_canonical_flags,
)
from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL, TxOut, op, p2sh, push, signature_hash, txid_hex,
)


class FourModePinningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = make_pinned_setup()
        cls.candidate = grind(cls.setup, "12" * 32, p2sh(op(0x51)))
        cls.evidence = build_receipt(cls.setup, cls.candidate)

    def test_four_distinct_canonical_sighash_modes(self):
        self.assertEqual([flag for _, flag in FLAGS],
                         [0x82, 0x02, 0x81, 0x01])
        self.assertEqual(len(set(self.setup.pin_pubkeys.values())), 4)
        for name, flag in FLAGS:
            sig = self.candidate.pin_signatures[name]
            self.assertEqual(sig[-1], flag)
            self.assertLessEqual(len(sig), TARGET_SIG_BYTES)
            digest = pin_digest(self.setup, self.candidate.tx, flag)
            self.assertEqual(digest, self.candidate.pin_digests[name])
            self.assertTrue(verifies(self.setup.pin_secrets[name], digest, sig))

    def test_nonce_after_all_pins_uses_selected_findanddelete_script(self):
        c = self.candidate
        self.assertEqual(len(c.nonce_subset), 5)
        pinned_base = replace(self.setup.base, script_pubkey=self.setup.script)
        code, removed = code_for_subset(pinned_base, c.nonce_subset)
        self.assertEqual(removed, 5)
        self.assertNotEqual(code, self.setup.script)
        self.assertEqual(signature_hash(code, c.tx, 1, SIGHASH_ALL),
                         c.nonce_digest)
        self.assertTrue(verifies(self.setup.base.puzzle_secret, c.nonce_digest,
                                 c.nonce_signature))
        self.assertEqual(c.nonce_signature[-1], SIGHASH_ALL)

    def test_all_stages_survive_later_field_changes(self):
        c = self.candidate
        tx = c.tx
        changed_other_outpoint = replace(
            tx, vin=(replace(tx.vin[0], prevout_n=tx.vin[0].prevout_n + 1),
                     tx.vin[1]),
        )
        self.assertEqual(
            pin_digest(self.setup, changed_other_outpoint, 0x82),
            pin_digest(self.setup, tx, 0x82),
        )
        self.assertNotEqual(
            pin_digest(self.setup, changed_other_outpoint, 0x02),
            pin_digest(self.setup, tx, 0x02),
        )
        changed_output = replace(tx, vout=(replace(tx.vout[0],
            script_pubkey=p2sh(op(0x52))),))
        for flag in (0x82, 0x02):
            self.assertEqual(pin_digest(self.setup, tx, flag),
                             pin_digest(self.setup, changed_output, flag))
        for flag in (0x81, 0x01):
            self.assertNotEqual(pin_digest(self.setup, tx, flag),
                                pin_digest(self.setup, changed_output, flag))
        changed_other_sequence = replace(tx, vin=(
            replace(tx.vin[0], sequence=tx.vin[0].sequence + 1), tx.vin[1],
        ))
        for flag in (0x82, 0x02, 0x81):
            self.assertEqual(pin_digest(self.setup, changed_other_sequence, flag),
                             pin_digest(self.setup, tx, flag))
        self.assertNotEqual(pin_digest(self.setup, changed_other_sequence, 0x01),
                            pin_digest(self.setup, tx, 0x01))

    def test_offchain_canonical_flag_verifier_rejects_modified_bytes(self):
        self.assertTrue(all(verify_canonical_flags(self.candidate, self.setup).values()))
        c = self.candidate
        changed_pins = dict(c.pin_signatures)
        changed_pins["all"] = changed_pins["all"][:-1] + b"\x82"
        forged = replace(c, pin_signatures=changed_pins)
        checks = verify_canonical_flags(forged, self.setup)
        self.assertFalse(checks["all"])
        self.assertTrue(checks["acp_none"])
        self.assertTrue(checks["none"])
        self.assertTrue(checks["acp_all"])

    def test_pinned_unlocking_script_leaves_nonce_stack_unchanged(self):
        c = self.candidate
        self.assertEqual(
            c.tx.vin[1].script_sig,
            build_pinned_script_sig(c.pin_signatures, c.nonce_signature,
                                    c.nonce_subset),
        )
        self.assertTrue(c.tx.vin[1].script_sig.startswith(b"\x00"))
        self.assertEqual(c.tx.vin[1].prevout_n, AUX_COUNT)
        self.assertEqual(len(c.tx.vout), 1)
        self.assertEqual(c.tx.locktime, 0)
        self.assertTrue(all(n > 0 for n in c.pin_attempts.values()))
        self.assertGreater(c.nonce_attempts, 0)

    def test_resource_and_receipt_limits(self):
        r = self.evidence
        bounds = r["resource_bounds"]
        self.assertTrue(bounds["within_201_nonpush_limit"])
        self.assertTrue(bounds["within_10000_script_size"])
        self.assertEqual(bounds["bare_total_sigops"], 10)
        self.assertEqual(bounds["bare_CHECKMULTISIG_sigops"], 6)
        self.assertEqual(bounds["spend_nonwitness_weight"],
                         bounds["signed_spend_size_bytes"] * 4)
        self.assertEqual(r["txid"], txid_hex(self.candidate.tx))
        self.assertTrue(all(r["canonical_offchain_checks"].values()))
        self.assertFalse(r["four_pins"]["all"]["altered_digest_matches"])
        self.assertFalse(r["four_pins"]["acp_all"]["altered_digest_matches"])
        self.assertTrue(r["four_pins"]["none"]["altered_digest_matches"])
        self.assertTrue(r["four_pins"]["acp_none"]["altered_digest_matches"])


if __name__ == "__main__":
    unittest.main()
