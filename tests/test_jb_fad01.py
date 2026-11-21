"""JB-FAD01: executable cryptographic controls for legacy FindAndDelete."""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402
from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    UINT256_ONE,
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
from jb_fad01 import (  # noqa: E402
    OP_1,
    AUX_REDEEM,
    PAYOUT_SATS,
    SECP256K1_ORDER,
    attack_cases,
    audit,
    build_variants,
    demo_scalar,
    make_setup,
    pubkey_bytes,
    script_sig,
    verifies,
)


class FindAndDeleteExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = make_setup()
        cls.variants = build_variants(cls.setup, "12" * 32, p2sh(AUX_REDEEM))

    def test_embedded_signatures_verify_at_constant_one(self):
        single = self.setup.single_secret
        self.assertNotEqual(self.setup.single_signatures["A"], self.setup.single_signatures["B"])
        for sig in self.setup.single_signatures.values():
            self.assertEqual(sig[-1], SIGHASH_SINGLE)
            self.assertTrue(verifies(single, UINT256_ONE, sig))
            r, s = utils.decode_dss_signature(sig[:-1])
            self.assertGreater(r, 0)
            self.assertLessEqual(s, SECP256K1_ORDER // 2)

    def test_findanddelete_changes_scriptcode_at_opcode_boundaries(self):
        a, b = self.variants["A"], self.variants["B"]
        self.assertEqual(a.removed_pushes, 1)
        self.assertEqual(b.removed_pushes, 1)
        self.assertNotEqual(a.script_code, b.script_code)
        self.assertNotEqual(a.sighash, b.sighash)
        self.assertEqual(len(self.setup.redeem_script) - len(a.script_code),
                         len(push(self.setup.single_signatures["A"])))
        self.assertEqual(len(self.setup.redeem_script) - len(b.script_code),
                         len(push(self.setup.single_signatures["B"])))
        blob = push(b"X" + self.setup.single_signatures["A"] + b"Y")
        _, n = find_and_delete(blob, push(self.setup.single_signatures["A"]))
        self.assertEqual(n, 0, "must never delete bytes from inside a push")

    def test_exact_scriptcode_needed_for_ecdsa(self):
        for branch, variant in self.variants.items():
            self.assertTrue(verifies(self.setup.puzzle_secret, variant.sighash,
                                     variant.puzzle_signature))
            wrong = signature_hash(self.setup.redeem_script, variant.tx, 1, SIGHASH_ALL)
            self.assertFalse(verifies(self.setup.puzzle_secret, wrong,
                                      variant.puzzle_signature))
            self.assertEqual(variant.puzzle_signature[-1], SIGHASH_ALL)
            self.assertEqual(signature_hash(variant.script_code, variant.tx, 1, SIGHASH_ALL),
                             variant.sighash, branch)

    def test_same_funded_outpoint_two_competing_valid_spends(self):
        a, b = self.variants["A"], self.variants["B"]
        self.assertEqual(a.tx.vin[1].prevout_hash, b.tx.vin[1].prevout_hash)
        self.assertEqual(a.tx.vin[1].prevout_n, 1)
        self.assertEqual(b.tx.vin[1].prevout_n, 1)
        self.assertEqual(a.tx.vout, b.tx.vout)
        self.assertNotEqual(txid_hex(a.tx), txid_hex(b.tx))
        self.assertLess(len(self.setup.redeem_script), 520)
        self.assertTrue(a.tx.vin[1].script_sig.endswith(push(self.setup.redeem_script)))
        self.assertTrue(b.tx.vin[1].script_sig.endswith(push(self.setup.redeem_script)))
        self.assertEqual(script_sig(self.setup, a.puzzle_signature, "B")[-len(push(self.setup.redeem_script)):],
                         push(self.setup.redeem_script))

    def test_attacks_rejected_by_real_ecdsa(self):
        checks = attack_cases(self.setup, self.variants)
        self.assertEqual(len(checks), 7)
        self.assertTrue(all(checks.values()), checks)
        a = self.variants["A"]
        extra_output = replace(a.tx, vout=a.tx.vout + (TxOut(0, op(OP_1)),))
        digest = signature_hash(a.script_code, extra_output, 1, SIGHASH_SINGLE)
        self.assertNotEqual(digest, UINT256_ONE)
        self.assertFalse(verifies(self.setup.single_secret, digest,
                                  self.setup.single_signatures["A"]))

    def test_funding_p2sh_commits_to_pool(self):
        # A mutated nonce pool cannot spend the original P2SH output.
        original = p2sh(self.setup.redeem_script)
        modified = p2sh(self.setup.redeem_script + op(OP_1))
        self.assertNotEqual(original, modified)
        self.assertEqual(original[:2], bytes.fromhex("a914"))
        self.assertEqual(original[-1], 0x87)

    def test_artifact_accounts_for_actual_serialized_bytes(self):
        receipt = audit(self.setup, self.variants)
        self.assertEqual(receipt["experiment"], "JB-FAD01")
        self.assertEqual(len(receipt["variants"]), 2)
        for variant in self.variants.values():
            recorded = receipt["variants"][variant.branch]
            self.assertEqual(bytes.fromhex(recorded["raw_transaction_hex"]), ser_tx(variant.tx))
            self.assertEqual(recorded["txid"], txid_hex(variant.tx))
            self.assertEqual(recorded["sighash_hex_raw_bytes"], variant.sighash.hex())


if __name__ == "__main__":
    unittest.main()
