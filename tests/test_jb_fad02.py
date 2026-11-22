"""JB-FAD02: 10-choose-5 nonce-pool, Rmin ECDSA and Script-stack tests."""

import itertools
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from jb_fad01 import AUX_REDEEM, verifies  # noqa: E402
from jb_fad02 import (  # noqa: E402
    MAX_CONTEXTS,
    POOL_N,
    POOL_T,
    TARGET_SIG_BYTES,
    attacks,
    candidate_for,
    compact_rmin,
    invalid_spends,
    make_setup,
    model_stack,
    puzzle_secret,
    puzzle_sign,
    receipt,
    search,
    selection_depths,
    unlocking_script,
)
from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL,
    SIGHASH_SINGLE,
    UINT256_ONE,
    TxOut,
    p2sh,
    sha256,
    signature_hash,
)


class NoncePoolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup = make_setup()
        cls.winners, cls.stats = search(cls.setup, "12" * 32, p2sh(AUX_REDEEM))

    def test_pool_10_choose_5_is_exactly_252_unique_scriptcodes(self):
        self.assertEqual(POOL_N, 10)
        self.assertEqual(POOL_T, 5)
        self.assertEqual(len(list(itertools.combinations(range(POOL_N), POOL_T))), 252)
        all_codes = set()
        winner_tx = self.winners[0].tx
        template = replace(winner_tx, vin=tuple(replace(x, script_sig=b"")
                                                for x in winner_tx.vin))
        for combo in itertools.combinations(range(POOL_N), POOL_T):
            c = candidate_for(self.setup, template, combo, 0)
            all_codes.add(c.script_code)
            self.assertEqual(c.removed, POOL_T)
            self.assertEqual(len(model_stack(self.setup, c.depths)), POOL_T)
        self.assertEqual(len(all_codes), 252)

    def test_every_selector_stack_path_is_exact(self):
        for combo in itertools.combinations(range(POOL_N), POOL_T):
            depths = selection_depths(combo)
            self.assertEqual(len(depths), POOL_T)
            sigs = model_stack(self.setup, depths)
            self.assertEqual(set(sigs), {self.setup.pool_sigs[i] for i in combo})
            for i, depth in enumerate(depths):
                self.assertGreaterEqual(depth, 0)
                self.assertLess(depth, POOL_N - i)
        for bad in [(0, 0, 1, 2, 3), (-1, 1, 2, 3, 4), (1, 2, 3, 4, 10)]:
            with self.assertRaises(ValueError):
                selection_depths(bad)

    def test_fixed_rmin_21_byte_point_and_genuine_signature(self):
        self.assertEqual(hex(compact_rmin()),
                         "0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63")
        for c in self.winners:
            self.assertTrue(verifies(puzzle_secret(), c.digest, c.puzzle_sig))
            self.assertLessEqual(len(c.puzzle_sig), TARGET_SIG_BYTES)
            self.assertEqual(c.puzzle_sig[-1], SIGHASH_ALL)

    def test_embedded_pool_sigs_are_real_constant_one(self):
        self.assertEqual(len(set(self.setup.pool_sigs)), POOL_N)
        self.assertTrue(all(verifies(self.setup.pool_secret, UINT256_ONE, sig)
                            for sig in self.setup.pool_sigs))
        self.assertTrue(all(sig[-1] == SIGHASH_SINGLE for sig in self.setup.pool_sigs))

    def test_grind_finds_distinct_subset_winners_and_tampering_fails(self):
        a, b = self.winners
        self.assertNotEqual(a.subset, b.subset)
        self.assertNotEqual(a.script_code, b.script_code)
        self.assertNotEqual(a.digest, b.digest)
        self.assertEqual(a.tx.vin[1].prevout_hash, b.tx.vin[1].prevout_hash)
        self.assertTrue(all(attacks(self.setup, self.winners).values()))
        self.assertEqual(len(invalid_spends(self.setup, a, b)), 5)
        self.assertLessEqual(self.stats["attempts"], 252 * MAX_CONTEXTS)

    def test_sighash_single_bug_is_required_for_all_embedded_sigs(self):
        a = self.winners[0]
        self.assertEqual(signature_hash(a.script_code, a.tx, 1, SIGHASH_SINGLE),
                         UINT256_ONE)
        two_outputs = replace(a.tx, vout=a.tx.vout + (TxOut(0, b"\x51"),))
        digest = signature_hash(a.script_code, two_outputs, 1, SIGHASH_SINGLE)
        self.assertNotEqual(digest, UINT256_ONE)
        self.assertFalse(verifies(self.setup.pool_secret, digest,
                                  self.setup.pool_sigs[a.subset[0]]))

    def test_script_bounds_and_actual_serialization(self):
        self.assertGreater(len(self.setup.script_pubkey), 520)
        self.assertLess(len(self.setup.script_pubkey), 10_000)
        for c in self.winners:
            self.assertEqual(len(c.tx.vout), 1)
            self.assertEqual(c.tx.vin[1].prevout_n, 1)
            self.assertTrue(c.tx.vin[1].script_sig.startswith(b"\x00"))
            self.assertEqual(c.tx.vin[1].script_sig,
                             unlocking_script(c.puzzle_sig, c.depths))
            self.assertEqual(signature_hash(c.script_code, c.tx, 1, SIGHASH_ALL),
                             c.digest)

    def test_receipt_keeps_extraction_evidence(self):
        r = receipt(self.setup, self.winners, self.stats)
        self.assertEqual(r["experiment"], "JB-FAD02")
        self.assertEqual(len(r["winners"]), 2)
        self.assertTrue(all(r["checks"].values()))
        self.assertEqual(r["locking_script_hex"], self.setup.script_pubkey.hex())
        for i, c in enumerate(self.winners):
            self.assertEqual(r["winners"][i]["subset"], list(c.subset))
            self.assertEqual(r["winners"][i]["deleted_sig_pushes"], 5)


if __name__ == "__main__":
    unittest.main()
