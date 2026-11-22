"""JB-FAD04: two-round real ECDSA, byte-exact referee and attack tests."""

import json
import struct
import sys
import unittest
from dataclasses import replace
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))

from jb_fad01 import AUX_REDEEM, verifies  # noqa: E402
from jb_fad02 import POOL_N,POOL_T,TARGET_SIG_BYTES  # noqa: E402
from jb_fad04 import (  # noqa: E402
    AUX_COUNT,AUX_VALUE_SATS,POOL_SATS,canonical_checks,grind,
    make_dual_setup,nonce_script_code,receipt,script_resources,synthetic_funding,
)
from jb_fad04_verify import (  # noqa: E402
    ProofRejected,build_merkle_branch,check_header_pow,make_envelope,
    parse_funding_tx,parse_legacy_tx,parse_canonical_pushes,
    verify_block_inclusion,verify_envelope,verify_transaction,
)
from seam_digests_standalone import (  # noqa: E402
    SIGHASH_ALL,SIGHASH_SINGLE,UINT256_ONE,TxOut,dsha256,
    op,p2sh,ser_tx,sha256,signature_hash,txid_hex,
)


def reject(fn, *args, **kwargs):
    with __import__("contextlib").nullcontext():
        try:
            fn(*args,**kwargs)
        except (ProofRejected,ValueError,KeyError):
            return True
        return False


class DualRoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.setup=make_dual_setup()
        cls.funding=synthetic_funding(cls.setup)
        cls.funding_hex=ser_tx(cls.funding).hex()
        cls.payout=p2sh(op(0x51))
        cls.candidate=grind(cls.setup,txid_hex(cls.funding),cls.payout)
        cls.report=receipt(cls.setup,cls.candidate)

    def base_kwargs(self,**overrides):
        c=self.candidate
        args=dict(
            raw_spend_hex=ser_tx(c.tx).hex(),
            raw_funding_hex=self.funding_hex,
            expected_payout_script_hex=self.payout.hex(),
            expected_indices=list(c.index_digest),
            min_payout_sats=170_000,
            setup=self.setup,
        )
        args.update(overrides)
        return args

    def test_two_independent_nonce_pools_are_real_ecdsa(self):
        a=self.setup.first
        b=self.setup.second
        self.assertEqual(len(a.pool_sigs),POOL_N)
        self.assertEqual(len(b.pool_sigs),POOL_N)
        self.assertFalse(set(a.pool_sigs)&set(b.pool_sigs))
        self.assertTrue(all(verifies(a.pool_secret,UINT256_ONE,x) for x in a.pool_sigs))
        self.assertTrue(all(verifies(b.pool_secret,UINT256_ONE,x) for x in b.pool_sigs))
        self.assertEqual(len(self.candidate.first_subset),POOL_T)
        self.assertEqual(len(self.candidate.second_subset),POOL_T)
        self.assertEqual(len(self.candidate.index_digest),10)
        self.assertEqual(set(self.candidate.nonce_attempts),
                         {"round_1","round_2"})

    def test_two_different_codeseparator_scriptcodes(self):
        c=self.candidate
        first,_=nonce_script_code(self.setup,1,c.first_subset)
        second,_=nonce_script_code(self.setup,2,c.second_subset)
        self.assertNotEqual(first,second)
        self.assertTrue(first.startswith(self.setup.script[:20]))
        self.assertTrue(second.startswith(self.setup.second.script_pubkey[:1]))
        self.assertEqual(signature_hash(first,c.tx,1,SIGHASH_ALL),
                         c.first_nonce_digest)
        self.assertEqual(signature_hash(second,c.tx,1,SIGHASH_ALL),
                         c.second_nonce_digest)
        for code in (first,second):
            self.assertEqual(signature_hash(code,c.tx,1,SIGHASH_SINGLE),
                             UINT256_ONE)

    def test_two_round_native_script_budget(self):
        r=script_resources(self.setup,self.candidate)
        self.assertTrue(r["within_201_nonpush_limit"])
        self.assertTrue(r["within_10000_script_size"])
        self.assertGreater(r["locking_script_bytes"],1156)
        self.assertEqual(r["sigops_accurate"],16)
        self.assertEqual(r["combinations_per_round"],252)
        self.assertAlmostEqual(r["raw_entropy_bits"],15.954,delta=.1)
        self.assertGreater(r["script_sig_bytes"],300)
        self.assertEqual(r["tx_weight"],4*r["nonwitness_tx_bytes"])

    def test_strict_raw_verifier_replays_all_six_signatures(self):
        proof=verify_transaction(**self.base_kwargs())
        self.assertTrue(proof["valid"])
        self.assertEqual(proof["txid"],self.candidate.txid)
        self.assertEqual(proof["binohash_indices"],list(self.candidate.index_digest))
        self.assertEqual(len(proof["checks"]),6)
        self.assertEqual(proof["payout_script"],self.payout.hex())
        self.assertTrue(all(canonical_checks(self.setup,self.candidate).values()))

    def test_misclaimed_or_swapped_indices_rejected(self):
        wrong=list(self.candidate.index_digest)
        wrong[0]=(wrong[0]+1)%10
        self.assertTrue(reject(verify_transaction,
                               **self.base_kwargs(expected_indices=wrong)))
        wrong2=wrong[:]
        wrong2[0]=self.candidate.index_digest[0]
        wrong2[-1]=(wrong2[-1]+1)%10
        self.assertTrue(reject(verify_transaction,
                               **self.base_kwargs(expected_indices=wrong2)))

    def test_stale_pins_fail_on_changed_payout(self):
        tx=self.candidate.tx
        changed=replace(tx,vout=(replace(
            tx.vout[0],script_pubkey=p2sh(op(0x52)),
        ),))
        self.assertTrue(reject(verify_transaction,
                               **self.base_kwargs(
                                   raw_spend_hex=ser_tx(changed).hex(),
                                   expected_payout_script_hex=p2sh(op(0x52)).hex(),
                               )))

    def test_altered_round2_sig_or_selector_rejected(self):
        script=bytearray(self.candidate.tx.vin[1].script_sig)
        # Mutate a valid small selector or ECDSA signature byte.
        items=parse_canonical_pushes(bytes(script))
        self.assertEqual(len(items),18)
        self.assertTrue(any(x for x in items[2:7]))
        script[5]^=0x01
        tx=replace(self.candidate.tx,vin=(self.candidate.tx.vin[0],
            replace(self.candidate.tx.vin[1],script_sig=bytes(script))))
        self.assertTrue(reject(verify_transaction,
                               **self.base_kwargs(raw_spend_hex=ser_tx(tx).hex())))

    def test_nonminimal_compactsize_rejected(self):
        data=ser_tx(self.candidate.tx)
        # Replace one-byte count=2 immediately after the version by
        # illegal 0xfd/0002 without changing the semantic contents.
        self.assertEqual(data[4],2)
        modified=data[:4]+b"\xfd\x02\x00"+data[5:]
        self.assertTrue(reject(parse_legacy_tx,modified))

    def test_segwit_funding_txid_is_stripped(self):
        base=ser_tx(self.funding)
        # 1-input synthetic funding with nonempty witness: add 00 01 marker
        # and one witness stack item before nLockTime.
        segwit=(base[:4]+b"\x00\x01"+base[4:-4]+
                b"\x01\x02\xab\xcd"+base[-4:])
        parsed=parse_funding_tx(segwit)
        self.assertEqual(ser_tx(parsed),base)
        self.assertEqual(txid_hex(parsed),txid_hex(self.funding))
        self.assertTrue(reject(parse_legacy_tx,segwit))
        proof=verify_transaction(**self.base_kwargs(raw_funding_hex=segwit.hex()))
        self.assertTrue(proof["valid"])

    def test_funding_pool_outpoint_must_match_exact_locking_script(self):
        funding=replace(self.funding,vout=(
            self.funding.vout[:AUX_COUNT]+
            (replace(self.funding.vout[AUX_COUNT],
                     script_pubkey=self.setup.script+b"\x51"),)+
            self.funding.vout[AUX_COUNT+1:]
        ))
        self.assertTrue(reject(
            verify_transaction,
            **self.base_kwargs(raw_funding_hex=ser_tx(funding).hex())))
        changed=replace(self.candidate.tx,vin=(
            self.candidate.tx.vin[0],
            replace(self.candidate.tx.vin[1],prevout_n=AUX_COUNT-1),
        ))
        self.assertTrue(reject(
            verify_transaction,
            **self.base_kwargs(raw_spend_hex=ser_tx(changed).hex())))

    def test_merkle_branch_and_trusted_header(self):
        txid=self.candidate.txid
        txids=["ab"*32,txid,"cd"*32]
        proof=build_merkle_branch(txids,1)
        def make_root(nodes):
            nodes=[bytes.fromhex(x)[::-1] for x in nodes]
            while len(nodes)>1:
                nodes=[dsha256(nodes[k]+nodes[k+1 if k+1<len(nodes) else k])
                       for k in range(0,len(nodes),2)]
            return nodes[0]
        root=make_root(txids)
        prefix=struct.pack("<i",4)+bytes(32)+root+struct.pack("<I",1_700_000_000)+struct.pack("<I",0x207fffff)
        header=None
        for nonce in range(100):
            candidate=prefix+struct.pack("<I",nonce)
            if check_header_pow(candidate):
                header=candidate
                break
        self.assertIsNotNone(header)
        trusted=dsha256(header)[::-1].hex()
        verdict=verify_block_inclusion(
            txid=txid,header_hex=header.hex(),
            claimed_block_hash=trusted,trusted_block_hash=trusted,merkle=proof,
        )
        self.assertTrue(verdict["included"])
        self.assertTrue(reject(verify_block_inclusion,
            txid=txid,header_hex=header.hex(),
            claimed_block_hash=trusted,trusted_block_hash="ff"*32,merkle=proof))
        fake=dict(proof)
        fake["siblings"]=list(proof["siblings"])
        fake["siblings"][0]="11"*32
        self.assertTrue(reject(verify_block_inclusion,
            txid=txid,header_hex=header.hex(),
            claimed_block_hash=trusted,trusted_block_hash=trusted,merkle=fake))

    def test_full_envelope_consistency(self):
        tx=self.candidate.tx
        root=bytes.fromhex(self.candidate.txid)[::-1]
        prefix=struct.pack("<i",4)+bytes(32)+root+struct.pack("<I",1_700_000_001)+struct.pack("<I",0x207fffff)
        header=next(prefix+struct.pack("<I",nonce) for nonce in range(100)
                    if check_header_pow(prefix+struct.pack("<I",nonce)))
        trusted=dsha256(header)[::-1].hex()
        trial=dict(self.report)
        trial["funding"]={"raw_tx":self.funding_hex}
        trial["block_evidence"]={
            "block_hash":trusted,"header_hex":header.hex(),
            "txids":[txid_hex(tx)],"position":0,
        }
        env=make_envelope(trial,
                          expected_payout_script_hex=self.payout.hex(),
                          min_payout_sats=170_000)
        policy={
            "schema":"jb-fad04-policy-v1",
            "vault_txid":txid_hex(self.funding),
            "vault_vout":AUX_COUNT,
            "vault_script_sha256":sha256(self.setup.script).hex(),
            "payout_script_hex":self.payout.hex(),
            "min_payout_sats":170_000,
            "index_digest":list(self.candidate.index_digest),
        }
        self.assertTrue(reject(verify_envelope,env,trusted_block_hash=trusted,
                               trusted_policy={}))
        out=verify_envelope(
            env,trusted_block_hash=trusted,trusted_policy=policy,
        )
        self.assertTrue(out["accepted"])
        self.assertEqual(out["transaction"]["spent_outpoint"],
                         txid_hex(self.funding)+":"+str(AUX_COUNT))
        env["claimed_indices"]=list(reversed(env["claimed_indices"]))
        self.assertTrue(reject(verify_envelope,env,trusted_block_hash=trusted,
                                trusted_policy=policy))
        env["claimed_indices"]=list(self.candidate.index_digest)
        bad_policy=dict(policy,vault_txid="ff"*32)
        self.assertTrue(reject(verify_envelope,env,trusted_block_hash=trusted,
                                trusted_policy=bad_policy))
        bad_policy=dict(policy,payout_script_hex=p2sh(op(0x52)).hex())
        self.assertTrue(reject(verify_envelope,env,trusted_block_hash=trusted,
                                trusted_policy=bad_policy))


if __name__=="__main__":
    unittest.main()
