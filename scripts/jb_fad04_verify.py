#!/usr/bin/env python3
"""JB-FAD04 strict raw-transaction and block-inclusion verifier.

Reads *raw bytes*, independently extracts both Binohash selector tuples,
reconstructs Bitcoin legacy signature hashes, checks ECDSA against public
keys, binds to the exact funded bare-script outpoint, checks the authorized
payout and optionally verifies a txid Merkle proof under a trusted header.

This is an off-chain Python referee prototype, not a deployed BitVM circuit.
The caller MUST supply an independently trusted block hash; the Merkle proof
alone cannot establish that a header belongs to Bitcoin's best-work chain.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from jb_fad01 import AUX_REDEEM, SECP256K1_ORDER, pubkey_bytes
from jb_fad02 import (
    POOL_N, POOL_T, POOL_SATS, TARGET_SIG_BYTES, model_stack,
    selection_depths,
)
from jb_fad03_pinning import (
    AUX_COUNT, AUX_VALUE_SATS, FLAGS, PAYOUT_BASE_SATS, OUTPUT_VARIANTS,
)
from jb_fad04 import (
    DualSetup, build_script_sig, make_dual_setup, nonce_script_code,
)
from seam_digests_standalone import (
    SIGHASH_ALL, SIGHASH_SINGLE, UINT256_ONE, Tx, TxIn, TxOut,
    dsha256, op, p2sh, ser_tx, signature_hash, txid_hex, sha256,
)


class ProofRejected(ValueError):
    pass


def need(cond: bool, msg: str):
    if not cond:
        raise ProofRejected(msg)


@dataclass
class ByteReader:
    data: bytes
    offset: int = 0

    def take(self, n: int) -> bytes:
        if n < 0 or n > len(self.data) - self.offset:
            raise ProofRejected("truncated or oversized raw Bitcoin field")
        out = self.data[self.offset:self.offset+n]
        self.offset += n
        return out

    def compactsize(self) -> int:
        first=self.take(1)[0]
        if first < 0xfd:
            return first
        if first == 0xfd:
            value=int.from_bytes(self.take(2),"little")
            need(value>=0xfd,"noncanonical CompactSize 0xfd")
        elif first == 0xfe:
            value=int.from_bytes(self.take(4),"little")
            need(value>0xffff,"noncanonical CompactSize 0xfe")
        else:
            value=int.from_bytes(self.take(8),"little")
            need(value>0xffffffff,"noncanonical CompactSize 0xff")
        return value


def parse_legacy_tx(raw: bytes) -> Tx:
    """Exact pre-SegWit parser; round-trip equality rejects ambiguous bytes."""
    need(10<=len(raw)<=4_000_000,"bad raw transaction length")
    r=ByteReader(raw)
    version=int.from_bytes(r.take(4),"little",signed=True)
    count=r.compactsize()
    need(1<=count<=100_000,"missing inputs, unsupported witness, or too many inputs")
    vin=[]
    for _ in range(count):
        previous=r.take(32)
        output=int.from_bytes(r.take(4),"little")
        length=r.compactsize()
        need(length<=10_000,"scriptSig too long")
        script=r.take(length)
        sequence=int.from_bytes(r.take(4),"little")
        vin.append(TxIn(previous,output,script,sequence))
    nouts=r.compactsize()
    need(1<=nouts<=100_000,"output count outside research parser bounds")
    vout=[]
    for _ in range(nouts):
        sats=int.from_bytes(r.take(8),"little",signed=True)
        need(0<=sats<=21_000_000*100_000_000,"invalid output value")
        n=r.compactsize()
        need(n<=10_000,"output script exceeds legacy limit")
        vout.append(TxOut(sats,r.take(n)))
    locktime=int.from_bytes(r.take(4),"little")
    need(r.offset==len(raw),"trailing raw transaction bytes")
    tx=Tx(version,tuple(vin),tuple(vout),locktime)
    need(ser_tx(tx)==raw,"noncanonical raw transaction encoding")
    return tx


def parse_canonical_pushes(script_sig: bytes) -> list[bytes]:
    """Parse push-only scriptSig and reject alternate representations."""
    items=[]
    r=ByteReader(script_sig)
    while r.offset<len(r.data):
        opcode=r.take(1)[0]
        if opcode==0:
            items.append(b"")
        elif 1<=opcode<=75:
            value=r.take(opcode)
            if len(value)==1:
                need(value[0] not in (0,0x81,*range(1,17)),
                     "nonminimal push for script number")
            items.append(value)
        elif opcode==0x4c:
            n=r.take(1)[0]
            need(n>=76,"nonminimal PUSHDATA1")
            items.append(r.take(n))
        elif opcode==0x4d:
            n=int.from_bytes(r.take(2),"little")
            need(n>255,"nonminimal PUSHDATA2")
            items.append(r.take(n))
        elif opcode==0x4e:
            n=int.from_bytes(r.take(4),"little")
            need(n>65535,"nonminimal PUSHDATA4")
            items.append(r.take(n))
        elif 0x51<=opcode<=0x60:
            items.append(bytes([opcode-0x50]))
        else:
            raise ProofRejected(f"non-push or noncanonical scriptSig opcode {opcode:02x}")
    return items


def _depths_to_subset(depths: tuple[int,...]) -> tuple[int,...]:
    need(len(depths)==POOL_T,"wrong subset width")
    ordered=[POOL_N-1-i-d for i,d in enumerate(depths)]
    need(all(0<=x<POOL_N for x in ordered),"selector out of range")
    need(all(ordered[i]>ordered[i+1] for i in range(POOL_T-1)),
         "duplicate or re-ordered subset")
    subset=tuple(sorted(ordered))
    need(selection_depths(subset)==depths,"selector encoding noncanonical")
    return subset


def decode_unlock(script_sig: bytes, setup: DualSetup) -> dict:
    items=parse_canonical_pushes(script_sig)
    need(len(items)==18,"expect 2*(dummy+nonce+5 indices)+4 pin signatures")
    need(items[0]==b"" and items[7]==b"", "nonempty OP_CHECKMULTISIG dummy")
    d2=tuple(x[0] if len(x)==1 else 0 if x==b"" else -1 for x in items[2:7])
    d1=tuple(x[0] if len(x)==1 else 0 if x==b"" else -1 for x in items[9:14])
    need(all(0<=x<=16 for x in d1+d2),"invalid selector numeric encoding")
    subset1=_depths_to_subset(d1)
    subset2=_depths_to_subset(d2)
    need(set(model_stack(setup.first,d1))==
         {setup.first.pool_sigs[i] for i in subset1},"first pool mismatch")
    need(set(model_stack(setup.second,d2))==
         {setup.second.pool_sigs[i] for i in subset2},"second pool mismatch")
    pins={name:sig for (name,_),sig in zip(reversed(FLAGS),items[14:18])}
    nonce1=items[8]
    nonce2=items[1]
    need(
        build_script_sig(pins,nonce1,subset1,nonce2,subset2)==script_sig,
        "scriptSig must be byte-exact canonical encoding",
    )
    return {
        "round1":subset1, "round2":subset2,
        "round1_sig":nonce1, "round2_sig":nonce2,
        "pins":pins,
        "index_digest":subset1+subset2,
    }


def verify_ecdsa_pubkey(pubkey: bytes, digest: bytes,
                        signature: bytes, flag: int):
    need(len(signature)>=9 and len(signature)<=TARGET_SIG_BYTES,
         "ECDSA signature violates 59-byte puzzle")
    need(signature[-1]==flag,"noncanonical sighash flag")
    try:
        r,s=utils.decode_dss_signature(signature[:-1])
    except ValueError as exc:
        raise ProofRejected("signature not strict DER") from exc
    need(0<r<SECP256K1_ORDER and 0<s<=SECP256K1_ORDER//2,
         "signature r/s outside strict low-S range")
    try:
        key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),pubkey)
        key.verify(signature[:-1],digest,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except (InvalidSignature,ValueError) as exc:
        raise ProofRejected("invalid public-key ECDSA signature") from exc


def verify_transaction(*, raw_spend_hex: str, raw_funding_hex: str,
                       expected_payout_script_hex: str,
                       expected_indices: list[int],
                       min_payout_sats: int,
                       setup: DualSetup | None = None) -> dict:
    """Reconstruct policy from raw bytes and a trusted expected payout.

    An on-chain spent-outpoint proof or trusted validated chainstate source
    is still needed before treating this as a Bitcoin-confirmed payment.
    """
    setup=setup or make_dual_setup()
    try:
        tx=parse_legacy_tx(bytes.fromhex(raw_spend_hex))
        funding=parse_legacy_tx(bytes.fromhex(raw_funding_hex))
        expected_script=bytes.fromhex(expected_payout_script_hex)
    except ValueError as exc:
        raise ProofRejected("malformed hexadecimal transaction or script") from exc

    need(tx.version==2 and tx.locktime==0,"invalid version or locktime")
    need(len(tx.vin)==2 and len(tx.vout)==1,"expected 2 inputs / 1 output")
    need(tx.vin[0].prevout_hash==tx.vin[1].prevout_hash,
         "auxiliary and pool inputs must spend same funding transaction")
    funding_hash=dsha256(bytes.fromhex(raw_funding_hex))
    need(tx.vin[1].prevout_hash==funding_hash,"wrong funded transaction identity")
    need(tx.vin[1].prevout_n==AUX_COUNT,"wrong pool vout")
    need(0<=tx.vin[0].prevout_n<AUX_COUNT,"auxiliary vout outside funded set")
    need(tx.vin[0].script_sig==bytes([1,0x51]),
         "auxiliary OP_TRUE redeemScript must use canonical push")
    need(len(funding.vout)>AUX_COUNT,"funding output count too small")
    need(funding.vout[tx.vin[0].prevout_n]==TxOut(AUX_VALUE_SATS,p2sh(AUX_REDEEM)),
         "auxiliary UTXO script or value mismatch")
    need(funding.vout[AUX_COUNT]==TxOut(POOL_SATS,setup.script),
         "funding UTXO does not commit to exact dual-round Script")
    need(
        all(0xF0000000<=i.sequence<0xF0000000+4096 for i in tx.vin),
        "sequence outside registered grind domain",
    )
    need(tx.vout[0].script_pubkey==expected_script,"unauthorized payout recipient")
    need(PAYOUT_BASE_SATS<=tx.vout[0].value<PAYOUT_BASE_SATS+OUTPUT_VARIANTS,
         "output outside registered payout search range")
    need(tx.vout[0].value>=min_payout_sats,"payout below application minimum")
    fee=POOL_SATS+AUX_VALUE_SATS-tx.vout[0].value
    need(0<=fee<=POOL_SATS+AUX_VALUE_SATS,"invalid spend fee")

    witness=decode_unlock(tx.vin[1].script_sig,setup)
    need(list(witness["index_digest"])==expected_indices,
         "Binohash indices differ from externally committed claim")
    checks=[]
    for name,flag in FLAGS:
        signed=signature_hash(setup.script,tx,1,flag)
        verify_ecdsa_pubkey(setup.pin_pubkeys[name],signed,
                            witness["pins"][name],flag)
        checks.append("pin_"+name)
    for round_no,key,subset,pub in (
        (1,"round1_sig",witness["round1"],
         pubkey_bytes(setup.first.puzzle_secret)),
        (2,"round2_sig",witness["round2"],
         pubkey_bytes(setup.second.puzzle_secret)),
    ):
        code,removed=nonce_script_code(setup,round_no,subset)
        need(removed==POOL_T,"wrong nonce pool deletions")
        signed=signature_hash(code,tx,1,SIGHASH_ALL)
        verify_ecdsa_pubkey(pub,signed,witness[key],SIGHASH_ALL)
        pool=setup.first if round_no==1 else setup.second
        need(signature_hash(code,tx,1,SIGHASH_SINGLE)==UINT256_ONE,
             "pool signature hash is not the constant-one bug")
        for sig in model_stack(pool,selection_depths(subset)):
            # Pool signatures are real and transaction-independent via
            # the legacy SINGLE bug on input 1 with one output.
            need(sig[-1]==SIGHASH_SINGLE,"pool signature hash flag changed")
            keybytes=pubkey_bytes(pool.pool_secret)
            try:
                key=ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256K1(),keybytes
                )
                key.verify(sig[:-1],UINT256_ONE,
                           ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except (InvalidSignature,ValueError) as exc:
                raise ProofRejected("embedded SINGLE pool signature invalid") from exc
        checks.append(f"round_{round_no}_nonce")
    return {
        "valid":True,
        "txid":txid_hex(tx),
        "funding_txid":txid_hex(funding),
        "spent_outpoint":f"{txid_hex(funding)}:{AUX_COUNT}",
        "binohash_indices":list(witness["index_digest"]),
        "payout_script":expected_script.hex(),
        "payout_sats":tx.vout[0].value,
        "spend_fee_sats":fee,
        "checks":checks,
        "scope":"validated raw transactions and authorization; block inclusion separate",
    }


def build_merkle_branch(txids: list[str], index: int) -> dict:
    need(0<=index<len(txids),"txid Merkle index outside block")
    nodes=[bytes.fromhex(x)[::-1] for x in txids]
    count=len(nodes)
    siblings=[]
    pos=index
    while len(nodes)>1:
        j=pos^1
        if j>=len(nodes):
            j=pos
        siblings.append(nodes[j][::-1].hex())
        nodes=[
            dsha256(nodes[k]+nodes[k+1 if k+1<len(nodes) else k])
            for k in range(0,len(nodes),2)
        ]
        pos//=2
    return {"tx_count":count,"position":index,"siblings":siblings}


def check_header_pow(header: bytes) -> bool:
    # Compact target decoded from nBits. This checks PoW on the provided
    # header, not the work of its ancestor chain.
    compact=int.from_bytes(header[72:76],"little")
    exponent=compact>>24
    mantissa=compact&0x007fffff
    if compact&0x00800000 or mantissa==0 or exponent>32:
        return False
    target = mantissa>>(8*(3-exponent)) if exponent<=3 else mantissa<<(8*(exponent-3))
    return 0<target<2**256 and int.from_bytes(dsha256(header),"little")<=target


def verify_block_inclusion(*, txid: str, header_hex: str,
                           claimed_block_hash: str, trusted_block_hash: str,
                           merkle: dict) -> dict:
    need(trusted_block_hash==claimed_block_hash,
         "block hash differs from externally trusted anchor")
    try:
        header=bytes.fromhex(header_hex)
    except ValueError as exc:
        raise ProofRejected("invalid block header hex") from exc
    need(len(header)==80,"Bitcoin block header must be exactly 80 bytes")
    need(dsha256(header)[::-1].hex()==claimed_block_hash,
         "header hash mismatch")
    need(check_header_pow(header),"header fails its compact proof-of-work target")
    pos=merkle["position"]
    count=merkle["tx_count"]
    need(isinstance(pos,int) and isinstance(count,int) and
         0<=pos<count<=1_000_000,"invalid block Merkle position/count")
    siblings=merkle["siblings"]
    need(isinstance(siblings,list),"Merkle siblings must be a list")
    h=bytes.fromhex(txid)[::-1]
    original_pos=pos
    used=0
    while count>1:
        need(used<len(siblings),"truncated Merkle branch")
        s=bytes.fromhex(siblings[used])[::-1]
        j=pos^1
        if j>=count:
            need(s==h,"odd-node Merkle duplication mismatch")
        h=dsha256(s+h) if j<pos else dsha256(h+s)
        pos//=2
        count=(count+1)//2
        used+=1
    need(used==len(siblings),"Merkle branch contains trailing nodes")
    need(h==header[36:68],"Merkle root differs from block header")
    return {
        "included":True,
        "block_hash":claimed_block_hash,
        "position":original_pos,
        "header_pow_valid":True,
        "trust_boundary":"trusted_block_hash supplied by a separate validated header chain",
    }


def make_envelope(receipt: dict, *, expected_payout_script_hex: str,
                  min_payout_sats: int) -> dict:
    evidence=receipt["block_evidence"]
    funding=receipt["funding"]
    return {
        "schema":"jb-fad04-referee-v1",
        "raw_spend_hex":receipt["raw_spend_tx"],
        "raw_funding_hex":funding["raw_tx"],
        "claimed_indices":receipt["two_round_binohash"]["concatenated_indices"],
        "expected_payout_script_hex":expected_payout_script_hex,
        "min_payout_sats":min_payout_sats,
        "block_header_hex":evidence["header_hex"],
        "claimed_block_hash":evidence["block_hash"],
        "merkle":build_merkle_branch(evidence["txids"],evidence["position"]),
    }


def verify_envelope(envelope: dict, *, trusted_block_hash: str) -> dict:
    need(envelope.get("schema")=="jb-fad04-referee-v1","invalid verifier schema")
    tx_result=verify_transaction(
        raw_spend_hex=envelope["raw_spend_hex"],
        raw_funding_hex=envelope["raw_funding_hex"],
        expected_payout_script_hex=envelope["expected_payout_script_hex"],
        expected_indices=envelope["claimed_indices"],
        min_payout_sats=envelope["min_payout_sats"],
    )
    block_result=verify_block_inclusion(
        txid=tx_result["txid"],
        header_hex=envelope["block_header_hex"],
        claimed_block_hash=envelope["claimed_block_hash"],
        trusted_block_hash=trusted_block_hash,
        merkle=envelope["merkle"],
    )
    return {
        "accepted":True,
        "transaction":tx_result,
        "block":block_result,
        "limits":[
            "requires independently validated header-chain anchor",
            "this Python verifier is not an in-circuit BitVM or ZK verifier",
            "no vault spend authorization enforced by this code",
        ],
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--native-receipt",required=True)
    ap.add_argument("--trusted-blockhash",required=True,
                    help="block hash verified by a separate header-chain oracle")
    ap.add_argument("--output",default="artifacts/jb-fad04/referee.json")
    args=ap.parse_args()
    receipt=json.loads(Path(args.native_receipt).read_text(encoding="utf-8"))
    tx=parse_legacy_tx(bytes.fromhex(receipt["raw_spend_tx"]))
    env=make_envelope(
        receipt,expected_payout_script_hex=tx.vout[0].script_pubkey.hex(),
        min_payout_sats=PAYOUT_BASE_SATS,
    )
    verdict=verify_envelope(env,trusted_block_hash=args.trusted_blockhash)
    out=Path(args.output)
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps({"envelope":env,"verdict":verdict},indent=2)+"\n",
                   encoding="utf-8")
    print(json.dumps({
        "accepted":verdict["accepted"],
        "txid":verdict["transaction"]["txid"],
        "block":verdict["block"]["block_hash"],
        "indices":verdict["transaction"]["binohash_indices"],
        "receipt":str(out),
    },indent=2))


if __name__=="__main__":
    main()
