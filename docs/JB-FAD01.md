# JB-FAD01: Native FindAndDelete bootstrap

Status: research experiment. Scope: Bitcoin's existing pre-SegWit P2SH consensus
rules, exercised with real ECDSA signatures, optional funded regtest outputs,
and direct block construction. This experiment does not implement the
cryptographic hardness or transaction introspection of Binohash.

## What is being tested

Legacy OP_CHECKMULTISIG removes every matched pushed-signature occurrence
from its scriptCode before calculating the signature digest. This behavior is
different from SegWit v0 and Tapscript, where FindAndDelete is absent.

Our original Jurassic seam fixtures measured this transformation using
placeholder signatures and a synthetic check hook. JB-FAD01 advances to
two real, conflicting, signed P2SH spending transactions:

1. The funded transaction has output 0 locked to P2SH(OP_TRUE) and output 1
   locked to the 219-ish-byte P2SH nonce-pool redeemScript.
2. The spending transaction consumes both outputs, putting the experimental
   input at index 1 with exactly one output. Legacy SIGHASH_SINGLE therefore
   uses the historical constant-one digest for this input.
3. The redeemScript contains two distinct, low-S DER signatures of that
   constant-one digest under the same public key. They can be produced before
   the funding txid exists, avoiding the circular script-to-funding-txid
   dependency.
4. A scriptSig selector chooses one embedded signature with OP_IF/ELSE.
   CHECKMULTISIG sees that signature and a separate SIGHASH_ALL signature.
5. FindAndDelete removes the selected embedded signature's push. The resulting
   scriptCode differs between A and B, changing the SIGHASH_ALL digest.
6. The second ECDSA signature is created over the correct branch's digest
   after the funding txid is known. Both A and B are independently valid
   against the same funding output. Only one can confirm.

Pseudo-script:

```text
# scriptSig for the experimental P2SH input:
OP_0 <puzzle_sig_ALL> <A_or_B> <redeemScript>

# redeemScript:
OP_IF
    <single_sig_A>
OP_ELSE
    <single_sig_B>
OP_ENDIF
OP_2 <puzzle_pubkey> <single_pubkey> OP_2 OP_CHECKMULTISIG
```

All keys are deterministic, publicly known research fixtures. The puzzle has
no artificial difficulty and supplies no keyless vault authorization by itself.

## Run locally

Python 3.12+ and cryptography 44+:

```sh
python -m pip install 'cryptography>=44,<47'
python -m unittest discover -s tests -p test_jb_fad01.py -v
python scripts/jb_fad01.py --output artifacts/jb-fad01/offline.json
```

Offline mode uses the fixed synthetic funding txid `1212...12` and returns
reproducible fully signed transactions plus checks. Their absent prevout means
they are **not** valid spend candidates for a real chain.

For a disposable, isolated Bitcoin Core 30.2 regtest node with a wallet:

```sh
export BITCOIND_RPC_URL=http://127.0.0.1:18443
export BITCOIND_RPC_USER=user
export BITCOIND_RPC_PASS=pass

python scripts/jb_fad01.py --live-regtest --output artifacts/jb-fad01/regtest-policy.json
python scripts/jb_fad01.py --live-regtest --confirm-branch A --output artifacts/jb-fad01/regtest-A.json
python scripts/jb_fad01.py --live-regtest --confirm-branch B --output artifacts/jb-fad01/regtest-B.json
```

The live runner refuses non-regtest chains, opens/creates the dedicated
`jb_fad01` wallet, mines mature coinbase funds only when necessary, funds
both P2SH outputs using a standard wallet-signed transaction, confirms the
funding transaction, builds both spending branches, and calls
`testmempoolaccept` for each. Supplying `--confirm-branch` then calls
`generateblock` with the selected raw transaction and checks the new
block actually includes its txid. Each invocation creates a fresh funding
pair so both branches can be tested independently.

Bitcoin Core 30.2 returned `mempool-script-verify-flag-failed
(Signature is found in scriptCode)` for both candidates under default policy.
It accepted direct `generateblock` submissions for A and B after independently
funding each trial. A cross-branch signature substitution was rejected by
`TestBlockValidity` on each trial with a false final stack element, leaving
the chain tip unchanged. See the passing
[native evidence run](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/44934441875).
These outcomes separate node relay policy from current consensus validation.

## Controls

- Compare A/B scriptCode and SIGHASH_ALL digest.
- Verify selected embedded SINGLE signature against Bitcoin's constant one.
- Verify actual puzzle ECDSA signatures against their branch-specific digest.
- Reject a puzzle signature under the unmodified scriptCode.
- Reject branch selector substitution without re-signing.
- Reject amount mutation and alternate sighash flag.
- Show the embedded SINGLE signature stops working when the experimental
  input index gets a corresponding output.
- Verify actual serialized raw bytes and txids in each receipt.
- Require a confirmed native Core block before marking a live branch confirmed.

ScriptCode deletion must match complete pushed-signature byte sequences at
opcode boundaries. A signature-shaped byte sequence inside the payload of a
larger push is never removed.

## Next milestone

JB-FAD02 should replace the binary IF/ELSE selector with an n-choose-t
embedded nonce pool and OP_ROLL selection, then add a small, verifiable
SIGHASH_ALL signature-size puzzle. Use W=0 or similarly toy-sized difficulty
first, measure real candidate costs, and enumerate noncanonical sighash
flags. That creates a Binohash-style readable digest research surface.

A BitVM/ZK integration milestone must separately prove that the digest
supplied to a verifier corresponds to the actual transaction and that any
fraud-proof covenant can enforce the verdict on the vault UTXO. That
cross-input authorization link remains open.

## References

- [Jurassic legacy sighash and FindAndDelete reference](../../scripts/seam_digests_standalone.py)
- [Binohash](https://robinlinus.com/binohash.pdf)
- [Bitcoin Core v30.0 FindAndDelete implementation](https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp)
- [Keyless CHECKSIG proposed semantics](https://github.com/patrickdugan/Spiral/blob/main/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md)
