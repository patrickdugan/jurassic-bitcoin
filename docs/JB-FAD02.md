# JB-FAD02: 10-choose-5 FindAndDelete nonce pool

Status: research experiment, stacked on [JB-FAD01](JB-FAD01.md).
Target: Bitcoin Core 30.2 legacy consensus on disposable regtest nodes.

## Why this branch

JB-FAD01 established that a legacy CHECKMULTISIG spend can delete a
signature embedded in its locking script before calculating SIGHASH_ALL,
and that the resulting P2SH transaction can be included in a direct
Bitcoin Core block even though default relay policy rejects it.

JB-FAD02 gives that mechanism combinatorial entropy. It creates ten
distinct ECDSA signatures over the historical SIGHASH_SINGLE constant-one
digest, then chooses five at spend time with OP_PICK and OP_ROLL. Each
distinct subset induces a distinct scriptCode. The set size is

    C(10, 5) = 252, log2(252) ~ 7.98 bits.

This reproduces the toy 10-choose-5 setting in Robin Linus's
[Binohash paper](https://robinlinus.com/binohash.pdf), section 4.5, with
a simpler fixed-pubkey pool and additional range-guard instrumentation.

The 10-signature locking script exceeds P2SH's 520-byte maximum
script-element push. We therefore fund a bare legacy script output by
constructing its funding transaction and passing its raw bytes directly
to Bitcoin Core's regtest generateblock RPC. The subsequent spend also
uses generateblock and is deliberately outside default relay policy.

## Unlocking stack

The input-1 scriptSig is push-only:

    OP_0 <puzzle_sig> <depth_0> <depth_1> <depth_2> <depth_3> <depth_4>

The OP_0 is CHECKMULTISIG's required NULLDUMMY. The output is the bare
locking Script:

    OP_5 OP_PICK OP_SIZE <59> OP_LESSTHANOREQUAL OP_VERIFY OP_DROP
    <single_sig_0> ... <single_sig_9>
    # 5 times: OP_PICK selector at depth (14 - 2*i);
    #          require 0 <= depth <= 9-i;
    #          OP_ROLL selected pool signature; OP_TOALTSTACK
    OP_DROP x10
    OP_FROMALTSTACK x5
    OP_6 <pubkey_Rmin> <pubkey_single> x5 OP_6 OP_CHECKMULTISIG

A selector is a depth from the top of the remaining unselected pool. The
five values are defined canonically from the descending indices of
the desired subset. An independent Python model checks all 252 subsets,
and verifies that the script-stack execution selects exactly the
intended five distinct signatures.

The five selected SINGLE signatures remain valid only if the experimental
input index (1) is greater than or equal to the number of outputs (1).
The consensus SIGHASH_SINGLE bug then returns uint256::ONE.

FindAndDelete removes the five selected signature pushes before hashing
the SIGHASH_ALL signature. The transaction version, locktime, prevouts,
sequences, all outputs, and the selected scriptCode contribute to its digest.

## Fixed-Rmin ECDSA size puzzle

The puzzle uses the actual secp256k1 point R = (1/2)G with

    r = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63

whose R encoding is 21 bytes. Set d = r^(-1) mod n, k = 1/2 mod n.
ECDSA then produces s = 2(z+1) mod n, where z is the real, branch-
specific SIGHASH_ALL digest. The script accepts a DER ECDSA signature
with the SIGHASH_ALL flag only when its total byte size is <=59.

That size requires s to fit into at most 31 DER bytes and gives a small
proof-of-work constraint. The search iterates candidate subsets and
calculates the actual, fixed-R ECDSA signature. A contextual locktime
range from 0 through 31 provides a bounded fallback when a single
transaction template has fewer than two qualifying subsets.

The measured attempt count, locktime, selected subset indices, actual
ECDSA DER signature, reconstructed scriptCode hash, sighash digest and
full raw transaction are retained in the JSON evidence receipt.

## Run

Install cryptography and run the deterministic offline path:

    python -m pip install 'cryptography>=44,<47'
    python -m unittest discover -s tests -p test_jb_fad02.py -v
    python scripts/jb_fad02.py --output artifacts/jb-fad02/offline.json

Offline inputs use a synthetic outpoint and are intentionally not
broadcastable.

On an isolated regtest node with RPC credentials set as in JB-FAD01:

    python scripts/jb_fad02.py --live-regtest --confirm \
      --output artifacts/jb-fad02/regtest.json

The live runner verifies the selected network is regtest, creates a
dedicated wallet, mines funding if necessary, signs and directly mines
a funding transaction with the bare pool output. After searching the
nonce subsets, it probes default mempool policy for both winner spends.

It then asks Core to build invalid blocks with a swapped subset,
changed payout amount, out-of-range OP_ROLL selector, extra output and
altered SIGHASH flag. Each negative trial must be rejected while the
best-block hash remains unchanged. Finally it mines one valid winner
and asserts its funded pool UTXO was consumed.

The CI workflow .github/workflows/jb-fad02.yml reproduces the offline
test and the whole native regtest campaign.

## Limits and next attack surface

The demonstrated extraction is approximately eight bits of combinatorial
nonce space. The locktime fallback introduces another degree of freedom,
which a security construction must bind explicitly.

There is no production transaction pinning in this milestone, and there
are no two nonce rounds. The publicly reproducible keys and fixed-R
signature construction mean the experimental signer has no privileged
authorization role. No BitVM vault, ZK verifier, DLC settlement guarantee
or general Keyless CHECKSIG is implemented here.

JB-FAD03 should implement Linus's four SIGHASH-mode pinning checks in
the existing bare Script, eliminate fallback transaction mutations,
enforce canonical scriptSig encoding, and measure all 256 sighash flag
variants against both consensus and standardness. A subsequent
two-round experiment can add the Lamport-signable Script-readable digest
for a BitVM verifier.
