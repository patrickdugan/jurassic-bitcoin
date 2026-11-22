# JB-FAD03B: staged four-mode ECDSA transaction pinning

This experiment is stacked on [JB-FAD03A](JB-FAD03.md), which demonstrates
a consensus-valid payout substitution under the FAD02 nonce-subset protocol.
The new locking script adds four independent, size-constrained ECDSA checks
ahead of the 10-choose-5 FindAndDelete selector, and keeps the Rmin nonce
puzzle as its fifth independent signature-size check.

The four signed legacy message domains are, in required order:

| Pin | Flag | Field changed during grind | Fields protected from later changes |
| --- | --- | --- | --- |
| ACP + NONE | 0x82 | Experimental input sequence | Version, locktime, input-1 outpoint, sequence, scriptCode |
| NONE | 0x02 | Auxiliary input outpoint index | Both input outpoints, experimental sequence, version, locktime, scriptCode |
| ACP + ALL | 0x81 | Only payout output value | Experimental input and ordered outputs |
| ALL | 0x01 | Auxiliary input sequence | Both inputs, sequences and ordered outputs |

The setup fixes nVersion=2, nLockTime=0, and exactly one transaction output
to preserve the historical SIGHASH_SINGLE out-of-range bug on input index 1.
The nonce pool signatures stay precomputed over that fixed bug value.
All signature checks use real secp256k1 ECDSA with a fixed 21-byte Rmin
coordinate and different deterministic public pin keys. The keys are
published and are security-neutral; only signing-work costs are being tested.

## Stack integration

The native unlocking script pushes the original FAD02 stack, then the four
pin signatures in reverse order:

    OP_0 <nonce puzzle sig> <5 selector indices>
      <ALL pin> <ACP-ALL pin> <NONE pin> <ACP-NONE pin>

The bare locking script executes four repetitions of:

    OP_SIZE 59 OP_LESSTHANOREQUAL OP_VERIFY
    <pin_pubkey> OP_CHECKSIGVERIFY

Then the unchanged FAD02 10-choose-5 script selects the embedded
SIGHASH_SINGLE signatures and verifies a final SIGHASH_ALL nonce puzzle.

The signing stage uses independent per-mode transaction fields so each
later stage can grind without breaking already-established signatures.
A pool of 2,048 separately funded OP_TRUE auxiliary outputs provides a
real outpoint index choice for the NONE stage. All are created in one
nonstandard regtest funding transaction; no forged previous outputs
are used in native validation.

## Validation obligations

The deterministic offline runner checks:

- Four independent ECDSA signatures with canonical flags and <=59 bytes.
- Their exact legacy signature messages under the actual final transaction.
- Independence of earlier hash domains from each subsequent stage's
  chosen transaction field.
- One successful 5-of-10 FindAndDelete witness after all pins are fixed.
- The exact unlocking script, transaction serialization, locking script
  size, nonpush opcode count, sigop count and transaction weight.
- A changed payout invalidates the ACP+ALL and ALL signatures, while
  preserving ACP+NONE and NONE digests.

Bitcoin Core's direct-block campaign then tries the original four pin
signatures with an altered destination. It requires a native Script
rejection with the chain tip unchanged, then confirms the genuine
four-pin transaction and verifies the funded pool UTXO was consumed.

The off-chain policy function explicitly checks the four canonical flag
bytes. Bitcoin Script can enforce ECDSA verification and signature size;
the exact trailing sighash bytes must be checked by the BitVM verifier.

## Run

    python -m pip install "cryptography>=44,<47"
    python -m unittest discover -s tests -p test_jb_fad03_pinning.py -v
    python scripts/jb_fad03_pinning.py --output artifacts/jb-fad03b/offline.json

For a disposable Bitcoin Core 30.2 regtest node:

    python scripts/jb_fad03_pinning.py --live-regtest \
      --output artifacts/jb-fad03b/native.json

The native workflow records the funding transaction's auxiliary output
count, the chosen outpoint and four modes' grind attempt counts, full
signed transactions, Core policy decisions and both consensus verdicts.

## Security scope

At this pilot's 59-byte threshold, pinning costs are deliberately low.
An adversary can re-grind one or more pin signatures; their cost must be
measured relative to the nonce entropy and the intended collision
resistance. The stage ordering is a proof of field independence, not
a proof of a production security level.

The constructed Script also lacks the two-round Binohash extractor,
an enforceable UTXO vault-spend program, on-chain Lamport import, a BitVM
dispute guarantee, and a general ZK proof verifier. The unforgeability of
cryptographic signatures is not assumed because the deterministic private
keys are public in these research examples. As in the Binohash paper,
the security argument would rest on the computational work required to
find the short signatures.

Reference: Robin Linus, Binohash, section 3.1 and Appendix A.
https://robinlinus.com/binohash.pdf

## Verified native receipt (2026-11-22)

[Core 30.2 run 44995348183](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/44995348183)
passed its offline and native-regtest jobs at the source head
`968c8474f2632c2c916dd2a9f4a60bce5efe5a58`.

The native campaign generated one funding transaction with 2,048 genuine
auxiliary OP_TRUE outputs and one pinned bare-script pool. The cumulative
pinning attempt counts were 279 (ACP|NONE), 67 (NONE), 215 (ACP|ALL),
and 255 (ALL), followed by 72 nonce-subset candidates.

A 1,156-byte locking script used 67 counted nonpush opcodes and 10 sigops.
The 433-byte signed spend serialized to 1,732 nonwitness weight units
and carried a 306-byte scriptSig.

The native node rejected an altered destination with the four original
pin signatures while preserving the current best-block hash. It then
confirmed the genuine four-pin spend in block
`0a84f72041c17ccb12191b45446dce18cba2e3242a760d20f68678ae3228c005`,
spending transaction
`85a47b90ca65f9ef2170699a6d6c6d6259e24971eceddde014467afa08b70a12`.
The `jb-fad03b-native` workflow artifact contains the signed funding
and spending bytes, per-mode signature digests and Core rejection details.

The evidence verifies one concrete transaction and one stale-payout
counterexample under current Core rules. A repeatable high-security
construction still needs larger work factors, collision analysis,
canonical byte parsing in the BitVM verifier and an enforceable vault
settlement path.
