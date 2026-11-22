# JB-FAD03A: all 256 legacy sighash bytes and a payout-alias counterexample

Research branch: research/jb-fad03-sighash-matrix.
Stacked on [JB-FAD02](JB-FAD02.md).
Bitcoin Core version for native tests: 30.2, regtest only.

## Motivation

The JB-FAD02 script constrains the Rmin puzzle signature's serialized length
to at most 59 bytes, with its public key fixed to d = rmin^(-1). The appended
sighash flag comes from the unlocking script. Bitcoin's legacy consensus
accepts every possible final sighash byte; standardness checks reject some
values, and the signature-hash algorithm treats unknown base types as ALL-like.

This creates an explicit transaction-binding failure in the FAD02 toy
construction: a spend using SIGHASH_ANYONECANPAY|NONE (0x82) only commits
to the current input and current scriptCode, so it can change the destination
and payout amount without changing the signature or selected nonce indices.

The Binohash paper identifies this exact mode as a second-preimage risk.
This experiment turns the risk into raw transaction and native block receipts.

## Attack construction

The same funded bare legacy script as FAD02 is used. The experiment selects
the same five pool signatures with indices [0, 1, 2, 3, 4] for both spends,
then searches the experimental input sequence field until the fixed-Rmin
signature with 0x82 at the end is at most 59 bytes.

The two transactions have exactly the same input outpoints, nSequence,
nVersion, nLockTime and scriptSig. Both have one payout output with the same
amount and different scriptPubKeys:

  txA -> recipient A
  txB -> recipient B

Since FindAndDelete removes the same five script signature pushes for both
transactions, the signed scriptCode is identical. SIGHASH_ANYONECANPAY|NONE
omits all output contents, so the resulting signed hash is identical as well.

The experiment first confirms txA in a direct regtest block, explicitly
invalidates the block, verifies the funding outpoint is restored, then
confirms txB in a separate direct block. These are alternative histories
spending the *same* funded coins. A final receipt records both raw
transactions and each block hash.

This is a consensus-accepted **counterexample** to any assertion that the
existing JB-FAD02 nonce subset alone binds the payout. An off-chain BitVM
verifier that accepts arbitrary hash types has the same exposure.

## Exhaustive 256-byte matrix

For flag in 0x00..0xff, the runner:

1. Calculates the actual pre-SegWit signature hash with that full hash type.
2. Varies only the experimental input sequence, holding the subset and
   payout fixed, until a low-S DER-encoded fixed-Rmin signature is <=59 bytes.
3. Checks ECDSA over the exact 32 raw digest bytes and records hash type,
   attempts, resulting signature, scriptCode digest, serialized transaction.
4. Under --all-native-flags, submits every candidate directly to the native
   regtest block validator. An accepted block is then invalidated and the
   funding output is checked before the next flag.
5. For a flag without a short fixed-Rmin candidate, submits the correctly
   signed overlong signature and requires Core to reject it.

The 8 bytes satisfying (flag & 0x1f) == 3 trigger the out-of-range legacy
SIGHASH_SINGLE behavior. In this sample the returned digest's *raw bytes*
are 01 00 ... 00, which ECDSA interprets as the big-endian scalar 2^248.
This is important: a direct fixed-Rmin signature is 60 bytes, violating
the 59-byte script limit. The experiment treats this as a result of the
specified fixed-R point and size gate, not a general impossibility theorem
over every other possible ECDSA nonce.

The other 248 bytes have ALL, NONE, or ALL-fallback base semantics with
or without ANYONECANPAY. Even if an unknown base type behaves like ALL,
the full hash-type byte remains in the serialized hash-domain suffix.

## Run

    python -m pip install "cryptography>=44,<47"
    python -m unittest discover -s tests -p test_jb_fad03.py -v
    python scripts/jb_fad03.py --output artifacts/jb-fad03/offline.json

For an isolated Bitcoin Core 30.2 regtest node with the same RPC variables
documented in [JB-FAD01](JB-FAD01.md):

    python scripts/jb_fad03.py --live-regtest --all-native-flags \
      --output artifacts/jb-fad03/native.json

The native workflow stores a JSON receipt with the complete 256-row matrix,
the funded transaction, raw positive and malicious transactions, and the
chainstate rollback evidence.

## Security interpretation and next implementation

JB-FAD03A establishes the exact missing constraint before attempting the
larger Binohash pinning construction. It does not yet add four pinning
signatures to the locking script.

For JB-FAD03B, compile four Rmin ECDSA size puzzles checked by
OP_CHECKSIGVERIFY under ALL, NONE, ANYONECANPAY|ALL and
ANYONECANPAY|NONE, with distinct grindable transaction fields. Each
requires its own signed hash and real ECDSA validation. The BitVM verifier
must check canonical flag bytes and replay all signature hashes against the
transaction that is claimed to be on chain.

Even with the four puzzles, the protocol requires a proof that changing the
transaction forces fresh pinning work. The vault authorization interface,
two-round nonce extraction, cross-input binding, and reliable miner inclusion
are outside this A-stage experiment.

Primary reference: Robin Linus, Binohash, sections 3.1 and 7,
https://robinlinus.com/binohash.pdf.
