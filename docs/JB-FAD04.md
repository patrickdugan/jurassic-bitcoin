# JB-FAD04: two-round Binohash and byte-exact referee

JB-FAD04 extends [JB-FAD03B](JB-FAD03B.md) with two separate
10-choose-5 legacy FindAndDelete pools executed inside **one bare
legacy script**. The existing four short-ECDSA transaction pinning
puzzles remain, followed by two independent nonce puzzles.

An OP_CODESEPARATOR between the rounds establishes a distinct
scriptCode for the second OP_CHECKMULTISIG. The first round ends with
OP_VERIFY, consuming its success boolean and exposing the lower
second-round unlocking stack.

Each round has C(10,5)=252 selectable subsets. Concatenating the two
ordered five-index tuples gives 2*log2(252) ~= 15.95 bits of raw
subset space. Linus's proposed production parameters use 120-choose-8
per round, roughly 79 bits of subset information. The experiment
does not establish production collision-security estimates.

## Four-stage grinder

The complete spend is subject to ECDSA size puzzles under:
0x82 (ACP|NONE), 0x02 (NONE), 0x81 (ACP|ALL), and 0x01 (ALL).
Each grind changes one transaction field while keeping the preceding
signed messages fixed: input-1 sequence, auxiliary input outpoint,
payout value, then input-0 sequence.

After the four pins succeed, the solver searches 252 subsets in round
one and 252 in round two. Failure to solve either round backtracks
to the fourth pin. The payout beneficiary remains fixed, locktime is
zero, and all signature keys are deterministic public fixtures.

### Unlocking-script grammar

    OP_0 <round2-nonce> <round2-depths[5]>
    OP_0 <round1-nonce> <round1-depths[5]>
    <ALL-pin> <ACP|ALL-pin> <NONE-pin> <ACP|NONE-pin>

The four CHECKSIGVERIFY puzzles execute first. The two CHECKMULTISIG
calls each select 5 precomputed SINGLE-bug signatures and validate
a fresh short SIGHASH_ALL signature.

## Byte-exact referee

The independent Python referee parses actual raw transactions and
checks the following:

- both inputs refer to the same exact funding transaction, with its
  bare pool output at the specified index and auxiliary OP_TRUE coin;
- the payout is authorized by the expected script and minimum sats;
- the scriptSig has exactly two correctly encoded nonce groups and four
  pin signatures, with canonical subset indices and signature flags;
- all four pin ECDSA signatures and both nonce signatures verify using
  public keys over recomputed legacy sighashes;
- selected embedded SINGLE-bug signatures verify over constant one;
- a native block header has the correct hash and compact proof-of-work,
  and its txid Merkle root includes this exact spending transaction.

The Merkle check requires an independently trusted block hash. A
header Merkle proof does not establish best-work chain membership by
itself. The funding tx parser also supports BIP144 SegWit witness
serialization and derives the non-witness funding txid that appears
in UTXO references.

This is a **Python referee prototype**. The transaction checks are
not yet compiled into a BitVM refutation circuit, and they do not
enforce a vault's spend authorization.

## Reproduction

Install dependency and run the deterministic offline specimen:

    python -m pip install "cryptography>=44,<47"
    python -m unittest discover -s tests -p test_jb_fad04.py -v
    python scripts/jb_fad04.py --output artifacts/jb-fad04/offline.json

Offline funding uses a fake prevout. Raw bytes are internally
consistent but cannot confirm on a real chain.

On an isolated Bitcoin Core 30.2 regtest with RPC configured:

    python scripts/jb_fad04.py --live-regtest \
      --output artifacts/jb-fad04/native.json

The native campaign funds 2,048 real auxiliary outputs and the bare
locking script, requires native Core block rejection of mutated payout,
changed round-two subset, and an extra output, then confirms the valid
spend and records the header and block txids.

A separate validation call needs a block hash from a trusted node or
validated header chain:

    python scripts/jb_fad04_verify.py \
      --native-receipt artifacts/jb-fad04/native.json \
      --trusted-blockhash <trusted_block_hash> \
      --trusted-policy <separately_authenticated_vault_policy.json> \
      --output artifacts/jb-fad04/referee.json

GitHub Actions in .github/workflows/jb-fad04.yml performs these stages
with explicit inputs and archives raw signed transaction receipts.

## Security and BitVM dependency

The needed future interface is an on-chain commitment to the selected
subset indices, a BitVM verifier that imports those *specific* indices
and proves the intended payout/state predicate over the exact Bitcoin
transaction, plus a Bitcoin-enforceable refutation or settlement route
for the **specific vault UTXO**. The present Python referee supplies
raw-data validation, with a trusted-block-hash requirement.

A HORS-style preimage commitment (described in Binohash section 6.4)
is a candidate for signing the selected indices inside Script. This
separate milestone must be fitted under the legacy opcode budget.

The current 59-byte signature-size target is deliberately low cost.
Neither production collision resistance, an enforceable BitVM
covenant, a general ZK verifier, nor permissionless dispute liveness
has been established. Nonstandard bare-script transactions require
miner-direct inclusion under current default relay policy.

References:

- Robin Linus, Binohash: https://robinlinus.com/binohash.pdf
- BIP144: https://bips.dev/144/
- Keyless CHECKSIG reference:
  https://github.com/patrickdugan/Spiral/blob/main/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md


## Trusted policy boundary

The referee CLI **requires** an external policy file with schema
jb-fad04-policy-v1. Its fields include the trusted vault funding txid,
pool vout, locking-script SHA256, expected recipient script, minimum
payout and expected ten nonce indices. The verifier compares these
separate inputs to bytes recovered from the actual transaction.

The verifier refuses an absent policy, a changed claimed payout, a
substituted vault outpoint, or different claimed indices. These checks
address the self-attestation hazard of deriving an authorization rule
from the transaction supplied by the claimant.

GitHub CI creates a clearly labeled policy fixture from its regtest
wallet's chosen funding and payout values to exercise the interface.
That CI-generated policy is not an independent authorization source.
A real BitVM deployment must register and authenticate the expected
policy through a mechanism that the adversary cannot edit. Whether
Bitcoin consensus enforces that policy through a fraud-proof/DLC
settlement path is still unproved.


## Native Bitcoin Core 30.2 results (2026-11-22)

[CI run 44996853844](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/44996853844)
passed all twelve offline tests, native direct-block confirmation, all
three native invalid-spend controls, and the independently implemented
public-key referee with a separately supplied CI registration policy.

The 2,150-byte locking script uses 120 non-push opcodes (within
the consensus 201-opcode bound) and 16 sigops. Its 372-byte
scriptSig produces a 499-byte legacy spend transaction, 1,996 WU.

The funded native experiment required 38 ACP|NONE, 555 NONE, 56
ACP|ALL and 441 ALL pinning attempts. The two nonce rounds found
solutions after 2 and 61 subset trials. The extracted indices are:

    round 1 = (0, 1, 2, 3, 5)
    round 2 = (0, 2, 3, 4, 9)

The confirmed spend TXID is
fc30e42869e54e873b77b43e33eaa59eebfd833eb7cba8d0d1a3efc8fdf14faf.
The native block hash is
750def605ca896bd71ad9e31941cf28cccf75911f44b5295e97892237e8824ff.

Bitcoin Core rejected a changed payout, a substituted round-2 selector
and an added output; each rejection preserved the block tip. The
signed-transaction referee then independently verified six ECDSA
sighashes, the exact 2048th indexed pool output, its funding txid,
the registered recipient, all ten selected indices, the header
proof-of-work, and the txid Merkle inclusion proof.

Artifact jb-fad04-native-and-referee (ID 14744505927) stores full
signed funding/spending bytes, the header, all Core decisions,
the exact JSON policy fixture and the final verifier verdict.
Archive SHA256:
9d431f94905d40eca8a96d4470fe07067f83324f75eda902d411876b7f4366d9.

The registered policy used in CI is explicitly a research fixture
generated by the same harness. A separate trusted registration and
actual BitVM covenant/fraud-proof settlement path remain unsolved.
