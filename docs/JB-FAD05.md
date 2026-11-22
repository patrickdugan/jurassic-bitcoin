# JB-FAD05: HORS subset attestation and the enforcement boundary of keyless BitVM settlement

Stacked on [JB-FAD04](JB-FAD04.md) (branch `research/jb-fad04-two-round`).
Branch: `research/jb-fad05-bitvm-enforcement`. Consensus oracle: unmodified
Bitcoin Core 30.2 on isolated regtest (CI); local iteration used Core 31.1.

## Result

The HORS subset attestation works as a consensus-enforced primitive. The
two-round Binohash vault now requires the spender to reveal the HASH160
preimage of the commitment for **exactly** the pool index whose signature
each `OP_ROLL` selected, in canonical order, in both rounds. Core rejects
corrupted, duplicated, cross-round, reordered and out-of-range openings.

That primitive does not carry the vault to Keyless-CHECKSIG security. Five
executable counterexamples, each confirmed or rejected by native Core
block validation, locate the gap:

| # | Counterexample | Native outcome | Guarantee it removes |
|---|---|---|---|
| CE1 | The holder of the HORS key (a setup key that must exist for the attestation to authorize anything) pays a non-policy recipient | Core **accepts**; referee rejects | Setup-key compromise cannot redirect funds |
| CE2 | After a reorg, a third party re-uses the ten preimages revealed in the honest settlement's scriptSig, grinds the unenforceable sighash flag byte, and pays itself | Core **accepts**; 2 pinned candidates in CI, 1 to 6 across local runs | The attested index vector binds the payout |
| CE3 | Production-shaped split (one round per UTXO): the round-1 UTXO is spent alone | Core **accepts**; round-2 UTXO stays unspent | Any cross-input dependency between rounds |
| CE4 | A third party prepends `OP_NOP` or a data push to the scriptSig, or re-encodes a selector non-minimally | Core **accepts** each twin; txid changes | Stable settlement txid for presigned children |
| CE5 | One unauthorized attestation (no second one): slash attempt with five real preimages plus a guess | Core **rejects** the slash | Consensus-enforced penalty for a single fraud |

The bond's equivocation branch *is* consensus-enforced: when the same HORS
key attests two different settlements, the union of revealed preimages has
at least six members in a round, and anyone can spend the bond. The
operator's release branch is held back by `OP_CHECKSEQUENCEVERIFY`.

## WP-A: on-chain subset attestation

### Round layout

Each round places a 10-entry commitment region directly below the 10 pool
signatures. Commitment `k` is `HASH160(pre[r][k])`, with
`pre[r][k] = SHA256("JB-FAD05/HORS-SUBSET-ATTESTATION/v1" || seed || r || k)[:20]`.

Unlocking group per round, bottom to top:

    nonce_sig  pre_0 .. pre_4  d_0 .. d_4

Step `i` of a round (remaining = 10 − i):

    <sel> PICK DUP <prev|0> PICK? <remaining> WITHIN VERIFY  ; d_{i-1} <= d_i < remaining
    ROLL TOALTSTACK                                          ; signature -> FindAndDelete set
    <sel-1> PICK <remaining-1> ADD ROLL                      ; same d, commitment region
    <k> ROLL HASH160 EQUALVERIFY                             ; consume pre_i, open it

One selector number drives both rolls. The two regions shrink identically,
so the commitment rolled at step `i` always belongs to the pool index whose
signature was rolled at step `i`, whatever `d` the spender supplies. The
`WITHIN` bound enforces nondecreasing depths, which is exactly the canonical
strictly-descending index order. The 120 permutations of a subset therefore
have one valid encoding.

Three layout decisions came out of measurement:

- **No end-of-round drops.** Dropping the unselected signatures, unselected
  commitments and selectors costs ⌈(2n − t)/2⌉ opcodes per round. That was
  affordable at 10-choose-5 (196 of 201) but scales with `n` and breaks at
  production sizes. Legacy consensus checks only the final top element;
  CLEANSTACK is relay policy. Rounds now leave their leftovers, and round 2
  addresses past round 1's 15 leftover items with a constant offset.
- **Nonce to altstack at the head.** The nonce signature moves to the
  altstack after its size gate. A fresh `OP_0` dummy is pushed before
  `CHECKMULTISIG`, and the puzzle key is listed last, so the nonce
  signature comes off the altstack on top.
- **Preimages consumed with `ROLL`.** Each preimage is rolled out of the
  stack rather than copied, so it leaves nothing behind.

`CHECKMULTISIG` also charges its key count to Core's opcode counter. The
budget figure below includes that charge.

### Measurements (fixture script, all runs)

| Quantity | Value |
|---|---|
| Locking script | 2,695 bytes, bare legacy |
| Non-push opcodes | 170 |
| Core opcode count incl. CHECKMULTISIG key charge | 182 / 201 |
| Accurate sigops / legacy block sigop count | 16 / 44 |
| HORS commitments / revealed preimages | 20 / 10 |
| Raw subset space | 2 × log2(252) = 15.95 bits |

The settlement transaction is 719 bytes (2,876 WU) with a 580-byte
scriptSig in every run. Grinding-attempt counts vary by funding txid; the
CI receipt records them.

## WP-B: canonical statement and referee

`jb_fad05_verify.py` reconstructs this versioned statement from raw bytes:

    version = 0x01
    vault_outpoint, funding_script_hash, transaction_bytes, block_header_anchor,
    binohash_round_1_indices, binohash_round_2_indices, verified_program_id,
    previous_state_root, successor_state_root, recipient_script,
    payout_amount, fee, proof_commitment

Each field is CompactSize-length-prefixed. The statement hash is
`TaggedHash("JB-FAD05/BITVM-SETTLEMENT/v1", serialization)` (BIP340 style).
`proof_commitment` is a tagged hash of the HORS root and the ten revealed
preimages in canonical order.

The settlement has one output. That is forced, because the pool's
SIGHASH_SINGLE-bug signatures need input index ≥ output count. The
successor state root therefore lives inside that single payout, as
`P2WSH(<successor_root> <salt> 2DROP <recipient body>)`. Pinning stage 3
grinds the 4-byte salt, so payout amount and fee are exact policy values.
The toy program is
`successor = TaggedHash("JB-FAD05/state", prev || vault_outpoint || recipient || payout || fee)`,
and its program id is the SHA-256 of that spec string.

The referee's inputs are separated by trust class:

- **policy (authenticated):** vault txid and vout, vault-script hash, HORS
  root, recipient, payout, fee, program id, previous state root.
- **witness (adversary-supplied):** raw funding and settlement bytes, the
  payout witness-script opening, block header, Merkle branch.
- **anchor (trusted):** a block hash from a validated header chain.

The referee re-parses the vault script from the funding output and rebuilds
it with its own layout code before trusting any field. Every check in its
output carries an `enforced_by` label: `bitcoin-consensus`, `referee-only`,
`external-policy` or `trusted-anchor`. It rejects non-canonical scriptSig
encodings, so the CE4 twins fail the referee even though Core accepts them.

## WP-C: settlement protocol and security game

### Transactions and branches

| Transaction | Script branch that enforces it |
|---|---|
| Funding F | creates vault V (FAD05 script), twin V′ (same script, for the substitution test), bond B₁/B₂ (one per round), split UTXOs S₁/S₂ |
| Settlement T | V's script: 4 pins + 2 HORS-attested Binohash rounds |
| Equivocation slash | B_r `IF` branch: six distinct preimages of round r's table, canonical order. No signature, so any challenger can spend it |
| Operator release | B_r `ELSE` branch: `<12> CSV DROP <operator> CHECKSIG` |

### Game

Setup publishes all pool, pin and puzzle keys; they are public scalars by
construction. Setup also creates the HORS key K and the bond, and registers
policy P.

The adversary receives every setup secret including K, controls its own
machines, can include its own transactions miner-direct, sees honest
transactions before confirmation, and can trigger reorgs.

The adversary wins the **safety game** if a Core-valid chain contains a
spend of V whose statement violates P. It wins the **penalty game** if it
also keeps its bond.

- **Safety game: adversary wins** (CE1). K is the only spend authorization
  the vault script checks, and the script relates the attested indices to
  nothing but the Binohash puzzle.
- **Penalty game: adversary wins** whenever it attests only once (CE5). The
  equivocation branch catches double attestation, not a false statement. A
  slash for a single false attestation would need a disprove script that
  links the attested index vector to the statement fields. That means
  evaluating legacy `SignatureHash` (FindAndDelete over a ~2.7 KB scriptCode,
  then SHA256d) and the fixed-R ECDSA size predicate for six signatures
  inside Script. No such BitVM circuit is built here.
- **Third-party adversary without K:** wins after any reorg or as the miner
  of the honest settlement (CE2). The revealed preimages are in the
  unsigned scriptSig, and legacy Script cannot inspect a signature's last
  byte. Each round then gets 240 independent ALL-like digests per candidate
  transaction.

The tested construction **cannot make an off-chain verifier's acceptance an
on-chain authorization condition**. The only authorization Bitcoin checks
is possession of the HORS preimages.

### Failed designs recorded as results

- **Baking the expected index vector into the vault script.** Every legacy
  sighash mode commits the spending input's own prevout, so the constant
  would have to be a fixed point of SHA256d. See `docs/grants/covenant_limits.md`.
- **Enforcing the sighash flag in Script.** Legacy Script sees only
  `OP_SIZE`; `OP_RIGHT`, `OP_CAT` and `OP_SUBSTR` are disabled. CE2 and the
  flag matrix are the measured consequence.
- **Splitting rounds across inputs to reach production sizes.** No
  cross-input dependency exists (CE3).
- **Malleating the CHECKMULTISIG dummy.** This was planned as a malleation
  twin. Core rejected it under NULLDUMMY, which segwit deployment made a
  block rule; the offline model was corrected to match.

## WP-D: native adversarial validation

Every rejection below was submitted through `generateblock` (miner-direct).
The harness asserts that the best-block hash is unchanged and the watched
coins are unspent afterwards. Every accepted alternative history was rolled
back with `invalidateblock` and checked the same way.

| Attack | Consensus | Failing check / note | Relay policy |
|---|---|---|---|
| payout +1 sat; fee +1,000 sats; altered successor root; altered recipient | reject | ACP\|ALL pin `CHECKSIGVERIFY` | nonstandard inputs |
| extra output | reject | pin `CHECKSIGVERIFY` | `scriptpubkey` |
| substituted vault outpoint (twin with identical script) | reject | ACP\|NONE pin covers own prevout | nonstandard inputs |
| corrupted / duplicated / cross-round preimage | reject | `EQUALVERIFY` | nonstandard inputs |
| reordered or ascending encoding of the same subset; selector reaching the commitment region | reject | `WITHIN … VERIFY` | nonstandard inputs |
| substituted round-2 subset with its real preimages | reject | `CHECKMULTISIG` false | nonstandard inputs |
| high-S twin of the nonce signature | reject | 59-byte size gate | nonstandard inputs |
| 256 sighash bytes on the round-2 nonce signature | accept iff signature ≤ 59 bytes | Core ignores the flag byte | nonstandard inputs |
| CE4 twins (OP_NOP, data push, non-minimal selector) | **accept** | txid changes | `scriptsig-not-pushonly` / nonstandard |
| CE2 front-run after reorg | **accept** | the honest settlement then conflicts (`missingorspent`) | nonstandard inputs |
| CE1 unauthorized operator payout | **accept** | referee: recipient mismatch | nonstandard inputs |
| equivocation slash (union of the two attestations' round-1 indices, at least 6) | accept | — | nonstandard inputs |
| CE5 single attestation + guess | reject | `EQUALVERIFY` | — |
| operator release at bond age 2 | reject | `bad-txns-nonfinal` (BIP68) | — |
| challenger censored 12 blocks, operator release, late slash | release accepted, slash reject | `missingorspent` | nonstandard inputs |
| CE3 split round-1 spend | **accept** | round-2 UTXO unspent | nonstandard inputs |

Relay policy rejects every FAD05 spend: bare-script inputs are nonstandard,
and the funding transaction's bare outputs fail `scriptpubkey`. Settlement,
slash and release all depend on miner-direct inclusion. Mempool replacement
does not apply; replacement here means a competing block.

## WP-E: security analysis

The cost model is in `scripts/jb_fad05_params.py`. Script sizes come from
calling the real `round_script` with placeholder 73-byte signature pushes.
The test suite checks that the model reproduces the fixture script's op
count exactly, and its byte count once the placeholder sizes are replaced
by the real ones.

`w` is the puzzle difficulty per round in bits, and `F` is the number of
sighash bytes an attacker may try.

| Parameters | Fits one bare script? | Honest nonce work | Front-run, F = 240 (consensus) | Front-run, F = 1 (referee only) |
|---|---|---|---|---|
| 10C5 × 2, w = 8 (this fixture) | yes, 2,695 B / 182 ops | 2^9 | 2^0.2 candidates (measured 1 to 6) | 2^16 candidates |
| 48C5 × 2 (largest single-script HORS shape) | yes, 9,896 B / 182 ops | 2^21.7 | 2^25.6 | 2^41.4 |
| 96C11, one round per input (largest split shape) | per input: 9,933 B / 188 ops | — | cross-input binding absent (CE3) | — |
| 120C8, one round with HORS | **no**: 11,996 B | — | — | — |
| 120C8, one round without HORS | yes: 9,350 B / 95 ops | 2^40.6 for two rounds | 2^63.4 | 2^79.2 |
| 120C8, two rounds without HORS | **no**: 18,558 B | — | — | — |

Findings:

- Binohash's 120-choose-8 parameters cannot carry a HORS table inside the
  10,000-byte legacy limit. That limit is binding because FindAndDelete
  exists only in legacy sighash: P2SH redeem scripts are capped at 520
  bytes, and the BIP143 and BIP341 sighashes omit FindAndDelete.
- The largest two-round HORS-attested shape in one script is about 41 bits
  of raw subset space (48-choose-5 per round).
- The flag byte costs the attacker nothing it cannot buy back: each round
  loses log2(240) ≈ 7.9 bits against a front-runner.
- The 15.95-bit toy space is **not** a security level, and these figures
  are not production estimates. They are the work model applied to measured
  layouts.

## Comparison with the proposed Keyless CHECKSIG soft fork

| Property | JB-FAD05 (existing consensus) | Keyless CHECKSIG (BIP341 TXCOMMIT draft) |
|---|---|---|
| Setup-key compromise | Unauthorized payout possible (CE1, Core-accepted) | No key exists; payout requires the script's verifier to accept a statement whose digest equals the actual BIP341 sighash |
| Transaction binding | Work-bound index vector; flag byte and statement fields externally checked; 2^0.2 front-run at toy size | Consensus compares a 32-byte SIGHASH_DEFAULT digest |
| Proof validity | No Script branch verifies the program; referee-only | The tapscript that contains the verifier |
| Vault authorization | Operator bypasses the referee | Not without satisfying the script |
| Challenger availability | Needed for any penalty; equivocation only; CSV window (scenario F) | Not needed for payout safety |
| Miner cooperation | All spends nonstandard, so miner-direct; miners see preimages (CE2) and can redirect the unsigned slash | Relayable tapscript after activation |
| Cryptographic work | Honest grinding 2^9 (toy) to 2^40.6 (120C8); adversary 2^0.2 to 2^63.4 | Hashing only |
| Deployment | Works today (Core 30.2 regtest) | Soft fork activation required |

## Enforcement classification

**Enforced by Bitcoin consensus**

- The settlement consumes the exact vault outpoint. Substituting a twin
  with an identical script is rejected by the ACP|NONE pin.
- Binohash puzzle validity: four pins and two nonce signatures meet the
  59-byte size gate over spender-chosen sighash bytes.
- HORS openings: for the selected index in each step of each round, with
  canonical order, no duplicates and no cross-round substitution.
- The equivocation slash (six distinct preimages of one round) and the
  operator release's CSV delay.

**Enforced through a BitVM challenge protocol**

- Nothing in this construction. Payout, fee, recipient, successor state and
  canonical flag bytes are referee-only. A BitVM disprove path for them
  would need an on-chain circuit for legacy SignatureHash and the fixed-R
  ECDSA size predicate; it is not built.

**Dependent on trusted setup or authenticated external policy**

- The HORS key holder's honesty: it is the vault's only spend authorization.
- The registered policy (recipient, payout, fee, program id, previous state
  root, HORS root, vault outpoint). CI uses a labeled fixture.
- The trusted block-hash anchor used by the referee.
- Pool, pin and puzzle keys need no trust; they are public.

**Dependent on miner inclusion or challenger availability**

- Every FAD05 transaction needs miner-direct inclusion. Settlement spends
  fail Core's CONST_SCRIPTCODE mempool policy even with `-acceptnonstdtxn`
  (confirmed on testnet4).
- A challenger must publish the slash within the CSV window. Censorship
  hands the bond back to the operator (scenario F).
- The miner of the honest settlement, or anyone after a reorg, can
  front-run it at toy parameters (CE2).
- The slash carries no signature, so its recipient is whoever gets it mined.

## Reproduction

    python -m pip install "cryptography>=44,<47"
    python -m unittest discover -s tests -p test_jb_fad05.py -v
    cd scripts && python jb_fad05_params.py --output /tmp/params.json

Against an isolated regtest node (RPC via `BITCOIND_RPC_URL`, `_USER`, `_PASS`):

    cd scripts
    python jb_fad05_native.py --output /tmp/jb-fad05/native.json
    python jb_fad05_ci_policy.py --native-receipt /tmp/jb-fad05/native.json --output /tmp/jb-fad05/policy.json
    python jb_fad05_verify.py --native-receipt /tmp/jb-fad05/native.json \
      --policy /tmp/jb-fad05/policy.json --trusted-blockhash <block> \
      --which honest --expect accept --output /tmp/jb-fad05/referee.json

`.github/workflows/jb-fad05.yml` runs both lanes on SHA256-pinned Core 30.2
and archives every receipt with a `SHA256SUMS` manifest.

## Native evidence (Bitcoin Core 30.2, 2026-11-22)

[CI run 45012434031](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/45012434031)
on commit `c99aa78` passed both lanes. The offline lane ran 19 FAD05 tests,
the unchanged FAD01–FAD04 suites, and the budget frontier. The native lane
ran scenarios A–G on SHA256-pinned Core 30.2, then the referee, the budget
model with measured attempts, and the SHA256 manifest. Run
[45012346895](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/45012346895)
on `349027c` also passed both lanes.

Job logs and artifacts of this public repository need authentication to
read, so the native lane publishes its verdicts as check-run notice
annotations. The values below are from those notices:

| Scenario | Core 30.2 result |
|---|---|
| Resources | `/Satoshi:30.2.0/`, script 2,695 B, ops 182/201, settlement 719 B / 2,876 WU, scriptSig 580 B |
| Honest settlement | txid `def45c21c0d18299e5dfb3462d5583ad96db86f8b7f880f4cd9c2eaf36d3ce3f`, block `23630870e63cc93329307f43a9c43ac4b98cfe1b0de764d6ba415f893b355725`, round 1 = (0,5,6,7,9), round 2 = (0,2,4,6,9); pins 2/19/56/31 attempts, rounds 123/78 subset trials |
| A | 14 of 14 mutations rejected, tip preserved each time |
| B | flags 0x01 and 0xfc accepted (signature ≤ 59 bytes); 254 of 256 rejected |
| C | all three malleated twins accepted with new txids |
| D | front-run accepted: txid `e612f1bc24977b03034c6885e8f02c5634a5379364a0eca91cfc494952a2e8e3`, block `15b347d73b7fc866f72d5243b08a7cb86d6ea2a713f4084b42e061671839645d`, nonce flags 0x1f / 0xa8, 2 pinned candidates |
| E | unauthorized payout accepted: txid `e0b0693f1074a82ef23f928f3125f516f7c33bd2a8b919c7118e61d409358eee`; index unions 8 and 8; equivocation slash accepted; single-attestation slash rejected |
| F | early release rejected; release confirmed in block `057a38cacf4dbcaf6bb5d813a5682374aad91f7d238186b0a2b9272c8a7adedd` after 12 unchallenged blocks; late slash rejected |
| G | round-1 split UTXO spent alone in block `7cdc603bfa325934c66e6894dc5a968d0c4ebc0e0892674f509166f993abbedb`; round-2 UTXO unspent |
| Referee | honest valid, statement hash `f902df21519b42ef59aebd0986d6b32696b7454c4def3a8fdb201a7f4a053521`; front-run rejected (noncanonical round-1 nonce flag); unauthorized rejected (recipient) |

SHA256 prefixes from the run's manifest: `native.json` ecf2912c3d631aa2,
`ci-fixture-policy.json` 54863085318d0a98, `referee-honest.json`
1d3f2a4235921736, `referee-front_run.json` 5943261259b652e9,
`referee-unauthorized.json` 4d633b877ccc4b90, `params.json`
561f847b758b1a4d. The full receipts are in artifact
`jb-fad05-native-and-referee`.

The CI policy is a research fixture generated from public constants and is
labelled as such. It is not an independent registration.

## Second consensus engine: bitcoin-rs

`scripts/jb_fad05_bitcoin_rs.py` runs the full A–G campaign against two
isolated regtest nodes with no P2P link between them:

- **Bitcoin Core** acts as wallet, miner and reference.
- **bitcoin-rs** (patrickdugan/bitcoin-rs `dev` at `dd6c2040`, native
  validation engine) is the second engine.

What each engine receives:

- Core's first 450 blocks are replayed into bitcoin-rs.
- Every block Core accepts is submitted to bitcoin-rs, and the two tips must
  match.
- Every `invalidateblock` is applied to both nodes.
- Every transaction Core refuses is wrapped in **one hand-built regtest
  block**: zero-value coinbase, BIP34 height, real proof-of-work. That same
  block goes to both engines, and both must refuse it with the same
  normalised reason (the failing opcode, or the `bad-txns-*` code).
- A hand-built block carrying the valid honest settlement is the positive
  control. Both engines must accept it, which shows the builder itself
  produces valid blocks.

Two changes keep the comparison meaningful:

- The campaign starts at height 450. bitcoin-rs activates regtest CSV at
  height 432 and Core at height 1, so the engines legitimately differ below
  432.
- The honest settlement is re-mined instead of using `reconsiderblock`,
  which bitcoin-rs does not implement.

Local result in WSL, Core 31.1 + bitcoin-rs `dd6c2040`
(`docs/JB-FAD05-two-engine-local.json`):

| Quantity | Value |
|---|---|
| Comparisons | 312 (29 Core-accepted blocks, 268 hand-built blocks with refused transactions, 14 invalidations, 1 positive control) |
| Disagreements | 0 |
| Rejection-reason class mismatches | 0 |
| Positive control | accepted by both engines |
| Final tips | equal |

The refusal classes seen are VERIFY, CHECKSIGVERIFY, EQUALVERIFY,
EVAL_FALSE, `bad-txns-inputs-missingorspent` and `bad-txns-nonfinal`.
bitcoin-rs therefore enforces every consensus property this report labels
`bitcoin-consensus`:

- the four Binohash pin and two nonce puzzles;
- the HORS openings;
- the canonical encoding;
- the bond equivocation slash and the CSV delay.

It also accepts every counterexample transaction that Core accepts (CE1–CE4).

One local run in four timed out on an RPC call at the 120-second client
limit. The launcher's clients now wait up to 900 s and record the slowest
call (0.13 s in the clean run).

CI job `bitcoin-rs-two-engine` builds bitcoin-rs
`dd6c2040606cc5069923211e5371decfd43cdb9d` and repeats the run against
Core 30.2. In
[run 45015858932](https://github.com/patrickdugan/jurassic-bitcoin/actions/runs/45015858932)
(commit `ebaa335`) it recorded:

- 307 comparisons: 24 Core-accepted blocks, 273 hand-built blocks with
  refused transactions, 9 invalidations, 1 positive control;
- 0 disagreements and 0 reason-class mismatches;
- positive control accepted by both engines, and final tips equal.

The receipt `two-engine.json` has sha256 `7fa8a89c33f1615f48a7e85572936de50deb163ced900bee87dc99949c49c273`.
The same run's native lane also passed A–G and the referee on Core 30.2.

## Testnet4 staging

`scripts/jb_fad05_testnet4.py` staged the vault on Bitcoin testnet4 on
2026-11-22 from wallet `m16`. The node was a local Core 31.1 started with
`-acceptnonstdtxn=1`, which test networks allow. The receipt is
`docs/JB-FAD05-testnet4-staging.json`.

| Item | Value |
|---|---|
| Funding txid | `e7708ccf9c77cf8a1aeedd58eb11ea526fb4ba52c0f7f90ff64534a2280b26c1` |
| Funding shape | 4 × 546-sat P2SH(OP_TRUE) aux coins + 1,000-sat bare FAD05 vault (vout 4) + change; 2,991 vB; 2,993 sats fee (1 sat/vB) |
| Settlement txid | `a53e1858b92a57671e77da22a1afdaf00a0fb8c09b0de700f90a58f837e44450`, round 1 = (0,1,4,5,6), round 2 = (1,2,6,8,9), pays P2WSH(successor ‖ salt ‖ wallet key) |
| Local mempool | funding accepted and announced to 10 peers |
| Settlement in mempool | refused: `mempool-script-verify-flag-failed (Signature is found in scriptCode)` |
| mempool.space testnet4 | funding refused: `scriptpubkey` |

Two relay facts come out of the staging:

- **Funding (outputs):** the public testnet4 nodes require standard outputs,
  and a bare 2,695-byte vault output is not a standard template. The funding
  transaction lives in this node's mempool and in any peer's that runs
  `-acceptnonstdtxn`.
- **Settlement (spend):** Core applies `SCRIPT_VERIFY_CONST_SCRIPTCODE` to
  every mempool spend. It is a policy flag, not a consensus rule, and
  `-acceptnonstdtxn` does not lift it; Core 31.1 also has no option to relax
  mempool script flags. Every Binohash/FindAndDelete spend therefore needs a
  miner who includes it directly, on testnet as much as on mainnet.

The signed settlement bytes are in the receipt. Unless a miner includes the
funding transaction, no testnet4 block will carry this staging.

## Not built

- A BitVM disprove circuit. The only referee is the Python one in this branch.
- A trusted policy-registration channel.
- Any measurement at production parameters beyond the layout and work model in WP-E.
