# Litecoin Testnet Ossification DNA Walk

This note captures the local Litecoin history pass requested for manipulable
ossification extrapolations. The current node only exposes LTCTEST history, so
these are testnet DNA samples and controls, not mainnet claims.

Generated artifacts:

- `artifacts/history/litecoin_testnet_ossification_dna.md`
- `artifacts/history/litecoin_testnet_ossification_dna.json`
- `artifacts/history/litecoin_testnet_tx_family_windows.md`
- `artifacts/history/litecoin_testnet_tx_family_windows.json`

Extracted windows:

| label | heights | records | purpose |
| --- | ---: | ---: | --- |
| `early` | `0..120` | 121 | pre-feature miner/payout baseline |
| `segwit` | `6000..6100` | 101 | buried SegWit activation control |
| `mweb` | `2215520..2215650` | 361 | MWEB activation boundary |
| `taproot` | `2241720..2241850` | 379 | Taproot activation boundary |
| `recent-vbit2` | `4683920..4684007` | 964 | tip-adjacent unknown-versionbit warning control |

## Tooling Delta

The shared transaction parser now understands Litecoin's extended marker/flag
serialization in addition to Bitcoin-style witness serialization. This matters
for MWEB-era transactions with flag `0x08`: the scanner can still parse the
ordinary input/output surface, record the MWEB extension marker, and classify
`OP_8 <32-byte>` outputs as `mweb_witness_v8`.

The scanner also skips extractor metadata JSON files so the same corpus
directories can be fed directly into the family and DNA reports.

## Candidate DNA Threads

### MWEB Extension Boundary

Signal:

- `mweb` window: 66 `mweb_extension_boundary` records
- `taproot` window: 130 `mweb_extension_boundary` records
- `recent-vbit2` window: 77 `mweb_extension_boundary` records
- output classifier sees `mweb_witness_v8` as the ordinary-chain boundary shape

Extrapolation:

MWEB gives the cleanest Litecoin DNA for hidden-state sidecars: consensus state
exists beyond the normal UTXO graph while the ordinary chain still presents
small, boring-looking transactions. This is a useful model for overlay protocols
that want verifiable side state without making every transition obvious in the
base script surface.

Reusable test DNA:

- positive specimens: one-input/one-output `mweb_witness_v8` boundary txs
- controls: ordinary witness/P2SH payments in the same heights
- detector target: distinguish hidden-state boundary markers from generic
  witness-program outputs without overfitting to one txid pattern

### Batch Carrier Camouflage

Signal:

- MWEB activation has two 20-input/200-output P2SH batches at heights `2215570`
  and `2215581`
- Taproot activation has a 20-input/200-output P2SH batch at height `2241790`
- Taproot activation also has a 53-input/2-output P2SH aggregator at height
  `2241788`
- recent vbit2 window has witness-keyhash aggregators up to 35 inputs

Extrapolation:

Large batch payouts and consolidations are useful camouflage for payload-bearing
or state-bearing transactions because they already normalize high fanout,
repeated denominations, and input churn. This gives an historical carrier family
for testing whether an observer can separate ordinary batching from deliberately
placed overlay state.

Reusable test DNA:

- medium fanout carriers: 20-in/200-out P2SH records
- aggregator controls: 25-plus-input consolidation records
- false-positive controls: high-value ordinary P2SH and witness-keyhash batches

### OP_RETURN And Coinbase Sidecars

Signal:

- MWEB window: 182 `op_return_anchor` records
- Taproot window: 204 `op_return_anchor` records
- recent vbit2 window: 615 `op_return_anchor` records
- early window is pure coinbase baseline: 121 coinbase records, mostly P2PKH

Extrapolation:

Explicit data anchors and miner-controlled outputs are still the simplest DNA for
sidecar commitments. They are not stealthy, but they are excellent boundary
controls because the carrier is visible and the parsing assumptions are
well-defined.

Reusable test DNA:

- explicit sidecar cases: OP_RETURN-bearing txs around MWEB and recent windows
- miner convention controls: early coinbase-only baseline
- mixed-output controls: OP_RETURN plus P2PKH/P2SH in the same transaction

### Witness Normalization

Signal:

- MWEB window: 257 `witness_envelope` records and 64 witness-program outputs
- Taproot window: 216 `witness_envelope` records and 56 witness-program outputs
- recent vbit2 window: 843 `witness_envelope` records and 764 witness-program
  outputs
- the narrow SegWit activation window sampled here was coinbase-only, so it is a
  weak direct witness-adoption sample and should be widened if needed

Extrapolation:

Once witness traffic becomes common, it turns from a novelty into a camouflage
layer. That is the ossification pattern worth carrying forward: branchiness,
commitments, and future script detail can move into structures that observers
eventually treat as normal wallet traffic.

Reusable test DNA:

- pre-normalization controls: early and narrow SegWit windows
- transition controls: MWEB/Taproot windows with P2SH plus witness output mixes
- normalized controls: recent witness-keyhash heavy window

### Versionbit Pressure Control

Signal:

- local RPC previously reported an active unknown versionbit warning
- recent extracted blocks are all version `536870912`, so the tx corpus should be
  paired with RPC chain-state monitoring rather than treated as sufficient by
  itself
- recent transaction traffic is still rich enough for false-positive controls:
  OP_RETURN, witness-keyhash, locktime, MWEB boundary, and aggregators all appear

Extrapolation:

Consensus-signaling churn and spend-level carrier behavior should be separated.
The recent window is useful because the node-level warning can be monitored while
ordinary traffic remains noisy enough to test classifier discipline.

Reusable test DNA:

- block-version and chain-warning monitor as the consensus-signal channel
- recent tx-family scanner output as ordinary-traffic control
- alert rule: do not infer overlay behavior solely from unknown signaling

## Next Mainnet Pass

The same commands should be rerun against Litecoin mainnet once a mainnet
datadir/RPC is available. Highest-value mainnet windows:

- MWEB activation boundary
- SegWit activation boundary with a wider non-coinbase sampling limit
- Taproot activation boundary plus later adoption windows
- current tip-adjacent versionbit/control windows

The testnet pass is already useful for parser and fixture DNA. Mainnet is needed
before making any claims about production adoption patterns.
