# Mainnet Forward Walk Strategy

This note captures what can be advanced without `blk*.dat` access and how to resume
the historical walk once the external HDD is attached.

## What We Have Tonight

- Existing extracted corpus:
  - `corpus/era-mainnet/mainnet-h0-tx0000.json`
  - `corpus/era-mainnet-2013-trial/*.json`
- Existing replay bundles:
  - `artifacts/era-mainnet-run/`
  - `artifacts/era-mainnet-2013-trial-run/`
- New offline scanner:
  - `scripts/scan_coinbase_corpus.py`
- Generated report from the 2013 trial slice:
  - `artifacts/history/coinbase_2013_trial_scan.json`
  - `artifacts/history/coinbase_2013_trial_scan.md`

Important constraint:

- `corpus/era-mainnet-2013-trial` is `tx0000`-only for 492 consecutive heights
  (`279000..279491`), so it is a coinbase/miner-behavior slice, not a general
  mempool/transaction slice.

## Interesting Things Already Surfaced

From `artifacts/history/coinbase_2013_trial_scan.md`:

- Strong miner-tag continuity and shifts:
  - `Eligius` first seen at `279000`
  - `/P2SH/` first seen at `279001`
  - `GHash.IO` first seen at `279003`
  - `Guild, Mined` first seen at `279004`
- Extreme payout fanout blocks worth deeper extraction:
  - `279289` with `430` outputs
  - `279217` with `426` outputs
  - `279192` with `421` outputs
- Repeated Eligius payout pattern worth clustering:
  - many blocks with `150..170` outputs and stable `/ssNN/` tags
- Small but real output-type variety inside the slice:
  - `p2pkh`: `7776`
  - `p2pk`: `29`
  - `op_return`: `3`

What this means:

- Even before touching full block data, we already have a measurable miner-behavior
  surface.
- The best immediate historical hooks are payout topology shifts, pool-tag changes,
  and rare output-type appearances inside coinbase transactions.

## What To Use This For

Three practical outputs:

1. Pick windows where historical structure changes sharply.
2. Extract richer per-block transaction slices around those windows.
3. Turn those slices into new seam families or museum specimens.

The coinbase slice is useful as a guide for where the chain changed shape, even if it
does not yet expose non-coinbase consensus edge cases.

## Tomorrow Morning: Block-Backed Walk

### Priority 1: deepen the 2013 trial slice

Goal: move from coinbase-only evidence to actual in-block transaction variety.

Suggested command pattern:

```powershell
$env:BITCOIND_RPC_URL  = "http://127.0.0.1:8332"
$env:BITCOIND_RPC_USER = "jurassic"
$env:BITCOIND_RPC_PASS = "jurassic-pass-local"

cargo run -p jurassic-bitcoin-cli -- extract-era `
  --start-height 279150 `
  --end-height 279320 `
  --limit-per-height 25 `
  --out-corpus corpus/era-mainnet-2013-deep-279150-279320 `
  --force
```

First target windows from the offline scan:

- `279192`
- `279217`
- `279289`
- `279450..279483`

Reason:

- these are the strongest payout-fanout / pool-pattern specimens already observed locally.

### Priority 2: walk known consensus boundaries forward

Use explicit windows, not blind full-history crawling first.

Recommended early sequence:

- `173780..173830`
  - BIP16 enforcement boundary
- `227900..227960`
  - BIP34 buried activation boundary
- `279150..279320`
  - miner payout/topology burst from the current trial corpus
- `363700..363760`
  - BIP66 era boundary
- `388360..388420`
  - BIP65 era boundary
- `419300..419360`
  - CSV / sequence-lock era boundary
- `481800..481860`
  - SegWit activation boundary
- `709610..709670`
  - Taproot activation boundary

For each window:

1. `extract-era` with `--limit-per-height 10` or `25`
2. scan the extracted corpus with `scripts/scan_coinbase_corpus.py`
3. promote interesting tx shapes into fixtures/manifests or fresh seam families

## What Counts As "Interesting"

Prioritize blocks or transactions that show one or more of:

- abrupt output-count jumps
- output-type mixture changes (`p2pk`, `p2sh`, `op_return`, unusual script forms)
- coinbase tag regime changes
- large coinbase-script payload shifts
- nontrivial locktime/version differences
- early examples near activation boundaries where policy shape or spend form changes

Avoid spending time first on:

- long flat stretches with homogeneous `tx0000` coinbase structure
- windows that only confirm already-known behavior without a visible structural pivot

## Best Near-Term Product

The fastest useful artifact is:

- a historical-window shortlist
- one deeper extracted corpus around the strongest 2013 payout fanout blocks
- one new museum/specimen family derived from that deeper slice

That gives a clean progression:

- tonight: find candidate windows offline
- tomorrow: extract richer tx slices from disk-backed blocks
- next: convert the best historical shapes into reusable test surfaces
