# Litecoin Procedural Token Flows

This repo now has a repo-local live suite for procedural-token experiments on
LTCTEST. The point is not just to prove standalone BitVM challenge mechanics.
It is to prove that TradeLayer Litecoin can mint and route procedural tokens
through different DLC and BitVM settlement graphs before we try to mirror the
same ideas back onto Jurassic Bitcoin-era artifacts.

## Flow Graphs

`receipt_rollover_redeem`

- Live entrypoint: `tests/litecoin-bitvm/procedural_receipt_contract_live.js`
- External execution: `tradelayer.js/tests/utxoBitvmReceiptContractLive.js`
- Token behavior:
  - issue a procedural receipt property
  - grant receipt units against a funded DLC contract
  - roll holder state from one contract reference to the next
  - redeem a holder position after the contract closes
- Settlement modes exercised:
  - `rollover`
  - `redeem`
- Why it matters:
  - proves that procedural issuance and redemption gates are tied to DLC state,
    not just free-floating managed tokens

`short_epoch_router`

- Live entrypoint: `tests/litecoin-bitvm/procedural_short_epoch_router_live.js`
- External execution: `tradelayer.js/tests/utxoBitvmShortEpochRouterLive.js`
- Token behavior:
  - issue a procedural short-side collateral property
  - grant units into a funded short epoch
  - route realized loss through a deterministic split:
    - bucket portion via `pnl_sweep`
    - excess portion via one or more `bitvm_cache` escrows
    - final release via `bitvm_payout`
- Settlement modes exercised:
  - `pnl_sweep`
  - `bitvm_cache`
  - `bitvm_payout`
- Why it matters:
  - proves that BitVM pathing can drive tokenized payout routing, not just
    oracle-side bookkeeping

`short_epoch_router_dispute`

- Live entrypoint: `tests/litecoin-bitvm/procedural_router_dispute_live.js`
- Token behavior:
  - issue a procedural short-side collateral property
  - bind four relayType `2` preludes onto the same contract ref before settlement:
    - two transcript-alias attestations with tags `aa` and `aaaa`
    - two identifier-namespace attestations with blob refs ending in `namespace-zero` and `namespace-32`
  - route bucket loss with `pnl_sweep`
  - open two excess `bitvm_cache` branches
  - send one branch through `bitvm_challenge -> bitvm_resolve(reject) -> bitvm_payout`
  - send the other branch through `bitvm_challenge -> bitvm_resolve(uphold)` and keep payout blocked
- Settlement modes exercised:
  - `pnl_sweep`
  - `bitvm_cache`
  - `bitvm_challenge`
  - `bitvm_resolve`
  - `bitvm_payout`
- Relay preludes exercised:
  - `transcript_alias_relay`
  - `identifier_namespace_bifurcation`
- Why it matters:
  - proves the router and tx30 guardrail are no longer just adjacent live suites
  - proves proposals `1`, `2`, and `3` can sit on one live challengeable procedural-token contract instead of living as separate harnesses
  - proves one procedural-token flow graph can branch into both released and refunded BitVM outcomes inside one LTCTEST run

`transcript_alias_relay`

- Live entrypoint: `tests/litecoin-bitvm/procedural_transcript_alias_live.js`
- Token behavior:
  - issue a procedural token and bind it to a DLC template and contract
  - publish two distinct signed tx30 relay transcripts against the same
    `stateHash` and `payloadHash`
- Settlement modes exercised:
  - none directly; this is a relay-surface proof
- Why it matters:
  - proves proposal `1`: multiple signed relay transcripts can attest the same
    underlying procedural-token state without changing the committed digest

`identifier_namespace_bifurcation`

- Live entrypoint: `tests/litecoin-bitvm/procedural_identifier_bifurcation_live.js`
- Token behavior:
  - issue a procedural token and bind it to a DLC template and contract
  - replay the same signed relay bundle under two distinct external namespace
    labels via `blobRef`
- Settlement modes exercised:
  - none directly; this is a namespace proof
- Why it matters:
  - proves proposal `2`: external identifiers can rotate while the signed core
    digest remains fixed

`oracle_sidecar_mesh`

- Live entrypoint: `tests/litecoin-bitvm/procedural_oracle_sidecar_mesh_live.js`
- Token behavior:
  - issue a procedural token and bind it to an oracle-sidecar style contract ref
  - publish two transcript-alias relay bundles for the same semantic sidecar state
  - replay the same semantic state under two distinct namespace-style public labels
  - attach ordinary payout-shaped carrier hints such as `spray202_oracle_cover` and `exact100_oracle_cover`
- Settlement modes exercised:
  - none directly; this is an application-mesh proof
- Why it matters:
  - prototypes how proposal `1`, `2`, and `3` can be used by DLC/oracle publication
    systems without assuming those systems are BitVM-first

`watchtower_beacon_mesh`

- Live entrypoint: `tests/litecoin-bitvm/procedural_watchtower_beacon_mesh_live.js`
- Token behavior:
  - issue a procedural token and bind it to a watchtower beacon contract ref
  - publish compact and full alert-proof transcripts against one committed state
  - rotate public alert handles while keeping the semantic proof core fixed
  - attach ordinary wallet-traffic carrier hints such as `rebalance_cover` and `sweep_cover`
- Settlement modes exercised:
  - none directly; this is an application-mesh proof
- Why it matters:
  - prototypes watcher and fraud-monitor systems that want relay flexibility,
    namespace rotation, and non-exotic publication shapes

`statechain_handoff_mesh`

- Live entrypoint: `tests/litecoin-bitvm/procedural_statechain_handoff_mesh_live.js`
- Token behavior:
  - issue a procedural token and bind it to a statechain-style handoff contract ref
  - publish acknowledgement and finalize transcripts for the same handoff state
  - rotate checkpoint handles while keeping the committed handoff core fixed
  - attach ordinary checkpoint publication hints such as wallet consolidation and settlement-batch cover
- Settlement modes exercised:
  - none directly; this is an application-mesh proof
- Why it matters:
  - prototypes off-chain transfer and checkpoint systems that want alternate
    handoff transcripts, rotating public handles, and ordinary-topology publication

## Applications Beyond BitVM

The point of these meshes is to stop treating the three quirks as
BitVM-exclusive.

- `oracle_sidecar_mesh` shows how the same motifs can describe DLC/oracle
  publication.
- `watchtower_beacon_mesh` shows how the same motifs can describe watcher and
  fraud-monitor alert systems.
- `statechain_handoff_mesh` shows how the same motifs can describe checkpoint
  and off-chain ownership transfer surfaces.

These are still repo-local LTCTEST prototypes, not final protocol claims. The
goal is to prove that the three quirks are portable design patterns before we
argue for broader protocol relevance.

## Relation To The Existing tx30 Suite

The existing live suite in `scripts/litecoin-bitvm/run_live_suite.ps1` still
matters. It proves the dispute side:

- `bitvm_cache`
- `bitvm_challenge`
- `bitvm_resolve`

The procedural suite now covers tokenized settlement, relay surfaces, and one
fused challengeable router. Together they give us the pieces we need for future
TradeLayer procedural tokens:

1. issue and route token balances through a flow graph
2. attach transcript and namespace relay surfaces to that same contract reference
3. interrupt or finalize those flows through BitVM dispute edges
4. prove a live fused graph where one route resolves to payout and another resolves to refund

The repo-level crosswalk for which surfaces are relay-only, settlement-live,
dispute-live, or still replay-only fossils is now in
`artifacts/grants/policy_envelope_mapping.md`.

## Run

If LTCTEST RPC is not already up:

```powershell
powershell -File .\scripts\litecoin-bitvm\start_testnet_node.ps1
```

Run both procedural flows:

```powershell
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1
```

By default the procedural runner creates fresh wallet addresses for admin,
oracle admin, and participants, then provisions wallet-visible UTXOs for the
sender roles. Pass `-AdminAddress <tltc...>` to reuse an existing admin address.

Run only one flow:

```powershell
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario receipt
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario router
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario transcript
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario identifier
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario hybrid
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario oracle
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario watchtower
powershell -File .\scripts\litecoin-bitvm\run_procedural_suite.ps1 -Scenario statechain
```

Artifacts are written under `artifacts/litecoin-bitvm/procedural/<yyyy-MM-dd>/`.

The procedural preflight provisions wallet-visible UTXOs when a fresh participant
address needs funds. It intentionally does not call `generatetoaddress` on
LTCTEST; confirmations must come from the public testnet if a later harness
requires confirmed-only inputs.

The runner provisions dedicated per-run admin and oracle addresses from
`wallet.dat`, funds them, confirms them, and then executes the flow. That keeps
procedural funding inventory isolated from the older fixed-address tx30 suite.
