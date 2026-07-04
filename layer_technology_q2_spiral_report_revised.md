# Layer Technology - Q2 2026 Spiral Report

Prepared for: Conor / Spiral  
Prepared by: Patrick Dugan  
Period: Q2 2026  
Focus: Jurassic Bitcoin, TLZK / zk observability, UTXORef, WebRTC relay surfaces, OP_RETURN-style commitments, Lightning / TradeLayer integration paths

## Short audit summary

I revised this report against the repos and local artifacts I could actually inspect.

What is concrete in the local tree:

- `jurassic-bitcoin` is a Rust workspace for Bitcoin consensus observability and differential testing. It has a CLI, corpus loader, Core RPC wrapper, Rust shadow executor, mutator, reducer, fixture loader, era replay flow, report generation, and museum/dashboard outputs.
- The Jurassic repo includes replayable fixtures and artifacts for 2009-2013 era analysis, P2SH/BIP16 seams, FindAndDelete/scriptCode surfaces, SIGHASH_SINGLE, DUMMYGRIND/NULLDUMMY-style identifier axes, OP_RETURN/nulldata policy discussion, and historical carrier analysis.
- The repo has a small Vite dashboard at `tools/quirk-museum-vite` that renders the Bitcoin DeFi graft map from `artifacts/grants/bitcoin_defi_graft_map.json`. This is a working local/static dashboard surface, not a full product.
- The repo has Litecoin/TradeLayer procedural-token live test harnesses under `tests/litecoin-bitvm` and PowerShell runners under `scripts/litecoin-bitvm`. Artifacts under `artifacts/litecoin-bitvm` record txids and outcomes for cache/challenge/resolve/payout flows and watchtower-style challenge submissions.
- The grant/paper material in `docs/grants` and `docs/bitcoin_defi_graft_diagrams.md` is substantial. It frames three recurring motifs: transcript multiplicity, identifier bifurcation, and carrier camouflage. Some of that is design language; the report below separates it from runnable code.
- `C:\projects\TLZK` is a standalone local TradeLayer ZK proof-kernel prototype. It has scripts, tests, artifacts, docs, web-worker templates, checkpoint bundles, and a Raito-shaped OP_RETURN inclusion path. I configured `origin` as `https://github.com/patrickdugan/TLZK.git`, but GitHub currently returns `Repository not found`; the repo still needs to be created on GitHub before the local `master` head `c3e7ce0451fae860e6601a3c3b61c88af196de74` can be pushed.
- `C:\projects\UTXORef\UTXO-Ref` contains a broad prototype tree: BitVM3 referee code, deterministic tests/demos, Lightning liquidity sidecar, wallet demo dashboard, stress dashboard, UTXORef/Ark/BitVM mechanism notes, and Lightning/TradeLayer integration sketches. Several surfaces are explicitly fixture/mock/reviewer demos, not live production systems.
- `C:\projects\TLWallet\tradelayer-wallet` contains browser wallet P2P/WebRTC code, including `WebRTCTransport`, signaling, data-channel muxing, tape replay, and tape verification. This supports the high-level WebRTC access-layer claim, but I am treating it as an integration track rather than a completed decentralized RPC network.
- `C:\projects\tradelayer.js` contains tx34 ZK batch movement docs and scripts, plus TradeLayer protocol files and tests. This supports the TradeLayer integration track and ZK envelope direction.

Live public GitHub check:

- Jurassic Bitcoin: `https://github.com/patrickdugan/jurassic-bitcoin`, `master`; this report itself lives on that branch, so use the latest GitHub head for the exact report commit.
- UTXORef: `https://github.com/patrickdugan/UTXO-Ref`, `tradelayer-ln-dlc-demo`, public head `5e98acde232c416538ce79be46c9183bb59229a5`.
- TradeLayer.js: `https://github.com/patrickdugan/tradelayer.js`, `zk-tx34-wasm-verifier`, public head `7869620f39b2f2b9f6a6773e950c2297de238ff6`.
- TradeLayer wallet: `https://github.com/tradelayer-wallet/tradelayer-wallet`, `feature/webrtc-p2p-mode`, public head `44bdc87ee8d2a2ceb2e24efdcde0814cccd027f1`.
- TL-Web: `https://github.com/patrickdugan/TL-Web`, public heads include `main` at `1b0169a6f65af29b3a6cacaf749302549124ca71`, `testnetwallet` at `c4cc48f6604e001d89d84363c3e88a7cdaf02afb`, and `recover-friday-wallet-main` at `72c92ded41e19486264dfbb4d0af5c79dab0df73`.
- tl-relayer: `https://github.com/tradelayer-wallet/tl-relayer`, `main`, public head `4af6cf4c3de82d44fda078c4bfa19a79deb878ec`.
- tl-collator: `https://github.com/tradelayer-wallet/tl-collator`, `master`, public head `60d3d2aa6bfbd765ea7abe13199f07714697caa4`.
- TLZK / zkTL: local remote is configured as `https://github.com/patrickdugan/TLZK.git`, but GitHub returns `Repository not found`; publish is blocked on creating that public repo.

What I did not verify:

- A fresh end-to-end run of all demos. I read existing artifacts and code; I did not rerun LTCTEST, TLZK, UTXORef, or browser demos.
- Any production readiness claim. The evidence supports alpha, prototype, fixture replay, local demo, and design-track language.

## Executive summary

Q2 was a consolidation quarter. The useful thing that came out of the work was not a single finished product, and I do not want to present it that way. The work converged into a more coherent Bitcoin-aligned stack:

- Bitcoin remains the durable reference and settlement layer.
- OP_RETURN/nulldata-style commitments are one portable commitment surface, not the whole design.
- UTXO references are the linking grammar between Bitcoin events, off-chain state, proofs, and application state.
- TLZK and the dashboard work make commitments, verifier results, and state transitions more observable.
- WebRTC/P2P wallet transport is the access-layer direction: reduce dependence on centralized RPC and hosted indexers where possible.
- Lightning is the payment and incentive rail.
- TradeLayer is the financial/application-state surface where some of these references become balances, contracts, routes, and settlement events.

The strongest Q2 result is that these pieces now have repo evidence behind them. There is implemented code, fixture replay, local dashboards, live-test artifacts, and technical notes. The work is still early, but the architecture is no longer just prose.

## 1. Thesis

Bitcoin's most valuable property here is not maximal expressivity. It is durable ordering, conservative settlement, and long-lived referenceability.

The design question I worked on in Q2 was:

How do we use Bitcoin as a durable reference layer for systems that execute, prove, index, and relay elsewhere?

The pattern that keeps recurring is compact commitment plus replayable context:

- commit a small handle or digest on or near Bitcoin;
- keep larger state, proof material, and application data outside the base layer;
- make the state transition reconstructible from ordered references, public data, and verifier artifacts;
- avoid depending on one hosted API as the only way to recover the system.

OP_RETURN-style commitments are useful because they make this pattern concrete. But the real object is broader: Bitcoin transaction references, UTXO handles, Raito-style inclusion receipts, TradeLayer OP_RETURN payloads, TLZK envelopes, WebRTC-relayed objects, and Lightning payment receipts can all be treated as reference surfaces if they are bound carefully.

## 2. Q2 deliverables by maturity

### Implemented code

- Jurassic Bitcoin Rust workspace:
  - `crates/jb-model`: shared schemas for test cases, execution results, and divergence events.
  - `crates/jb-core-exec`: Bitcoin Core RPC/template execution wrapper with deterministic stub fallback.
  - `crates/jb-rust-shadow`: narrow Rust shadow executor.
  - `crates/jb-diff`, `jb-corpus`, `jb-mutator`, `jb-reducer`, `jb-fixtures`.
  - `crates/jurassic-bitcoin-cli`: commands including `replay`, `fuzz`, `reduce`, `doctor`, `demo-run`, `summarize`, `museum`, `replay-era`, `fetch-fixtures`, fixture minters, and `report`.
- Jurassic fixture and artifact pipeline:
  - manifests under `fixtures/manifests`;
  - blobs under `fixtures/blobs`;
  - historical and grant-facing generated outputs under `artifacts`.
- Local Vite dashboard:
  - `tools/quirk-museum-vite` renders the Bitcoin DeFi graft map and Core source anchors.
  - It consumes `artifacts/grants/bitcoin_defi_graft_map.json` and has a built-in fallback.
- TLZK proof-kernel prototype:
  - `C:\projects\TLZK` has scripts/tests for TradeLayer state kernels, Raito-shaped OP_RETURN inclusion, checkpoint bundles, web wallet sync bundles, and ZK consensus envelopes.
  - This is local-only in the current audit; the intended public remote is configured, but the GitHub repo does not exist yet.
  - It includes browser worker templates and WASM verifier scaffolding.
- TradeLayer tx34 ZK batch movement path:
  - `C:\projects\tradelayer.js\docs\TX34_ZK_BATCH_MOVEMENT_DRAFT.md`;
  - scripts such as `runZkFullProofArtifactDemo.js`, `runZkVerifierRejectionDemo.js`, and related verifier/envelope tooling.
- Wallet/WebRTC P2P transport:
  - `C:\projects\TLWallet\tradelayer-wallet\packages\wallet-fe\src\p2p\webrtc\WebRTCTransport.ts`;
  - signaling, data-channel muxing, tape replay, and tape verification files.
  - The wallet repo and WebRTC branch are now public at `feature/webrtc-p2p-mode`.

### Working prototypes / local demos

- Jurassic replay/fuzz/reduce/museum demo flow documented in `README.md`.
- Era replay and cross-epoch comparison for curated 2009-2013 fixtures.
- Litecoin/TradeLayer BitVM procedural-token live suite:
  - `receipt_rollover_redeem`;
  - `short_epoch_router`;
  - `short_epoch_router_dispute`;
  - transcript alias and identifier namespace relay surfaces;
  - watchtower beacon, Taproot Assets anchor mesh, oracle sidecar mesh, and statechain-style handoff mesh.
- Artifacts show live LTCTEST txids for cache, challenge, resolve, payout, and watchtower challenge flows. Example: `artifacts/litecoin-bitvm/2026-04-17/run-summary.md`.
- UTXORef wallet demo / sidecar:
  - Lightning liquidity adapter demo;
  - deterministic stress dashboard;
  - sidecar endpoints;
  - wallet backend profiles;
  - ZEUS-style screen sketches;
  - fixture-fed adapter events for LDK, Ark/Bark, Taproot Assets, and TradeLayer.

### Partial prototypes

- Jurassic Rust shadow executor is intentionally narrow. It parses transaction encoding and handles a constrained P2WPKH-style path, but the README explicitly calls out limits: one input, narrow witness form, no full signature hashing/crypto verification yet.
- TLZK currently proves/records bounded kernels and batch-binding artifacts. It does not yet prove full TradeLayer consensus history. Its README is explicit that prior history is committed as an initial state root, and unported transaction types are audit-bound rather than fully executed.
- UTXORef BitVM3 referee has deterministic formats, Merkle membership verification, settlement safety checks, and tests/demos. Its own technical plan says hash-circuit logic is still placeholder and not production cryptographic hashing.
- WebRTC transport exists in the wallet code, but the broader decentralized RPC network is still an integration direction, not a finished public network.

### Design notes and research tracks

- `docs/grants/jurassic_design_motifs.tex` and `docs/bitcoin_defi_graft_diagrams.md` develop the design language around transcript multiplicity, identifier bifurcation, and carrier camouflage.
- `artifacts/grants/policy_envelope_mapping.md` classifies which surfaces are replay-only fossils, historical cover, live LTCTEST relay surfaces, settlement graphs, or dispute graphs.
- OP_RETURN/nulldata is treated as one portable commitment surface among others. The current repo does not claim that every system should force all data into OP_RETURN.
- Lightning, Ark, Taproot Assets, Shinigami-style proof execution, and Filecoin/IPFS/Nostr-style references should be framed as integration paths unless backed by the specific local demo files.

## 3. Jurassic Bitcoin

Jurassic Bitcoin is now more concrete than the old draft suggested. It is not only a "long-horizon design track"; it is a working consensus observability harness with a Bitcoin Core comparison path, a shadow executor, curated fixtures, artifacts, and a local museum/dashboard loop.

The core purpose is still modest and Bitcoin-aligned:

- make consensus and policy behavior more observable;
- preserve reproducible artifacts;
- find and minimize divergence cases;
- study old consensus/policy seams without proposing base-layer changes.

The repo is explicit about non-goals: it is not a production node, wallet, mempool, miner, or consensus-rule-change project.

The most important Q2 technical work was turning historical Bitcoin behavior into measurable design motifs:

- `FindAndDelete` / legacy scriptCode mutation -> transcript multiplicity.
- CHECKMULTISIG dummy/NULLDUMMY surfaces -> identifier bifurcation.
- OP_RETURN/nulldata policy and historical payout-like carriers -> carrier camouflage.
- SIGHASH_SINGLE edge behavior -> hazard-filter and transcript branch analysis.

Those motifs are not presented as "we can rebroadcast old weird transactions today." The repo's own policy mapping is careful: many Bitcoin fossil surfaces are replay-only or policy-rejected today. The usable modern demonstrations happen through Litecoin/TradeLayer procedural-token flows, relay blobs, namespace handles, and application-level state transitions.

Evidence from repos:

- `README.md` documents the Rust workspace, CLI, Core RPC setup, demo-run, era replay, museum, and seam fixture commands.
- `fixtures/manifests/*.json` and `fixtures/blobs/*.json` hold the curated replay material.
- `docs/era-2009-2013.md`, `docs/forward-walk-mainnet.md`, and `docs/bitcoin_defi_graft_diagrams.md` explain the historical and design mapping.
- `artifacts/grants/policy_envelope_mapping.md` separates replay-only fossils from live modern isomorphisms.
- Recent commits include `Add Jurassic Bitcoin prototype and paper workflow`, `Add grant-facing Jurassic surfaces note`, `Add report command for seam figure tables`, and funded seam work for DUMMYGRIND and SIGHASH_SINGLE.

Q2 status: implemented local harness plus active research/prototype track. Not production infrastructure.

## 4. OP_RETURN-style commitments and UTXO references

The useful framing is:

OP_RETURN is a compact commitment surface. UTXO references are the grammar that lets that commitment point into a larger system.

In the Jurassic repo, this appears through:

- OP_RETURN and nulldata policy notes;
- carrier-camouflage analysis in `scripts/analyze_fixture_carriers.py`;
- historical payout carrier artifacts;
- oracle sidecar payloads and overlay carrier benchmarks;
- graft-map outputs tying OP_RETURN-style sidecars to DLC/oracle, watchtower, Taproot Assets, Ark, and proof-execution patterns.

In TLZK and TradeLayer, the same idea shows up as tx34 / ZK envelope work:

- a compact OP_RETURN-style anchor such as `z2|envelopeId`;
- a larger DA/witness envelope containing proof hash, verifier id, public input hash, signed L1 tx hash, batch L2 tx hash, and movement roots;
- consensus logic that rejects an anchor if the envelope cannot be resolved or checked.

In UTXORef, it shows up as a reference/referee layer:

- deterministic `CommitmentPackage`, `PayoutLeaf`, and `SweepObject` formats;
- Merkle membership proofs against committed withdrawal roots;
- settlement safety checks around epoch binding, payout cap, residual amount, and destination;
- Lightning/Ark/BitVM-style mechanism references and receipt ids.

This is the through-line I want to keep: do not overload Bitcoin with execution. Use Bitcoin-linked commitments and UTXO handles to make external execution auditable and recoverable.

Q2 status: implemented pieces across repos, but the unified UTXO reference grammar is still alpha. The next step is to produce a small canonical example that resolves one Bitcoin or TradeLayer event into one reference object, one external data object, and one verifier/dashboard view.

## 5. TLZK / zk observability

The original draft called this "zk Dashboard." The more accurate Q2 description is:

I built and connected pieces of a zk/verifier observability pipeline, plus dashboard surfaces around the proof/reference model. A finished general zk dashboard is still Q3 work.

What exists:

- `C:\projects\TLZK` has a standalone TradeLayer proof-kernel prototype.
- The TLZK/zkTL checkout is local-only in this audit; it has an intended remote, but it should not be described as a live public repo until `patrickdugan/TLZK` is created and reachable.
- It models Raito-shaped Bitcoin OP_RETURN inclusion receipts.
- It computes canonical TradeLayer state roots and typed transition kernels for many TradeLayer tx types.
- It has tests, scripts, artifacts, checkpoint announcements, web wallet sync bundles, and browser worker templates.
- `docs/ZK_CONSENSUS_ENVELOPE.md` records a concrete demo envelope id, proof hash, verifier id, movement root, signed L1 tx hash, batch L2 tx hash, DA blob hash, and consensus transition.
- `docs/WEB_WALLET_SYNC.md` describes browser-oriented sync using signed checkpoint announcements, TL state checkpoints, Raito-backed OP_RETURN claims, and balance Merkle branches.
- `C:\projects\tradelayer.js` includes the tx34 ZK batch movement draft and scripts for proof artifact binding and verifier rejection demos.
- `tools/quirk-museum-vite` gives a local dashboard shape for graft-map observability, though it is not the full TLZK dashboard.

Honest boundary:

- TLZK is not yet a full proof of all TradeLayer consensus history.
- The current STWO/Cairo path includes batch-binding and remote proof handoff work, but full per-transition Cairo execution is not complete.
- The dashboard work is useful for reviewer observability, but the general-purpose verifier dashboard remains a proposed Q3 deliverable.

Q2 status: proof-kernel prototype, artifact pipeline, and dashboard-adjacent observability. Not a production verifier UI.

## 6. WebRTC / disintermediated access layer

I am keeping this high level because the work spans the wallet, relayer, collator, and desktop paths.

The concrete repo evidence is strongest in the TradeLayer wallet:

- `WebRTCTransport.ts` establishes browser-side WebRTC data-channel transport using signaling, STUN, and a reliable ordered data channel.
- `DataChannelMux`, `SignalingClient`, `PeerTransport`, and related P2P files define the transport boundary.
- `TapeVerifier.ts` verifies ordered tape entries by sequence, previous hash, entry hash, and optional collator signature.
- Wallet services include P2P settings, transport, orderbook, and collator-related service files.

The design target is not "no servers." It is replaceable servers:

- clients should be able to fetch, relay, and cross-check state through more than one route;
- browser/device clients should have a path that is not just "trust this hosted RPC endpoint";
- relays/collators can still exist, but they should produce verifiable tapes, hashes, receipts, or signatures that other clients can audit.

This matters for the rest of the stack because a commitment/reference system fails in practice if the only way to resolve references is one centralized API.

Q2 status: wallet-side WebRTC/P2P transport and verification primitives exist in the local wallet branch; public relayer and collator repos are live at `https://github.com/tradelayer-wallet/tl-relayer` and `https://github.com/tradelayer-wallet/tl-collator`. The broader disintermediated RPC/relay network remains an alpha integration track, not a finished public network.

## 7. Lightning and TradeLayer integration

Lightning is best framed as the payment and incentive rail, not as something fully solved inside this quarter.

Concrete evidence:

- `docs/litecoin-bitvm/ln_deposit_to_tradelayer_lnbtc.md` defines a minimum build path for a small Lightning deposit that ends as wallet-visible tokenized BTC in TradeLayer.
- `docs/bitcoin-testnet4/lnbtc_deposit_grant_run.md` records a BTCTEST4 run using a mock-settled LN receipt, a `tlBTC` property, a grant amount of `0.00001000`, a destination testnet address, a Bitcoin testnet4 grant txid, and a listener balance response.
- `scripts/bitcoin-testnet4/lnbtc_deposit_grant.js` is the harness for that grant/recovery path.
- UTXORef has a Lightning liquidity sidecar with quote/pay/mint-intent endpoints and LND REST environment variables.
- UTXORef wallet demo notes show fixture-backed Lightning adapter feeds and stress dashboards.

TradeLayer is the application/financial state layer:

- Jurassic's Litecoin procedural-token suite shows TradeLayer-style procedural token flows, relay preludes, cache/challenge/resolve/payout edges, and watchtower challenge submissions.
- `tradelayer.js` contains protocol and tx34 ZK batch movement work.
- TLZK targets TradeLayer state kernels and checkpoint/proof workflows.

Honest boundary:

- The LN-to-TradeLayer demo includes mock-settled paths and local DB repair notes. That is useful, but it is not a mainnet bridge.
- The UTXORef Lightning sidecar and wallet dashboard are credible reviewer demos and adapter prototypes, not production custody/payment infrastructure.
- Mainnet readiness requires real LND/CLN settlement verification, duplicate-payment protection, reserve accounting, redemption/burn paths, key isolation, and adversarial tests.

Q2 status: working local/testnet paths and strong integration sketches. Production Lightning/TradeLayer bridge remains future work.

## 8. Evidence from repos

Public repo anchors:

- Jurassic Bitcoin: `https://github.com/patrickdugan/jurassic-bitcoin` (`master`; use the latest GitHub head for the exact report commit).
- UTXORef: `https://github.com/patrickdugan/UTXO-Ref` (`tradelayer-ln-dlc-demo`, public head `5e98acde232c416538ce79be46c9183bb59229a5`).
- TradeLayer.js: `https://github.com/patrickdugan/tradelayer.js` (`zk-tx34-wasm-verifier`, `7869620f39b2f2b9f6a6773e950c2297de238ff6`).
- TradeLayer wallet: `https://github.com/tradelayer-wallet/tradelayer-wallet` (`feature/webrtc-p2p-mode`, public head `44bdc87ee8d2a2ceb2e24efdcde0814cccd027f1`).
- TL-Web: `https://github.com/patrickdugan/TL-Web` (`main`, `1b0169a6f65af29b3a6cacaf749302549124ca71`; `testnetwallet`, `c4cc48f6604e001d89d84363c3e88a7cdaf02afb`).
- tl-relayer: `https://github.com/tradelayer-wallet/tl-relayer` (`main`, `4af6cf4c3de82d44fda078c4bfa19a79deb878ec`).
- tl-collator: `https://github.com/tradelayer-wallet/tl-collator` (`master`, `60d3d2aa6bfbd765ea7abe13199f07714697caa4`).
- TLZK / zkTL: intended remote is `https://github.com/patrickdugan/TLZK.git`, but GitHub returns `Repository not found`; cite local files only until the repo is created and pushed.

High-signal files and artifacts to cite or attach:

- Jurassic:
  - `README.md`
  - `Cargo.toml`
  - `crates/jurassic-bitcoin-cli/src/main.rs`
  - `docs/bitcoin_defi_graft_diagrams.md`
  - `docs/litecoin-bitvm/procedural_tokens.md`
  - `artifacts/grants/policy_envelope_mapping.md`
  - `artifacts/grants/bitcoin_defi_graft_map.md`
  - `artifacts/litecoin-bitvm/2026-04-17/run-summary.md`
  - `tools/quirk-museum-vite/README.md`
- TLZK:
  - Local-only evidence in this audit; create `patrickdugan/TLZK` on GitHub and push before citing as a public repo.
  - `C:\projects\TLZK\README.md`
  - `C:\projects\TLZK\package.json`
  - `C:\projects\TLZK\docs\ZK_CONSENSUS_ENVELOPE.md`
  - `C:\projects\TLZK\docs\WEB_WALLET_SYNC.md`
  - `C:\projects\TLZK\artifacts\zk_consensus\zk_batch_movement_latest.json`
  - `C:\projects\TLZK\artifacts\web_wallet_sync\web_wallet_sync_bundle_latest.json`
- UTXORef:
  - `C:\projects\UTXORef\UTXO-Ref\SPIRAL_GRANT_README.md`
  - `C:\projects\UTXORef\UTXO-Ref\DEMO_PACKAGE.md`
  - `C:\projects\UTXORef\UTXO-Ref\bitvm3\utxo_referee\GRANT_TECH_PLAN.md`
  - `C:\projects\UTXORef\UTXO-Ref\integrations\lightning-liquidity-lease-sidecar\README.md`
  - `C:\projects\UTXORef\UTXO-Ref\integrations\wallet-demo\DASHBOARD_UI_PLAN.md`
- WebRTC / wallet:
  - Public branch evidence exists at `feature/webrtc-p2p-mode`.
  - `C:\projects\TLWallet\tradelayer-wallet\packages\wallet-fe\src\p2p\webrtc\WebRTCTransport.ts`
  - `C:\projects\TLWallet\tradelayer-wallet\packages\wallet-fe\src\p2p\tape\TapeVerifier.ts`
  - `C:\projects\tl-relayer`
  - `C:\projects\tl-collator`
- TradeLayer:
  - `C:\projects\tradelayer.js\docs\TX34_ZK_BATCH_MOVEMENT_DRAFT.md`
  - `C:\projects\tradelayer.js\scripts\runZkFullProofArtifactDemo.js`
  - `C:\projects\tradelayer.js\src\zkConsensusEnvelope.js`

## 9. Q3 next steps

### 1. Canonical UTXO Ref Alpha example

Build one small example that a reviewer can follow end to end:

- input: one Bitcoin/TradeLayer transaction or fixture;
- reference: txid:vout or OP_RETURN/envelope id;
- external object: proof/data/receipt JSON;
- verifier result: hash/check/status;
- output: CLI and dashboard view showing the resolved chain.

This should be boring and reproducible. The goal is not to impress with breadth; it is to make the reference grammar real.

### 2. Dashboard pass tied to real artifacts

Turn the dashboard into a small observability surface over actual artifacts:

- commitment source;
- UTXO or OP_RETURN/envelope reference;
- external data object;
- proof/verifier status;
- state transition claim;
- whether the artifact is live, fixture replay, mock, or design-only.

This can start by reusing the Jurassic graft map, TLZK envelope artifacts, and UTXORef wallet demo outputs.

### 3. WebRTC relay demo

Show one browser/device peer retrieving a commitment/proof/reference object through the P2P path and verifying a tape entry/hash/signature locally.

Minimum credible demo:

- one collator/relay;
- one browser client;
- one requested object;
- one signed or hash-chained tape entry;
- fallback to HTTP only as a comparison path.

### 4. Lightning / TradeLayer narrow integration

Tighten the LN-to-TradeLayer path:

- replace mock-settled receipt with one real LND or CLN testnet settlement where possible;
- bind payment hash/preimage evidence into the reference object;
- show TradeLayer listener balance response;
- add duplicate-payment and reserve-accounting notes.

### 5. Separate public repo story from research repo sprawl

Before sending broader funding materials, package the work with:

- repo links;
- exact commit hashes;
- screenshots;
- one architecture diagram;
- one "what is live / fixture / mock / design" table;
- reproducible demo commands;
- explicit non-goals and security assumptions.

## 10. What Spiral support would unlock

The bottleneck is consolidation and proof-quality packaging, not another new idea.

With support, Q3 would focus on turning the current prototype mass into a clear open-source artifact:

- a small UTXO Ref Alpha demo;
- a dashboard view tied to actual repo artifacts;
- a WebRTC retrieval/verification proof of concept;
- a cleaned-up TLZK/TradeLayer proof-envelope story;
- one narrow Lightning/TradeLayer integration demo;
- documentation that is honest about what is implemented, mocked, fixture-backed, or still design.

The output I want is not a token launch or a consensus-change proposal. It is Bitcoin-adjacent infrastructure: references, proofs, observability, relay, and application-state integration that respect Bitcoin's base-layer conservatism.

## Closing

Q2's main progress was convergence backed by code.

Jurassic Bitcoin gives the historical and consensus-observability lens. OP_RETURN/nulldata commitments give one compact publication surface. UTXO references give the linking grammar. TLZK and the dashboard work give a verification and observability path. WebRTC gives a route away from single-provider access. Lightning gives the payment rail. TradeLayer gives a concrete application-state environment.

That is the stack I want to keep building: Bitcoin as durable reference layer; external systems as execution/proof/data layers; peer infrastructure as access; dashboards as observability; UTXO references as the connective tissue.

## Remaining evidence to add before sending

- Create the missing public GitHub repo `patrickdugan/TLZK` and push local `master` (`c3e7ce0451fae860e6601a3c3b61c88af196de74`).
- Exact Q2 commit ranges by repo, if Conor wants milestone-style attribution rather than current public heads.
- Fresh screenshots:
  - Jurassic/Vite graft dashboard;
  - UTXORef wallet dashboard or Vercel reviewer dashboard;
  - TLZK artifact/checkpoint output;
  - TradeLayer wallet balance showing the grant/demo result.
- One architecture diagram showing Bitcoin reference -> UTXORef -> proof/envelope -> dashboard -> WebRTC retrieval -> Lightning/TradeLayer application state.
- Demo links or recordings for:
  - Jurassic replay/museum;
  - UTXORef wallet stress dashboard;
  - WebRTC/P2P transport if available;
  - TLZK workflow output.
- Fresh test outputs:
  - `cargo test` or targeted Jurassic command output;
  - `npm test` in TLZK;
  - UTXORef BitVM referee tests/demos;
  - any wallet P2P tests that currently pass.
- Public status of the BTCTEST4 txid and whether it confirmed after the local note was written.
- Exact Q2 dates for each demo artifact if Conor may compare them to grant milestones.

## Short email blurb

Subject: Q2 Layer Technology update - grounded repo pass

Conor,

Attached is a revised Q2 update for the Layer Technology work. I tried to make this one much more concrete: what is implemented, what is a local or fixture-backed prototype, what is still design/research, and what I think should be built in Q3.

The short version is that the work has converged around a Bitcoin reference-layer stack: Jurassic Bitcoin for consensus/history observability, OP_RETURN-style commitments as one compact publication surface, UTXO references as the linking grammar, TLZK/dashboard work for verification visibility, WebRTC/P2P paths for access, Lightning for payments/incentives, and TradeLayer for application-state integration.

It is still alpha/prototype-stage, but there is real evidence now: Rust harnesses, fixture/replay artifacts, a local dashboard, TLZK proof-envelope artifacts, UTXORef demos, and TradeLayer/LN integration notes. I kept the production claims out and separated live public repos from local-only or unpublished branches.

Patrick
