# Four Ossification Proposals

This note captures the four proposal lanes recovered from the April 16, 2026 working thread and anchors each lane to current repo artifacts.

## 1. Transcript Multiplicity

Thesis:
One broad spend family can admit multiple effective signing transcripts.

Why it matters:
- BitVM branch transcript steering
- DLC or oracle outcome-set compression
- Lightning adaptor transcript selection

Current evidence:
- `FindAndDelete` context split in `artifacts/grants/overlay_hook_summary.md`
- `SIGHASH_SINGLE` collapse controls in `artifacts/grants/overlay_hook_summary.md`
- LTCTEST procedural relay proof in `artifacts/litecoin-bitvm/procedural/2026-04-17-procedural-transcript-c/run-summary.md`
- fused LTCTEST router/dispute graft in `artifacts/litecoin-bitvm/procedural/2026-04-17-procedural-hybrid-a/run-summary.md`

Current status:
- ready now
- already supported by the measured seam artifacts in `artifacts/p2sh-findanddelete-core-seam` and `artifacts/sighash-single-core-seam`
- now also live-proven as a TradeLayer Litecoin procedural-token relay surface
- now also grafted onto the same live challengeable `short_epoch_router_dispute` contract ref that carries proposal `3`

## 2. Identifier Bifurcation

Thesis:
Externally visible identifiers can move while the core contract digest stays fixed.

Why it matters:
- Lightning rendezvous or channel-factory namespace search
- BitVM anchor or session-id search
- OP_RETURN commitment namespaces
- Taproot Asset proof-anchor search

Current evidence:
- `DUMMYGRIND` summary in `artifacts/grants/overlay_hook_summary.md`
- LTCTEST namespace proof in `artifacts/litecoin-bitvm/procedural/2026-04-17-procedural-identifier-a/run-summary.md`
- fused LTCTEST router/dispute graft in `artifacts/litecoin-bitvm/procedural/2026-04-17-procedural-hybrid-a/run-summary.md`

Current status:
- ready now
- supported by the cached 2013 aggregation cover manifest at `fixtures/manifests/overlay_identifier_bifurcation_2013_poc.json`
- now also live-proven as a TradeLayer Litecoin procedural-token namespace surface
- now also grafted onto the same live challengeable `short_epoch_router_dispute` contract ref that carries proposal `3`

## 3. Carrier Camouflage

Thesis:
Overlay commitments should hide inside ordinary-looking historical payout and redistribution topology instead of relying on obviously exotic carrier transactions.

Why it matters:
- OP_RETURN oracle publication near payout-shaped batches
- DLC settlement sidecars
- BitVM watcher publication cadence
- Taproot Asset distribution-shadow experiments

Current evidence:
- 2013 carrier family report in `artifacts/history/payout_2013_carrier_camouflage.md`
- oracle-sidecar fixture set in `fixtures/manifests/overlay_oracle_sidecar_2013_poc.json`
- synthetic oracle-sidecar casebook in `artifacts/grants/overlay_carrier_bench_2013.md`
- payload and replay assets in `artifacts/grants/oracle_sidecar_payloads_2013.md` and `fixtures/manifests/oracle_sidecar_2013_replay_poc.json`
- LTCTEST fused router/dispute proof in `artifacts/litecoin-bitvm/procedural/2026-04-17-procedural-hybrid-a/run-summary.md`
- the same LTCTEST fused graph now carries proposal `1` transcript tags and proposal `2` namespace labels as relay preludes on that contract ref

Current status:
- live in the `279150..279320` post-BIP34 window
- strongest ordinary covers are the `202`-output spray, the `101`-output exact-value spray, and the `27`-input aggregator
- now also live-proven as a fused TradeLayer Litecoin procedural-token graph with both released and refunded BitVM branches
- that live graph now carries proposal `1` and `2` preludes on the same contract reference, so the Litecoin proof is no longer proposal-isolated

## 4. Policy-Envelope Mapping

Thesis:
The project should map which fossils remain relay-compatible, which are consensus-only, and which have clean modern isomorphisms.

Why it matters:
- separates museum curiosities from usable overlay search surfaces
- gives the grant story a forward-looking engineering filter
- tells us where a modern BitVM, Lightning, DLC, or Taproot Asset graft is realistic

Current evidence:
- forward-walk windowing strategy in `docs/forward-walk-mainnet.md`
- activation-boundary shortlist and historical windows in the same note
- generated crosswalk in `artifacts/grants/policy_envelope_mapping.md`

Current status:
- formalized now
- historical fossils, 2013 carrier cover, and LTCTEST TradeLayer isomorphisms are now classified in one generated matrix
- should be refreshed when new live grafts land

## Practical Readiness

Ready now:
- proposal `1` transcript multiplicity
- proposal `2` identifier bifurcation
- proposal `3` carrier camouflage in the 2013 burst window
- proposal `4` policy-envelope mapping as an engineering filter across the Bitcoin and Litecoin evidence bundles

## Immediate Next Move

The policy-envelope crosswalk now exists in `artifacts/grants/policy_envelope_mapping.md`. Its current conclusion is:

- proposals `1` and `2` have clean standalone relay-surface isomorphisms on LTCTEST and are now also grafted into the fused challengeable router graph
- proposal `3` now has a fused challengeable router graph on LTCTEST that carries the proposal `1` and `2` relay preludes on the same contract ref, while the Bitcoin replay side still needs funded prevouts
- the historical Bitcoin sidecar replay path still needs real prevouts because the current synthetic replay fixtures stop at `missing-inputs`

The highest-value next move is to turn that fused LTCTEST graph into reusable procedural-token templates so relay preludes, router buckets, and BitVM dispute edges are declared by flow-graph shape instead of one-off live harnesses.
