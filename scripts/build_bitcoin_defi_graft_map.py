#!/usr/bin/env python3
"""Build a Bitcoin DeFi graft map from the three Jurassic motifs to demos."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FLOW_GRAPH = ROOT / "fixtures" / "litecoin-bitvm" / "procedural_flow_graphs.json"
DEFAULT_MOTIF_CSV = ROOT / "artifacts" / "grants" / "bitcoin_defi_motif_table.csv"
DEFAULT_OUT_JSON = ROOT / "artifacts" / "grants" / "bitcoin_defi_graft_map.json"
DEFAULT_OUT_MD = ROOT / "artifacts" / "grants" / "bitcoin_defi_graft_map.md"
DEFAULT_PROGRAMMABLE_LIGHTNING_ZK = (
    ROOT.parents[1]
    / "UTXORef"
    / "UTXO-Ref"
    / "bitvm3"
    / "utxo_referee"
    / "artifacts"
    / "lightning_zk_programs"
    / "programmable_lightning_zk_latest.json"
)


BITCOIN_CORE_LINKS = {
    "find_and_delete_v30": {
        "label": "v30.0 FindAndDelete",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L228-L236",
        "why": "Pre-segwit signatures are stripped from scriptCode, giving the fossil source for transcript aliases.",
    },
    "checksig_finddelete_v30": {
        "label": "v30.0 CHECKSIG FindAndDelete call",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L325-L331",
        "why": "BASE sigversion removes the checked signature before hashing the script transcript.",
    },
    "checkmultisig_finddelete_v30": {
        "label": "v30.0 CHECKMULTISIG FindAndDelete call",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1142-L1148",
        "why": "Multisig signatures are individually stripped from the legacy script transcript.",
    },
    "finddelete_v012_checksig": {
        "label": "v0.12.0 CHECKSIG scriptCode mutation",
        "url": "https://github.com/bitcoin/bitcoin/blob/v0.12.0/src/script/interpreter.cpp#L831-L835",
        "why": "Legacy scriptCode mutation shows the historical form of self-reference removal.",
    },
    "finddelete_v012_multisig": {
        "label": "v0.12.0 CHECKMULTISIG scriptCode mutation",
        "url": "https://github.com/bitcoin/bitcoin/blob/v0.12.0/src/script/interpreter.cpp#L887-L891",
        "why": "Legacy multisig transcript mutation is the historical source for grouped alias traces.",
    },
    "nulldummy_v30": {
        "label": "v30.0 NULLDUMMY check",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1197-L1202",
        "why": "The extra CHECKMULTISIG stack element is constrained by policy/flags, but remains a useful identifier-axis fossil.",
    },
    "nulldummy_v012": {
        "label": "v0.12.0 NULLDUMMY check",
        "url": "https://github.com/bitcoin/bitcoin/blob/v0.12.0/src/script/interpreter.cpp#L932-L939",
        "why": "The older dummy-element handling shows the identifier-bifurcation surface before modern cleanup.",
    },
    "sighash_single_v30": {
        "label": "v30.0 SIGHASH_SINGLE out-of-range digest",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1599-L1605",
        "why": "The consensus-preserved uint256::ONE return is the fossil source for hazard-filter transcript branches.",
    },
    "sighash_single_v012": {
        "label": "v0.12.0 SIGHASH_SINGLE out-of-range digest",
        "url": "https://github.com/bitcoin/bitcoin/blob/v0.12.0/src/script/interpreter.cpp#L1080-L1085",
        "why": "The legacy one-digest path shows the long-lived form of the preserved SIGHASH_SINGLE quirk.",
    },
    "op_return_v30": {
        "label": "v30.0 OP_RETURN script failure",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L666-L668",
        "why": "OP_RETURN is an intentional script stop; the demos use this as the fossil source for sidecar separation.",
    },
    "op_return_v012": {
        "label": "v0.12.0 OP_RETURN script failure",
        "url": "https://github.com/bitcoin/bitcoin/blob/v0.12.0/src/script/interpreter.cpp#L433-L435",
        "why": "The older OP_RETURN behavior anchors the historical carrier-camouflage motif.",
    },
    "datacarrier_policy_v30": {
        "label": "v30.0 nulldata datacarrier standardness",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/policy/policy.cpp#L136-L150",
        "why": "Modern relay policy meters nulldata bytes, so demos keep payloads as policy-shaped sidecars or hashes.",
    },
    "standard_tx_policy_v30": {
        "label": "v30.0 standard transaction policy entry",
        "url": "https://github.com/bitcoin/bitcoin/blob/v30.0/src/policy/policy.cpp#L99-L105",
        "why": "Standardness is the relay envelope around the carrier-camouflage demos.",
    },
}


MOTIFS = {
    1: {
        "name": "Transcript Multiplicity",
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "checksig_finddelete_v30",
            "checkmultisig_finddelete_v30",
            "sighash_single_v30",
            "finddelete_v012_checksig",
            "finddelete_v012_multisig",
            "sighash_single_v012",
        ],
        "bitcoin_code_handles": [
            "legacy scriptCode and signature-removal fixtures",
            "FindAndDelete context tags",
            "SIGHASH_SINGLE control and hazard-filter digests",
            "modern relay signed bundle fields",
        ],
        "mutable_fields": [
            "aliasTag",
            "eventId",
            "signatureHex",
            "payloadHash",
            "stateHash",
            "statementTag",
        ],
    },
    2: {
        "name": "Identifier Bifurcation",
        "bitcoin_core_link_ids": [
            "nulldummy_v30",
            "nulldummy_v012",
            "checkmultisig_finddelete_v30",
            "finddelete_v012_multisig",
        ],
        "bitcoin_code_handles": [
            "CHECKMULTISIG dummy-element txid-axis fixtures",
            "public namespace labels",
            "contract and DLC references",
            "proof-anchor or rendezvous handles",
        ],
        "mutable_fields": [
            "blobRef",
            "namespaceTag",
            "dlcRef",
            "contractRef",
            "sessionId",
            "proofAnchor",
        ],
    },
    3: {
        "name": "Carrier Camouflage",
        "bitcoin_core_link_ids": [
            "op_return_v30",
            "op_return_v012",
            "datacarrier_policy_v30",
            "standard_tx_policy_v30",
        ],
        "bitcoin_code_handles": [
            "OP_RETURN or nulldata sidecar payloads",
            "P2PKH payout fanout and exact-value batches",
            "input-consolidation clusters",
            "wallet-batch and sweep carrier hints",
        ],
        "mutable_fields": [
            "relayBlob",
            "carrierHint",
            "placementMode",
            "outputCount",
            "changeDecoy",
            "addData payload",
        ],
    },
}


TARGETS = [
    {
        "target_id": "bitvm_router_dispute",
        "protocol_family": "BitVM / TradeLayer procedural token",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["short_epoch_router_dispute"],
        "supporting_flow_ids": ["transcript_alias_relay", "identifier_namespace_bifurcation", "plan_a_guardrail"],
        "diagram_steps": [
            "TradeLayer procedural-token commit",
            "compact/full transcript aliases",
            "router namespace handle",
            "BitVM cache/challenge/resolve edges",
            "ordinary payout-shaped carrier",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "FindAndDelete and SIGHASH_SINGLE fossils become alternate transcript aliases and hazard-filter branches.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Router branch ids are separated from proof and transcript ids, echoing the CHECKMULTISIG dummy axis.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Published state is shaped as payout or sidecar traffic instead of a bespoke dispute announcement.",
            },
        ],
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "checksig_finddelete_v30",
            "checkmultisig_finddelete_v30",
            "sighash_single_v30",
            "nulldummy_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Use transcript aliases and namespace handles as relay preludes, then route value through "
            "BitVM cache, challenge, resolve, and payout edges."
        ),
        "demo_architecture": "challengeable short-epoch router with one released branch and one blocked branch",
        "build_status": "live_ltc_testnet_mesh",
    },
    {
        "target_id": "dlc_oracle_sidecar",
        "protocol_family": "DLC / oracle publication",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["oracle_sidecar_mesh"],
        "supporting_flow_ids": ["transcript_alias_relay", "identifier_namespace_bifurcation"],
        "diagram_steps": [
            "oracle fact",
            "compact/full attestations",
            "sidecar handle namespace",
            "DLC payout selection",
            "payout-spray or exact-batch carrier",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "One oracle fact is packaged as compact and full transcripts over the same state.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Oracle event id, sidecar blob reference, and DLC reference remain distinct handles.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Oracle publication is placed inside payout-like or exact-batch traffic.",
            },
        ],
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "checksig_finddelete_v30",
            "sighash_single_v30",
            "op_return_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Bind one oracle sidecar state to compact/full transcript variants, rotate public sidecar "
            "handles, and select payout-shaped carrier hints."
        ),
        "demo_architecture": "oracle sidecar mesh with payout-spray and exact-batch cover hints",
        "build_status": "live_ltc_testnet_mesh; bitcoin_replay_needs_funded_prevouts",
    },
    {
        "target_id": "lightning_watchtower_beacon",
        "protocol_family": "Lightning / watchtower",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["watchtower_beacon_mesh"],
        "supporting_flow_ids": ["transcript_alias_relay", "identifier_namespace_bifurcation"],
        "diagram_steps": [
            "channel or route state",
            "LN payment condition proof",
            "Ark UTXORef challenge ZK receipt",
            "compact/full fraud proofs",
            "rotating alert handle",
            "rebalance or sweep-like carrier",
            "programmable watchtower response package",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "Watcher alerts have compact and full proof encodings over one monitored state plus a payment-conditioned ZK receipt bundle.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Alert handles, payment proof ids, and Ark receipt ids rotate separately from channel state and proof payloads.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Publication cadence is shaped to resemble rebalances, sweeps, or maintenance batches.",
            },
        ],
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "checksig_finddelete_v30",
            "nulldummy_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Bind an opaque Lightning payment proof to an Ark UTXORef challenge receipt, package compact "
            "and full fraud-monitor proofs over one state, rotate alert handles, and hide watcher "
            "publication cadence inside rebalance or sweep-like traffic."
        ),
        "demo_architecture": "watchtower beacon mesh plus UTXORef programmable ZK watchtower receipt bundle",
        "build_status": "live_ltc_testnet_mesh; utxoref_programmable_zk_watchtower_bundle_verified",
    },
    {
        "target_id": "taproot_assets_anchor",
        "protocol_family": "Taproot Assets",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["taproot_assets_anchor_mesh"],
        "supporting_flow_ids": ["identifier_namespace_bifurcation", "oracle_sidecar_mesh"],
        "diagram_steps": [
            "asset transition",
            "compact/full transfer proof",
            "asset-id or universe-anchor handle",
            "wallet batch or distribution shadow",
            "proof-anchor mesh",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "Asset transfer proof material is split into compact and full transcript packages.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Asset id, universe anchor, and local proof anchor are separate names for one transition.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Anchors are published under wallet-batch or distribution-shadow hints.",
            },
        ],
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "nulldummy_v30",
            "op_return_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Represent one asset transition through compact/full proof packages, rotate asset-id or "
            "universe-anchor handles, and publish under wallet-batch distribution-shadow hints."
        ),
        "demo_architecture": "proof-anchor mesh for asset ids, universe anchors, and transfer-proof packaging",
        "build_status": "repo_local_mesh_registered; live_run_ready",
    },
    {
        "target_id": "ark_batch_liquidity",
        "protocol_family": "Ark",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["short_epoch_router", "statechain_handoff_mesh"],
        "supporting_flow_ids": ["short_epoch_router_dispute"],
        "diagram_steps": [
            "Ark round proposal",
            "cooperative/refresh/exit transcripts",
            "VTXO or claim namespace",
            "round-batch carrier",
            "path-witness ZK receipt",
            "refresh or offboard package",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "Cooperative round, refresh, and exit paths become alternate transcripts over related liquidity state.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "VTXO, claim, round, and proof receipt ids are explicit namespaces rather than one overloaded identifier.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Round batches provide natural cover for proof and liquidity metadata.",
            },
        ],
        "bitcoin_core_link_ids": [
            "checkmultisig_finddelete_v30",
            "nulldummy_v30",
            "standard_tx_policy_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Map cooperative round, refresh, exit, and offboard packages to alternate transcripts; "
            "treat VTXO, claim, ASP obligation, and proof receipt ids as namespace handles; use round batches as carrier cover."
        ),
        "demo_architecture": "short-epoch router plus statechain-style handoff checkpoint analogue, UTXORef Ark ZK miniscript receipt path, and programmable ASP policy sidecar",
        "build_status": "live_ltc_testnet_mesh_components; utxoref_ark_zk_miniscript_receipts_verified_5_of_5; programmable_asp_policy_verified",
    },
    {
        "target_id": "programmable_ark_asp_policy",
        "protocol_family": "Ark / Lightning ASP",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["short_epoch_router", "watchtower_beacon_mesh"],
        "supporting_flow_ids": ["statechain_handoff_mesh", "short_epoch_router_dispute"],
        "diagram_steps": [
            "LN payment condition proof",
            "cooperative Ark round ZK receipt",
            "ASP forfeit-guard ZK receipt",
            "inbound liquidity, fee, and CLTV checks",
            "settle fee or slash/force-exit action",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "The ASP sees a payment-conditioned public receipt while cooperative and forfeit Ark paths remain separate proof transcripts.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Payment proof id, settlement receipt id, forfeit receipt id, route id, and ASP id are distinct handles.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "ASP obligations are carried as round or maintenance sidecar receipts instead of bespoke LN route disclosures.",
            },
        ],
        "bitcoin_core_link_ids": [
            "checkmultisig_finddelete_v30",
            "nulldummy_v30",
            "standard_tx_policy_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Use the Lightning payment receipt as a private trigger, then bind Ark cooperative-round and "
            "forfeit-guard ZK receipts to ASP settlement or slash decisions without exposing the route."
        ),
        "demo_architecture": "programmable Ark ASP policy sidecar for payment-conditioned settle, slash, or force-exit decisions",
        "build_status": "utxoref_programmable_asp_zk_receipt_bundle_verified",
    },
    {
        "target_id": "shinigami_proof_execution",
        "protocol_family": "Shinigami-style proof-carrying execution",
        "motif_ids": [1, 2, 3],
        "primary_flow_ids": ["oracle_sidecar_mesh", "short_epoch_router_dispute"],
        "supporting_flow_ids": ["transcript_alias_relay", "identifier_namespace_bifurcation"],
        "diagram_steps": [
            "proof-carrying execution",
            "compact/full verifier transcripts",
            "public proof handle",
            "Ark selected-path witness",
            "ordinary settlement carrier",
            "BitVM-style challenge or acceptance path",
        ],
        "motif_mechanics": [
            {
                "motif": "Transcript Multiplicity",
                "mechanic": "Proof execution has compact and full verification transcripts plus selected Taproot path-witness branches.",
            },
            {
                "motif": "Identifier Bifurcation",
                "mechanic": "Public proof handle, local proof package, and settlement reference remain distinct.",
            },
            {
                "motif": "Carrier Camouflage",
                "mechanic": "Proof material is committed through ordinary settlement or nulldata-shaped envelopes.",
            },
        ],
        "bitcoin_core_link_ids": [
            "find_and_delete_v30",
            "checksig_finddelete_v30",
            "sighash_single_v30",
            "op_return_v30",
            "datacarrier_policy_v30",
        ],
        "bitcoin_manipulation": (
            "Model proof publication as alternate execution transcripts, verifier-visible proof handles, "
            "selected-path witness receipts, and ordinary settlement-batch carrier placement."
        ),
        "demo_architecture": "proof publication scaffold using oracle-sidecar, router-dispute, and UTXORef Ark ZK miniscript receipt meshes",
        "build_status": "utxoref_ark_shinigami_path_witness_receipts_verified_on_snacksack",
    },
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_optional_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return load_json(path)


def load_motif_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def flow_lookup(flow_graph: dict) -> dict[str, dict]:
    flows = {flow["id"]: flow for flow in flow_graph.get("flows", [])}
    adjacent = flow_graph.get("adjacent_dispute_flow")
    if adjacent:
        flows[adjacent["id"]] = adjacent
    return flows


def resolve_core_links(link_ids: list[str]) -> list[dict]:
    links = []
    for link_id in link_ids:
        if link_id not in BITCOIN_CORE_LINKS:
            raise RuntimeError(f"Unknown Bitcoin Core link id: {link_id}")
        links.append({"id": link_id, **BITCOIN_CORE_LINKS[link_id]})
    return links


def summarize_programmable_lightning_zk(bundle: dict, source_path: Path) -> dict:
    if not bundle:
        return {}
    watchtower = bundle.get("watchtower", {})
    asp_policy = bundle.get("aspPolicy", {})
    bundle_core = bundle.get("bundleCore", {})
    verification = bundle.get("verification", {})
    asp_core = asp_policy.get("policyCore", {})
    watchtower_challenge = watchtower.get("challenge", {})
    asp_challenge = asp_policy.get("challenge", {})
    payment_proof = bundle.get("paymentProof", {})
    promised = str(asp_core.get("promisedInboundSats", "75000"))
    delivered = str(asp_core.get("deliveredInboundSats", "75000"))
    negative_delivered = "10000"
    return {
        "kind": bundle.get("kind", ""),
        "source_path": str(source_path),
        "bundle_id": bundle.get("bundleId", ""),
        "payment_proof_id": bundle_core.get("paymentProofId", ""),
        "verified": bool(verification.get("ok")),
        "watchtower": {
            "program_id": watchtower.get("programId", ""),
            "action": bundle_core.get("watchtowerAction", ""),
            "receipt_role": watchtower.get("zkReceiptRef", {}).get("role", ""),
            "receipt_id": watchtower.get("zkReceiptRef", {}).get("receiptId", ""),
            "challengeable": bool(watchtower.get("challenge", {}).get("challengeable")),
        },
        "asp": {
            "policy_id": asp_policy.get("policyId", ""),
            "action": bundle_core.get("aspAction", ""),
            "settlement_receipt_role": asp_policy.get("settlementReceiptRef", {}).get("role", ""),
            "settlement_receipt_id": asp_policy.get("settlementReceiptRef", {}).get("receiptId", ""),
            "forfeit_receipt_role": asp_policy.get("forfeitReceiptRef", {}).get("role", ""),
            "forfeit_receipt_id": asp_policy.get("forfeitReceiptRef", {}).get("receiptId", ""),
            "slashable": bool(asp_policy.get("challenge", {}).get("slashable")),
        },
        "bitvm_receipt_challenge_walkthrough": {
            "title": "What BitVM Is Contesting",
            "plain_english": (
                "The happy-path receipt says an opaque Lightning payment can release an Ark-backed "
                "ASP settlement. The challenged branch asks whether that same receipt set proves the "
                "ASP actually delivered the signed inbound-liquidity minimum."
            ),
            "contested_violation": "deliveredInboundMet",
            "asp_counterclaim": "deliveredInboundSats >= promisedInboundSats; settle and release ASP fee",
            "challenger_claim": "deliveredInboundSats < promisedInboundSats; slash or force exit",
            "happy_path_values": {
                "promisedInboundSats": promised,
                "deliveredInboundSats": delivered,
                "script_check": f"{delivered} {promised} OP_GREATERTHANOREQUAL",
                "result": str(int(delivered) >= int(promised)).lower(),
            },
            "negative_branch_example": {
                "promisedInboundSats": promised,
                "deliveredInboundSats": negative_delivered,
                "script_check": f"{negative_delivered} {promised} OP_GREATERTHANOREQUAL",
                "result": "false",
                "slash_or_exit": "slash ASP bond, force exit, or reroute liquidity demand",
            },
            "bitvm_verifier_model": [
                "Commit the ZK verifier program id and public inputs: payment proof id, Ark receipt ids, promised sats, delivered sats, fee ceiling, CLTV ceiling.",
                "If the ASP disputes the result, bisect the committed verifier trace until one step is opened.",
                "The opened step is the delivery comparator, not the Lightning route: deliveredInboundSats >= promisedInboundSats.",
                "If that step evaluates false, the challenge path authorizes slash or force-exit handling."
            ],
            "receipts": [
                {
                    "stage": "payment-condition-receipt",
                    "label": "Opaque LN payment fact",
                    "receipt_id": payment_proof.get("proofId", ""),
                    "proves": "Payment hash, amount, invoice hash, and preimage-witness commitment are bound without exposing the route."
                },
                {
                    "stage": "watchtower-utxoref-receipt",
                    "label": "Watchtower Ark/UTXORef receipt",
                    "receipt_id": watchtower.get("zkReceiptRef", {}).get("receiptId", ""),
                    "proves": "The watched UTXORef transition is tied to the payment-conditioned program state."
                },
                {
                    "stage": "asp-settlement-receipt",
                    "label": "Cooperative Ark round receipt",
                    "receipt_id": asp_policy.get("settlementReceiptRef", {}).get("receiptId", ""),
                    "proves": "The ASP has a normal settlement path if delivery, fee, CLTV, and exit checks all pass."
                },
                {
                    "stage": "asp-forfeit-receipt",
                    "label": "ASP forfeit guard receipt",
                    "receipt_id": asp_policy.get("forfeitReceiptRef", {}).get("receiptId", ""),
                    "proves": "A slash or force-exit path exists if the ASP cannot satisfy the opened verifier step."
                },
                {
                    "stage": "watchtower-challenge-id",
                    "label": "Watchtower challenge artifact",
                    "receipt_id": watchtower_challenge.get("challengeId", ""),
                    "proves": "Mismatched payment-conditioned UTXORef transitions become challengeable evidence."
                },
                {
                    "stage": "asp-challenge-id",
                    "label": "ASP policy challenge artifact",
                    "receipt_id": asp_challenge.get("challengeId", ""),
                    "proves": "Failed ASP policy checks become slashable or force-exit evidence."
                },
            ],
            "caveat": (
                "Bitcoin Script does not natively verify a full modern ZK proof here. The BitVM shape is "
                "an optimistic verifier-trace dispute: receipts commit to the proof result, and fraud "
                "opens the contested verifier step."
            ),
        },
    }


def enrich_motifs() -> dict[int, dict]:
    return {
        motif_id: {
            **motif,
            "bitcoin_core_links": resolve_core_links(motif.get("bitcoin_core_link_ids", [])),
        }
        for motif_id, motif in MOTIFS.items()
    }


def programmable_artifacts_for_target(target_id: str, summary: dict) -> dict:
    if not summary:
        return {}
    artifact_refs = [
        {
            "label": "Programmable Lightning ZK bundle",
            "path": summary.get("source_path", ""),
            "id": summary.get("bundle_id", ""),
        }
    ]
    if target_id == "lightning_watchtower_beacon":
        watchtower = summary.get("watchtower", {})
        return {
            "program_outputs": [
                {"label": "Watchtower action", "value": watchtower.get("action", "")},
                {"label": "Challengeable", "value": str(watchtower.get("challengeable", False)).lower()},
                {"label": "Ark receipt role", "value": watchtower.get("receipt_role", "")},
                {"label": "Ark receipt id", "value": watchtower.get("receipt_id", "")},
            ],
            "artifact_refs": artifact_refs,
        }
    if target_id in {"ark_batch_liquidity", "programmable_ark_asp_policy"}:
        asp = summary.get("asp", {})
        return {
            "program_outputs": [
                {"label": "ASP action", "value": asp.get("action", "")},
                {"label": "Slashable", "value": str(asp.get("slashable", False)).lower()},
                {"label": "Settlement role", "value": asp.get("settlement_receipt_role", "")},
                {"label": "Forfeit role", "value": asp.get("forfeit_receipt_role", "")},
            ],
            "artifact_refs": artifact_refs,
        }
    return {}


def enrich_targets(targets: list[dict], flows: dict[str, dict], programmable_lightning_zk: dict) -> list[dict]:
    enriched = []
    for target in targets:
        missing = [
            flow_id
            for flow_id in target["primary_flow_ids"] + target["supporting_flow_ids"]
            if flow_id not in flows
        ]
        if missing:
            raise RuntimeError(f"{target['target_id']} references missing flows: {', '.join(missing)}")
        target_flows = [flows[flow_id] for flow_id in target["primary_flow_ids"]]
        supporting_flows = [flows[flow_id] for flow_id in target["supporting_flow_ids"]]
        enriched.append(
            {
                **target,
                **programmable_artifacts_for_target(target["target_id"], programmable_lightning_zk),
                "motifs": [MOTIFS[motif_id]["name"] for motif_id in target["motif_ids"]],
                "bitcoin_core_links": resolve_core_links(target.get("bitcoin_core_link_ids", [])),
                "primary_entrypoints": [flow.get("entrypoint", "") for flow in target_flows],
                "supporting_entrypoints": [flow.get("entrypoint", "") for flow in supporting_flows],
                "policy_envelope_classes": sorted(
                    {
                        flow.get("policy_envelope_class", "")
                        for flow in target_flows + supporting_flows
                        if flow.get("policy_envelope_class")
                    }
                ),
                "relay_statuses": sorted(
                    {
                        flow.get("relay_compatibility", "")
                        for flow in target_flows + supporting_flows
                        if flow.get("relay_compatibility")
                    }
                ),
            }
        )
    return enriched


def build_report(flow_graph: dict, motif_rows: list[dict], args: argparse.Namespace) -> dict:
    flows = flow_lookup(flow_graph)
    programmable_lightning_zk_path = Path(args.programmable_lightning_zk).resolve()
    programmable_lightning_zk = summarize_programmable_lightning_zk(
        load_optional_json(programmable_lightning_zk_path),
        programmable_lightning_zk_path,
    )
    return {
        "kind": "bitcoin_defi_graft_map",
        "scope": "three_jurassic_motifs_to_bitcoin_defi_architectures",
        "generated_from": {
            "flow_graph": str(Path(args.flow_graph).resolve()),
            "motif_csv": str(Path(args.motif_csv).resolve()),
            "programmable_lightning_zk": str(programmable_lightning_zk_path),
        },
        "motifs": enrich_motifs(),
        "motif_table_rows": motif_rows,
        "targets": enrich_targets(TARGETS, flows, programmable_lightning_zk),
        "utxoref_programmable_lightning_zk": programmable_lightning_zk,
        "code_surface_rule": (
            "Bitcoin fossils are used as motif sources. Live demos manipulate modern relay blobs, "
            "namespace handles, procedural-token state, and carrier hints rather than attempting to "
            "rebroadcast policy-rejected legacy forms."
        ),
    }


def render_markdown(report: dict) -> str:
    def link_list(links: list[dict]) -> str:
        return "; ".join(f"[{link['label']}]({link['url']})" for link in links)

    lines = [
        "# Bitcoin DeFi Graft Map",
        "",
        "This artifact maps the three Jurassic Bitcoin motifs to concrete Bitcoin-code surfaces and repo-local demos.",
        "",
        "## Motif Code Surfaces",
        "",
        "| motif | Bitcoin code handles | Bitcoin Core anchors | mutable knobs |",
        "| --- | --- | --- | --- |",
    ]
    for motif_id in sorted(report["motifs"], key=int):
        motif = report["motifs"][motif_id]
        lines.append(
            f"| `{motif_id}: {motif['name']}` | "
            f"{'; '.join(motif['bitcoin_code_handles'])} | "
            f"{link_list(motif['bitcoin_core_links'])} | "
            f"`{'; '.join(motif['mutable_fields'])}` |"
        )
    lines.extend(
        [
            "",
            "## Target Architectures",
            "",
            "| target | family | motifs | primary flows | Bitcoin manipulation | status |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for target in report["targets"]:
        lines.append(
            f"| `{target['target_id']}` | {target['protocol_family']} | "
            f"{', '.join(target['motifs'])} | "
            f"`{', '.join(target['primary_flow_ids'])}` | "
            f"{target['bitcoin_manipulation']} | `{target['build_status']}` |"
        )
    lines.extend(
        [
            "",
            "## Entrypoints",
            "",
            "| target | runnable entrypoints | supporting entrypoints | demo architecture |",
            "| --- | --- | --- | --- |",
        ]
    )
    for target in report["targets"]:
        primary = ", ".join(f"`{item}`" for item in target["primary_entrypoints"] if item)
        supporting = ", ".join(f"`{item}`" for item in target["supporting_entrypoints"] if item)
        lines.append(
            f"| `{target['target_id']}` | {primary} | {supporting} | {target['demo_architecture']} |"
        )
    lines.extend(
        [
            "",
            "## Demo Flow Diagrams",
            "",
            "| target | flow steps | motif mechanics |",
            "| --- | --- | --- |",
        ]
    )
    for target in report["targets"]:
        mechanics = "; ".join(
            f"{item['motif']}: {item['mechanic']}" for item in target.get("motif_mechanics", [])
        )
        lines.append(
            f"| `{target['target_id']}` | {' -> '.join(target.get('diagram_steps', []))} | {mechanics} |"
        )
    artifact_targets = [target for target in report["targets"] if target.get("artifact_refs")]
    if artifact_targets:
        lines.extend(
            [
                "",
                "## Program Artifacts",
                "",
                "| target | outputs | artifacts |",
                "| --- | --- | --- |",
            ]
        )
        for target in artifact_targets:
            outputs = "; ".join(
                f"{item['label']}: `{item['value']}`" for item in target.get("program_outputs", [])
            )
            artifacts = "; ".join(
                f"{item['label']}: `{item['id']}` ({item['path']})"
                for item in target.get("artifact_refs", [])
            )
            lines.append(f"| `{target['target_id']}` | {outputs} | {artifacts} |")
    walkthrough = report.get("utxoref_programmable_lightning_zk", {}).get(
        "bitvm_receipt_challenge_walkthrough", {}
    )
    if walkthrough:
        happy = walkthrough.get("happy_path_values", {})
        negative = walkthrough.get("negative_branch_example", {})
        lines.extend(
            [
                "",
                "## Programmable Watchtower / ASP Challenge Walkthrough",
                "",
                walkthrough.get("plain_english", ""),
                "",
                f"- Contested violation: `{walkthrough.get('contested_violation', '')}`",
                f"- ASP counterclaim: `{walkthrough.get('asp_counterclaim', '')}`",
                f"- Challenger claim: `{walkthrough.get('challenger_claim', '')}`",
                f"- Happy path check: `{happy.get('script_check', '')}` -> `{happy.get('result', '')}`",
                f"- Disputed branch check: `{negative.get('script_check', '')}` -> `{negative.get('result', '')}`",
                "",
                "| receipt stage | receipt id | what it proves |",
                "| --- | --- | --- |",
            ]
        )
        for receipt in walkthrough.get("receipts", []):
            lines.append(
                f"| `{receipt.get('stage', '')}` | `{receipt.get('receipt_id', '')}` | "
                f"{receipt.get('proves', '')} |"
            )
        lines.extend(
            [
                "",
                "Verifier-trace model:",
                "",
            ]
        )
        for step in walkthrough.get("bitvm_verifier_model", []):
            lines.append(f"- {step}")
        lines.extend(["", f"Caveat: {walkthrough.get('caveat', '')}", ""])
    lines.extend(
        [
            "",
            "## Bitcoin Core Source Links By Demo",
            "",
            "| target | exploited Bitcoin Core anchors |",
            "| --- | --- |",
        ]
    )
    for target in report["targets"]:
        lines.append(f"| `{target['target_id']}` | {link_list(target['bitcoin_core_links'])} |")
    lines.extend(["", f"Rule: {report['code_surface_rule']}", ""])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build Bitcoin DeFi graft map artifacts")
    parser.add_argument("--flow-graph", default=str(DEFAULT_FLOW_GRAPH))
    parser.add_argument("--motif-csv", default=str(DEFAULT_MOTIF_CSV))
    parser.add_argument("--programmable-lightning-zk", default=str(DEFAULT_PROGRAMMABLE_LIGHTNING_ZK))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report(
        load_json(Path(args.flow_graph).resolve()),
        load_motif_csv(Path(args.motif_csv).resolve()),
        args,
    )
    out_json = Path(args.out_json).resolve()
    out_md = Path(args.out_md).resolve()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(str(out_json))
    print(str(out_md))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
