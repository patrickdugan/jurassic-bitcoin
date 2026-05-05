import './style.css';

const CLASS_STYLE = {
  SCRIPT_FAIL: { hue: 38, label: 'Script Fossil' },
  PARSE_FAIL: { hue: 22, label: 'Parsing Fossil' },
  POLICY_FAIL: { hue: 48, label: 'Policy Fossil' },
  SIG_FAIL: { hue: 15, label: 'Signature Fossil' },
  PREVOUT_MISSING: { hue: 8, label: 'Prevout Fossil' },
  UNCLASSIFIED: { hue: 30, label: 'Unclassified Fossil' },
};

const CORE_SOURCE_LINKS = {
  find_and_delete_v30: {
    id: 'find_and_delete_v30',
    label: 'v30.0 FindAndDelete',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L228-L236',
    why: 'Pre-segwit signatures are stripped from scriptCode, giving the fossil source for transcript aliases.',
  },
  checksig_finddelete_v30: {
    id: 'checksig_finddelete_v30',
    label: 'v30.0 CHECKSIG FindAndDelete call',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L325-L331',
    why: 'BASE sigversion removes the checked signature before hashing the script transcript.',
  },
  checkmultisig_finddelete_v30: {
    id: 'checkmultisig_finddelete_v30',
    label: 'v30.0 CHECKMULTISIG FindAndDelete call',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1142-L1148',
    why: 'Multisig signatures are individually stripped from the legacy script transcript.',
  },
  nulldummy_v30: {
    id: 'nulldummy_v30',
    label: 'v30.0 NULLDUMMY check',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1197-L1202',
    why: 'The extra CHECKMULTISIG stack element is the identifier-axis fossil.',
  },
  sighash_single_v30: {
    id: 'sighash_single_v30',
    label: 'v30.0 SIGHASH_SINGLE out-of-range digest',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L1599-L1605',
    why: 'The consensus-preserved uint256::ONE return is the hazard-filter transcript branch.',
  },
  op_return_v30: {
    id: 'op_return_v30',
    label: 'v30.0 OP_RETURN script failure',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/script/interpreter.cpp#L666-L668',
    why: 'OP_RETURN acts as the fossil source for sidecar separation.',
  },
  datacarrier_policy_v30: {
    id: 'datacarrier_policy_v30',
    label: 'v30.0 nulldata datacarrier standardness',
    url: 'https://github.com/bitcoin/bitcoin/blob/v30.0/src/policy/policy.cpp#L136-L150',
    why: 'Modern relay policy meters nulldata bytes, shaping payloads into sidecars or hashes.',
  },
};

const coreLinks = (...ids) => ids.map((id) => CORE_SOURCE_LINKS[id]);

const GRAFT_FALLBACK = {
  motifs: {
    1: {
      name: 'Transcript Multiplicity',
      bitcoin_code_handles: ['FindAndDelete context tags', 'SIGHASH_SINGLE digests', 'modern relay signed bundles'],
      mutable_fields: ['aliasTag', 'eventId', 'signatureHex', 'payloadHash', 'stateHash'],
    },
    2: {
      name: 'Identifier Bifurcation',
      bitcoin_code_handles: ['CHECKMULTISIG dummy txid-axis fixtures', 'namespace labels', 'contract references'],
      mutable_fields: ['blobRef', 'namespaceTag', 'dlcRef', 'contractRef', 'proofAnchor'],
    },
    3: {
      name: 'Carrier Camouflage',
      bitcoin_code_handles: ['OP_RETURN sidecars', 'payout fanout', 'exact-value batches', 'wallet-batch hints'],
      mutable_fields: ['relayBlob', 'carrierHint', 'placementMode', 'outputCount', 'changeDecoy'],
    },
  },
  targets: [
    {
      target_id: 'bitvm_router_dispute',
      protocol_family: 'BitVM / TradeLayer procedural token',
      motifs: ['Transcript Multiplicity', 'Identifier Bifurcation', 'Carrier Camouflage'],
      primary_flow_ids: ['short_epoch_router_dispute'],
      primary_entrypoints: ['tests/litecoin-bitvm/procedural_router_dispute_live.js'],
      supporting_entrypoints: [
        'tests/litecoin-bitvm/procedural_transcript_alias_live.js',
        'tests/litecoin-bitvm/procedural_identifier_bifurcation_live.js',
      ],
      diagram_steps: [
        'TradeLayer procedural-token commit',
        'compact/full transcript aliases',
        'router namespace handle',
        'BitVM cache/challenge/resolve edges',
        'ordinary payout-shaped carrier',
      ],
      motif_mechanics: [
        {
          motif: 'Transcript Multiplicity',
          mechanic: 'FindAndDelete and SIGHASH_SINGLE fossils become alternate transcript aliases and hazard-filter branches.',
        },
        {
          motif: 'Identifier Bifurcation',
          mechanic: 'Router branch ids are separated from proof and transcript ids, echoing the CHECKMULTISIG dummy axis.',
        },
        {
          motif: 'Carrier Camouflage',
          mechanic: 'Published state is shaped as payout or sidecar traffic instead of a bespoke dispute announcement.',
        },
      ],
      bitcoin_manipulation: 'Use transcript aliases and namespace handles as relay preludes, then route value through BitVM cache, challenge, resolve, and payout edges.',
      demo_architecture: 'Challengeable short-epoch router with one released branch and one blocked branch.',
      build_status: 'live_ltc_testnet_mesh',
      bitcoin_core_links: coreLinks(
        'find_and_delete_v30',
        'checksig_finddelete_v30',
        'checkmultisig_finddelete_v30',
        'sighash_single_v30',
        'nulldummy_v30',
        'datacarrier_policy_v30',
      ),
    },
    {
      target_id: 'taproot_assets_anchor',
      protocol_family: 'Taproot Assets',
      motifs: ['Transcript Multiplicity', 'Identifier Bifurcation', 'Carrier Camouflage'],
      primary_flow_ids: ['taproot_assets_anchor_mesh'],
      primary_entrypoints: ['tests/litecoin-bitvm/procedural_taproot_assets_anchor_mesh_live.js'],
      supporting_entrypoints: ['tests/litecoin-bitvm/procedural_identifier_bifurcation_live.js'],
      diagram_steps: [
        'asset transition',
        'compact/full transfer proof',
        'asset-id or universe-anchor handle',
        'wallet batch or distribution shadow',
        'proof-anchor mesh',
      ],
      motif_mechanics: [
        {
          motif: 'Transcript Multiplicity',
          mechanic: 'Asset transfer proof material is split into compact and full transcript packages.',
        },
        {
          motif: 'Identifier Bifurcation',
          mechanic: 'Asset id, universe anchor, and local proof anchor are separate names for one transition.',
        },
        {
          motif: 'Carrier Camouflage',
          mechanic: 'Anchors are published under wallet-batch or distribution-shadow hints.',
        },
      ],
      bitcoin_manipulation: 'Represent one asset transition through compact/full proof packages, rotate asset-id or universe-anchor handles, and publish under wallet-batch distribution-shadow hints.',
      demo_architecture: 'Proof-anchor mesh for asset ids, universe anchors, and transfer-proof packaging.',
      build_status: 'repo_local_mesh_registered; live_run_ready',
      bitcoin_core_links: coreLinks('find_and_delete_v30', 'nulldummy_v30', 'op_return_v30', 'datacarrier_policy_v30'),
    },
    {
      target_id: 'lightning_watchtower_beacon',
      protocol_family: 'Lightning / watchtower',
      motifs: ['Transcript Multiplicity', 'Identifier Bifurcation', 'Carrier Camouflage'],
      primary_flow_ids: ['watchtower_beacon_mesh'],
      primary_entrypoints: ['tests/litecoin-bitvm/procedural_watchtower_beacon_mesh_live.js'],
      supporting_entrypoints: ['tests/litecoin-bitvm/procedural_transcript_alias_live.js'],
      diagram_steps: [
        'channel or route state',
        'LN payment condition proof',
        'Ark UTXORef challenge ZK receipt',
        'compact/full fraud proofs',
        'rotating alert handle',
        'rebalance or sweep-like carrier',
        'programmable watchtower response package',
      ],
      motif_mechanics: [
        {
          motif: 'Transcript Multiplicity',
          mechanic: 'Watcher alerts have compact and full proof encodings over one monitored state plus a payment-conditioned ZK receipt bundle.',
        },
        {
          motif: 'Identifier Bifurcation',
          mechanic: 'Alert handles, payment proof ids, and Ark receipt ids rotate separately from channel state and proof payloads.',
        },
        {
          motif: 'Carrier Camouflage',
          mechanic: 'Publication cadence is shaped to resemble rebalances, sweeps, or maintenance batches.',
        },
      ],
      bitcoin_manipulation: 'Bind an opaque Lightning payment proof to an Ark UTXORef challenge receipt, package compact and full fraud-monitor proofs over one state, rotate alert handles, and hide watcher cadence inside rebalance or sweep-like traffic.',
      demo_architecture: 'Watchtower beacon mesh plus UTXORef programmable ZK watchtower receipt bundle.',
      build_status: 'live_ltc_testnet_mesh; utxoref_programmable_zk_watchtower_bundle_verified',
      bitcoin_core_links: coreLinks('find_and_delete_v30', 'checksig_finddelete_v30', 'nulldummy_v30', 'datacarrier_policy_v30'),
    },
    {
      target_id: 'programmable_ark_asp_policy',
      protocol_family: 'Ark / Lightning ASP',
      motifs: ['Transcript Multiplicity', 'Identifier Bifurcation', 'Carrier Camouflage'],
      primary_flow_ids: ['short_epoch_router', 'watchtower_beacon_mesh'],
      primary_entrypoints: [
        'tests/litecoin-bitvm/procedural_short_epoch_router_live.js',
        'tests/litecoin-bitvm/procedural_watchtower_beacon_mesh_live.js',
      ],
      supporting_entrypoints: ['tests/litecoin-bitvm/procedural_router_dispute_live.js'],
      diagram_steps: [
        'LN payment condition proof',
        'cooperative Ark round ZK receipt',
        'ASP forfeit-guard ZK receipt',
        'inbound liquidity, fee, and CLTV checks',
        'settle fee or slash/force-exit action',
      ],
      motif_mechanics: [
        {
          motif: 'Transcript Multiplicity',
          mechanic: 'The ASP sees a payment-conditioned public receipt while cooperative and forfeit Ark paths remain separate proof transcripts.',
        },
        {
          motif: 'Identifier Bifurcation',
          mechanic: 'Payment proof id, settlement receipt id, forfeit receipt id, route id, and ASP id are distinct handles.',
        },
        {
          motif: 'Carrier Camouflage',
          mechanic: 'ASP obligations are carried as round or maintenance sidecar receipts instead of bespoke LN route disclosures.',
        },
      ],
      bitcoin_manipulation: 'Use the Lightning payment receipt as a private trigger, then bind Ark cooperative-round and forfeit-guard ZK receipts to ASP settlement or slash decisions without exposing the route.',
      demo_architecture: 'Programmable Ark ASP policy sidecar for payment-conditioned settle, slash, or force-exit decisions.',
      build_status: 'utxoref_programmable_asp_zk_receipt_bundle_verified',
      bitcoin_core_links: coreLinks('checkmultisig_finddelete_v30', 'nulldummy_v30', 'standard_tx_policy_v30', 'datacarrier_policy_v30'),
    },
  ],
  utxoref_programmable_lightning_zk: {
    kind: 'programmable_lightning_zk_watchtower_asp_bundle',
    bundle_id: '92ecd80d8f10764833d16df5c0eee90fe381214bd96c9fe2f9d241f90f0f6f6f',
    payment_proof_id: 'ebb9fc532cd6e5417f272c3e720ba75d94eec9c7864afa8796da170f2e214395',
    verified: true,
    watchtower: {
      action: 'accept_and_monitor',
      receipt_role: 'utxoref_challenge_publication',
      receipt_id: '9e8cf05d6d7d58b10265ff065de8b1339415c7cfaf482e597cfe3e657e4e1f39',
      challengeable: false,
    },
    asp: {
      action: 'settle_and_release_asp_fee',
      settlement_receipt_role: 'cooperative_round',
      settlement_receipt_id: '9b8f3a7342bf1815c2951aa62b6dc5b03f006160db2c7c8a29d6ca8ddede6eec',
      forfeit_receipt_role: 'asp_forfeit_guard',
      forfeit_receipt_id: '45cf25cad368ae31ce24a9368723a790509b416f0aebe195d8be7afff0477817',
      slashable: false,
    },
    bitvm_receipt_challenge_walkthrough: {
      title: 'What BitVM Is Contesting',
      plain_english: 'A payment-conditioned ASP policy is challenged when the ASP claims the route delivery met the signed inbound-liquidity minimum, but the receipt-bound verifier path says otherwise.',
      contested_violation: 'deliveredInboundMet',
      asp_counterclaim: 'deliveredInboundSats >= promisedInboundSats; settle and release ASP fee',
      challenger_claim: 'deliveredInboundSats < promisedInboundSats; slash or force exit',
      happy_path_values: {
        promisedInboundSats: '75000',
        deliveredInboundSats: '75000',
        script_check: '75000 75000 OP_GREATERTHANOREQUAL',
        result: 'true',
      },
      negative_branch_example: {
        promisedInboundSats: '75000',
        deliveredInboundSats: '10000',
        script_check: '10000 75000 OP_GREATERTHANOREQUAL',
        result: 'false',
        slash_or_exit: 'slash ASP bond, force exit, or reroute liquidity demand',
      },
      bitvm_verifier_model: [
        'Commit the ZK verifier program id and public inputs.',
        'Bisect the committed verifier trace if the ASP disputes the result.',
        'Open the delivery comparator step: deliveredInboundSats >= promisedInboundSats.',
        'Authorize slash or force-exit handling if the opened step is false.',
      ],
      receipts: [
        { stage: 'payment-condition-receipt', label: 'Opaque LN payment fact', receipt_id: 'ebb9fc532cd6e5417f272c3e720ba75d94eec9c7864afa8796da170f2e214395', proves: 'Payment hash and amount bind without route disclosure.' },
        { stage: 'watchtower-utxoref-receipt', label: 'Watchtower Ark/UTXORef receipt', receipt_id: '9e8cf05d6d7d58b10265ff065de8b1339415c7cfaf482e597cfe3e657e4e1f39', proves: 'The watched transition binds to the payment-conditioned program state.' },
        { stage: 'asp-settlement-receipt', label: 'Cooperative Ark round receipt', receipt_id: '9b8f3a7342bf1815c2951aa62b6dc5b03f006160db2c7c8a29d6ca8ddede6eec', proves: 'Normal settlement is available if policy checks pass.' },
        { stage: 'asp-forfeit-receipt', label: 'ASP forfeit guard receipt', receipt_id: '45cf25cad368ae31ce24a9368723a790509b416f0aebe195d8be7afff0477817', proves: 'Slash or force-exit handling is available if checks fail.' },
        { stage: 'watchtower-challenge-id', label: 'Watchtower challenge artifact', receipt_id: 'd9961287679a890db8fdac7340b7350c1886f4fdbbc1f8b90c610863c1deb701', proves: 'Mismatched payment-conditioned UTXORef transitions become challengeable evidence.' },
        { stage: 'asp-challenge-id', label: 'ASP policy challenge artifact', receipt_id: '0ffbf2d26384c99eecee140e1729de4d312dd10b8237a04ea8566f6fdc3c66dc', proves: 'Failed ASP policy checks become slashable or force-exit evidence.' },
      ],
      caveat: 'This is an optimistic verifier-trace dispute model, not native Bitcoin Script verification of a full ZK proof.',
    },
  },
  code_surface_rule: 'Bitcoin fossils are motif sources. Live demos manipulate modern relay blobs, namespace handles, procedural-token state, and carrier hints.',
};

const app = document.querySelector('#app');
app.innerHTML = `
  <main class="museum-shell">
    <section class="hero-layer">
      <div>
        <p class="eyebrow">Jurassic Bitcoin Observatory</p>
        <h1>Quirk Museum</h1>
        <p>Fossil specimens, live grafts, and reusable Bitcoin DeFi surfaces.</p>
      </div>
      <nav class="dashboard-tabs" aria-label="Dashboard tabs">
        <button class="dashboard-tab active" data-tab="museum">Museum Timeline</button>
        <button class="dashboard-tab" data-tab="defi">Bitcoin DeFi Grafts</button>
      </nav>
    </section>

    <section class="dashboard-view" id="museum-view">
      <section class="timeline-layer">
        <div class="timeline-backdrop"></div>
        <div class="timeline-header">
          <h2>Quirk Museum Timeline</h2>
          <p>Click strata in the glass scroller to inspect era-specific fossils.</p>
        </div>
        <div class="glass-scroller" id="glass-scroller"></div>
        <div class="timeline-track" id="timeline-track"></div>
      </section>

      <section class="insight-layer">
        <div class="summary-card" id="summary-card"></div>
        <div class="bubble-grid" id="bubble-grid"></div>
        <aside class="detail-panel" id="detail-panel">
          <h2>Specimen Detail</h2>
          <p>Select a bubble to inspect metadata.</p>
        </aside>
      </section>
    </section>

    <section class="dashboard-view hidden" id="defi-view">
      <section class="defi-overview" id="defi-overview"></section>
      <section class="zk-explainer" id="zk-explainer"></section>
      <section class="motif-grid" id="motif-grid"></section>
      <section class="graft-layer">
        <div class="target-grid" id="target-grid"></div>
        <aside class="target-panel" id="target-panel"></aside>
      </section>
    </section>
  </main>
`;

const tabButtons = Array.from(document.querySelectorAll('.dashboard-tab'));
const museumView = document.getElementById('museum-view');
const defiView = document.getElementById('defi-view');
const timelineTrack = document.getElementById('timeline-track');
const glassScroller = document.getElementById('glass-scroller');
const summaryCard = document.getElementById('summary-card');
const bubbleGrid = document.getElementById('bubble-grid');
const detailPanel = document.getElementById('detail-panel');
const defiOverview = document.getElementById('defi-overview');
const zkExplainer = document.getElementById('zk-explainer');
const motifGrid = document.getElementById('motif-grid');
const targetGrid = document.getElementById('target-grid');
const targetPanel = document.getElementById('target-panel');

let state = {
  activeTab: 'museum',
  data: null,
  graftMap: GRAFT_FALLBACK,
  epochs: [],
  selectedEpoch: '',
  selectedSpecimen: null,
  selectedTargetId: '',
};

init();

async function init() {
  tabButtons.forEach((button) => {
    button.addEventListener('click', () => {
      state.activeTab = button.dataset.tab;
      renderTabs();
    });
  });

  const [museumData, graftMap] = await Promise.all([
    fetchJson('./data.json').catch(() => null),
    fetchJson('./bitcoin-defi-graft-map.json').catch(() => GRAFT_FALLBACK),
  ]);

  state.data = museumData;
  state.graftMap = graftMap || GRAFT_FALLBACK;
  state.epochs = museumData?.epochs?.map((e) => e.epoch) || [];
  state.selectedEpoch = state.epochs[0] || '';
  state.selectedTargetId = state.graftMap.targets?.[0]?.target_id || '';

  renderTabs();
  renderTimeline();
  renderEpoch();
  renderGraftMap();
}

async function fetchJson(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Unable to fetch ${path}`);
  return response.json();
}

function renderTabs() {
  tabButtons.forEach((button) => {
    button.classList.toggle('active', button.dataset.tab === state.activeTab);
  });
  museumView.classList.toggle('hidden', state.activeTab !== 'museum');
  defiView.classList.toggle('hidden', state.activeTab !== 'defi');
}

function renderTimeline() {
  timelineTrack.innerHTML = '';
  glassScroller.innerHTML = '';

  if (!state.data) {
    glassScroller.innerHTML = '<p class="empty-note">Museum data was not synced into this build.</p>';
    return;
  }

  state.epochs.forEach((epoch, idx) => {
    const marker = document.createElement('button');
    marker.className = `track-marker ${epoch === state.selectedEpoch ? 'active' : ''}`;
    marker.textContent = epoch;
    marker.style.setProperty('--marker-index', idx + 1);
    marker.addEventListener('click', () => {
      state.selectedEpoch = epoch;
      state.selectedSpecimen = null;
      renderTimeline();
      renderEpoch();
    });
    timelineTrack.appendChild(marker);

    const glassChip = document.createElement('button');
    glassChip.className = `glass-chip ${epoch === state.selectedEpoch ? 'active' : ''}`;
    glassChip.textContent = epoch;
    glassChip.addEventListener('click', () => {
      state.selectedEpoch = epoch;
      state.selectedSpecimen = null;
      renderTimeline();
      renderEpoch();
    });
    glassScroller.appendChild(glassChip);
  });
}

function renderEpoch() {
  if (!state.data) {
    summaryCard.innerHTML = '<h2>No Museum Data</h2><p>Run <code>npm run sync:data</code> after generating artifacts.</p>';
    bubbleGrid.innerHTML = '';
    detailPanel.innerHTML = '<h2>Specimen Detail</h2><p>No synced specimen data available.</p>';
    return;
  }

  const epoch = state.selectedEpoch;
  const specimens = state.data.specimens.filter((s) => s.epoch === epoch);
  const epochSummary = state.data.epochs.find((e) => e.epoch === epoch);

  summaryCard.innerHTML = `
    <h2>${escapeHtml(epoch)}</h2>
    <div class="metrics">
      <div><span>Total</span><strong>${epochSummary?.total_events ?? specimens.length}</strong></div>
      <div><span>Classes</span><strong>${Object.keys(epochSummary?.counts_by_normalized_class || {}).length}</strong></div>
      <div><span>Labeled</span><strong>${specimens.filter((s) => s.label).length}</strong></div>
    </div>
    <div class="class-row">
      ${Object.entries(epochSummary?.counts_by_normalized_class || {})
        .map(([klass, count]) => `<span class="class-pill class-${klass}">${escapeHtml(klass)}: ${count}</span>`)
        .join('')}
    </div>
  `;

  bubbleGrid.innerHTML = '';
  specimens.forEach((specimen) => {
    const style = CLASS_STYLE[specimen.normalized_class] || CLASS_STYLE.UNCLASSIFIED;
    const bubble = document.createElement('button');
    bubble.className = `quirk-bubble ${state.selectedSpecimen?.specimen_id === specimen.specimen_id ? 'active' : ''}`;
    bubble.style.setProperty('--hue', style.hue);
    bubble.innerHTML = `
      <span class="bubble-type">${style.label}</span>
      <strong>${escapeHtml(specimen.label || specimen.normalized_class)}</strong>
      <small>${escapeHtml(truncate(specimen.specimen_id, 20))}</small>
    `;
    bubble.addEventListener('click', () => {
      state.selectedSpecimen = specimen;
      renderEpoch();
      renderDetail(specimen);
    });
    bubbleGrid.appendChild(bubble);
  });

  if (!state.selectedSpecimen && specimens[0]) {
    state.selectedSpecimen = specimens[0];
    renderDetail(specimens[0]);
  } else if (!specimens.length) {
    detailPanel.innerHTML = '<h2>Specimen Detail</h2><p>No specimens in this epoch.</p>';
  }
}

function renderDetail(specimen) {
  const coreReason = specimen.core_reason || '<none>';
  const rustReason = specimen.rust_reason || '<none>';
  const trace = specimen.script_trace || '<none>';
  const mutations = (specimen.mutations_applied || []).join(', ') || '<none>';
  detailPanel.innerHTML = `
    <h2>${escapeHtml(specimen.label || specimen.normalized_class)}</h2>
    <p><strong>Specimen:</strong> <code>${escapeHtml(specimen.specimen_id)}</code></p>
    <p><strong>Testcase:</strong> <code>${escapeHtml(specimen.testcase_id)}</code></p>
    <p><strong>Core:</strong> ${escapeHtml(coreReason)}</p>
    <p><strong>Rust:</strong> ${escapeHtml(rustReason)}</p>
    <p><strong>Trace:</strong> ${escapeHtml(trace)}</p>
    <p><strong>Mutations:</strong> ${escapeHtml(mutations)}</p>
    <p class="detail-links">
      <a href="${specimen.event_path}" target="_blank" rel="noreferrer">event.json</a>
      ${specimen.testcase_path ? `<a href="${specimen.testcase_path}" target="_blank" rel="noreferrer">testcase.json</a>` : ''}
      ${specimen.reduced_testcase_path ? `<a href="${specimen.reduced_testcase_path}" target="_blank" rel="noreferrer">reduced.json</a>` : ''}
    </p>
  `;
}

function renderGraftMap() {
  const map = state.graftMap || GRAFT_FALLBACK;
  const targets = map.targets || [];
  const motifs = Object.entries(map.motifs || {});
  const liveCount = targets.filter((target) => String(target.build_status || '').includes('live')).length;

  defiOverview.innerHTML = `
    <div>
      <p class="eyebrow">Bitcoin DeFi Grafts</p>
      <h2>From Fossil Motifs To Product Surfaces</h2>
      <p>${escapeHtml(map.code_surface_rule || GRAFT_FALLBACK.code_surface_rule)}</p>
    </div>
    <div class="metrics defi-metrics">
      <div><span>Motifs</span><strong>${motifs.length}</strong></div>
      <div><span>Targets</span><strong>${targets.length}</strong></div>
      <div><span>Live Meshes</span><strong>${liveCount}</strong></div>
    </div>
  `;

  renderZkExplainer(map.utxoref_programmable_lightning_zk || {});

  motifGrid.innerHTML = '';
  motifs.forEach(([motifId, motif]) => {
    const card = document.createElement('article');
    card.className = 'motif-card';
    card.innerHTML = `
      <span class="motif-index">0${motifId}</span>
      <h3>${escapeHtml(motif.name)}</h3>
      <p>${escapeHtml((motif.bitcoin_code_handles || []).join('; '))}</p>
      <div class="mini-pills">
        ${(motif.mutable_fields || []).map((field) => `<span>${escapeHtml(field)}</span>`).join('')}
      </div>
    `;
    motifGrid.appendChild(card);
  });

  targetGrid.innerHTML = '';
  targets.forEach((target) => {
    const button = document.createElement('button');
    button.className = `target-card ${target.target_id === state.selectedTargetId ? 'active' : ''}`;
    button.innerHTML = `
      <span>${escapeHtml(target.protocol_family)}</span>
      <strong>${escapeHtml(target.target_id)}</strong>
      <small>${escapeHtml(target.build_status)}</small>
    `;
    button.addEventListener('click', () => {
      state.selectedTargetId = target.target_id;
      renderGraftMap();
    });
    targetGrid.appendChild(button);
  });

  renderTargetDetail(targets.find((target) => target.target_id === state.selectedTargetId) || targets[0]);
}

function renderZkExplainer(program) {
  const walkthrough = program.bitvm_receipt_challenge_walkthrough;
  if (!walkthrough) {
    zkExplainer.innerHTML = '';
    return;
  }

  zkExplainer.innerHTML = `
    <div class="zk-copy">
      <p class="eyebrow">Programmable Watchtower / ASP</p>
      <h2>${escapeHtml(walkthrough.title || 'What BitVM Is Contesting')}</h2>
      <p>${escapeHtml(walkthrough.plain_english || '')}</p>
      <div class="zk-values">
        ${renderCheckCard('Happy path', walkthrough.happy_path_values)}
        ${renderCheckCard('Disputed branch', walkthrough.negative_branch_example)}
      </div>
      <div class="target-section">
        <strong>Contested violation</strong>
        <code>${escapeHtml(walkthrough.contested_violation || '')}</code>
        <span>ASP counterclaim: ${escapeHtml(walkthrough.asp_counterclaim || '')}</span>
        <span>Challenger claim: ${escapeHtml(walkthrough.challenger_claim || '')}</span>
      </div>
    </div>
    <div class="zk-process">
      <strong>How BitVM checks it</strong>
      <ol>
        ${(walkthrough.bitvm_verifier_model || []).map((step) => `<li>${escapeHtml(step)}</li>`).join('')}
      </ol>
      <strong>Receipts carried through the process</strong>
      <div class="receipt-stack">
        ${(walkthrough.receipts || []).map(renderReceipt).join('')}
      </div>
      <p class="zk-caveat">${escapeHtml(walkthrough.caveat || '')}</p>
    </div>
  `;
}

function renderCheckCard(label, values = {}) {
  return `
    <div class="zk-check-card">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(values.script_check || '')}</strong>
      <small>promised ${escapeHtml(values.promisedInboundSats || '')} sats / delivered ${escapeHtml(values.deliveredInboundSats || '')} sats</small>
      <code>result: ${escapeHtml(values.result || '')}</code>
      ${values.slash_or_exit ? `<small>${escapeHtml(values.slash_or_exit)}</small>` : ''}
    </div>
  `;
}

function renderReceipt(receipt) {
  return `
    <article class="receipt-card">
      <span>${escapeHtml(receipt.stage || '')}</span>
      <strong>${escapeHtml(receipt.label || '')}</strong>
      <code>${escapeHtml(receipt.receipt_id || '')}</code>
      <small>${escapeHtml(receipt.proves || '')}</small>
    </article>
  `;
}

function renderTargetDetail(target) {
  if (!target) {
    targetPanel.innerHTML = '<h2>No Graft Targets</h2><p>Sync the Bitcoin DeFi graft map artifact.</p>';
    return;
  }

  const sourceLinks = target.bitcoin_core_links || target.source_links || [];

  targetPanel.innerHTML = `
    <p class="eyebrow">${escapeHtml(target.protocol_family)}</p>
    <h2>${escapeHtml(target.target_id)}</h2>
    <p>${escapeHtml(target.bitcoin_manipulation)}</p>
    <div class="target-section">
      <strong>Demo architecture</strong>
      <span>${escapeHtml(target.demo_architecture)}</span>
    </div>
    ${renderProgramOutputs(target.program_outputs || [])}
    ${renderArtifactRefs(target.artifact_refs || [])}
    <div class="target-section">
      <strong>Flow diagram</strong>
      ${renderFlowDiagram(target.diagram_steps || [])}
    </div>
    <div class="target-section motif-mechanics">
      <strong>Ossified quirk leverage</strong>
      ${
        (target.motif_mechanics || []).length
          ? target.motif_mechanics.map(renderMotifMechanic).join('')
          : '<span>No motif mechanics synced for this target.</span>'
      }
    </div>
    <div class="target-section">
      <strong>Primary flows</strong>
      <span>${escapeHtml((target.primary_flow_ids || []).join(', '))}</span>
    </div>
    <div class="target-section">
      <strong>Runnable entrypoints</strong>
      ${(target.primary_entrypoints || []).map((entrypoint) => `<code>${escapeHtml(entrypoint)}</code>`).join('')}
    </div>
    <div class="target-section">
      <strong>Motifs</strong>
      <div class="mini-pills">${(target.motifs || []).map((motif) => `<span>${escapeHtml(motif)}</span>`).join('')}</div>
    </div>
    <div class="target-section source-links">
      <strong>Bitcoin Core anchors exploited</strong>
      ${
        sourceLinks.length
          ? sourceLinks.map(renderSourceLink).join('')
          : '<span>No Bitcoin Core source links synced for this target.</span>'
      }
    </div>
  `;
}

function renderProgramOutputs(outputs) {
  if (!outputs.length) return '';
  return `
    <div class="target-section">
      <strong>Program outputs</strong>
      <div class="program-output-grid">
        ${outputs.map((item) => `
          <div class="program-output-item">
            <span>${escapeHtml(item.label || 'Output')}</span>
            <code>${escapeHtml(item.value || '')}</code>
          </div>
        `).join('')}
      </div>
    </div>
  `;
}

function renderArtifactRefs(artifacts) {
  if (!artifacts.length) return '';
  return `
    <div class="target-section artifact-refs">
      <strong>Evidence artifacts</strong>
      ${artifacts.map((item) => `
        <div class="artifact-ref">
          <span>${escapeHtml(item.label || 'Artifact')}</span>
          <code>${escapeHtml(item.id || '')}</code>
          <small>${escapeHtml(item.path || '')}</small>
        </div>
      `).join('')}
    </div>
  `;
}

function renderFlowDiagram(steps) {
  if (!steps.length) return '<span>No flow diagram synced for this target.</span>';
  return `
    <div class="flow-diagram">
      ${steps.map((step, index) => `
        <div class="flow-node">
          <span>${String(index + 1).padStart(2, '0')}</span>
          <strong>${escapeHtml(step)}</strong>
        </div>
      `).join('')}
    </div>
  `;
}

function renderMotifMechanic(item) {
  return `
    <div class="motif-mechanic">
      <span>${escapeHtml(item.motif || 'Motif')}</span>
      <p>${escapeHtml(item.mechanic || '')}</p>
    </div>
  `;
}

function renderSourceLink(link) {
  return `
    <a href="${escapeAttr(link.url)}" target="_blank" rel="noreferrer">
      <span>${escapeHtml(link.label || link.id || 'Bitcoin Core source')}</span>
      <small>${escapeHtml(link.why || '')}</small>
    </a>
  `;
}

function truncate(v, max) {
  return v.length <= max ? v : `${v.slice(0, max)}...`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

function escapeAttr(s) {
  return escapeHtml(s).replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
