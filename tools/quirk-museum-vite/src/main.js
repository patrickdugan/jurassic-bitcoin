import './style.css';

const CLASS_STYLE = {
  SCRIPT_FAIL: { hue: 38, label: 'Script Fossil' },
  PARSE_FAIL: { hue: 22, label: 'Parsing Fossil' },
  POLICY_FAIL: { hue: 48, label: 'Policy Fossil' },
  SIG_FAIL: { hue: 15, label: 'Signature Fossil' },
  PREVOUT_MISSING: { hue: 8, label: 'Prevout Fossil' },
  UNCLASSIFIED: { hue: 30, label: 'Unclassified Fossil' },
};

const app = document.querySelector('#app');
app.innerHTML = `
  <main class="museum-shell">
    <section class="timeline-layer">
      <div class="timeline-backdrop"></div>
      <div class="timeline-header">
        <h1>Quirk Museum Timeline</h1>
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
  </main>
`;

const timelineTrack = document.getElementById('timeline-track');
const glassScroller = document.getElementById('glass-scroller');
const summaryCard = document.getElementById('summary-card');
const bubbleGrid = document.getElementById('bubble-grid');
const detailPanel = document.getElementById('detail-panel');

let state = {
  data: null,
  epochs: [],
  selectedEpoch: '',
  selectedSpecimen: null,
};

init();

async function init() {
  const data = await fetch('./data.json').then((r) => r.json());
  state.data = data;
  state.epochs = data.epochs.map((e) => e.epoch);
  state.selectedEpoch = state.epochs[0] || '';
  renderTimeline();
  renderEpoch();
}

function renderTimeline() {
  timelineTrack.innerHTML = '';
  glassScroller.innerHTML = '';

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
  const epoch = state.selectedEpoch;
  const specimens = state.data.specimens.filter((s) => s.epoch === epoch);
  const epochSummary = state.data.epochs.find((e) => e.epoch === epoch);

  summaryCard.innerHTML = `
    <h2>${epoch}</h2>
    <div class="metrics">
      <div><span>Total</span><strong>${epochSummary?.total_events ?? specimens.length}</strong></div>
      <div><span>Classes</span><strong>${Object.keys(epochSummary?.counts_by_normalized_class || {}).length}</strong></div>
      <div><span>Labeled</span><strong>${specimens.filter((s) => s.label).length}</strong></div>
    </div>
    <div class="class-row">
      ${Object.entries(epochSummary?.counts_by_normalized_class || {})
        .map(([klass, count]) => `<span class="class-pill class-${klass}">${klass}: ${count}</span>`)
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
      <strong>${specimen.label || specimen.normalized_class}</strong>
      <small>${truncate(specimen.specimen_id, 20)}</small>
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
    <h2>${specimen.label || specimen.normalized_class}</h2>
    <p><strong>Specimen:</strong> <code>${specimen.specimen_id}</code></p>
    <p><strong>Testcase:</strong> <code>${specimen.testcase_id}</code></p>
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

function truncate(v, max) {
  return v.length <= max ? v : `${v.slice(0, max)}...`;
}

function escapeHtml(s) {
  return String(s)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}
