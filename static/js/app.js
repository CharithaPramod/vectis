// ── status cycling: untested -> pass -> fail -> na -> untested ──
const CYCLE = ['untested', 'pass', 'fail', 'na'];
const GLYPH = { untested: '', pass: '✓', fail: '✕', na: 'N/A' };

let currentFilterStatus = 'all';
let currentFilterSev = 'all';
let currentSearchQuery = '';
let currentFilterEndpointId = null;

function nextStatus(cur) {
  const i = CYCLE.indexOf(cur);
  return CYCLE[(i + 1) % CYCLE.length];
}

function applyProjectStatusUI(cb, status) {
  cb.classList.remove('pass', 'fail', 'na');
  if (status !== 'untested') cb.classList.add(status);
  cb.textContent = GLYPH[status];
  cb.dataset.status = status;

  const ci = cb.closest('.ci');
  ci.dataset.status = status;
  const cl = ci.querySelector('.cl');
  cl.classList.remove('pass', 'fail');
  if (status === 'pass' || status === 'fail') cl.classList.add(status);

  // show/hide CVSS row
  const cvssRow = ci.querySelector('.cvss-row');
  if (cvssRow) {
    cvssRow.style.display = (status === 'fail') ? 'flex' : 'none';
  }

  if (status !== 'untested') {
    ci.classList.add('tested');
  } else {
    ci.classList.remove('tested');
  }

  if (status === 'fail') {
    ci.classList.add('expanded');
    initCommandBoxes(ci);
  }
}

function cycleProjectStatus(cb, projectId, vulnId) {
  const status = nextStatus(cb.dataset.status || 'untested');
  applyProjectStatusUI(cb, status);

  fetch(`/api/project/${projectId}/checklist/${vulnId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  })
  .then(r => r.json())
  .then(data => {
    if (data.endpoint_vulns) {
      updateSitemapBadges(data.endpoint_vulns);
    }
    refreshStatsCounters();
  });
}

function saveProjectNotes(textarea, projectId, vulnId) {
  fetch(`/api/project/${projectId}/checklist/${vulnId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: textarea.value })
  }).then(() => flashSaved(textarea));
}

function saveProjectCvss(input, projectId, vulnId) {
  fetch(`/api/project/${projectId}/checklist/${vulnId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cvss: input.value })
  }).then(() => {
    const hint = input.parentElement.querySelector('.save-hint');
    if (hint) { hint.classList.add('show'); setTimeout(() => hint.classList.remove('show'), 1200); }
  });
}

// ── affected endpoints manager ─────────────────────────────────
function attachSelectedEndpoint(selectEl, projectId, vulnId) {
  const endpointId = parseInt(selectEl.value, 10);
  if (!endpointId) return;

  fetch(`/api/project/${projectId}/checklist/${vulnId}/affected-endpoints`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'add', endpoint_id: endpointId })
  })
  .then(r => r.json())
  .then(data => {
    renderAffectedChips(vulnId, data.affected_endpoints, data.custom_affected, projectId);
    if (data.endpoint_vulns) updateSitemapBadges(data.endpoint_vulns);
    selectEl.value = '';
  });
}

function removeAffectedEndpoint(projectId, vulnId, endpointId, btnEl) {
  fetch(`/api/project/${projectId}/checklist/${vulnId}/affected-endpoints`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'remove', endpoint_id: endpointId })
  })
  .then(r => r.json())
  .then(data => {
    renderAffectedChips(vulnId, data.affected_endpoints, data.custom_affected, projectId);
    if (data.endpoint_vulns) updateSitemapBadges(data.endpoint_vulns);
  });
}

function attachCustomEndpoint(inputEl, projectId, vulnId) {
  const customUrl = inputEl.value.trim();
  if (!customUrl) return;

  fetch(`/api/project/${projectId}/checklist/${vulnId}/affected-endpoints`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'add_custom', custom_url: customUrl })
  })
  .then(r => r.json())
  .then(data => {
    renderAffectedChips(vulnId, data.affected_endpoints, data.custom_affected, projectId);
    inputEl.value = '';
  });
}

function removeCustomAffectedEndpoint(projectId, vulnId, customUrl, btnEl) {
  fetch(`/api/project/${projectId}/checklist/${vulnId}/affected-endpoints`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'remove_custom', custom_url: customUrl })
  })
  .then(r => r.json())
  .then(data => {
    renderAffectedChips(vulnId, data.affected_endpoints, data.custom_affected, projectId);
  });
}

function renderAffectedChips(vulnId, affectedEps, customEps, projectId) {
  const container = document.getElementById(`affChips-${vulnId}`);
  if (!container) return;

  const ci = container.closest('.ci');
  const affIds = affectedEps.map(e => e.id);
  if (ci) ci.dataset.affectedIds = JSON.stringify(affIds);

  container.innerHTML = '';
  affectedEps.forEach(ep => {
    const chip = document.createElement('span');
    chip.className = 'affected-ep-chip';
    chip.dataset.endpointId = ep.id;
    chip.innerHTML = `
      <span class="method-tag method-${ep.method}">${ep.method}</span>
      <span class="chip-path">${ep.path}</span>
      <button type="button" class="btn-ep-remove" onclick="removeAffectedEndpoint(${projectId}, '${vulnId}', ${ep.id}, this)" title="Remove endpoint">✕</button>
    `;
    container.appendChild(chip);
  });

  (customEps || []).forEach(cUrl => {
    const chip = document.createElement('span');
    chip.className = 'affected-ep-chip custom-chip';
    chip.dataset.customUrl = cUrl;
    chip.innerHTML = `
      <span class="method-tag method-CUSTOM">URL</span>
      <span class="chip-path">${cUrl}</span>
      <button type="button" class="btn-ep-remove" onclick="removeCustomAffectedEndpoint(${projectId}, '${vulnId}', '${cUrl}', this)" title="Remove endpoint">✕</button>
    `;
    container.appendChild(chip);
  });

  const total = affectedEps.length + (customEps ? customEps.length : 0);
  const summaryEl = document.getElementById(`affSummary-${vulnId}`);
  if (summaryEl) {
    summaryEl.textContent = (total > 0) ? `🎯 ${total} affected endpoint(s)` : '';
  }
}

function updateSitemapBadges(endpointVulns) {
  for (const [epId, counts] of Object.entries(endpointVulns)) {
    const badgeContainer = document.getElementById(`epBadges-${epId}`);
    if (!badgeContainer) continue;

    let html = '';
    if (counts.critical > 0) html += `<span class="sev-badge-sm sev-critical" title="Critical: ${counts.critical}">${counts.critical}C</span>`;
    if (counts.high > 0) html += `<span class="sev-badge-sm sev-high" title="High: ${counts.high}">${counts.high}H</span>`;
    if (counts.medium > 0) html += `<span class="sev-badge-sm sev-medium" title="Medium: ${counts.medium}">${counts.medium}M</span>`;
    if (counts.low > 0) html += `<span class="sev-badge-sm sev-low" title="Low: ${counts.low}">${counts.low}L</span>`;
    if (counts.total === 0) html += `<span class="sev-badge-sm sev-clean" title="No vulnerabilities attached">clean</span>`;

    badgeContainer.innerHTML = html;
  }
}

function refreshStatsCounters() {
  const total = document.querySelectorAll('.ci').length;
  const tested = document.querySelectorAll('.cb.pass, .cb.fail, .cb.na').length;
  const failed = document.querySelectorAll('.cb.fail').length;

  const testedEl = document.getElementById('statTested');
  const failedEl = document.getElementById('statFailed');
  const pctEl = document.getElementById('statPct');

  if (testedEl) testedEl.textContent = tested;
  if (failedEl) failedEl.textContent = failed;
  if (pctEl) pctEl.textContent = `${total ? Math.round(100 * tested / total) : 0}%`;
}

// ── notes auto-expansion & utilities ────────────────────────────
function autoResizeTextarea(textarea) {
  if (!textarea) return;
  textarea.style.height = 'auto';
  const isExpandedLarge = textarea.classList.contains('expanded-large');
  const computedMin = isExpandedLarge ? 280 : 85;
  const computedMax = isExpandedLarge ? 750 : 460;
  const newHeight = Math.min(Math.max(textarea.scrollHeight + 4, computedMin), computedMax);
  textarea.style.height = `${newHeight}px`;
}

function toggleNotesSize(btn) {
  const box = btn.closest('.notes-wrapper') || btn.closest('.ci');
  const textarea = box ? box.querySelector('.notes-area') : null;
  if (!textarea) return;
  textarea.classList.toggle('expanded-large');
  autoResizeTextarea(textarea);
  btn.textContent = textarea.classList.contains('expanded-large') ? '🗗 Compact' : '🗖 Expand';
}

function copyNotesContent(btn) {
  const box = btn.closest('.notes-wrapper') || btn.closest('.ci');
  const textarea = box ? box.querySelector('.notes-area') : null;
  if (!textarea || !textarea.value.trim()) return;
  navigator.clipboard.writeText(textarea.value.trim()).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1200);
  });
}

// ── checklist item expand & tabs ────────────────────────────────
function toggleExpand(clEl) {
  const ci = clEl.closest('.ci');
  ci.classList.toggle('expanded');
  if (ci.classList.contains('expanded')) {
    initCommandBoxes(ci);
    ci.querySelectorAll('.notes-area').forEach(autoResizeTextarea);
  }
}

// ── filters: status, severity, search, endpoint ─────────────────
function filterChecksByStatus(status, btnEl) {
  currentFilterStatus = status;
  document.querySelectorAll('[data-status-filter]').forEach(b => b.classList.toggle('active', b === btnEl));
  applyAllFilters();
}

function filterChecksBySev(sev, btnEl) {
  currentFilterSev = sev;
  document.querySelectorAll('[data-sev-filter]').forEach(b => b.classList.toggle('active', b === btnEl));
  applyAllFilters();
}

function filterChecksBySearch(query) {
  currentSearchQuery = query.trim().toLowerCase();
  applyAllFilters();
}

function filterChecklistByEndpoint(endpointId, method, path) {
  currentFilterEndpointId = endpointId;
  document.querySelectorAll('.ep-row').forEach(row => {
    row.classList.toggle('active', parseInt(row.dataset.endpointId, 10) === endpointId);
  });

  const banner = document.getElementById('activeEndpointBanner');
  const nameEl = document.getElementById('activeEndpointName');
  if (banner && nameEl) {
    nameEl.textContent = `${method} ${path}`;
    banner.style.display = 'flex';
  }

  applyAllFilters();
}

function clearEndpointFilter() {
  currentFilterEndpointId = null;
  document.querySelectorAll('.ep-row').forEach(row => row.classList.remove('active'));
  const banner = document.getElementById('activeEndpointBanner');
  if (banner) banner.style.display = 'none';
  applyAllFilters();
}

function applyAllFilters() {
  document.querySelectorAll('.ph-block').forEach(ph => {
    let anyVisible = false;
    ph.querySelectorAll('.ci').forEach(ci => {
      const status = ci.dataset.status || 'untested';
      const sev = (ci.dataset.sev || 'info').toLowerCase();
      const text = ci.textContent.toLowerCase();

      let matchStatus = (currentFilterStatus === 'all') || (currentFilterStatus === status);
      let matchSev = (currentFilterSev === 'all') || (currentFilterSev === sev);
      let matchSearch = (!currentSearchQuery || text.includes(currentSearchQuery));
      let matchEndpoint = true;

      if (currentFilterEndpointId !== null) {
        try {
          const affIds = JSON.parse(ci.dataset.affectedIds || '[]');
          matchEndpoint = affIds.includes(currentFilterEndpointId);
        } catch (e) {
          matchEndpoint = false;
        }
      }

      const isVisible = matchStatus && matchSev && matchSearch && matchEndpoint;
      ci.style.display = isVisible ? 'block' : 'none';
      if (isVisible) anyVisible = true;
    });
    ph.style.display = anyVisible ? 'block' : 'none';
  });
}

// ── recommendation to notes helper ──────────────────────────────
function copyRecomToNotes(btn) {
  const ci = btn.closest('.ci');
  const recomText = ci.querySelector('.recom-text').textContent.trim();
  const textarea = ci.querySelector('.notes-area');
  if (!textarea) return;

  const addition = `[Remediation Recommendation]\n${recomText}`;
  if (textarea.value.trim()) {
    textarea.value = `${textarea.value.trim()}\n\n${addition}`;
  } else {
    textarea.value = addition;
  }
  autoResizeTextarea(textarea);
  textarea.dispatchEvent(new Event('blur'));

  const orig = btn.textContent;
  btn.textContent = '✓ Inserted!';
  setTimeout(() => { btn.textContent = orig; }, 1200);
}

// ── API Vault & Secrets Storage Engine ───────────────────────────
function getApiVault() {
  try {
    return JSON.parse(localStorage.getItem('webpt_api_vault') || '{}');
  } catch (e) {
    return {};
  }
}

function saveApiVault(vault) {
  localStorage.setItem('webpt_api_vault', JSON.stringify(vault || {}));
}

function getApiKeyForParam(param) {
  if (!param) return '';
  const vault = getApiVault();
  const p = param.trim();
  const pUpper = p.toUpperCase();

  if (vault[p]) return vault[p];
  if (vault[pUpper]) return vault[pUpper];

  if (pUpper === 'TOKEN' || pUpper === 'BEARER' || pUpper === 'USER_TOKEN' || pUpper === 'AUTH_TOKEN' || pUpper === 'AUTH_HEADER') {
    return vault['TOKEN'] || vault['BEARER_TOKEN'] || '';
  }
  if (pUpper === 'API_KEY' || pUpper === 'KEY') {
    return vault['API_KEY'] || '';
  }
  if (pUpper === 'SHODAN_API_KEY' || pUpper === 'SHODAN_KEY') {
    return vault['SHODAN_API_KEY'] || '';
  }
  if (pUpper === 'HUNTER_API_KEY' || pUpper === 'HUNTER_KEY') {
    return vault['HUNTER_API_KEY'] || '';
  }
  if (pUpper === 'SECURITYTRAILS_API_KEY' || pUpper === 'SECURITYTRAILS_KEY') {
    return vault['SECURITYTRAILS_API_KEY'] || '';
  }
  if (pUpper === 'VIRUSTOTAL_API_KEY' || pUpper === 'VT_KEY') {
    return vault['VIRUSTOTAL_API_KEY'] || '';
  }
  if (pUpper === 'GITHUB_TOKEN' || pUpper === 'GIT_TOKEN') {
    return vault['GITHUB_TOKEN'] || '';
  }
  if (pUpper === 'AWS_ACCESS_KEY_ID' || pUpper === 'AWS_KEY') {
    return vault['AWS_ACCESS_KEY_ID'] || '';
  }
  if (pUpper === 'AWS_SECRET_ACCESS_KEY' || pUpper === 'AWS_SECRET') {
    return vault['AWS_SECRET_ACCESS_KEY'] || '';
  }
  if (pUpper === 'AWS_DEFAULT_REGION' || pUpper === 'AWS_REGION') {
    return vault['AWS_DEFAULT_REGION'] || 'us-east-1';
  }
  if (pUpper === 'OPENAI_API_KEY') {
    return vault['OPENAI_API_KEY'] || '';
  }
  if (pUpper === 'ANTHROPIC_API_KEY') {
    return vault['ANTHROPIC_API_KEY'] || '';
  }
  return '';
}

function openApiVaultModal() {
  const modal = document.getElementById('apiVaultModal');
  if (!modal) return;
  const vault = getApiVault();

  ['SHODAN_API_KEY', 'SECURITYTRAILS_API_KEY', 'HUNTER_API_KEY', 'VIRUSTOTAL_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET', 'GITHUB_TOKEN', 'TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'].forEach(k => {
    const el = document.getElementById('vault_' + k);
    if (el) el.value = vault[k] || '';
  });

  const customCont = document.getElementById('customVaultRows');
  if (customCont) {
    customCont.innerHTML = '';
    const knownSet = new Set(['SHODAN_API_KEY', 'SECURITYTRAILS_API_KEY', 'HUNTER_API_KEY', 'VIRUSTOTAL_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET', 'GITHUB_TOKEN', 'TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY']);
    Object.entries(vault).forEach(([k, v]) => {
      if (!knownSet.has(k) && k) {
        addCustomVaultRow(k, v);
      }
    });
  }

  const notice = document.getElementById('vaultSaveNotice');
  if (notice) notice.style.display = 'none';
  modal.style.display = 'flex';
}

function closeApiVaultModal() {
  const modal = document.getElementById('apiVaultModal');
  if (modal) modal.style.display = 'none';
}

function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
}

function addCustomVaultRow(key = '', val = '') {
  const cont = document.getElementById('customVaultRows');
  if (!cont) return;
  const row = document.createElement('div');
  row.className = 'custom-vault-row';
  row.innerHTML = `
    <input type="text" placeholder="KEY_NAME (e.g. SLACK_WEBHOOK)" value="${escapeHtml(key)}" class="custom-vault-key" style="flex:1">
    <input type="text" placeholder="VALUE" value="${escapeHtml(val)}" class="custom-vault-val" style="flex:2">
    <button type="button" class="btn-micro" onclick="this.parentElement.remove()" style="color:var(--red)">✕</button>
  `;
  cont.appendChild(row);
}

function saveApiVaultFromModal() {
  const vault = getApiVault();
  ['SHODAN_API_KEY', 'SECURITYTRAILS_API_KEY', 'HUNTER_API_KEY', 'VIRUSTOTAL_API_KEY', 'CENSYS_API_ID', 'CENSYS_API_SECRET', 'GITHUB_TOKEN', 'TOKEN', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_DEFAULT_REGION', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY'].forEach(k => {
    const el = document.getElementById('vault_' + k);
    if (el) vault[k] = el.value.trim();
  });

  document.querySelectorAll('#customVaultRows .custom-vault-row').forEach(row => {
    const k = (row.querySelector('.custom-vault-key')?.value || '').trim().toUpperCase();
    const v = (row.querySelector('.custom-vault-val')?.value || '').trim();
    if (k) vault[k] = v;
  });

  saveApiVault(vault);

  const notice = document.getElementById('vaultSaveNotice');
  if (notice) {
    notice.style.display = 'inline-block';
    setTimeout(() => { if (notice) notice.style.display = 'none'; }, 2500);
  }

  // Update open command boxes
  document.querySelectorAll('.tool-cmd-box').forEach(box => {
    const inputs = box.querySelectorAll('.param-input');
    inputs.forEach(inp => {
      const v = inp.dataset.var;
      const vaultVal = getApiKeyForParam(v);
      if (vaultVal && (!inp.value || inp.value.includes('...'))) {
        inp.value = vaultVal;
      }
    });
    updateRenderedCommand(box);
  });
}

// ── tool & command parameter interpolation engine ───────────────
function extractParamsFromTemplate(tmpl) {
  const matches = tmpl.match(/\{\{([A-Za-z0-9_]+)\}\}/g) || [];
  return [...new Set(matches.map(m => m.replace(/[\{\}]/g, '')))];
}

function getDefaultParamValue(param, box) {
  const url = box.dataset.url || '';
  const host = box.dataset.host || '';
  const method = box.dataset.method || 'GET';
  const path = box.dataset.path || '/';
  const target = box.dataset.target || '';

  // Check stored API vault first
  const vaultVal = getApiKeyForParam(param);
  if (vaultVal) return vaultVal;

  let inferredHost = host;
  let inferredPort = '443';
  if (url && url.startsWith('http')) {
    try {
      const u = new URL(url);
      inferredHost = u.hostname;
      inferredPort = u.port || (u.protocol === 'https:' ? '443' : '80');
    } catch (e) {}
  } else if (target && target.startsWith('http')) {
    try {
      const u = new URL(target);
      inferredHost = u.hostname;
      inferredPort = u.port || (u.protocol === 'https:' ? '443' : '80');
    } catch (e) {}
  }

  const pUpper = param.toUpperCase();
  if (pUpper === 'URL' || pUpper === 'TARGET_URL') return url || target || 'https://target.com';
  if (pUpper === 'HOST' || pUpper === 'TARGET_HOST') return inferredHost || target || 'target.com';
  if (pUpper === 'PORT') return inferredPort;
  if (pUpper === 'METHOD') return method || 'GET';
  if (pUpper === 'PATH') return path || '/';
  if (pUpper === 'TARGET') return target || url || 'target.com';
  if (pUpper === 'PACKAGE' || pUpper === 'PACKAGE_NAME') return target.includes('.') && !target.startsWith('http') ? target : 'com.example.app';
  if (pUpper === 'BUNDLE_ID') return target.includes('.') && !target.startsWith('http') ? target : 'com.example.app';
  if (pUpper === 'APK_FILE') return 'app-release.apk';
  if (pUpper === 'BINARY_PATH') return '/Payload/App.app/App';
  if (pUpper === 'TOKEN' || pUpper === 'BEARER' || pUpper === 'USER_TOKEN') return 'eyJhbGciOi...';
  if (pUpper === 'SCHEME') return 'myapp';
  if (pUpper === 'ACTIVITY_NAME') return '.MainActivity';
  if (pUpper === 'RECEIVER_NAME') return '.PushReceiver';
  return param.toLowerCase();
}

function initCommandBoxes(root) {
  root = root || document;
  root.querySelectorAll('.tool-cmd-box').forEach(box => {
    const tmpl = box.dataset.template;
    if (!tmpl) return;

    const paramRow = box.querySelector('.param-inputs-row');
    const codeEl = box.querySelector('.cmd-rendered-code');
    if (!paramRow || !codeEl) return;

    if (paramRow.children.length === 0) {
      const params = extractParamsFromTemplate(tmpl);
      params.forEach(param => {
        const val = getDefaultParamValue(param, box);
        const item = document.createElement('div');
        item.className = 'param-item';
        item.innerHTML = `
          <label class="param-label">{{${param}}}</label>
          <input type="text" class="param-input" data-var="${param}" value="${escapeHtml(val)}">
        `;
        item.querySelector('input').addEventListener('input', () => updateRenderedCommand(box));
        paramRow.appendChild(item);
      });
    }

    updateRenderedCommand(box);
  });
}

function updateRenderedCommand(box) {
  let tmpl = box.dataset.template || '';
  const inputs = box.querySelectorAll('.param-input');
  inputs.forEach(input => {
    const v = input.dataset.var;
    const val = input.value || '';
    const regex = new RegExp(`\\{\\{${v}\\}\\}`, 'g');
    tmpl = tmpl.replace(regex, val);
  });
  const codeEl = box.querySelector('.cmd-rendered-code');
  if (codeEl) codeEl.textContent = tmpl;
}

function copyRenderedCommand(btn) {
  const box = btn.closest('.tool-cmd-box');
  const codeEl = box.querySelector('.cmd-rendered-code');
  if (!codeEl) return;

  const text = codeEl.textContent.trim();
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = '✓ COPIED!';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1500);
  }).catch(err => {
    alert('Failed to copy: ' + err);
  });
}

// ── sitemap tree helper ─────────────────────────────────────────
function toggleNode(hdr) {
  const node = hdr.parentElement;
  node.classList.toggle('open');
  const kids = node.querySelector(':scope > .node-children');
  if (kids) kids.style.display = node.classList.contains('open') ? 'block' : 'none';
  const caret = hdr.querySelector('.caret');
  if (caret) caret.textContent = node.classList.contains('open') ? '▾' : '▸';
}

function filterTree(q) {
  q = q.trim().toLowerCase();
  document.querySelectorAll('.ep-row').forEach(row => {
    const path = (row.querySelector('.ep-path').getAttribute('title') || '').toLowerCase();
    row.style.display = (!q || path.includes(q)) ? 'flex' : 'none';
  });
  if (q) {
    document.querySelectorAll('.node').forEach(n => {
      n.classList.add('open');
      const kids = n.querySelector(':scope > .node-children');
      if (kids) kids.style.display = 'block';
      const caret = n.querySelector(':scope > .node-hdr > .caret');
      if (caret) caret.textContent = '▾';
    });
  }
}

// ── WebPT Integrated Terminal & Process Runner Engine ───────────
let currentTerminalContext = {
  projectId: null,
  vulnId: null,
  checkName: '',
  command: '',
  processId: null,
  rawOutput: '',             // Cumulative session history for terminal display
  currentSectionOutput: '',  // Output of the currently running command section
  lastSectionOutput: '',     // Output of the latest finished command section
  currentSectionCommand: '', // Command text for current/latest section
  currentSectionVulnId: null,
  currentSectionProjectId: null,
  currentSectionEl: null,
  currentSectionContentEl: null,
  previewUrl: '',
  assessmentDir: '',
  assessmentName: '',
  autoSave: true,
  isRunning: false,
  timerInterval: null,
  startTime: null
};

let pendingExecution = null;

// ANSI Color Code to HTML Parser
function ansiToHtml(text) {
  if (!text) return '';
  
  let escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const ansiMap = {
    '0': '</span>',
    '1': '<span class="ansi-bold">',
    '2': '<span class="ansi-dim">',
    '30': '<span class="ansi-black">',
    '31': '<span class="ansi-red">',
    '32': '<span class="ansi-green">',
    '33': '<span class="ansi-yellow">',
    '34': '<span class="ansi-blue">',
    '35': '<span class="ansi-magenta">',
    '36': '<span class="ansi-cyan">',
    '37': '<span class="ansi-white">',
    '90': '<span class="ansi-gray">',
    '91': '<span class="ansi-red-bright">',
    '92': '<span class="ansi-green-bright">',
    '93': '<span class="ansi-yellow-bright">',
    '94': '<span class="ansi-blue-bright">',
    '95': '<span class="ansi-magenta-bright">',
    '96': '<span class="ansi-cyan-bright">',
    '97': '<span class="ansi-white-bright">'
  };

  let html = escaped.replace(/\u001b\[([0-9;]+)m|\033\[([0-9;]+)m/g, (match, p1, p2) => {
    const codes = (p1 || p2 || '').split(';');
    let spanTags = '';
    for (const code of codes) {
      if (ansiMap[code]) {
        spanTags += ansiMap[code];
      }
    }
    return spanTags || '';
  });

  return html;
}

function stripAnsi(text) {
  return (text || '').replace(/\u001b\[[0-9;]*m|\033\[[0-9;]*m/g, '');
}

function openTerminalDrawer() {
  const drawer = document.getElementById('terminalDrawer');
  const floating = document.getElementById('floatingTermToggle');
  if (drawer) drawer.classList.add('open');
  if (floating) floating.style.display = 'none';
}

function closeTerminalDrawer() {
  const drawer = document.getElementById('terminalDrawer');
  const floating = document.getElementById('floatingTermToggle');
  if (drawer) drawer.classList.remove('open', 'maximized');
  if (floating) floating.style.display = 'flex';
}

function toggleTerminalDrawer() {
  const drawer = document.getElementById('terminalDrawer');
  if (drawer && drawer.classList.contains('open')) {
    closeTerminalDrawer();
  } else {
    openTerminalDrawer();
  }
}

function toggleMaximizeTerminal() {
  const drawer = document.getElementById('terminalDrawer');
  const btn = document.getElementById('btnMaximizeTerminal');
  if (!drawer) return;
  drawer.classList.toggle('maximized');
  if (btn) {
    btn.textContent = drawer.classList.contains('maximized') ? '🗗 RESTORE' : '🗖 EXPAND';
  }
}

function clearTerminal() {
  const out = document.getElementById('terminalOutput');
  if (out) out.innerHTML = '';
  currentTerminalContext.rawOutput = '';
  currentTerminalContext.currentSectionOutput = '';
  currentTerminalContext.lastSectionOutput = '';
  currentTerminalContext.currentSectionEl = null;
  currentTerminalContext.currentSectionContentEl = null;
  setTerminalStatus('IDLE', 'idle');
  updateTerminalTargetInfo();
  hideInteractivePromptBanner();
}

function setTerminalStatus(text, type) {
  const badge = document.getElementById('terminalStatus');
  const floatStatus = document.getElementById('floatingTermStatus');
  const floatDot = document.querySelector('#floatingTermToggle .term-dot');
  
  if (badge) {
    badge.textContent = `● ${text}`;
    badge.className = `term-status-badge ${type}`;
  }
  if (floatStatus) floatStatus.textContent = text;
  if (floatDot) {
    floatDot.className = `term-dot ${type}`;
  }
}

function updateTerminalTargetInfo() {
  const infoEl = document.getElementById('terminalTargetInfo');
  if (!infoEl) return;
  if (currentTerminalContext.vulnId) {
    infoEl.textContent = `Check: ${currentTerminalContext.vulnId} ${currentTerminalContext.checkName ? '— ' + currentTerminalContext.checkName : ''}`;
  } else {
    infoEl.textContent = '';
  }
}

function toggleAutoSaveNotes(checked) {
  currentTerminalContext.autoSave = checked;
  localStorage.setItem('webpt_term_autosave', checked ? 'true' : 'false');
}

// ── Run Script from Card & Pre-Execution Key Verification ─────────
function runScriptCommand(btn, projectId, vulnId) {
  const box = btn.closest('.tool-cmd-box');
  if (!box) return;

  updateRenderedCommand(box);
  const codeEl = box.querySelector('.cmd-rendered-code');
  let command = codeEl ? codeEl.textContent.trim() : '';

  if (!command) {
    alert('No command rendered to execute.');
    return;
  }

  const ci = btn.closest('.ci');
  const checkName = ci ? (ci.querySelector('.cl-title')?.textContent || '').trim() : '';
  const targetUrl = box.dataset.url || box.dataset.target || '';

  // Check for missing API keys or default placeholder values
  const missingKeys = [];
  const inputs = box.querySelectorAll('.param-input');
  inputs.forEach(inp => {
    const v = inp.dataset.var;
    const val = (inp.value || '').trim();
    const isKeyParam = /^(API_KEY|TOKEN|BEARER|SHODAN|HUNTER|SECURITYTRAILS|VIRUSTOTAL|GITHUB|AWS_SECRET|AWS_KEY|PASSWORD|SECRET|ACCESS_KEY)/i.test(v);
    const isPlaceholder = !val || val === 'eyJhbGciOi...' || val === 'shodan_key' || val === 'hunter_key' || val === 'vt_key' || val === 'your-api-key' || val === 'secret_key';

    if (isKeyParam && isPlaceholder) {
      missingKeys.push({ varName: v, currentVal: val });
    }
  });

  if (missingKeys.length > 0) {
    pendingExecution = {
      box: box,
      projectId: projectId,
      vulnId: vulnId,
      checkName: checkName,
      targetUrl: targetUrl,
      missingKeys: missingKeys
    };
    openKeyPromptModal(missingKeys);
    return;
  }

  startTerminalExecution(projectId, vulnId, checkName, targetUrl, command);
}

function openKeyPromptModal(missingKeys) {
  const modal = document.getElementById('keyPromptModal');
  const list = document.getElementById('keyPromptFieldsList');
  if (!modal || !list) return;

  list.innerHTML = '';
  missingKeys.forEach(item => {
    const stored = getApiKeyForParam(item.varName);
    const row = document.createElement('div');
    row.className = 'field';
    row.innerHTML = `
      <label style="color:var(--cyan);font-weight:bold">${escapeHtml(item.varName)} (API Key / Token):</label>
      <input type="text" class="key-prompt-input" data-var="${escapeHtml(item.varName)}" value="${escapeHtml(stored || '')}" placeholder="Enter ${escapeHtml(item.varName)} for execution...">
    `;
    list.appendChild(row);
  });

  modal.style.display = 'flex';
}

function closeKeyPromptModal() {
  const modal = document.getElementById('keyPromptModal');
  if (modal) modal.style.display = 'none';
  pendingExecution = null;
}

function confirmKeyPromptAndRun() {
  if (!pendingExecution) return;
  const modal = document.getElementById('keyPromptModal');
  const inputs = modal.querySelectorAll('.key-prompt-input');
  const saveToVault = document.getElementById('chkSaveKeyToVault')?.checked;
  const vault = getApiVault();

  inputs.forEach(inp => {
    const v = inp.dataset.var;
    const val = inp.value.trim();
    if (val) {
      if (saveToVault) vault[v] = val;
      const cardInput = pendingExecution.box.querySelector(`.param-input[data-var="${v}"]`);
      if (cardInput) cardInput.value = val;
    }
  });

  if (saveToVault) saveApiVault(vault);
  updateRenderedCommand(pendingExecution.box);
  const codeEl = pendingExecution.box.querySelector('.cmd-rendered-code');
  const command = codeEl ? codeEl.textContent.trim() : '';

  const { projectId, vulnId, checkName, targetUrl } = pendingExecution;
  closeKeyPromptModal();
  startTerminalExecution(projectId, vulnId, checkName, targetUrl, command);
}

function startTerminalExecution(projectId, vulnId, checkName, targetUrl, command) {
  currentTerminalContext.projectId = projectId;
  currentTerminalContext.vulnId = vulnId;
  currentTerminalContext.checkName = checkName;
  currentTerminalContext.targetUrl = targetUrl;
  currentTerminalContext.command = command;

  openTerminalDrawer();
  updateTerminalTargetInfo();

  const isClickjack = vulnId === 'WSTG-CLNT-09' || command.includes('clickjacking') || (checkName || '').toLowerCase().includes('clickjack');
  const previewBtn = document.getElementById('btnTermPreview');
  if (previewBtn) {
    if (isClickjack || targetUrl) {
      previewBtn.style.display = 'inline-block';
      currentTerminalContext.previewUrl = isClickjack
        ? `/preview/clickjacking?url=${encodeURIComponent(targetUrl)}&project_id=${projectId}&vuln_id=${vulnId}`
        : `/preview/viewer?target=${encodeURIComponent(targetUrl)}`;
    } else {
      previewBtn.style.display = 'none';
    }
  }

  executeCommandInTerminal(command, projectId);
}

// ── Core SSE Execution Function ─────────────────────────────────
async function executeCommandInTerminal(command, projectId) {
  if (!command || !command.trim()) return;

  const outputEl = document.getElementById('terminalOutput');
  const stopBtn = document.getElementById('btnStopProcess');
  const inputEl = document.getElementById('termInteractiveInput');
  if (inputEl) inputEl.value = command;

  const pid = projectId || currentTerminalContext.projectId;
  const vid = currentTerminalContext.vulnId;

  // Initialize section state for this specific command execution
  currentTerminalContext.command = command;
  currentTerminalContext.currentSectionCommand = command;
  currentTerminalContext.currentSectionVulnId = vid;
  currentTerminalContext.currentSectionProjectId = pid;
  currentTerminalContext.currentSectionOutput = '';

  // Create isolated section container in terminal DOM
  const sectionEl = document.createElement('div');
  sectionEl.className = 'term-section';
  sectionEl.dataset.cmd = command;
  if (vid) sectionEl.dataset.vulnId = vid;
  if (pid) sectionEl.dataset.projectId = String(pid);

  const cmdHeader = document.createElement('div');
  cmdHeader.className = 'term-cmd-banner';
  cmdHeader.innerHTML = `
    <div class="cmd-run-info">
      <span class="cmd-run-icon">▶</span>
      <span class="cmd-run-text">$ ${escapeHtml(command)}</span>
      <span class="cmd-run-time">${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="cmd-run-actions">
      <button type="button" class="btn-micro" onclick="saveSpecificSectionToNotes(this)" title="Save only this command output to check notes">📝 Save Section</button>
      <button type="button" class="btn-micro" onclick="copySpecificSectionOutput(this)" title="Copy this command output to clipboard">📋 Copy</button>
    </div>
  `;
  sectionEl.appendChild(cmdHeader);

  const sectionContent = document.createElement('div');
  sectionContent.className = 'term-section-output';
  sectionEl.appendChild(sectionContent);

  outputEl.appendChild(sectionEl);
  currentTerminalContext.currentSectionEl = sectionEl;
  currentTerminalContext.currentSectionContentEl = sectionContent;

  currentTerminalContext.isRunning = true;
  currentTerminalContext.startTime = Date.now();
  currentTerminalContext.rawOutput += `\n$ ${command}\n`;

  if (stopBtn) stopBtn.style.display = 'inline-block';
  setTerminalStatus('RUNNING...', 'running');
  hideInteractivePromptBanner();

  const vault = getApiVault();

  try {
    const response = await fetch('/api/tools/run-command', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command: command,
        project_id: pid,
        api_keys: vault
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP Error ${response.status}: ${response.statusText}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const jsonStr = line.replace('data: ', '').trim();
        if (!jsonStr) continue;

        try {
          const evt = JSON.parse(jsonStr);
          handleStreamEvent(evt, outputEl);
        } catch (e) {
          console.error('Error parsing SSE event:', e, jsonStr);
        }
      }
    }
  } catch (err) {
    const errLine = document.createElement('div');
    errLine.className = 'term-line term-error';
    errLine.textContent = `[Execution Error]: ${err.message}`;
    if (currentTerminalContext.currentSectionContentEl) {
      currentTerminalContext.currentSectionContentEl.appendChild(errLine);
    } else {
      outputEl.appendChild(errLine);
    }
    setTerminalStatus('ERROR', 'error');
  } finally {
    currentTerminalContext.isRunning = false;
    if (stopBtn) stopBtn.style.display = 'none';
    hideInteractivePromptBanner();
  }
}

function handleStreamEvent(evt, outputEl) {
  const targetOutput = currentTerminalContext.currentSectionContentEl || outputEl;
  const currentSection = currentTerminalContext.currentSectionEl || outputEl;

  if (evt.type === 'start') {
    currentTerminalContext.processId = evt.process_id;
    currentTerminalContext.assessmentDir = evt.assessment_dir;
    currentTerminalContext.assessmentName = evt.assessment_name;

    const dirBadge = document.getElementById('termAssessmentDir');
    if (dirBadge && evt.assessment_name) {
      dirBadge.textContent = `📁 assessments/${evt.assessment_name}`;
      dirBadge.title = `Assessment dedicated folder: ${evt.assessment_dir}`;
    }
  } else if (evt.type === 'stdout' || evt.type === 'stderr') {
    const raw = evt.text || '';
    currentTerminalContext.currentSectionOutput += raw;
    currentTerminalContext.rawOutput += raw;

    const lineEl = document.createElement('div');
    lineEl.className = 'term-line';
    lineEl.innerHTML = ansiToHtml(raw);

    const urlMatch = raw.match(/https?:\/\/[^\s\)\"\']+/i);
    if (urlMatch && !currentTerminalContext.previewUrl) {
      currentTerminalContext.previewUrl = urlMatch[0];
      const previewBtn = document.getElementById('btnTermPreview');
      if (previewBtn) previewBtn.style.display = 'inline-block';
    }

    targetOutput.appendChild(lineEl);
    outputEl.scrollTop = outputEl.scrollHeight;

    // Check if process is requesting input / API key
    checkAndShowInteractivePrompt(raw);
  } else if (evt.type === 'exit') {
    const code = evt.code;
    const duration = evt.duration;
    const isSuccess = code === 0;

    currentTerminalContext.lastSectionOutput = currentTerminalContext.currentSectionOutput;

    hideInteractivePromptBanner();

    const exitEl = document.createElement('div');
    exitEl.className = `term-exit-banner ${isSuccess ? 'success' : 'failed'}`;
    exitEl.innerHTML = `
      <span>● Process finished with exit code <b>${code}</b></span>
      <span>⏱ Duration: <b>${duration}s</b></span>
      <span>📁 Output: <b>${escapeHtml(evt.assessment_dir || 'assessments/')}</b></span>
    `;
    currentSection.appendChild(exitEl);
    outputEl.scrollTop = outputEl.scrollHeight;

    setTerminalStatus(isSuccess ? `COMPLETED (${duration}s)` : `FAILED (code ${code})`, isSuccess ? 'pass' : 'fail');

    if (!isSuccess) {
      const failureInfo = detectScriptFailureReason(currentTerminalContext.currentSectionOutput || currentTerminalContext.rawOutput, code, currentTerminalContext.currentSectionCommand || currentTerminalContext.command);
      renderTerminalFailureRecovery(currentSection, failureInfo, code);
    }

    if (currentTerminalContext.autoSave && currentTerminalContext.currentSectionVulnId && currentTerminalContext.currentSectionProjectId) {
      autoSaveTerminalToNotes();
    }
  } else if (evt.type === 'error') {
    const lineEl = document.createElement('div');
    lineEl.className = 'term-line term-error';
    lineEl.textContent = `[System Error]: ${evt.text}`;
    targetOutput.appendChild(lineEl);
    outputEl.scrollTop = outputEl.scrollHeight;
    setTerminalStatus('ERROR', 'error');

    const failureInfo = detectScriptFailureReason(evt.text || '', 1, currentTerminalContext.currentSectionCommand || currentTerminalContext.command);
    renderTerminalFailureRecovery(currentSection, failureInfo, 1);
  }
}

// ── Script Failure Detection & In-Terminal Recovery Assistant ────
function detectScriptFailureReason(rawOutput, code, command) {
  const text = (rawOutput || '').toLowerCase();
  const cmd = (command || '').toLowerCase();

  // 1. Specific Recon / Threat Intel API Providers
  if (text.includes('shodan') || cmd.includes('shodan') || /shodan.*(key|unauthorized|invalid|401|403|require)/i.test(text)) {
    return {
      type: 'shodan_key',
      title: 'Shodan API Key / Authentication Error',
      description: 'Shodan reported an authentication or authorization failure. A valid SHODAN_API_KEY is required to query Shodan search & host endpoints.',
      keyVar: 'SHODAN_API_KEY'
    };
  }

  if (text.includes('hunter') || cmd.includes('hunter') || /hunter.*(key|unauthorized|invalid|401|403)/i.test(text)) {
    return {
      type: 'hunter_key',
      title: 'Hunter.io API Key / Auth Error',
      description: 'Hunter.io email enumeration failed due to missing or invalid credentials. A valid HUNTER_API_KEY is required.',
      keyVar: 'HUNTER_API_KEY'
    };
  }

  if (text.includes('securitytrails') || cmd.includes('securitytrails') || /securitytrails.*(key|unauthorized|invalid|401|403)/i.test(text)) {
    return {
      type: 'sectrails_key',
      title: 'SecurityTrails API Key Error',
      description: 'SecurityTrails reconnaissance failed. A valid SECURITYTRAILS_API_KEY is required.',
      keyVar: 'SECURITYTRAILS_API_KEY'
    };
  }

  if (text.includes('virustotal') || cmd.includes('virustotal') || /virustotal.*(key|unauthorized|invalid|401|403)/i.test(text)) {
    return {
      type: 'vt_key',
      title: 'VirusTotal API Key Error',
      description: 'VirusTotal threat intelligence query failed. A valid VIRUSTOTAL_API_KEY is required.',
      keyVar: 'VIRUSTOTAL_API_KEY'
    };
  }

  if (text.includes('censys') || cmd.includes('censys') || /censys.*(key|secret|id|unauthorized|401|403)/i.test(text)) {
    return {
      type: 'censys_key',
      title: 'Censys Credentials Error',
      description: 'Censys host query failed. A valid CENSYS_API_ID and CENSYS_API_SECRET are required.',
      keyVar: 'CENSYS_API_SECRET'
    };
  }

  if (text.includes('github') || cmd.includes('github') || /github.*(token|bad credentials|rate limit|401|403)/i.test(text)) {
    return {
      type: 'github_token',
      title: 'GitHub API Token Error',
      description: 'GitHub API request failed or was rate limited. A valid GITHUB_TOKEN is required.',
      keyVar: 'GITHUB_TOKEN'
    };
  }

  if (text.includes('aws') || cmd.includes('aws') || /(accessdenied|signaturedoesnotmatch|security token|credential|403)/i.test(text)) {
    return {
      type: 'aws_key',
      title: 'AWS Credentials / Permission Error',
      description: 'AWS CLI reported an authentication or permission error. Verify AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY.',
      keyVar: 'AWS_ACCESS_KEY_ID'
    };
  }

  if (text.includes('openai') || text.includes('anthropic') || /(sk-proj-|sk-ant-|openai_api_key|anthropic_api_key)/i.test(text)) {
    return {
      type: 'ai_key',
      title: 'AI / LLM API Key Error',
      description: 'AI model invocation failed due to invalid or missing credentials. Check OPENAI_API_KEY or ANTHROPIC_API_KEY.',
      keyVar: 'OPENAI_API_KEY'
    };
  }

  // 2. Generic HTTP 401/403 or Token/Key rejection
  if (/(401 unauthorized|403 forbidden|invalid token|token expired|bearer token required|missing authorization header|authentication failed|access denied|invalid api key|api key required|unauthorized)/i.test(text)) {
    return {
      type: 'auth_token',
      title: 'Authentication / Token Rejection (401/403)',
      description: 'The target server or API rejected the request due to missing, invalid, or expired authentication token / credentials.',
      keyVar: 'TOKEN'
    };
  }

  // 3. Network / Connection errors
  if (/(connection refused|name or service not known|could not resolve host|no route to host|network is unreachable|operation timed out|timed out)/i.test(text)) {
    return {
      type: 'network',
      title: 'Target Network / Host Unreachable',
      description: 'The target host could not be reached or timed out. Verify target URL, port, host routing, or proxy settings.',
      keyVar: null
    };
  }

  // 4. Missing tool / Binary error
  if (/(command not found|no such file or directory|executable file not found)/i.test(text)) {
    return {
      type: 'tool_missing',
      title: 'Command / Tool Not Found',
      description: 'The executable specified in the command is not installed or not present on the system PATH.',
      keyVar: null
    };
  }

  // 5. Generic Non-Zero Exit Failure
  return {
    type: 'generic_failure',
    title: `Script Execution Failed (Exit Code ${code})`,
    description: `The command encountered an error during execution. You can adjust API keys, reconfigure parameters, or edit the command below.`,
    keyVar: (cmd.includes('bearer') || cmd.includes('token') || cmd.includes('auth') || cmd.includes('-h "authorization')) ? 'TOKEN' : null
  };
}

function renderTerminalFailureRecovery(outputEl, detected, code) {
  const recoveryDiv = document.createElement('div');
  recoveryDiv.className = 'term-error-recovery-box';

  const storedKey = detected.keyVar ? (getApiKeyForParam(detected.keyVar) || '') : '';

  recoveryDiv.innerHTML = `
    <div class="recovery-hdr">
      <span class="recovery-icon">⚠️</span>
      <div class="recovery-title-wrap">
        <div class="recovery-title">// TROUBLESHOOT: ${escapeHtml(detected.title)}</div>
        <div class="recovery-desc">${escapeHtml(detected.description)}</div>
      </div>
    </div>
    <div class="recovery-body">
      ${detected.keyVar ? `
        <div class="recovery-input-row">
          <label class="recovery-lbl">🔑 CONFIGURE ${escapeHtml(detected.keyVar)} &amp; RETRY:</label>
          <div class="recovery-input-wrap">
            <input type="text" class="recovery-key-input" data-var="${escapeHtml(detected.keyVar)}" placeholder="Paste new / updated ${escapeHtml(detected.keyVar)} here..." value="${escapeHtml(storedKey)}">
            <button type="button" class="btn-recovery-apply" onclick="applyRecoveryKeyAndRerun(this, '${escapeHtml(detected.keyVar)}')">💾 SAVE &amp; RE-RUN</button>
          </div>
        </div>
      ` : ''}
      <div class="recovery-actions-row">
        <button type="button" class="btn-pill" onclick="editLastCommandInTerminal()">✏️ EDIT COMMAND</button>
        <button type="button" class="btn-pill" onclick="openApiVaultModal()">🔑 OPEN API VAULT</button>
        <button type="button" class="btn-pill" onclick="retryLastTerminalCommand()">🔄 RETRY EXACT SCRIPT</button>
      </div>
    </div>
  `;

  outputEl.appendChild(recoveryDiv);
  outputEl.scrollTop = outputEl.scrollHeight;
}

function applyRecoveryKeyAndRerun(btn, keyVar) {
  const box = btn.closest('.term-error-recovery-box');
  const input = box ? box.querySelector('.recovery-key-input') : null;
  const newVal = input ? input.value.trim() : '';

  if (!newVal) {
    alert(`Please enter a valid value for ${keyVar}.`);
    return;
  }

  // 1. Save to Vault
  const vault = getApiVault();
  vault[keyVar] = newVal;
  saveApiVault(vault);

  // 2. Update active checklist card if open
  if (currentTerminalContext.vulnId) {
    const cardInput = document.querySelector(`.ci[data-check-id="${currentTerminalContext.vulnId}"] .param-input[data-var="${keyVar}"]`);
    if (cardInput) cardInput.value = newVal;
  }

  // 3. Update rendered command if it contains the variable or older placeholder
  let cmd = currentTerminalContext.command || '';
  if (cmd.includes(`{{${keyVar}}}`)) {
    cmd = cmd.replace(new RegExp(`\\{\\{${keyVar}\\}\\}`, 'g'), newVal);
  }

  const outputEl = document.getElementById('terminalOutput');
  const noticeLine = document.createElement('div');
  noticeLine.className = 'term-line';
  noticeLine.style.color = 'var(--cyan)';
  noticeLine.innerHTML = `[Recovery] ✓ Updated <b>${escapeHtml(keyVar)}</b> in Vault &amp; Environment. Re-running script...`;
  if (outputEl) outputEl.appendChild(noticeLine);

  // 4. Re-execute command
  executeCommandInTerminal(cmd, currentTerminalContext.projectId);
}

function editLastCommandInTerminal() {
  const inputEl = document.getElementById('termInteractiveInput');
  if (!inputEl) return;
  inputEl.value = currentTerminalContext.command || '';
  inputEl.focus();
  inputEl.select();

  const outputEl = document.getElementById('terminalOutput');
  const noticeLine = document.createElement('div');
  noticeLine.className = 'term-line term-warning';
  noticeLine.textContent = '✏️ Command loaded into terminal prompt below. Edit parameters/flags and press Enter.';
  if (outputEl) {
    outputEl.appendChild(noticeLine);
    outputEl.scrollTop = outputEl.scrollHeight;
  }
}

function retryLastTerminalCommand() {
  if (!currentTerminalContext.command) return;
  executeCommandInTerminal(currentTerminalContext.command, currentTerminalContext.projectId);
}

// ── Interactive Stdin / Prompt Handling While Process Paused ─────
function checkAndShowInteractivePrompt(raw) {
  if (!raw || !currentTerminalContext.isRunning) return;
  const trimmed = raw.trim();

  // Pattern detecting when a running tool prompts for input (API key, password, choice, [y/n], etc.)
  const isPrompt = /(\b(api[_\s-]?key|token|password|enter|choice|continue|confirm|input|username|passphrase|secret)\b.*[:\?]\s*$|\[y\/n\]|\[\?\]|\(y\/n\))/i.test(trimmed) ||
                   (trimmed.length < 80 && (trimmed.endsWith(':') || trimmed.endsWith('?') || trimmed.endsWith('...')));

  if (isPrompt) {
    showInteractivePromptBanner(trimmed);
  }
}

function showInteractivePromptBanner(promptText) {
  const banner = document.getElementById('termPromptBanner');
  const txtEl = document.getElementById('termPromptText');
  const promptLine = document.querySelector('.prompt-line');
  const symEl = document.getElementById('termPromptSymbol');
  const execBtn = document.getElementById('btnTermExec');
  const inputEl = document.getElementById('termInteractiveInput');

  if (txtEl) txtEl.textContent = promptText;
  if (banner) banner.style.display = 'flex';
  if (promptLine) promptLine.classList.add('waiting-input');
  if (symEl) symEl.textContent = 'INPUT >';
  if (execBtn) execBtn.textContent = '💬 SEND INPUT';
  if (inputEl) {
    inputEl.placeholder = `Input required for: "${promptText.substring(0, 45)}..." (press Enter to send)`;
    inputEl.focus();
  }
}

function hideInteractivePromptBanner() {
  const banner = document.getElementById('termPromptBanner');
  const promptLine = document.querySelector('.prompt-line');
  const symEl = document.getElementById('termPromptSymbol');
  const execBtn = document.getElementById('btnTermExec');
  const inputEl = document.getElementById('termInteractiveInput');

  if (banner) banner.style.display = 'none';
  if (promptLine) promptLine.classList.remove('waiting-input');
  if (symEl) symEl.textContent = '$';
  if (execBtn) execBtn.textContent = 'EXECUTE';
  if (inputEl) inputEl.placeholder = 'Type shell command or script and press Enter (or click [▶ RUN SCRIPT])...';
}

function handleTerminalExecuteOrSend() {
  const inputEl = document.getElementById('termInteractiveInput');
  if (!inputEl) return;
  const val = inputEl.value;

  if (currentTerminalContext.isRunning) {
    sendInputToRunningProcess(val);
    inputEl.value = '';
  } else {
    executeInteractiveTerminalInput();
  }
}

function handleTerminalInputKey(e) {
  if (e.key === 'Enter') {
    handleTerminalExecuteOrSend();
  }
}

function executeInteractiveTerminalInput() {
  const input = document.getElementById('termInteractiveInput');
  if (!input || !input.value.trim()) return;
  const cmd = input.value.trim();
  executeCommandInTerminal(cmd, currentTerminalContext.projectId);
}

async function sendInputToRunningProcess(text) {
  if (!currentTerminalContext.processId) return;

  const outputEl = document.getElementById('terminalOutput');
  const targetOutput = currentTerminalContext.currentSectionContentEl || outputEl;
  const echoLine = document.createElement('div');
  echoLine.className = 'term-line';
  echoLine.style.color = 'var(--cyan)';
  echoLine.innerHTML = `&gt; <b>${escapeHtml(text)}</b>`;
  if (targetOutput) {
    targetOutput.appendChild(echoLine);
  }
  if (outputEl) {
    outputEl.scrollTop = outputEl.scrollHeight;
  }

  currentTerminalContext.currentSectionOutput += `> ${text}\n`;
  currentTerminalContext.rawOutput += `> ${text}\n`;

  try {
    await fetch('/api/tools/send-input', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        process_id: currentTerminalContext.processId,
        input: text
      })
    });
  } catch (e) {
    console.error('Error sending stdin input:', e);
  }
  hideInteractivePromptBanner();
}

function sendQuickInput(val) {
  sendInputToRunningProcess(val);
}

function quickSendStoredKey() {
  const vault = getApiVault();
  const keys = Object.entries(vault).filter(([k, v]) => v && v.length > 0);
  if (keys.length === 0) {
    openApiVaultModal();
    return;
  }

  const defaultVal = vault['TOKEN'] || vault['SHODAN_API_KEY'] || keys[0][1];
  const listStr = keys.map(([k, v]) => `• ${k}`).join('\n');
  const entered = prompt(`Select or enter API Key / Token to send to running script:\n\nAvailable keys in Vault:\n${listStr}`, defaultVal);
  if (entered !== null) {
    sendInputToRunningProcess(entered);
  }
}

function stopCurrentProcess() {
  if (!currentTerminalContext.processId) return;

  fetch('/api/tools/stop-command', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ process_id: currentTerminalContext.processId })
  })
  .then(r => r.json())
  .then(data => {
    setTerminalStatus('STOPPED', 'idle');
    const stopBanner = document.createElement('div');
    stopBanner.className = 'term-line term-warning';
    stopBanner.textContent = '⏹ Process was stopped by user.';
    const outputEl = document.getElementById('terminalOutput');
    if (outputEl) outputEl.appendChild(stopBanner);
    hideInteractivePromptBanner();
  });
}

// ── Assessment Artifacts Explorer Engine ─────────────────────────
function openArtifactsModal(projectId) {
  const pid = projectId || currentTerminalContext.projectId;
  if (!pid) return;
  const modal = document.getElementById('artifactsModal');
  if (modal) modal.style.display = 'flex';
  loadProjectArtifacts(pid);
}

function closeArtifactsModal() {
  const modal = document.getElementById('artifactsModal');
  if (modal) modal.style.display = 'none';
}

async function loadProjectArtifacts(projectId) {
  const listEl = document.getElementById('artifactsFilesList');
  const pathEl = document.getElementById('artifactsDirPath');
  if (!listEl) return;

  listEl.innerHTML = '<div style="text-align:center;color:var(--dim);padding:24px 0;font-size:11px">Scanning assessment artifacts directory...</div>';

  try {
    const res = await fetch(`/api/project/${projectId}/artifacts`);
    const data = await res.json();

    if (pathEl && data.assessment_dir) {
      pathEl.textContent = data.assessment_dir;
    }

    if (!data.files || data.files.length === 0) {
      listEl.innerHTML = `
        <div style="text-align:center;color:var(--dim);padding:30px 14px;border:1px dashed var(--border2);border-radius:4px;font-size:11px;line-height:1.6">
          📁 No files generated in this assessment directory yet.<br>
          Any scripts or tools producing output files (e.g. <code>nmap -oN</code>, <code>nikto -output</code>, <code>whatweb --log-json</code>, <code>sqlmap</code>) automatically store them in this dedicated folder!
        </div>
      `;
      return;
    }

    let html = '';
    data.files.forEach(f => {
      const ext = f.name.split('.').pop().toLowerCase();
      let icon = '📄';
      if (ext === 'json') icon = '📊';
      else if (ext === 'xml') icon = '📦';
      else if (ext === 'html' || ext === 'htm') icon = '🌐';
      else if (ext === 'pcap' || ext === 'cap') icon = '🛡️';
      else if (ext === 'apk') icon = '📱';
      else if (ext === 'txt' || ext === 'log') icon = '📝';

      const sizeKb = (f.size / 1024).toFixed(1);
      const sizeStr = f.size > 1048576 ? (f.size / 1048576).toFixed(2) + ' MB' : (sizeKb + ' KB');

      html += `
        <div class="artifact-file-row">
          <div class="artifact-file-info">
            <span class="artifact-file-icon">${icon}</span>
            <div>
              <div class="artifact-file-name">${escapeHtml(f.relpath)}</div>
              <div class="artifact-file-meta">${sizeStr} · Modified ${f.modified}</div>
            </div>
          </div>
          <div class="artifact-file-actions">
            <button type="button" class="btn-pill" onclick="viewArtifactFile(${projectId}, '${escapeHtml(f.relpath)}')">👁️ VIEW</button>
            <a href="/api/project/${projectId}/artifacts/download/${encodeURIComponent(f.relpath)}" class="btn-pill" style="text-decoration:none" download>⬇️ DOWNLOAD</a>
          </div>
        </div>
      `;
    });
    listEl.innerHTML = html;
  } catch (err) {
    listEl.innerHTML = `<div style="color:var(--red);padding:20px 0;font-size:11px">Failed to load artifacts: ${err.message}</div>`;
  }
}

async function viewArtifactFile(projectId, filename) {
  const modal = document.getElementById('fileViewerModal');
  const titleEl = document.getElementById('fileViewerTitle');
  const contentEl = document.getElementById('fileViewerContent');
  const downloadBtn = document.getElementById('fileViewerDownloadBtn');

  if (!modal || !contentEl) return;

  if (titleEl) titleEl.textContent = `📄 ${filename}`;
  if (downloadBtn) downloadBtn.href = `/api/project/${projectId}/artifacts/download/${encodeURIComponent(filename)}`;
  contentEl.textContent = 'Loading file content...';
  modal.style.display = 'flex';

  try {
    const res = await fetch(`/api/project/${projectId}/artifacts/view/${encodeURIComponent(filename)}`);
    const data = await res.json();
    if (data.ok) {
      contentEl.textContent = data.content;
    } else {
      contentEl.textContent = `Error loading file: ${data.error || 'Unknown error'}`;
    }
  } catch (e) {
    contentEl.textContent = `Error loading file: ${e.message}`;
  }
}

function closeFileViewerModal() {
  const modal = document.getElementById('fileViewerModal');
  if (modal) modal.style.display = 'none';
}

function escapeHtml(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Save Terminal Output to Notes ───────────────────────────────
function insertTerminalOutputToActiveCheck() {
  const pid = currentTerminalContext.projectId;
  const vid = currentTerminalContext.vulnId;

  if (!pid || !vid) {
    alert('Please select or run a script on a specific checklist item first to save output to its notes.');
    return;
  }

  // 1. Check if user highlighted/selected specific text in terminal drawer
  const selection = window.getSelection();
  let selectedText = '';
  if (selection && !selection.isCollapsed) {
    const termEl = document.getElementById('terminalBody') || document.getElementById('terminalDrawer');
    if (termEl && termEl.contains(selection.anchorNode)) {
      selectedText = selection.toString().trim();
    }
  }

  let textToSave = '';
  let noteHeader = '';

  if (selectedText) {
    textToSave = selectedText;
    noteHeader = `[Selected Terminal Output Evidence]\nCommand: ${currentTerminalContext.currentSectionCommand || currentTerminalContext.command || 'custom'}\nTimestamp: ${new Date().toISOString()}`;
  } else {
    // 2. Use ONLY the active / latest command section's output
    const sectionRaw = currentTerminalContext.currentSectionOutput || currentTerminalContext.lastSectionOutput || currentTerminalContext.rawOutput;
    textToSave = stripAnsi(sectionRaw).trim();
    noteHeader = `[Live Terminal Execution Evidence]\nCommand: ${currentTerminalContext.currentSectionCommand || currentTerminalContext.command || 'custom'}\nTimestamp: ${new Date().toISOString()}`;
  }

  if (!textToSave) {
    alert('No output available to save in notes.');
    return;
  }

  const payload = {
    notes: `${noteHeader}\n\n${textToSave}`
  };

  if (textToSave.includes('FAIL') || textToSave.includes('[✕ FAIL]')) {
    payload.status = 'fail';
  } else if (textToSave.includes('PASS') || textToSave.includes('[✓ PASS]')) {
    payload.status = 'pass';
  }

  fetch(`/api/project/${pid}/checklist/${vid}/append-notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(data => {
    const textarea = document.querySelector(`.ci[data-check-id="${vid}"] .notes-area`) ||
                     document.querySelector(`textarea[onblur*="${vid}"]`);
    if (textarea) {
      textarea.value = data.notes;
      autoResizeTextarea(textarea);
      flashSaved(textarea);
    }

    const btn = document.getElementById('btnInsertTerminalNotes');
    if (btn) {
      const orig = btn.textContent;
      btn.textContent = '✓ SAVED TO NOTES!';
      btn.classList.add('saved');
      setTimeout(() => {
        btn.textContent = orig;
        btn.classList.remove('saved');
      }, 1800);
    }
  })
  .catch(err => {
    alert('Failed to save notes: ' + err);
  });
}

function autoSaveTerminalToNotes() {
  const vid = currentTerminalContext.currentSectionVulnId || currentTerminalContext.vulnId;
  const pid = currentTerminalContext.currentSectionProjectId || currentTerminalContext.projectId;
  const cmd = currentTerminalContext.currentSectionCommand || currentTerminalContext.command;
  
  if (!vid || !pid) return;

  // Use ONLY the current command section's output, NOT the cumulative terminal history
  const sectionRaw = currentTerminalContext.currentSectionOutput || currentTerminalContext.lastSectionOutput;
  const cleanText = stripAnsi(sectionRaw).trim();
  if (!cleanText || cleanText.length < 5) return;

  const payload = {
    notes: `[Automated Tool Execution Evidence]\nCommand: ${cmd}\nExecuted: ${new Date().toLocaleTimeString()}\n\n${cleanText}`
  };

  if (cleanText.includes('FAIL') || cleanText.includes('[✕ FAIL]')) {
    payload.status = 'fail';
  }

  fetch(`/api/project/${pid}/checklist/${vid}/append-notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(data => {
    const textarea = document.querySelector(`.ci[data-check-id="${vid}"] .notes-area`) ||
                     document.querySelector(`textarea[onblur*="${vid}"]`);
    if (textarea) {
      textarea.value = data.notes;
      autoResizeTextarea(textarea);
      flashSaved(textarea);
    }
  });
}

function saveSpecificSectionToNotes(btn) {
  const sectionEl = btn.closest('.term-section');
  if (!sectionEl) return;

  const vid = sectionEl.dataset.vulnId || currentTerminalContext.vulnId;
  const pid = sectionEl.dataset.projectId || currentTerminalContext.projectId;
  const cmd = sectionEl.dataset.cmd || currentTerminalContext.command || 'custom';

  if (!vid || !pid) {
    alert('Please select a checklist item first before saving this section to notes.');
    return;
  }

  const contentEl = sectionEl.querySelector('.term-section-output');
  const textContent = contentEl ? contentEl.innerText.trim() : '';
  const cleanText = stripAnsi(textContent).trim();

  if (!cleanText) {
    alert('No output content in this section to save.');
    return;
  }

  const payload = {
    notes: `[Command Section Evidence]\nCommand: ${cmd}\nTimestamp: ${new Date().toISOString()}\n\n${cleanText}`
  };

  if (cleanText.includes('FAIL') || cleanText.includes('[✕ FAIL]')) {
    payload.status = 'fail';
  } else if (cleanText.includes('PASS') || cleanText.includes('[✓ PASS]')) {
    payload.status = 'pass';
  }

  const origText = btn.textContent;
  btn.textContent = 'Saving...';

  fetch(`/api/project/${pid}/checklist/${vid}/append-notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  .then(r => r.json())
  .then(data => {
    const textarea = document.querySelector(`.ci[data-check-id="${vid}"] .notes-area`) ||
                     document.querySelector(`textarea[onblur*="${vid}"]`);
    if (textarea) {
      textarea.value = data.notes;
      autoResizeTextarea(textarea);
      flashSaved(textarea);
    }

    btn.textContent = '✓ SAVED!';
    btn.classList.add('saved');
    setTimeout(() => {
      btn.textContent = origText;
      btn.classList.remove('saved');
    }, 1800);
  })
  .catch(err => {
    btn.textContent = origText;
    alert('Failed to save section to notes: ' + err);
  });
}

function copySpecificSectionOutput(btn) {
  const sectionEl = btn.closest('.term-section');
  if (!sectionEl) return;

  const contentEl = sectionEl.querySelector('.term-section-output');
  const textContent = contentEl ? contentEl.innerText.trim() : '';

  if (!textContent) {
    alert('No content to copy.');
    return;
  }

  navigator.clipboard.writeText(textContent).then(() => {
    const origText = btn.textContent;
    btn.textContent = '✓ COPIED!';
    btn.classList.add('saved');
    setTimeout(() => {
      btn.textContent = origText;
      btn.classList.remove('saved');
    }, 1500);
  }).catch(() => {
    alert('Could not copy to clipboard.');
  });
}

// ── Preview Modal & Launchers ───────────────────────────────────
function openPreviewForCheck(btn, projectId, vulnId, checkName) {
  const box = btn.closest('.tool-cmd-box');
  const targetUrl = box ? (box.dataset.url || box.dataset.target || '') : '';
  const isClickjack = vulnId === 'WSTG-CLNT-09' || (checkName || '').toLowerCase().includes('clickjack') || (checkName || '').toLowerCase().includes('framing');

  const previewUrl = isClickjack
    ? `/preview/clickjacking?url=${encodeURIComponent(targetUrl)}&project_id=${projectId}&vuln_id=${vulnId}`
    : `/preview/viewer?target=${encodeURIComponent(targetUrl)}`;

  openPreviewModal(previewUrl, isClickjack ? `👁️ CLICKJACKING & FRAMING DIAGNOSTIC // ${vulnId}` : `👁️ PREVIEW VIEWER // ${vulnId}`);
}

function openTerminalActivePreview() {
  if (currentTerminalContext.previewUrl) {
    openPreviewModal(currentTerminalContext.previewUrl, `👁️ TEST PREVIEW // ${currentTerminalContext.vulnId || ''}`);
  }
}

function openPreviewModal(url, title) {
  const overlay = document.getElementById('previewModalOverlay');
  const iframe = document.getElementById('previewModalIframe');
  const titleEl = document.getElementById('previewModalTitle');
  const extLink = document.getElementById('previewModalExternalLink');

  if (titleEl) titleEl.textContent = title || '👁️ BROWSER PREVIEW';
  if (extLink) extLink.href = url;
  if (iframe) iframe.src = url;
  if (overlay) overlay.style.display = 'flex';
}

function closePreviewModal() {
  const overlay = document.getElementById('previewModalOverlay');
  const iframe = document.getElementById('previewModalIframe');
  if (iframe) iframe.src = 'about:blank';
  if (overlay) overlay.style.display = 'none';
}

// ── Helper: flash visual feedback ────────────────────────────────
function flashSaved(el) {
  el.classList.add('flash-saved');
  setTimeout(() => el.classList.remove('flash-saved'), 800);
}

// ── Auto-initialize on load ──────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCommandBoxes();

  document.querySelectorAll('.notes-area').forEach(autoResizeTextarea);

  const autoSaveSaved = localStorage.getItem('webpt_term_autosave');
  if (autoSaveSaved !== null) {
    const isAuto = autoSaveSaved === 'true';
    currentTerminalContext.autoSave = isAuto;
    const checkbox = document.getElementById('termAutoSaveCheckbox');
    if (checkbox) checkbox.checked = isAuto;
  }
});

