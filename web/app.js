'use strict';
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const labels = {normalized:'Ready to export', needs_mapping:'Needs review', drift:'Format changed', quarantined:'Couldn’t process'};
const fieldNames = {src_ip:'Source IP', dst_ip:'Destination IP', action:'Action', src_port:'Source port', dst_port:'Destination port', protocol:'Protocol', timestamp:'Time'};
const fieldHelp = {src_ip:'Where traffic came from', dst_ip:'Where traffic was going', action:'Whether the device allowed or denied traffic', src_port:'Port used by the sender', dst_port:'Port on the receiving device', protocol:'TCP, UDP, ICMP, or ICMPv6', timestamp:'Date and time, including timezone'};
let state = {events:[], counts:{}, contracts:[], audit:[], targets:[]};
let connected = false, loaded = false, refreshing = null, signature = '', filter = 'all', page = 1, selected = null, inputMethod = 'file', chosenFile = null;
let importing = false;
let hosted = location.hostname.endsWith('.onrender.com'), authenticated = !hosted;
const pageSize = 25;
const number = value => Number(value || 0).toLocaleString();
const countText = (value, noun = 'log') => `${number(value)} ${noun}${value === 1 ? '' : 's'}`;
const isReview = row => ['needs_mapping','drift'].includes(row.status);
const sizeText = bytes => bytes < 1000 ? `${number(bytes)} bytes` : bytes < 1000000 ? `${(bytes / 1000).toFixed(1)} KB` : `${(bytes / 1000000).toFixed(1)} MB`;
function notify(message, error = false) {
  $('#notice').textContent = message;
  $('#notice').className = error ? 'notice error' : 'notice';
  $('#notice').hidden = false;
}
function setConnection(ok) {
  connected = ok;
  $('#connection-text').textContent = ok ? (hosted ? 'Status: connected' : 'Status: local') : 'Status: unavailable';
  $('#connection-status').classList.toggle('offline', !ok);
  $('#connection-banner').hidden = ok;
  $('#connection-message').textContent = loaded
    ? 'The server stopped responding. The logs below are from the last successful update. Start run.ps1 in the project folder to reconnect.'
    : 'Start run.ps1 in the project folder, then open http://127.0.0.1:8765/. This page needs the local server to read and process your logs.';
  if (hosted) $('#connection-message').textContent = 'The workspace is reconnecting. Wait a moment, then refresh.';
  $$('[data-import]').forEach(button => button.disabled = !ok);
  $('#verify').disabled = !ok || !state.events.length;
  $('#export').disabled = !ok || !state.counts.normalized;
  $('#import-submit').disabled = !ok || importing;
  if ($('#approve')) $('#approve').disabled = !ok;
  if ($('#rollback')) $('#rollback').disabled = !ok;
}
async function request(path, payload) {
  let response;
  try {
    response = await fetch(path, {
      ...(payload === undefined ? {} : {method:'POST', headers:{'Content-Type':'application/json', 'Idempotency-Key':crypto.randomUUID()}, body:JSON.stringify(payload)}),
      cache:'no-store', signal:AbortSignal.timeout(hosted ? 60000 : 15000)
    });
  } catch {
    setConnection(false);
    throw new Error(hosted ? 'The service is reconnecting. Refresh to see whether your change was saved before trying again.' : 'Cannot reach the local server. Start run.ps1, then try again.');
  }
  if (!response.ok) {
    if (response.status === 401 && hosted) showAuth();
    const error = await response.json().catch(() => ({}));
    if (response.status === 404 || response.status >= 500) setConnection(false);
    throw new Error(error.error || 'The server could not complete this request.');
  }
  return response;
}
async function api(path, payload) {
  const response = await request(path, payload);
  if (!(response.headers.get('Content-Type') || '').includes('application/json')) {
    setConnection(false);
    throw new Error('This page is not connected to the log server. Open your local workspace.');
  }
  return response.json();
}
async function refresh() {
  if (hosted && !authenticated) return;
  if (refreshing) return refreshing;
  refreshing = (async () => {
    const next = await api('/api/state');
    if (!Array.isArray(next.events) || !next.counts) throw new Error('Unexpected workspace response.');
    state = next; loaded = true;
    const nextSignature = JSON.stringify([next.events.map(row => [row.id,row.revision]), next.contracts, next.audit]);
    if (nextSignature !== signature) {
      signature = nextSignature;
      renderWorkspace();
    }
    setConnection(true);
    $('#last-updated').textContent = `Updated ${new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})} · refreshes every 10s`;
  })();
  try { await refreshing; } catch (error) { setConnection(false); throw error; } finally { refreshing = null; }
}
function renderWorkspace() {
  const review = state.counts.needs_mapping + state.counts.drift;
  $('#total').textContent = number(state.events.length);
  $('#nav-count').textContent = number(state.events.length);
  $('#event-count').textContent = number(state.events.length);
  $('#normalized').textContent = number(state.counts.normalized);
  $('#review').textContent = number(review);
  $('#quarantined').textContent = number(state.counts.quarantined);
  $('#bytes').textContent = `${sizeText(state.raw_bytes)} of originals saved`;
  $('#getting-started').hidden = state.events.length > 0;
  $('#review-banner').hidden = !review;
  $('#review-summary').textContent = `${countText(review)} ${review === 1 ? 'needs' : 'need'} a quick review`;
  $('#list-caption').textContent = state.events.length ? 'Newest first. Open a log to see its details or review its fields.' : 'Only the logs you add appear here.';
  const sources = [...new Set(state.events.map(row => row.source))].sort();
  const source = $('#source-filter').value;
  $('#source-filter').innerHTML = '<option value="">All sources</option>' + sources.map(name => `<option value="${esc(name)}">${esc(name)}</option>`).join('');
  $('#source-filter').value = sources.includes(source) ? source : '';
  $('#known-sources').innerHTML = sources.map(name => `<option value="${esc(name)}"></option>`).join('');
  renderEvents(); renderSources(); renderActivity();
}
function renderEvents() {
  const query = $('#search').value.trim().toLowerCase();
  const source = $('#source-filter').value;
  const rows = state.events.filter(row => (filter === 'all' || (filter === 'review' ? isReview(row) : row.status === filter)) && (!source || row.source === source) && (!query || `${row.source} ${row.raw_text} ${JSON.stringify(row.canonical)}`.toLowerCase().includes(query))).reverse();
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  page = Math.min(page, pages);
  const visible = rows.slice((page - 1) * pageSize, page * pageSize);
  $('#events-body').innerHTML = visible.map(row => `<tr><td><button class="event-button" data-inspect="${row.id}"><strong>${esc(row.source)}</strong><small>Log #${row.id}</small></button></td><td class="connection-cell"><span>${esc(row.canonical.src_ip || 'Not identified')}</span><span class="connection-arrow">→</span><span>${esc(row.canonical.dst_ip || 'Not identified')}</span>${row.status !== 'normalized' && Object.keys(row.canonical).length ? '<small>Suggested · not yet validated</small>' : ''}</td><td>${row.canonical.action ? `<span class="action-label ${row.canonical.action === 'allow' ? 'allow' : 'deny'}">${row.canonical.action === 'allow' ? 'Allow' : 'Deny'}</span>` : '<span class="muted">—</span>'}</td><td><span class="format-label">${esc(row.format)}</span></td><td><span class="status ${row.status}">${labels[row.status]}</span></td><td><button class="icon-button" data-inspect="${row.id}" aria-label="Open log ${row.id}">→</button></td></tr>`).join('');
  $('#table-wrap').hidden = !rows.length;
  $('#empty').hidden = !!rows.length;
  const hasData = state.events.length > 0;
  $('#empty-title').textContent = hasData ? 'No logs match these filters' : 'Start with your first log file';
  $('#empty-description').textContent = hasData ? 'Try a different search, source, or status to find your logs.' : 'Add logs from a firewall, gateway, or other network device. We’ll keep the originals and help you review the important fields.';
  $('#empty-action').textContent = hasData ? 'Clear filters' : '＋ Add your first logs';
  $('#empty-action').toggleAttribute('data-import', !hasData);
  $('#empty-action').disabled = !connected && !hasData;
  $('#empty-formats').hidden = hasData;
  $('#footer-count').textContent = rows.length ? `Showing ${number((page - 1) * pageSize + 1)}–${number(Math.min(page * pageSize, rows.length))} of ${countText(rows.length)}` : hasData ? `0 of ${countText(state.events.length)}` : 'No logs added yet';
  $('#page-number').textContent = `Page ${page} of ${pages}`;
  $('#previous-page').disabled = page <= 1;
  $('#next-page').disabled = page >= pages;
}
function renderSources() {
  const sources = [...new Set(state.events.map(row => row.source))].sort();
  $('#source-list').innerHTML = sources.length ? sources.map(source => {
    const rows = state.events.filter(row => row.source === source);
    const ready = rows.filter(row => row.status === 'normalized').length;
    const review = rows.filter(isReview).length;
    const rules = state.contracts.filter(rule => rule.source === source && rule.active);
    return `<article class="source-card"><div class="source-card-heading"><span class="source-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M5 4.5h14v15H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg></span><h2>${esc(source)}</h2></div><p>${[...new Set(rows.map(row => row.format))].map(esc).join(' · ')}</p><div class="source-stats"><div><strong>${number(rows.length)}</strong><span>Logs added</span></div><div><strong>${number(ready)}</strong><span>Ready to export</span></div><div><strong>${number(review)}</strong><span>Need review</span></div></div><div class="source-card-footer"><span>${rules.length ? `${countText(rules.length, 'format')} reviewed` : 'Field review needed'}</span><button class="button" data-source="${esc(source)}">View logs →</button></div>${rules.length ? `<details><summary>Saved field settings</summary>${rules.map(rule => `<div class="saved-rule"><strong>Settings version ${rule.version}</strong><dl>${Object.entries(JSON.parse(rule.mapping)).map(([key,target]) => `<div><dt>${esc(fieldNames[target])}</dt><dd>${esc(key)}</dd></div>`).join('')}</dl></div>`).join('')}</details>` : ''}</article>`;
  }).join('') : '<div class="plain-empty"><span aria-hidden="true" class="empty-icon"><svg viewBox="0 0 24 24"><path d="M5 4.5h14v15H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></svg></span><h2>No sources yet</h2><p>Add your first logs and give the device a name. It will appear here automatically.</p><button class="button primary" data-import>＋ Add logs</button></div>';
}
function renderActivity() {
  $('#activity-list').innerHTML = state.audit.length ? state.audit.map(item => {
    const detail = JSON.parse(item.details);
    const title = item.action === 'mapping_approved' ? 'Field settings saved' : item.action === 'mapping_rollback' ? 'Earlier field settings restored' : item.action.replaceAll('_', ' ');
    const description = item.action === 'cloud_export' ? `${countText(detail.records)} sent to ${detail.destination}` : `${detail.source || ''} · Settings version ${detail.version || '—'}`;
    const icon = item.action === 'mapping_rollback' ? '<svg viewBox="0 0 24 24"><path d="M8 8H4l4-4"/><path d="M4 8a8 8 0 1 1 2.3 5.7"/></svg>' : '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="m8 12 2.6 2.7 5.4-5.5"/></svg>';
    return `<article class="activity-item"><span class="activity-icon" aria-hidden="true">${icon}</span><div><h2>${esc(title)}</h2><p>${esc(description)}</p>${detail.validation ? `<small>${countText(detail.validation.length)} checked · ${number(detail.validation.filter(check => check.valid).length)} passed validation</small>` : ''}</div><time datetime="${esc(item.at)}">${esc(new Date(item.at).toLocaleString())}</time></article>`;
  }).join('') + '<p class="muted">Showing the latest 30 decisions at most.</p>' : '<div class="plain-empty"><span aria-hidden="true" class="empty-icon"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5l3.2 2"/></svg></span><h2>Your decisions will appear here</h2><p>When you save field settings or restore a previous version, we’ll record it here.</p></div>';
}
function changeView(view) {
  $$('.view').forEach(element => element.hidden = element.id !== `${view}-view`);
  $$('.nav').forEach(button => {
    button.classList.toggle('active', button.dataset.view === view);
    if (button.dataset.view === view) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
  });
  $('#view-label').textContent = {logs:'Logs', sources:'Sources', activity:'Activity', help:'How it works'}[view];
}
function setFilter(value) {
  filter = value; page = 1;
  $$('[data-filter]').forEach(button => { button.classList.toggle('selected', button.dataset.filter === value); button.setAttribute('aria-pressed', String(button.dataset.filter === value)); });
  renderEvents();
}
function friendlyError(text) {
  if (text.startsWith('Required field unavailable: ')) return `Choose a field for ${fieldNames[text.split(': ')[1]] || text.split(': ')[1]}.`;
  if (text.includes('Duplicate field:')) return 'This log repeats a field name. We saved the original, but cannot safely decide which value to use.';
  if (text.includes('port outside')) return 'A port number is outside the valid range (0–65535).';
  if (text.includes('action: unknown vocabulary')) return 'The device action is not recognized. This value needs a source-specific rule.';
  if (text.includes('timestamp: timezone')) return 'The time has no timezone. Use a time field that includes one, or leave this optional field unassigned.';
  if (text.includes('Unsupported structure')) return 'This log format is not supported yet. Its original content is saved and available to download.';
  return text;
}
function inspect(id) {
  const row = state.events.find(item => item.id === id);
  if (!row) return;
  selected = row;
  const required = row.profile?.required || ['src_ip','dst_ip','action'];
  const active = state.contracts.find(rule => rule.source === row.source && rule.fingerprint === row.fingerprint && rule.active);
  const mapping = active ? JSON.parse(active.mapping) : row.suggested_mapping;
  const keys = Object.keys(row.fields);
  const matching = state.events.filter(item => item.source === row.source && item.fingerprint === row.fingerprint).length;
  const explanations = {normalized:'These fields passed validation and are included in your export.',needs_mapping:'Check the suggested field names below. Saving applies your choices to matching logs from this source.',drift:'This source is sending a different set of fields. Review the new structure before exporting.',quarantined:'This log could not pass processing. The original is saved. Check the reason below.'};
  const errors = row.errors.filter(error => !['Review source mapping before export','Structure changed; review mapping before export'].includes(error));
  $('#detail-source').textContent = `${row.source} · ${row.format}`;
  $('#detail-title').textContent = `Log #${row.id}`;
  $('#detail-content').innerHTML = `<div class="detail-summary"><span class="status ${row.status}">${labels[row.status]}</span><p>${explanations[row.status]}</p></div><div id="detail-error" class="form-error" role="alert" hidden></div>${errors.length ? `<div class="validation-note"><strong>What needs attention</strong><ul>${errors.map(error => `<li>${esc(friendlyError(error))}</li>`).join('')}</ul></div>` : ''}
    ${row.ai_suggestions?.length ? `<div class="ai-note"><strong>${row.ai_suggestions.length === 1 ? 'Possible field match' : 'Possible field matches'}</strong><p>${row.ai_suggestions.map(item => `${esc(item.field)} → ${esc(fieldNames[item.target])}`).join(' · ')}</p><small>Check the meaning against your device documentation before saving.</small></div>` : ''}
    ${row.warnings?.length ? `<div class="validation-note"><strong>About this log type</strong><ul>${row.warnings.map(message => `<li>${esc(message)}</li>`).join('')}</ul></div>` : ''}
    <h3>${row.status === 'normalized' ? 'Reviewed fields' : 'Suggested fields'}</h3><dl class="field-values">${Object.entries(fieldNames).map(([target,label]) => `<div><dt>${label}</dt><dd>${esc(row.canonical[target] ?? 'Not identified')}</dd></div>`).join('')}</dl>
    ${keys.length ? `<details class="mapping-section" ${row.status !== 'normalized' ? 'open' : ''}><summary>${row.status === 'normalized' ? 'Edit field settings' : 'Review field settings'}</summary><p>Match each meaning on the left to a field in your log. Check your device’s documentation if you’re unsure. Required fields must be assigned.</p><div id="mapping-fields">${Object.entries(fieldNames).map(([target,label]) => `<div class="mapping-row"><label for="map-${target}">${label} ${required.includes(target) ? '<span class="required-label">Required</span>' : '<span class="optional-label">Optional</span>'}<small>${fieldHelp[target]}</small></label><select id="map-${target}" data-target="${target}"><option value="">${required.includes(target) ? 'Choose a field…' : 'Leave unassigned'}</option>${keys.map((key,index) => `<option value="${index}" ${mapping[key] === target ? 'selected' : ''}>${esc(key)} — ${esc(String(row.fields[key]).slice(0,80))}</option>`).join('')}</select></div>`).join('')}</div><div class="mapping-footer"><p>Applies to ${countText(matching)} with this structure from <strong>${esc(row.source)}</strong>, plus future matches. Invalid values remain excluded from export.</p><div class="detail-actions"><button class="button primary" id="approve" ${!connected ? 'disabled' : ''}>Save settings & process logs</button>${active && state.contracts.some(rule => rule.source === row.source && rule.fingerprint === row.fingerprint && rule.version < active.version) ? `<button class="button" id="rollback" ${!connected ? 'disabled' : ''}>Restore previous settings</button>` : ''}</div></div></details>` : ''}
    <details class="detail-section"><summary>Original log</summary><p>Exactly what was received. Download preserves the original bytes, including line endings.</p><pre>${esc(row.raw_text)}</pre><button class="button" id="download-raw">↓ Download original</button></details>
    <details class="detail-section"><summary>Technical details & field history</summary><p>Each reviewed value can be traced to its original field.</p>${Object.entries(row.lineage).map(([target,line]) => `<div class="lineage-item"><strong>${esc(fieldNames[target])}</strong><span>From <code>${esc(line.selector)}</code> · original value <code>${esc(JSON.stringify(line.original_value))}</code></span></div>`).join('')}<h3>Original content checksum (SHA-256)</h3><code class="raw-hash">${esc(row.raw_sha256)}</code><p>Checks local byte consistency; it does not verify the sending device.</p><h3>Output schema</h3><code>${esc(row.schema)}</code><h3>Additional fields kept from your log</h3><pre>${esc(JSON.stringify(row.unmapped,null,2))}</pre><button class="button" id="show-history">View processing history (${row.revision})</button><div id="history-panel"></div></details>`;
  if (!$('#detail-dialog').open) $('#detail-dialog').showModal();
}
function download(data, name) {
  const url = URL.createObjectURL(data instanceof Blob ? data : new Blob([data], {type:'application/octet-stream'}));
  const link = document.createElement('a'); link.href = url; link.download = name; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function showImport() {
  $('#import-error').hidden = true;
  $('#import-dialog').showModal();
  $('#source-name').focus();
}
function setInputMethod(method) {
  inputMethod = method;
  $('#file-input-panel').hidden = method !== 'file';
  $('#text-input-panel').hidden = method !== 'text';
  $$('[data-input]').forEach(button => { button.classList.toggle('selected',button.dataset.input === method); button.setAttribute('aria-pressed',String(button.dataset.input === method)); });
}
function selectFile(file) {
  chosenFile = file || null;
  $('#file-title').textContent = file ? file.name : 'Choose a log file or drop it here';
  $('#file-description').textContent = file ? `${sizeText(file.size)} · click to choose a different file` : 'LOG, TXT, JSON, NDJSON, JSONL, XML, CSV · up to 2 MB';
  $('#drop-zone').classList.toggle('has-file', !!file);
}
document.addEventListener('click', async event => {
  const button = event.target.closest('button');
  if (!button || button.disabled) return;
  const busyIds = ['approve','rollback','verify','export','refresh','retry'];
  const busy = busyIds.includes(button.id);
  if (busy) button.disabled = true;
  try {
    if (button.classList.contains('close-dialog')) { button.closest('dialog').close(); return; }
    if (button.dataset.view) { changeView(button.dataset.view); return; }
    if (button.hasAttribute('data-import')) { showImport(); return; }
    if (button.dataset.input) { setInputMethod(button.dataset.input); return; }
    if (button.dataset.filter) { setFilter(button.dataset.filter); return; }
    if (button.dataset.inspect) { inspect(Number(button.dataset.inspect)); return; }
    if (button.dataset.source) { changeView('logs'); $('#source-filter').value = button.dataset.source; $('#search').value = ''; setFilter('all'); return; }
    if (button.id === 'empty-action') { $('#search').value = ''; $('#source-filter').value = ''; setFilter('all'); }
    if (button.id === 'previous-page') { page--; renderEvents(); }
    if (button.id === 'next-page') { page++; renderEvents(); }
    if (button.id === 'review-next') inspect(state.events.find(isReview).id);
    if (['refresh','retry'].includes(button.id)) { await refresh(); $('#notice').hidden = true; }
    if (button.id === 'verify') { const result = await api('/api/verify'); notify(result.failed.length ? `${countText(result.failed.length)} failed the original-content check. Affected IDs: ${result.failed.join(', ')}.` : `All ${countText(result.verified)} match their saved original bytes.`, !!result.failed.length); }
    if (button.id === 'export') { const response = await request('/api/export'); download(await response.blob(),'traceweave-logs.ndjson'); notify('Your reviewed logs have been exported as NDJSON.'); }
    if (button.id === 'download-raw') download(Uint8Array.from(atob(selected.raw_base64), char => char.charCodeAt(0)), `log-${selected.id}-original.log`);
    if (button.id === 'show-history') { const rows = await api(`/api/history?id=${selected.id}`); $('#history-panel').innerHTML = rows.map(row => `<div class="history-item"><strong>Revision ${row.revision} · ${labels[row.status]}</strong><p>${row.contract_version ? `Field settings version ${row.contract_version}` : 'No approved field settings'}</p><pre>${esc(JSON.stringify(row.canonical,null,2))}</pre></div>`).join(''); }
    if (button.id === 'approve') {
      const required = selected.profile?.required || ['src_ip','dst_ip','action'];
      const mapping = {}, keys = Object.keys(selected.fields);
      for (const select of $$('[data-target]')) {
        if (select.value === '') { if (required.includes(select.dataset.target)) throw new Error(`Choose a field for ${fieldNames[select.dataset.target]}.`); continue; }
        const key = keys[Number(select.value)];
        if (Object.hasOwn(mapping,key)) throw new Error('Each source field can be used once. Choose a different field for each meaning.');
        mapping[key] = select.dataset.target;
      }
      const result = await api('/api/approve', {source:selected.source,fingerprint:selected.fingerprint,mapping});
      await refresh(); inspect(selected.id);
      notify(`Field settings saved. ${countText(result.normalized)} ready to export out of ${countText(result.replayed)} processed.`);
    }
    if (button.id === 'rollback') { const result = await api('/api/rollback',{source:selected.source,fingerprint:selected.fingerprint}); await refresh(); inspect(selected.id); notify(`Restored settings version ${result.version} and processed ${countText(result.replayed)} again.`); }
  } catch (error) {
    if ($('#detail-dialog').open) { $('#detail-error').textContent = error.message; $('#detail-error').hidden = false; $('#detail-error').scrollIntoView({block:'nearest'}); }
    else notify(error.message,true);
  } finally {
    if (busy) button.disabled = !connected && !['retry','refresh'].includes(button.id);
    if (busy) { $('#verify').disabled = !connected || !state.events.length; $('#export').disabled = !connected || !state.counts.normalized; }
  }
});
$('#search').addEventListener('input', () => { page = 1; renderEvents(); });
$('#source-filter').addEventListener('change', () => { page = 1; renderEvents(); });
$('#log-file').addEventListener('change', () => selectFile($('#log-file').files[0]));
for (const name of ['dragenter','dragover']) $('#drop-zone').addEventListener(name, event => { event.preventDefault(); $('#drop-zone').classList.add('dragging'); });
$('#drop-zone').addEventListener('dragleave', () => $('#drop-zone').classList.remove('dragging'));
$('#drop-zone').addEventListener('drop', event => { event.preventDefault(); $('#drop-zone').classList.remove('dragging'); if (event.dataTransfer.files.length > 1) { $('#import-error').textContent = 'Please add one file at a time.'; $('#import-error').hidden = false; return; } selectFile(event.dataTransfer.files[0]); });
$('#import-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (importing) return;
  importing = true;
  const button = $('#import-submit'); button.disabled = true; button.textContent = 'Processing…';
  $('#import-error').hidden = true;
  let added = null;
  try {
    const data = {source:$('#source-name').value.trim(), record_mode:$('#record-mode').value};
    if (!data.source) throw new Error('Enter a device or source name.');
    if (inputMethod === 'file') {
      if (!chosenFile) throw new Error('Choose a log file first, or switch to Paste logs.');
      if (!chosenFile.size || chosenFile.size > 2000000) throw new Error('Choose a non-empty file up to 2 MB.');
      const bytes = new Uint8Array(await chosenFile.arrayBuffer()); let binary = '';
      for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
      data.base64 = btoa(binary);
    } else {
      data.text = $('#log-input').value;
      if (!data.text.trim()) throw new Error('Paste the logs you want to add.');
      if (new TextEncoder().encode(data.text).length > 2000000) throw new Error('Pasted logs exceed the 2 MB limit.');
    }
    added = await api('/api/ingest', data);
    $('#import-dialog').close();
    $('#log-input').value = ''; $('#log-file').value = ''; selectFile(null);
    await refresh();
    changeView('logs'); $('#source-filter').value = added.source; $('#search').value = ''; setFilter('all');
    const reviewCount = state.events.filter(row => row.source === added.source && isReview(row)).length;
    notify(`${countText(added.ingested)} added from ${added.source}. ${reviewCount ? 'Open a log marked Needs review to confirm its fields.' : 'Open a log to see its results.'}`);
  } catch (error) {
    if (added) notify(`${countText(added.ingested)} were saved, but the display could not refresh. Reconnect to see them; do not upload again.`,true);
    else { $('#import-error').textContent = error.message; $('#import-error').hidden = false; }
  } finally { importing = false; button.disabled = !connected; button.textContent = 'Add logs →'; }
});
$$('[data-import]').forEach(button => button.disabled = true);
startWorkspace().catch(error => { document.documentElement.classList.remove('hosted-preload'); $('#boot-screen').hidden = true; setConnection(false); notify(error.message, true); });
setInterval(() => { if (!document.hidden) refresh().catch(() => {}); }, 10000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh().catch(() => {}); });

function loadModelInfo() {
  api('/api/model').then(info => { if (info.available) { $('#ai-overview').hidden = false; $('#ai-overview-text').textContent = 'A field-matching helper suggests likely meanings for unfamiliar names. Known device rules take priority, and you approve every new structure before export.'; } }).catch(() => {});
}

function showAuth() {
  authenticated = false;
  state = {events:[], counts:{}, contracts:[], audit:[], targets:[]};
  signature = ''; selected = null;
  $$('dialog[open]').forEach(dialog => dialog.close());
  $('#auth-screen').hidden = false;
  $('.sidebar').hidden = true; $('.workspace').hidden = true;
}
async function startWorkspace() {
  const session = await api('/api/session');
  document.documentElement.classList.remove('hosted-preload');
  $('#boot-screen').hidden = true;
  hosted = session.hosted; authenticated = session.authenticated;
  if (hosted) {
    $('.help-footer').textContent = 'The online service runs in your browser. Free hosting may take a moment to wake up after inactivity.';
    $('#ai-overview small').textContent = 'Check each suggested match before saving. Uncertain fields remain unassigned.';
    $('#sign-out').hidden = false;
    $('#auth-google').href = '/api/auth/google';
    if (!authenticated) {
      showAuth();
      const hash = new URLSearchParams(location.hash.replace(/^#/, ''));
      if (hash.get('type') === 'recovery' && hash.get('access_token')) {
        recoveryToken = hash.get('access_token');
        setAuthMode('reset');
      } else if (new URLSearchParams(location.search).get('auth_error')) {
        const authError = new URLSearchParams(location.search).get('auth_error');
        $('#auth-message').textContent = authError === 'google_unconfigured' ? 'Google sign-in is not configured yet. Use email sign-in for now.' : 'Google sign-in could not be completed. Try email sign-in or try Google again.';
        $('#auth-message').classList.add('auth-error');
      }
      return;
    }
  }
  $('#auth-screen').hidden = true;
  $('.sidebar').hidden = false; $('.workspace').hidden = false;
  await refresh(); loadModelInfo();
}
let authBusy = false, authMode = 'signin', recoveryToken = '';
function setAuthMode(mode) {
  if (authBusy) return;
  authMode = mode;
  const create = mode === 'signup', recover = mode === 'recover', reset = mode === 'reset';
  $('#auth-title').textContent = create ? 'Create your account' : recover ? 'Reset your password' : reset ? 'Choose a new password' : 'Welcome back';
  $('#auth-description').textContent = create ? 'Enter your email and choose a password.' : recover ? 'Enter your email and we’ll send a reset link.' : reset ? 'Choose a new password for your workspace.' : 'Sign in to your workspace.';
  $('#auth-submit').textContent = create ? 'Create account' : recover ? 'Send reset link' : reset ? 'Save new password' : 'Sign in';
  $('#auth-password').autocomplete = create || reset ? 'new-password' : 'current-password';
  $('#auth-password').minLength = create || reset ? 8 : 1;
  $('#auth-password').value = ''; $('#auth-confirm').value = '';
  $('#auth-password').type = 'password';
  $('#auth-reveal').textContent = 'Show'; $('#auth-reveal').setAttribute('aria-label','Show password'); $('#auth-reveal').setAttribute('aria-pressed','false');
  $('#auth-confirm').setCustomValidity('');
  $('#auth-email').disabled = reset; $('#auth-email').required = !reset;
  $('#auth-password').required = !recover; $('#auth-password-field').hidden = recover;
  $('#auth-confirm').disabled = !(create || reset); $('#auth-confirm').required = create || reset;
  $('#auth-confirm-field').hidden = !(create || reset); $('#auth-password-hint').hidden = !(create || reset);
  $('#auth-email-field').hidden = reset;
  $('#auth-forgot').hidden = !(!create && !recover && !reset);
  $('#auth-divider').hidden = !(!create && !recover && !reset);
  $('#auth-google').hidden = !(!create && !recover && !reset);
  $('#auth-back').hidden = !recover && !reset;
  $('.auth-modes').hidden = recover || reset;
  $('#auth-message').textContent = ''; $('#auth-message').classList.remove('auth-error');
  for (const [id, active] of [['auth-signin', mode === 'signin'], ['auth-create', create]]) {
    $('#' + id).classList.toggle('selected', active);
    $('#' + id).setAttribute('aria-pressed', String(active));
  }
}
async function authenticate() {
  const create = authMode === 'signup', recover = authMode === 'recover', reset = authMode === 'reset';
  $('#auth-confirm').setCustomValidity((create || reset) && $('#auth-password').value !== $('#auth-confirm').value ? 'Passwords do not match.' : '');
  if (authBusy || !$('#auth-form').reportValidity()) return;
  authBusy = true; $('#auth-submit').disabled = true; $('#auth-create').disabled = true; $('#auth-signin').disabled = true;
  $('#auth-message').classList.remove('auth-error');
  $('#auth-message').textContent = create ? 'Creating your account…' : recover ? 'Sending reset link…' : reset ? 'Updating your password…' : 'Opening your workspace…';
  try {
    const endpoint = create ? '/api/auth/signup' : recover ? '/api/auth/recover' : reset ? '/api/auth/reset' : '/api/auth/login';
    const payload = recover ? {email:$('#auth-email').value.trim()} : reset ? {token:recoveryToken, password:$('#auth-password').value} : {email:$('#auth-email').value.trim(), password:$('#auth-password').value};
    const result = await api(endpoint, payload);
    $('#auth-password').value = ''; $('#auth-confirm').value = '';
    if (create || recover) {
      authBusy = false; setAuthMode('signin');
      $('#auth-message').textContent = create ? 'Check your email to confirm your account, then sign in here.' : result.message;
    }
    else if (reset) { recoveryToken = ''; history.replaceState(null, '', location.pathname); $('#auth-message').textContent = ''; await startWorkspace(); }
    else { $('#auth-message').textContent = ''; await startWorkspace(); }
  } catch (error) { $('#auth-message').textContent = error.message; $('#auth-message').classList.add('auth-error'); }
  finally { authBusy = false; $('#auth-submit').disabled = false; $('#auth-create').disabled = false; $('#auth-signin').disabled = false; }
}
$('#auth-form').addEventListener('submit', event => { event.preventDefault(); authenticate(); });
$('#auth-create').addEventListener('click', () => setAuthMode('signup'));
$('#auth-signin').addEventListener('click', () => setAuthMode('signin'));
$('#auth-forgot').addEventListener('click', () => setAuthMode('recover'));
$('#auth-back').addEventListener('click', () => setAuthMode('signin'));
$('#auth-confirm').addEventListener('input', () => $('#auth-confirm').setCustomValidity(''));
$('#auth-reveal').addEventListener('click', () => {
  const reveal = $('#auth-password').type === 'password';
  $('#auth-password').type = reveal ? 'text' : 'password';
  $('#auth-reveal').textContent = reveal ? 'Hide' : 'Show';
  $('#auth-reveal').setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
  $('#auth-reveal').setAttribute('aria-pressed', String(reveal));
});
$('#sign-out').addEventListener('click', async () => {
  try { await api('/api/auth/logout', {}); location.reload(); }
  catch (error) { notify(error.message, true); }
});
