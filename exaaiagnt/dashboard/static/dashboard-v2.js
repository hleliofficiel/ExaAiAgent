/* ExaAi Mission Control — Dashboard v2 (vanilla JS, no dependencies) */
'use strict';

const state = {
    ws: null,
    reconnectDelay: 1000,
    maxReconnectDelay: 15000,
    reconnectTimer: null,
    findings: [],
    severityFilter: 'all',
    startTime: null,
    seenVulnEvents: new Set(),
    alertsPrimed: false,
    muted: false,
    auditTimer: null,
    activeProvider: null,
};

try { state.muted = localStorage.getItem('exaai_mute_alerts') === '1'; } catch (_) { state.muted = false; }

const $ = (id) => document.getElementById(id);

/* ---------- Auth token (reused for all API calls) ----------
   Token comes from ?token=... in the URL or localStorage 'exaai_dashboard_token'.
   When the server has EXAAI_DASHBOARD_TOKEN unset, no header is needed and this is a no-op. */
const authToken = (() => {
    try {
        const fromUrl = new URLSearchParams(window.location.search).get('token');
        if (fromUrl) {
            try { localStorage.setItem('exaai_dashboard_token', fromUrl); } catch (_) { /* noop */ }
            return fromUrl;
        }
        return localStorage.getItem('exaai_dashboard_token') || '';
    } catch (_) {
        return '';
    }
})();

function apiFetch(path, options) {
    const opts = options ? Object.assign({}, options) : {};
    const headers = Object.assign({ 'Accept': 'application/json' }, opts.headers || {});
    if (authToken) headers['Authorization'] = `Bearer ${authToken}`;
    opts.headers = headers;
    return fetch(path, opts);
}

function escapeHtml(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtUptime(seconds) {
    if (seconds == null || Number.isNaN(seconds)) return '--:--:--';
    const s = Math.max(0, Math.floor(seconds));
    const h = String(Math.floor(s / 3600)).padStart(2, '0');
    const m = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const sec = String(s % 60).padStart(2, '0');
    return `${h}:${m}:${sec}`;
}

function fmtTs(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return String(ts);
    return d.toLocaleTimeString();
}

/* ---------- WebSocket with reconnect ---------- */
function connectWs() {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${window.location.host}/ws`;
    setConn('connecting');
    try {
        state.ws = new WebSocket(url);
    } catch (err) {
        scheduleReconnect();
        return;
    }
    state.ws.onopen = () => {
        state.reconnectDelay = 1000;
        setConn('online');
    };
    state.ws.onmessage = (msg) => {
        try {
            handleFrame(JSON.parse(msg.data));
        } catch (err) {
            console.error('Bad WS frame', err);
        }
    };
    state.ws.onclose = () => {
        setConn('offline');
        scheduleReconnect();
    };
    state.ws.onerror = () => {
        try { state.ws.close(); } catch (_) { /* noop */ }
    };
}

function scheduleReconnect() {
    if (state.reconnectTimer) return;
    setConn('offline');
    state.reconnectTimer = setTimeout(() => {
        state.reconnectTimer = null;
        state.reconnectDelay = Math.min(state.reconnectDelay * 2, state.maxReconnectDelay);
        connectWs();
    }, state.reconnectDelay);
}

function setConn(status) {
    const dot = $('conn-dot');
    const text = $('conn-text');
    dot.classList.remove('online', 'offline');
    if (status === 'online') { dot.classList.add('online'); text.textContent = 'live'; }
    else if (status === 'offline') { dot.classList.add('offline'); text.textContent = 'reconnecting'; }
    else { text.textContent = 'connecting'; }
}

/* ---------- Frame handling ---------- */
function handleFrame(data) {
    if (Array.isArray(data.events)) maybeAlertOnEvents(data.events);
    if (data.counters) {
        $('tile-confirmed').textContent = data.counters.confirmed ?? 0;
        $('tile-suspected').textContent = data.counters.suspected ?? 0;
        $('tile-tools').textContent = data.counters.tool_calls ?? 0;
        $('tile-agents').textContent = data.counters.agents_running ?? 0;
    }
    if (Array.isArray(data.events)) renderEvents(data.events);
}

function renderEvents(events) {
    const feed = $('event-feed');
    const nearBottom = feed.scrollHeight - feed.scrollTop - feed.clientHeight < 60;
    feed.innerHTML = events.map((ev) => {
        const sev = ev.severity ? ` sev-${escapeHtml(ev.severity)}` : '';
        const type = escapeHtml(ev.type || 'event');
        const sevLabel = ev.severity ? ` · ${escapeHtml(ev.severity)}` : '';
        return `<div class="event type-${type}${sev}">
            <div class="event-meta"><span>${type}${sevLabel}</span><span>${escapeHtml(fmtTs(ev.ts))}</span></div>
            <div class="event-summary">${escapeHtml(ev.summary || '')}</div>
        </div>`;
    }).join('');
    if (nearBottom) feed.scrollTop = feed.scrollHeight;
}

/* ---------- Polling: state + vulnerabilities ---------- */
async function pollState() {
    try {
        const res = await apiFetch('/api/state');
        if (!res.ok) return;
        const s = await res.json();
        $('run-name').textContent = s.run_name || 'no active run';
        updateScanPanel(s);
        if (s.uptime_seconds != null) {
            $('uptime').textContent = fmtUptime(s.uptime_seconds);
        } else if (s.start_time) {
            const start = new Date(s.start_time).getTime();
            if (!Number.isNaN(start)) $('uptime').textContent = fmtUptime((Date.now() - start) / 1000);
        }
        if (s.counters) {
            $('tile-confirmed').textContent = s.counters.confirmed ?? 0;
            $('tile-suspected').textContent = s.counters.suspected ?? 0;
            $('tile-tools').textContent = s.counters.tool_calls ?? 0;
            $('tile-agents').textContent = s.counters.agents_running ?? 0;
        }
    } catch (err) {
        console.error('state poll failed', err);
    }
}

async function pollVulnerabilities() {
    try {
        const res = await apiFetch('/api/vulnerabilities');
        if (!res.ok) return;
        const vulns = await res.json();
        state.findings = Array.isArray(vulns) ? vulns : [];
        renderFindings();
        renderAttackSurface();
    } catch (err) {
        console.error('vulnerabilities poll failed', err);
    }
}

function renderFindings() {
    const tbody = $('findings-body');
    const filtered = state.findings.filter((v) =>
        state.severityFilter === 'all' || String(v.severity || '').toLowerCase() === state.severityFilter
    );
    if (!filtered.length) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No findings' +
            (state.severityFilter !== 'all' ? ' for this severity' : ' yet') + '</td></tr>';
        return;
    }
    tbody.innerHTML = filtered.map((v) => {
        const sev = String(v.severity || 'info').toLowerCase();
        const evidence = Array.isArray(v.evidence_ids) && v.evidence_ids.length
            ? v.evidence_ids.map(escapeHtml).join(', ')
            : '—';
        const tool = v.tool_name || v.agent || '—';
        return `<tr>
            <td><span class="badge badge-${escapeHtml(sev)}">${escapeHtml(sev)}</span></td>
            <td>${escapeHtml(v.title || 'untitled')}</td>
            <td class="evidence">${evidence}</td>
            <td>${escapeHtml(tool)}</td>
        </tr>`;
    }).join('');
}

/* ---------- Attack surface: group by tool/module, fall back to severity ---------- */
function renderAttackSurface() {
    const body = $('surface-body');
    const modeEl = $('surface-mode');
    const vulns = state.findings;

    const toolKeys = vulns.map((v) => v.tool_name || v.module || v.agent).filter(Boolean);
    let groups = {};
    let mode = 'grouped by tool';
    if (toolKeys.length) {
        for (const v of vulns) {
            const key = v.tool_name || v.module || v.agent || 'unknown';
            groups[key] = (groups[key] || 0) + 1;
        }
    } else if (vulns.length) {
        mode = 'grouped by severity (no tool metadata)';
        for (const v of vulns) {
            const key = String(v.severity || 'info').toLowerCase();
            groups[key] = (groups[key] || 0) + 1;
        }
    }

    modeEl.textContent = mode;
    const entries = Object.entries(groups).sort((a, b) => b[1] - a[1]);
    if (!entries.length) {
        body.innerHTML = '<p class="empty-note">No data yet</p>';
        return;
    }
    const max = Math.max(...entries.map(([, n]) => n));
    body.innerHTML = entries.map(([name, count]) => `
        <div class="surface-row">
            <div class="surface-row-head"><span>${escapeHtml(name)}</span><span class="surface-count">${count}</span></div>
            <div class="surface-bar"><div class="surface-bar-fill" style="width:${Math.round((count / max) * 100)}%"></div></div>
        </div>`).join('');
}

/* ---------- Wire-up ---------- */
$('severity-filter').addEventListener('change', (e) => {
    state.severityFilter = e.target.value;
    renderFindings();
});

connectWs();
pollState();
pollVulnerabilities();
setInterval(pollState, 5000);
setInterval(pollVulnerabilities, 3000);
setInterval(() => {
    // keep uptime ticking between polls
    const cur = $('uptime').textContent;
    const parts = cur.split(':').map(Number);
    if (parts.length === 3 && parts.every((n) => !Number.isNaN(n))) {
        const total = parts[0] * 3600 + parts[1] * 60 + parts[2] + 1;
        $('uptime').textContent = fmtUptime(total);
    }
}, 1000);

/* =========================================================
   Dashboard v2.1 — Operations section
   ========================================================= */

/* ---------- Toasts ---------- */
function showToast(title, body, level, opts) {
    level = level || 'info';
    opts = opts || {};
    const container = $('toast-container');
    if (!container) return;
    const el = document.createElement('div');
    el.className = `toast toast-${level}`;
    el.innerHTML = `<div class="toast-body"><div class="toast-title">${escapeHtml(title)}</div>${body ? `<div>${escapeHtml(body)}</div>` : ''}</div>`;
    const actions = document.createElement('div');
    actions.className = 'toast-actions';
    if (opts.alert) {
        const muteBtn = document.createElement('button');
        muteBtn.type = 'button';
        muteBtn.className = 'toast-btn';
        muteBtn.textContent = 'Mute';
        muteBtn.addEventListener('click', () => setMuted(true));
        actions.appendChild(muteBtn);
    }
    const dismissBtn = document.createElement('button');
    dismissBtn.type = 'button';
    dismissBtn.className = 'toast-btn';
    dismissBtn.textContent = '✕';
    dismissBtn.setAttribute('aria-label', 'Dismiss');
    dismissBtn.addEventListener('click', () => el.remove());
    actions.appendChild(dismissBtn);
    el.appendChild(actions);
    container.appendChild(el);
    const ttl = opts.ttl == null ? (level === 'crit' || level === 'high' ? 15000 : 6000) : opts.ttl;
    if (ttl > 0) setTimeout(() => { try { el.remove(); } catch (_) { /* noop */ } }, ttl);
}

/* ---------- Mute (persisted) ---------- */
function setMuted(muted) {
    state.muted = !!muted;
    try { localStorage.setItem('exaai_mute_alerts', state.muted ? '1' : '0'); } catch (_) { /* noop */ }
    const btn = $('mute-toggle');
    if (btn) {
        btn.textContent = state.muted ? '🔕' : '🔔';
        btn.title = state.muted ? 'Alerts muted (click to unmute)' : 'Mute alerts';
        btn.setAttribute('aria-pressed', state.muted ? 'true' : 'false');
    }
}

/* ---------- WebAudio beep ---------- */
let audioCtx = null;
function ensureAudio() {
    if (audioCtx) return audioCtx;
    try {
        const Ctx = window.AudioContext || window.webkitAudioContext;
        if (Ctx) audioCtx = new Ctx();
    } catch (_) { audioCtx = null; }
    return audioCtx;
}
function beep(severity) {
    if (state.muted) return;
    const ctx = ensureAudio();
    if (!ctx) return;
    try {
        if (ctx.state === 'suspended') ctx.resume().catch(() => {});
        const notes = severity === 'critical' ? [880, 660] : [660];
        notes.forEach((freq, i) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'sine';
            osc.frequency.value = freq;
            const t0 = ctx.currentTime + i * 0.22;
            gain.gain.setValueAtTime(0.0001, t0);
            gain.gain.exponentialRampToValueAtTime(0.18, t0 + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.18);
            osc.connect(gain).connect(ctx.destination);
            osc.start(t0);
            osc.stop(t0 + 0.2);
        });
    } catch (err) {
        console.error('beep failed', err);
    }
}

/* ---------- Browser notifications ---------- */
function maybeRequestNotificationPermission() {
    try {
        if (window.Notification && Notification.permission === 'default') {
            Notification.requestPermission().catch(() => {});
        }
    } catch (_) { /* noop */ }
}
document.addEventListener('click', function onFirstClick() {
    maybeRequestNotificationPermission();
    ensureAudio();
    document.removeEventListener('click', onFirstClick);
});

function notifyVulnerability(ev) {
    const severity = String(ev.severity || 'high').toLowerCase();
    const title = severity === 'critical' ? 'Critical vulnerability found' : 'High severity vulnerability found';
    const body = ev.summary || 'New finding reported';
    try {
        if (window.Notification && Notification.permission === 'granted') {
            const n = new Notification(title, { body, tag: `exaai-${severity}` });
            n.onclick = () => { try { window.focus(); } catch (_) { /* noop */ } n.close(); };
        }
    } catch (err) {
        console.error('notification failed', err);
    }
    showToast(title, body, severity === 'critical' ? 'crit' : 'high', { alert: true });
    beep(severity);
}

function maybeAlertOnEvents(events) {
    const fresh = [];
    for (const ev of events) {
        if (!ev || ev.type !== 'vulnerability') continue;
        const sev = String(ev.severity || '').toLowerCase();
        if (sev !== 'critical' && sev !== 'high') continue;
        const key = `${ev.type}|${ev.ts || ''}|${ev.summary || ''}`;
        if (state.seenVulnEvents.has(key)) continue;
        state.seenVulnEvents.add(key);
        fresh.push(ev);
    }
    if (!state.alertsPrimed) {
        // First frame after page load establishes a baseline; do not alert for backlog.
        state.alertsPrimed = true;
        return;
    }
    for (const ev of fresh) {
        if (state.muted) {
            // Still surface a subtle toast even when muted? No — mute silences alerts.
            continue;
        }
        notifyVulnerability(ev);
    }
}

/* ---------- Update badge ---------- */
async function checkForUpdate() {
    const badge = $('update-badge');
    if (!badge) return;
    try {
        const res = await apiFetch('/api/update');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const current = data && data.current ? String(data.current) : null;
        const latest = data && data.latest ? String(data.latest) : null;
        const available = data ? data.update_available : null;
        badge.classList.remove('update-available', 'update-current', 'update-unknown');
        if (available === true && latest) {
            badge.textContent = `v${latest} available`;
            badge.href = data.url || 'https://pypi.org/project/exaaiagnt/';
            badge.title = `Current: ${current || 'unknown'} · Latest: ${latest} — click to open release page`;
            badge.classList.add('update-available');
        } else if (available === false) {
            badge.textContent = 'up to date';
            badge.href = data.url || 'https://pypi.org/project/exaaiagnt/';
            badge.title = `ExaAi ${current || ''} is the latest release`.trim();
            badge.classList.add('update-current');
        } else {
            badge.textContent = 'version unknown';
            badge.removeAttribute('href');
            badge.title = 'Could not determine latest version (offline or unavailable)';
            badge.classList.add('update-unknown');
        }
    } catch (err) {
        const badge2 = $('update-badge');
        if (badge2) {
            badge2.textContent = 'version unknown';
            badge2.removeAttribute('href');
            badge2.title = 'Update check failed (offline or endpoint unavailable)';
            badge2.classList.remove('update-available', 'update-current');
            badge2.classList.add('update-unknown');
        }
    }
}

/* ---------- Providers panel ---------- */
function envKeyForProvider(name) {
    const n = String(name || '').toLowerCase();
    if (n.includes('anthropic') || n.includes('claude')) return 'ANTHROPIC_API_KEY';
    if (n.includes('gemini') || n.includes('google')) return 'GEMINI_API_KEY';
    if (n.includes('openrouter')) return 'OPENROUTER_API_KEY';
    if (n.includes('azure')) return 'AZURE_API_KEY';
    if (n.includes('ollama')) return 'OLLAMA_API_BASE';
    if (n.includes('litellm')) return 'LLM_API_KEY';
    if (n.includes('openai')) return 'OPENAI_API_KEY';
    return 'LLM_API_KEY';
}

function maskedOrDash(v) { return v ? String(v) : '—'; }

async function loadProviders() {
    const list = $('providers-list');
    const hint = $('providers-hint');
    try {
        const res = await apiFetch('/api/providers');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderProviders(data);
        if (hint) hint.textContent = (data && data.active && data.active.provider) ? `active: ${data.active.provider}` : 'no active provider';
    } catch (err) {
        if (list) list.innerHTML = '<p class="empty-note">Providers unavailable (endpoint not ready or offline).</p>';
        if (hint) hint.textContent = 'unavailable';
    }
}

function renderProviders(data) {
    const list = $('providers-list');
    const select = $('active-provider');
    const modelInput = $('model-input');
    if (!list) return;
    const providers = Array.isArray(data && data.providers) ? data.providers : [];
    const active = (data && data.active) || {};
    state.activeProvider = active.provider || null;

    if (modelInput) modelInput.placeholder = active.model ? `model (current: ${active.model})` : 'model (optional)';

    // Rebuild active-provider select: configured providers + litellm when LLM_API_KEY configured
    if (select) {
        const configured = providers.filter((p) => p && p.configured).map((p) => String(p.name));
        const llmKeyConfigured = providers.some((p) => p && p.configured && String(p.source || '') === 'LLM_API_KEY');
        const options = [...configured];
        if (llmKeyConfigured && !options.includes('litellm')) options.push('litellm');
        const current = active.provider || '';
        select.innerHTML = '<option value="">Set active provider…</option>' +
            options.map((n) => `<option value="${escapeHtml(n)}"${n === current ? ' selected' : ''}>${escapeHtml(n)}</option>`).join('');
    }

    if (!providers.length) {
        list.innerHTML = '<p class="empty-note">No providers reported by the backend.</p>';
        return;
    }

    list.innerHTML = providers.map((p) => {
        const name = String((p && p.name) || 'unknown');
        const configured = !!(p && p.configured);
        const isActive = !!(p && p.active) || (active.provider && String(active.provider) === name);
        const envKey = envKeyForProvider(name);
        return `<div class="provider-card ${configured ? 'configured' : 'unconfigured'}${isActive ? ' active' : ''}" data-provider="${escapeHtml(name)}" data-envkey="${escapeHtml(envKey)}">
            <span class="provider-dot" title="${configured ? 'Configured' : 'Not configured'}"></span>
            <div class="provider-main">
                <div class="provider-name">${escapeHtml(name)}${isActive ? ' <span class="provider-star" title="Active provider">★</span>' : ''}</div>
                <div class="provider-meta">
                    <span title="Masked key">${escapeHtml(maskedOrDash(p && p.masked_key))}</span>
                    <span title="Base host">${escapeHtml(maskedOrDash(p && p.base))}</span>
                    <span title="Source env var">${escapeHtml(maskedOrDash(p && p.source))}</span>
                </div>
            </div>
            <div class="provider-actions">
                <button class="btn provider-test-btn" type="button"${configured ? '' : ' disabled title="Not configured"'}>Test</button>
                <button class="btn provider-setkey-btn" type="button">Set key</button>
                <span class="test-result" hidden></span>
            </div>
        </div>`;
    }).join('');
}

async function testProvider(card) {
    const name = card.getAttribute('data-provider');
    const btn = card.querySelector('.provider-test-btn');
    const result = card.querySelector('.test-result');
    if (!name || !btn || !result) return;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>';
    result.hidden = false;
    result.className = 'test-result pending';
    result.textContent = 'testing…';
    try {
        const res = await apiFetch('/api/providers/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider: name }),
        });
        let data = null;
        try { data = await res.json(); } catch (_) { data = null; }
        if (!res.ok) {
            const detail = (data && data.detail) || `HTTP ${res.status}`;
            result.className = 'test-result fail';
            result.textContent = 'FAIL';
            result.title = String(detail);
        } else if (data && data.ok) {
            const ms = (data.latency_ms != null) ? ` · ${data.latency_ms}ms` : '';
            result.className = 'test-result ok';
            result.textContent = `OK${ms}`;
            result.title = data.detail ? String(data.detail) : 'Provider reachable';
        } else {
            result.className = 'test-result fail';
            result.textContent = 'FAIL';
            result.title = (data && data.detail) ? String(data.detail) : 'Provider test failed';
        }
    } catch (err) {
        result.className = 'test-result fail';
        result.textContent = 'FAIL';
        result.title = 'Network error contacting test endpoint';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Test';
    }
}

/* Set-key modal */
let setkeyTarget = { provider: null, envKey: null };
function openSetKeyModal(provider, envKey) {
    setkeyTarget = { provider, envKey };
    $('setkey-title').textContent = `Set key — ${provider}`;
    $('setkey-sub').textContent = `Writes ${envKey} to the live environment.`;
    $('setkey-envkey').textContent = envKey;
    $('setkey-input').value = '';
    $('setkey-modal').hidden = false;
    setTimeout(() => { try { $('setkey-input').focus(); } catch (_) { /* noop */ } }, 30);
}
function closeSetKeyModal() {
    $('setkey-modal').hidden = true;
    $('setkey-input').value = '';
}
async function saveSetKey() {
    const input = $('setkey-input');
    const value = input.value;
    if (!value) {
        showToast('Nothing to save', 'Enter a value first.', 'warn');
        return;
    }
    const btn = $('setkey-save');
    btn.disabled = true;
    try {
        const res = await apiFetch('/api/providers/env', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: setkeyTarget.envKey, value }),
        });
        let data = null;
        try { data = await res.json(); } catch (_) { data = null; }
        if (!res.ok) {
            const detail = (data && data.detail) || `HTTP ${res.status}`;
            showToast('Save failed', String(detail), 'warn');
        } else {
            const restart = !!(data && data.restart_required);
            showToast('Saved', restart ? 'Effective for live env; restart required for new processes.' : 'Saved.', 'ok');
            closeSetKeyModal();
            loadProviders();
        }
    } catch (err) {
        showToast('Save failed', 'Network error contacting env endpoint.', 'warn');
    } finally {
        btn.disabled = false;
    }
}

async function applyActiveProvider() {
    const select = $('active-provider');
    const modelInput = $('model-input');
    const name = select ? select.value : '';
    if (!name) {
        showToast('No provider selected', 'Choose a provider from the dropdown first.', 'warn');
        return;
    }
    const btn = $('save-active-provider');
    btn.disabled = true;
    try {
        const res = await apiFetch('/api/providers/env', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: 'EXAAI_LLM_PROVIDER', value: name }),
        });
        let data = null;
        try { data = await res.json(); } catch (_) { data = null; }
        if (!res.ok) {
            showToast('Save failed', String((data && data.detail) || `HTTP ${res.status}`), 'warn');
            return;
        }
        const restart = !!(data && data.restart_required);
        const model = modelInput ? modelInput.value.trim() : '';
        if (model) {
            try {
                const res2 = await apiFetch('/api/providers/env', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'LITELLM_MODEL', value: model }),
                });
                if (!res2.ok) {
                    let d2 = null;
                    try { d2 = await res2.json(); } catch (_) { d2 = null; }
                    showToast('Model not saved', String((d2 && d2.detail) || `HTTP ${res2.status}`), 'warn');
                }
            } catch (_) {
                showToast('Model not saved', 'Network error saving LITELLM_MODEL.', 'warn');
            }
        }
        showToast('Active provider set', restart ? 'Effective for live env; restart required for new processes.' : `Active provider: ${name}`, 'ok');
        if (modelInput) modelInput.value = '';
        loadProviders();
    } catch (err) {
        showToast('Save failed', 'Network error contacting env endpoint.', 'warn');
    } finally {
        btn.disabled = false;
    }
}

/* ---------- Scan control ---------- */
function updateScanPanel(s) {
    const running = (s && s.counters && Number(s.counters.agents_running)) || 0;
    const isRunning = running > 0;
    const stopBtn = $('stop-scan-btn');
    if (stopBtn) stopBtn.disabled = !isRunning;
    const hint = $('scan-status-hint');
    if (hint) hint.textContent = isRunning ? `running · ${running} agent${running === 1 ? '' : 's'}` : 'idle';
    const runEl = $('scan-run-name');
    if (runEl) runEl.textContent = (s && s.run_name) || 'no active run';
    const upEl = $('scan-uptime');
    if (upEl) {
        if (s && s.uptime_seconds != null) upEl.textContent = fmtUptime(s.uptime_seconds);
        else if (s && s.start_time) {
            const start = new Date(s.start_time).getTime();
            upEl.textContent = Number.isNaN(start) ? '--:--:--' : fmtUptime((Date.now() - start) / 1000);
        } else upEl.textContent = '--:--:--';
    }
    const agentsEl = $('scan-agents-running');
    if (agentsEl) agentsEl.textContent = String(running);
}

function openStopModal() { $('stop-modal').hidden = false; }
function closeStopModal() { $('stop-modal').hidden = true; }
async function confirmStopScan() {
    const btn = $('stop-confirm');
    btn.disabled = true;
    try {
        const res = await apiFetch('/api/scan/stop', { method: 'POST' });
        let data = null;
        try { data = await res.json(); } catch (_) { data = null; }
        if (!res.ok) {
            showToast('Stop failed', String((data && data.detail) || `HTTP ${res.status}`), 'warn');
        } else {
            showToast('Stop requested', (data && data.detail) ? String(data.detail) : 'stop requested', 'ok');
        }
    } catch (err) {
        showToast('Stop failed', 'Network error contacting stop endpoint.', 'warn');
    } finally {
        btn.disabled = false;
        closeStopModal();
    }
}

/* ---------- Audit log ---------- */
async function loadAudit() {
    const tbody = $('audit-body');
    if (!tbody) return;
    try {
        const res = await apiFetch('/api/audit?limit=20');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const entries = Array.isArray(data) ? data : (Array.isArray(data && data.entries) ? data.entries : []);
        if (!entries.length) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="3">No audit entries</td></tr>';
            return;
        }
        tbody.innerHTML = entries.map((e) => `<tr>
            <td>${escapeHtml(fmtTs(e && e.ts))}</td>
            <td>${escapeHtml((e && e.action) || '—')}</td>
            <td>${escapeHtml((e && e.detail) || '—')}</td>
        </tr>`).join('');
    } catch (err) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="3">Audit log unavailable</td></tr>';
    }
}
function syncAuditPolling() {
    const details = $('audit-details');
    if (!details) return;
    if (details.open) {
        loadAudit();
        if (state.auditTimer) clearInterval(state.auditTimer);
        state.auditTimer = setInterval(loadAudit, 15000);
    } else if (state.auditTimer) {
        clearInterval(state.auditTimer);
        state.auditTimer = null;
    }
}

/* ---------- Export full (.zip) ---------- */
async function exportFull() {
    try {
        const res = await apiFetch('/api/export/full');
        if (res.status === 404) {
            showToast('Export unavailable', 'report files not ready yet', 'warn');
            return;
        }
        if (!res.ok) {
            showToast('Export failed', `HTTP ${res.status}`, 'warn');
            return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'exaai-report.zip';
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
    } catch (err) {
        showToast('Export failed', 'Network error contacting export endpoint.', 'warn');
    }
}

/* ---------- Wire-up: v2.1 controls ---------- */
$('mute-toggle').addEventListener('click', () => setMuted(!state.muted));
setMuted(state.muted);

$('export-full').addEventListener('click', exportFull);
$('print-pdf').addEventListener('click', () => window.print());

$('providers-list').addEventListener('click', (e) => {
    const testBtn = e.target.closest('.provider-test-btn');
    if (testBtn && !testBtn.disabled) {
        const card = testBtn.closest('.provider-card');
        if (card) testProvider(card);
        return;
    }
    const setKeyBtn = e.target.closest('.provider-setkey-btn');
    if (setKeyBtn) {
        const card = setKeyBtn.closest('.provider-card');
        if (card) openSetKeyModal(card.getAttribute('data-provider'), card.getAttribute('data-envkey'));
    }
});
$('save-active-provider').addEventListener('click', applyActiveProvider);
$('setkey-cancel').addEventListener('click', closeSetKeyModal);
$('setkey-save').addEventListener('click', saveSetKey);
$('setkey-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') saveSetKey(); });
$('setkey-modal').addEventListener('click', (e) => { if (e.target === $('setkey-modal')) closeSetKeyModal(); });

$('stop-scan-btn').addEventListener('click', openStopModal);
$('stop-cancel').addEventListener('click', closeStopModal);
$('stop-confirm').addEventListener('click', confirmStopScan);
$('stop-modal').addEventListener('click', (e) => { if (e.target === $('stop-modal')) closeStopModal(); });

$('audit-details').addEventListener('toggle', syncAuditPolling);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeSetKeyModal(); closeStopModal(); }
});

/* ---------- Init: update check + providers ---------- */
checkForUpdate();
setInterval(checkForUpdate, 6 * 60 * 60 * 1000); // every 6h
loadProviders();
