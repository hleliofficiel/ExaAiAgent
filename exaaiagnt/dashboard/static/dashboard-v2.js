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
};

const $ = (id) => document.getElementById(id);

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
        const res = await fetch('/api/state', { headers: { 'Accept': 'application/json' } });
        if (!res.ok) return;
        const s = await res.json();
        $('run-name').textContent = s.run_name || 'no active run';
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
        const res = await fetch('/api/vulnerabilities', { headers: { 'Accept': 'application/json' } });
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
