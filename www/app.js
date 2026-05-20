(function () {
  const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const esc = (s) => String(s ?? '').replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;');

  let cfg = null;
  const PAGE_SIZE = 50;
  let logState = { entries: [], total: 0, offset: 0, filter: '', sse: null };

  // ---------- theme ----------
  const THEME_KEY = 'guardian.theme';
  function applyTheme(t) {
    if (t === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
    else document.documentElement.removeAttribute('data-theme');
  }
  applyTheme(localStorage.getItem(THEME_KEY) ||
    (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

  $('#theme-toggle').addEventListener('click', () => {
    const cur = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
    const next = cur === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
  });

  function setStatus(msg, isErr) {
    const el = $('#save-msg');
    el.textContent = msg || '';
    el.classList.toggle('err', !!isErr);
  }

  // Hosts list <-> comma-separated string
  const hostsToStr = (h) => Array.isArray(h) ? h.join(', ') : '';
  const strToHosts = (s) => {
    const out = String(s || '').split(',').map((x) => x.trim()).filter(Boolean);
    return out.length ? out : undefined;
  };

  function renderScopedTable(tableId, entries) {
    const tbody = $('#' + tableId + ' tbody');
    tbody.innerHTML = '';
    (entries || []).forEach((entry, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><input type="text" data-idx="${idx}" data-field="value" value="${esc(entry.value)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="hosts" value="${esc(hostsToStr(entry.hosts))}" placeholder="*"></td>
        <td><button class="row-del" data-idx="${idx}" title="Delete">&times;</button></td>`;
      tbody.appendChild(tr);
    });
  }

  function readScopedTable(tableId) {
    const rows = $$('#' + tableId + ' tbody tr');
    const out = [];
    rows.forEach((tr) => {
      const value = tr.querySelector('[data-field="value"]').value.trim();
      const hosts = strToHosts(tr.querySelector('[data-field="hosts"]').value);
      if (value) out.push(hosts ? { value, hosts } : { value });
    });
    return out;
  }

  function renderWAF() {
    const tbody = $('#waf-table tbody');
    tbody.innerHTML = '';
    (cfg.waf_rules || []).forEach((rule, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><input type="checkbox" data-idx="${idx}" data-field="enabled" ${rule.enabled ? 'checked' : ''}></td>
        <td><input type="text" data-idx="${idx}" data-field="name" value="${esc(rule.name)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="pattern" value="${esc(rule.pattern)}"></td>
        <td><input type="text" data-idx="${idx}" data-field="hosts" value="${esc(hostsToStr(rule.hosts))}" placeholder="*"></td>
        <td><button class="row-del" data-idx="${idx}" title="Delete">&times;</button></td>`;
      tbody.appendChild(tr);
    });
  }

  function applyToUI(c) {
    cfg = c;
    renderScopedTable('ip-allow-table', c.ip_allowlist);
    renderScopedTable('ip-block-table', c.ip_blocklist);
    renderScopedTable('ua-table', c.ua_blocklist);
    renderWAF();
    $('#rate-enabled').checked = !!c.rate_limit?.enabled;
    $('#rate-rpm').value = c.rate_limit?.requests_per_minute ?? 120;
    $('#rate-burst').value = c.rate_limit?.burst ?? 30;
    $('#honeypot-enabled').checked = !!c.honeypot?.enabled;
    $('#honeypot-ban-secs').value = c.honeypot?.ban_seconds ?? 3600;
    renderScopedTable('honeypot-table', c.honeypot?.paths || []);
    $('#autoban-enabled').checked = !!c.auto_ban?.enabled;
    $('#autoban-threshold').value = c.auto_ban?.threshold ?? 5;
    $('#autoban-window').value = c.auto_ban?.window_seconds ?? 60;
    $('#autoban-ban-secs').value = c.auto_ban?.ban_seconds ?? 600;
    $('#trust-xff').checked = !!c.trust_xff;
  }

  function collectUI() {
    const wafRules = [];
    $$('#waf-table tbody tr').forEach((tr) => {
      const rule = {
        enabled: tr.querySelector('[data-field="enabled"]').checked,
        name: tr.querySelector('[data-field="name"]').value.trim(),
        pattern: tr.querySelector('[data-field="pattern"]').value,
        hosts: strToHosts(tr.querySelector('[data-field="hosts"]').value),
      };
      if (!rule.hosts) delete rule.hosts;
      if (rule.name || rule.pattern) wafRules.push(rule);
    });
    return {
      ip_allowlist: readScopedTable('ip-allow-table'),
      ip_blocklist: readScopedTable('ip-block-table'),
      ua_blocklist: readScopedTable('ua-table'),
      waf_rules: wafRules,
      rate_limit: {
        enabled: $('#rate-enabled').checked,
        requests_per_minute: parseInt($('#rate-rpm').value, 10) || 120,
        burst: parseInt($('#rate-burst').value, 10) || 30,
      },
      honeypot: {
        enabled: $('#honeypot-enabled').checked,
        ban_seconds: parseInt($('#honeypot-ban-secs').value, 10) || 3600,
        paths: readScopedTable('honeypot-table'),
      },
      auto_ban: {
        enabled: $('#autoban-enabled').checked,
        threshold: parseInt($('#autoban-threshold').value, 10) || 5,
        window_seconds: parseInt($('#autoban-window').value, 10) || 60,
        ban_seconds: parseInt($('#autoban-ban-secs').value, 10) || 600,
      },
      trust_xff: $('#trust-xff').checked,
    };
  }

  async function fetchConfig() {
    setStatus('Loading…');
    const r = await fetch('./api/config', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) { setStatus('Load failed', true); return; }
    applyToUI(await r.json());
    setStatus('Loaded');
  }

  async function saveConfig() {
    const body = collectUI();
    setStatus('Saving…');
    const r = await fetch('./api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify(body),
    });
    if (!r.ok) { setStatus('Save failed: ' + r.status, true); return; }
    setStatus('Saved');
    applyToUI(body);
  }

  // ---------- block log: paginated + SSE-live ----------
  function renderLog() {
    const tbody = $('#log-table tbody');
    tbody.innerHTML = '';
    const filter = logState.filter.toLowerCase();
    const visible = filter ? logState.entries.filter((e) =>
      [e.ip, e.host, e.reason, e.user_agent, e.request_uri].some((v) => String(v || '').toLowerCase().includes(filter))
    ) : logState.entries;

    visible.forEach((e) => {
      const tr = document.createElement('tr');
      if (e.__fresh) { tr.classList.add('fresh-row'); delete e.__fresh; }
      const t = e.time ? new Date(e.time).toLocaleString() : '';
      const src = e.source || 'guardian';
      tr.innerHTML = `<td>${esc(t)}</td><td><span class="src src-${esc(src)}">${esc(src)}</span></td><td><code>${esc(e.ip)}</code></td><td>${esc(e.host)}</td><td>${esc(e.method)}</td><td><code>${esc(e.request_uri)}</code></td><td>${esc(e.user_agent)}</td><td><code>${esc(e.reason)}</code></td><td>${e.status || ''}</td>`;
      tbody.appendChild(tr);
    });
    $('#log-count').textContent = logState.total ? `(${visible.length}/${logState.total})` : '';
    $('#log-pager-info').textContent =
      logState.entries.length >= logState.total
        ? 'all loaded'
        : `showing ${logState.entries.length} of ${logState.total}`;
    $('#log-older').disabled = logState.entries.length >= logState.total;
  }

  async function fetchLogPage(append) {
    const offset = append ? logState.entries.length : 0;
    const r = await fetch(`./api/blocklog?offset=${offset}&limit=${PAGE_SIZE}`, {
      headers: { 'X-CSRF-Token': csrfToken },
    });
    if (!r.ok) return;
    const data = await r.json();
    logState.total = data.total;
    if (append) {
      logState.entries = logState.entries.concat(data.entries);
    } else {
      logState.entries = data.entries;
    }
    renderLog();
  }

  function connectLogStream() {
    if (logState.sse) {
      logState.sse.close();
      logState.sse = null;
    }
    try {
      const es = new EventSource('./api/blocklog/stream');
      es.addEventListener('block', (ev) => {
        try {
          const entry = JSON.parse(ev.data);
          entry.__fresh = true;
          logState.entries.unshift(entry);
          logState.total += 1;
          renderLog();
        } catch (_) { /* ignore */ }
      });
      es.onopen = () => $('#live').classList.add('on');
      es.onerror = () => {
        $('#live').classList.remove('on');
        // EventSource auto-reconnects; nothing to do.
      };
      logState.sse = es;
    } catch (_) {
      $('#live').classList.remove('on');
    }
  }

  // ---------- temp bans ----------
  async function fetchTempBans() {
    const r = await fetch('./api/tempbans', { headers: { 'X-CSRF-Token': csrfToken } });
    if (!r.ok) return;
    const bans = await r.json();
    const tbody = $('#tempbans-table tbody');
    tbody.innerHTML = '';
    bans.sort((a, b) => a.expires.localeCompare(b.expires));
    bans.forEach((b) => {
      const tr = document.createElement('tr');
      const exp = new Date(b.expires).toLocaleString();
      tr.innerHTML = `<td><code>${esc(b.ip)}</code></td><td>${esc(exp)}</td><td><button data-clear-ip="${esc(b.ip)}">Clear</button></td>`;
      tbody.appendChild(tr);
    });
    $('#tempbans-count').textContent = bans.length ? `(${bans.length})` : '';
  }

  async function clearTempBan(ip) {
    await fetch(`./api/tempbans/clear?ip=${encodeURIComponent(ip)}`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrfToken },
    });
    fetchTempBans();
  }

  // ---------- wiring ----------
  $$('.tab').forEach((t) => t.addEventListener('click', () => {
    $$('.tab').forEach((x) => x.classList.remove('active'));
    $$('.tab-panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $('#tab-' + t.dataset.tab).classList.add('active');
    if (t.dataset.tab === 'log') fetchLogPage(false);
    if (t.dataset.tab === 'tempbans') fetchTempBans();
  }));

  document.body.addEventListener('click', (e) => {
    const add = e.target.dataset.add;
    if (add === 'ip-allow') { (cfg.ip_allowlist ||= []).push({ value: '' }); renderScopedTable('ip-allow-table', cfg.ip_allowlist); }
    else if (add === 'ip-block') { (cfg.ip_blocklist ||= []).push({ value: '' }); renderScopedTable('ip-block-table', cfg.ip_blocklist); }
    else if (add === 'ua') { (cfg.ua_blocklist ||= []).push({ value: '' }); renderScopedTable('ua-table', cfg.ua_blocklist); }
    else if (add === 'honeypot') {
      cfg.honeypot = cfg.honeypot || { enabled: false, ban_seconds: 3600, paths: [] };
      cfg.honeypot.paths = cfg.honeypot.paths || [];
      cfg.honeypot.paths.push({ value: '' });
      renderScopedTable('honeypot-table', cfg.honeypot.paths);
    }
    else if (e.target.dataset.clearIp) {
      clearTempBan(e.target.dataset.clearIp);
    }
    else if (e.target.matches('.row-del')) {
      const table = e.target.closest('table');
      const tr = e.target.closest('tr');
      tr.remove();
      Array.from(table.querySelectorAll('tbody tr')).forEach((row, i) => {
        row.querySelectorAll('[data-idx]').forEach((el) => el.dataset.idx = i);
      });
    }
  });

  $('#waf-add').addEventListener('click', () => {
    cfg.waf_rules = cfg.waf_rules || [];
    cfg.waf_rules.push({ name: 'new-rule', pattern: '', enabled: true });
    renderWAF();
  });

  $('#save').addEventListener('click', saveConfig);
  $('#reload').addEventListener('click', fetchConfig);
  $('#log-refresh').addEventListener('click', () => fetchLogPage(false));
  $('#log-older').addEventListener('click', () => fetchLogPage(true));
  $('#log-filter').addEventListener('input', (e) => { logState.filter = e.target.value; renderLog(); });
  $('#tempbans-refresh').addEventListener('click', fetchTempBans);

  fetchConfig();
  connectLogStream();
})();
