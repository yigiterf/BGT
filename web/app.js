/* ==========================================================================
   MiniFirewall Lab — arayüz mantığı
   Her karar sunucudaki Python motorundan gelir; burada sadece görselleştirme,
   kural düzenleme ve canlı akış yönetimi vardır.
   ========================================================================== */
'use strict';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  rules: [],
  policy: 'deny',
  stateful: false,
  scenario: '',
  scenarioLabel: '',
  stats: { total: 0, allowed: 0, denied: 0, block_rate: 0, history: [], rule_hits: [] },
  scenarios: [],
  bursts: [],
  services: [],
  realEndpoints: [],
  sourceFiles: [],
  lastSeq: 0,
  filter: 'all',
  lastDecision: null,
  editingIndex: null,
  seen: new Set(),
  historyKey: '',
  logRows: 0,
  codeFile: 'engine.py',
  busy: false,
  lint: [],
  floodLimit: null,
  floodDefault: 30,
  auto: false,
  autoTimer: null,
  presentation: false,
};

/* Sunum modu: projeksiyon/gün ışığı için canvas üzerindeki yazı ve kutuları büyütür. */
function pScale() {
  return state.presentation ? 1.3 : 1;
}

function applyPresentation(on) {
  state.presentation = on;
  document.documentElement.classList.toggle('presentation', on);
  const btn = $('#presentBtn');
  if (btn) {
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-pressed', on ? 'true' : 'false');
    btn.innerHTML = on ? '☀️ Sunum modu açık' : '☀️ Sunum modu';
  }
  try {
    localStorage.setItem('mfw_presentation', on ? '1' : '0');
  } catch (_) {
    /* özel pencere/depolama kapalı olabilir, sorun değil */
  }
  resizeCanvas();
}

const FALLBACK_SERVICES = [
  { ip: '10.0.0.10', name: 'Web', ports: [80, 443], color: '#22d3ee' },
  { ip: '10.0.0.53', name: 'DNS', ports: [53], color: '#a78bfa' },
  { ip: '10.0.0.20', name: 'SSH', ports: [22], color: '#fbbf24' },
  { ip: '10.0.0.30', name: 'DB', ports: [3306], color: '#34d399' },
];

const ATTACK_ICONS = {
  portscan: '🔍', synflood: '🌊', ddos: '🤖', sshbrute: '🔑',
  dns: '🧬', ping: '📡', db: '🗄️',
};

/* ============================== yardımcılar ============================== */
function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function num(value) {
  const n = parseInt(String(value).trim(), 10);
  return Number.isFinite(n) ? n : null;
}

function fmtTime(ts) {
  const d = new Date(ts * 1000);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

function packetText(packet) {
  const src = packet.src_port != null ? `${packet.src_ip}:${packet.src_port}` : packet.src_ip;
  const dst = packet.dst_port != null ? `${packet.dst_ip}:${packet.dst_port}` : packet.dst_ip;
  const flags = packet.flags ? ` [${packet.flags}]` : '';
  return `${String(packet.protocol).toUpperCase()} ${src} → ${dst}${flags}`;
}

function shortPort(packet) {
  if (packet.protocol === 'icmp') return 'icmp';
  return `:${packet.dst_port}`;
}

let toastTimer = null;
function toast(message, kind = '') {
  const el = $('#toast');
  el.textContent = message;
  el.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.className = 'toast'; }, 2800);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Sunucu hatası (${res.status})`);
  return data;
}

/* ============================== uygulama durumu ============================== */
function applyState(data) {
  if (!data) return;
  if (data.scenarios) state.scenarios = data.scenarios;
  if (data.bursts) state.bursts = data.bursts;
  if (data.services) state.services = data.services;
  if (data.real_endpoints) state.realEndpoints = data.real_endpoints;
  if (data.source_files) state.sourceFiles = data.source_files;

  state.rules = data.rules || [];
  state.policy = data.default_policy || 'deny';
  state.stateful = Boolean(data.stateful);
  state.floodLimit = data.flood_limit || null;
  if (data.flood_default) state.floodDefault = data.flood_default;
  state.lint = data.lint || [];
  state.scenario = data.scenario || state.scenario;
  state.stats = data.stats || state.stats;

  state.scenarioLabel =
    (state.scenarios.find((s) => s.name === state.scenario) || {}).label || state.scenario;

  renderScenarioSelect();
  renderBursts();
  renderRealEndpoints();
  renderRules();
  updatePolicyUI();
  updateStatefulUI();
  updateFloodUI();
  updateStats(state.stats);
  $('#stageScenario').textContent = state.scenarioLabel;
}

function renderScenarioSelect() {
  const select = $('#scenarioSelect');
  if (select.options.length !== state.scenarios.length) {
    select.innerHTML = state.scenarios
      .map((s) => `<option value="${esc(s.name)}">${esc(s.label)}</option>`)
      .join('');
  }
  select.value = state.scenario;
  select.title = (state.scenarios.find((s) => s.name === state.scenario) || {}).description || '';
}

function renderBursts() {
  const grid = $('#attackGrid');
  if (grid.dataset.built === String(state.bursts.length)) return;
  grid.dataset.built = String(state.bursts.length);
  grid.innerHTML = state.bursts
    .map(
      (b) => `<button type="button" class="attack-btn" data-kind="${esc(b.kind)}"
        title="${esc(b.label)} — ${b.count} paket">
        <span class="em">${ATTACK_ICONS[b.kind] || '⚡'}</span>
        <span>${esc(b.label)}</span>
        <span class="n">${b.count}</span>
      </button>`
    )
    .join('');
}

function renderRealEndpoints() {
  const grid = $('#realGrid');
  if (grid.dataset.built === String(state.realEndpoints.length)) return;
  grid.dataset.built = String(state.realEndpoints.length);
  grid.innerHTML = state.realEndpoints
    .map(
      (e) => `<a href="${esc(e.path)}" target="_blank" rel="noopener"
        title="${esc(e.label)} — gerçek HTTP isteği">${esc(e.path)} ↗</a>`
    )
    .join('');
}

function updatePolicyUI() {
  $$('#policySeg button').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.policy === state.policy);
  });
  $('#policyLabel').textContent = state.policy.toUpperCase();
  $('#policyLabel').style.color = state.policy === 'deny' ? 'var(--red)' : 'var(--green)';
}

function updateStatefulUI() {
  $('#statefulToggle').checked = state.stateful;
}

function updateFloodUI() {
  $('#floodToggle').checked = Boolean(state.floodLimit);
  $('#floodLabel').textContent = state.floodLimit
    ? `Flood guard · ${state.floodLimit}/sn`
    : 'Flood guard';
}

function lintFor(index) {
  return (state.lint || []).filter((f) => f.index === index);
}

function lintBadge(index) {
  const items = lintFor(index);
  if (!items.length) return '';
  const rank = { error: 3, warn: 2, info: 1 };
  const worst = items.reduce((a, b) => (rank[b.level] > rank[a.level] ? b : a));
  const icon = worst.level === 'info' ? 'ⓘ' : '⚠';
  const title = items.map((f) => f.message).join('\n');
  return `<span class="lint ${worst.level}" title="${esc(title)}">${icon} ${esc(lintShort(worst))}</span>`;
}

function lintShort(f) {
  return { shadowed: 'asla çalışmaz', redundant: 'gereksiz', overlap: 'çakışma', broad: 'çok geniş' }[f.kind] || f.kind;
}

/* ============================== kurallar ============================== */
function ruleLine(rule) {
  const src = rule.src + (rule.sport !== 'any' ? `:${rule.sport}` : '');
  const dst = rule.dst + (rule.dport !== 'any' ? `:${rule.dport}` : '');
  const flags = rule.flags ? ` [${rule.flags}]` : '';
  return `${rule.protocol.toUpperCase()}  ${src} → ${dst}${flags}`;
}

function renderRules() {
  const list = $('#ruleList');
  $('#ruleCount').textContent = String(state.rules.length);

  if (!state.rules.length) {
    list.innerHTML = `<div class="rules-empty">
      Kural yok.<br>Varsayılan politika <b>${state.policy.toUpperCase()}</b> uygulanır.
      <br><br>“+ Kural” ile ilk kuralı ekle.</div>`;
    return;
  }

  const maxHits = Math.max(1, ...state.rules.map((r) => r.hits || 0));
  const policyNotes = (state.lint || []).filter((f) => f.index == null);
  const notes = policyNotes
    .map((f) => `<div class="lint-note ${f.level}">⚠ ${esc(f.message)}</div>`)
    .join('');
  list.innerHTML = notes + state.rules
    .map((r, i) => {
      const bar = r.hits ? Math.max(4, Math.min(100, (r.hits / maxHits) * 100)) : 0;
      const lintCls = lintFor(i).some((f) => f.level === 'error') ? 'lint-error' : '';
      return `<div class="rule-row ${r.enabled ? '' : 'disabled'} ${lintCls}" data-index="${i}"
          title="${esc(r.text)}">
        <span class="rule-num">${i + 1}</span>
        <span class="rule-action ${r.action}">${r.action.toUpperCase()}</span>
        <span class="rule-main">
          <span class="rule-text">${esc(ruleLine(r))}</span>
          <span class="rule-sub">${esc(r.comment || 'açıklama yok')}
            <span class="hits" data-hits="${i}">${r.hits ? `· ${r.hits} eşleşme` : ''}</span>
            ${r.enabled ? '' : ' · devre dışı'}
          </span>
          ${r.enabled ? lintBadge(i) : ''}
        </span>
        <span class="rule-controls">
          <button class="rule-btn" data-act="up" title="Yukarı taşı">↑</button>
          <button class="rule-btn" data-act="down" title="Aşağı taşı">↓</button>
          <button class="rule-btn" data-act="toggle" title="${r.enabled ? 'Devre dışı bırak' : 'Etkinleştir'}">${r.enabled ? '◉' : '○'}</button>
          <button class="rule-btn del" data-act="del" title="Sil">✕</button>
        </span>
        <span class="rule-bar" style="width:${bar}%"></span>
      </div>`;
    })
    .join('');
}

async function saveRules(rules) {
  const data = await api('/api/rules', {
    method: 'POST',
    body: JSON.stringify({ rules }),
  });
  applyState(data);
}

async function onRuleAction(index, action) {
  const rules = state.rules.map((r) => ({ ...r }));
  if (action === 'del') {
    rules.splice(index, 1);
  } else if (action === 'toggle') {
    rules[index].enabled = !rules[index].enabled;
  } else if (action === 'up' && index > 0) {
    [rules[index - 1], rules[index]] = [rules[index], rules[index - 1]];
  } else if (action === 'down' && index < rules.length - 1) {
    [rules[index + 1], rules[index]] = [rules[index], rules[index + 1]];
  } else {
    return;
  }
  try {
    await saveRules(rules);
    toast('Kurallar güncellendi', 'ok');
  } catch (err) {
    toast(err.message, 'bad');
  }
}

/* ============================== kural modalı ============================== */
function openRuleModal(index = null) {
  state.editingIndex = index;
  const r = index == null
    ? { action: 'allow', protocol: 'tcp', src: 'any', sport: 'any', dst: 'any', dport: 'any', flags: '', comment: '' }
    : state.rules[index];

  $('#rAction').value = r.action;
  $('#rProto').value = r.protocol;
  $('#rSrc').value = r.src;
  $('#rSport').value = r.sport;
  $('#rDst').value = r.dst;
  $('#rDport').value = r.dport;
  $('#rFlags').value = r.flags || '';
  $('#rComment').value = r.comment || '';
  $('#ruleError').textContent = '';
  $('#modalTitle').textContent = index == null ? 'Yeni kural' : `Kural #${index + 1} düzenle`;
  $('#deleteRuleBtn').hidden = index == null;
  updatePreview();
  showModal('#ruleModal');
  setTimeout(() => $('#rSrc').focus(), 60);
}

function updatePreview() {
  const action = $('#rAction').value;
  const field = (id) => $(id).value.trim() || 'any';
  let line = `${field('#rProto')} ${field('#rSrc')} ${field('#rSport')} ${field('#rDst')} ${field('#rDport')}`;
  const flags = $('#rFlags').value.trim();
  if (flags) line += ` flags=${flags.toUpperCase()}`;
  const comment = $('#rComment').value.trim();
  $('#rulePreview').innerHTML =
    `<span class="act-${action}">${action}</span> ${esc(line)}` +
    (comment ? ` <span class="cmt"># ${esc(comment)}</span>` : '');
}

async function submitRule(event) {
  event.preventDefault();
  const action = $('#rAction').value;
  const rule = {
    action,
    protocol: $('#rProto').value,
    src: $('#rSrc').value.trim() || 'any',
    sport: $('#rSport').value.trim() || 'any',
    dst: $('#rDst').value.trim() || 'any',
    dport: $('#rDport').value.trim() || 'any',
    flags: $('#rFlags').value.trim().toUpperCase(),
    comment: $('#rComment').value.trim(),
    enabled: true,
  };

  const rules = state.rules.map((r) => ({ ...r }));
  if (state.editingIndex == null) {
    rules.push(rule);
  } else {
    rules[state.editingIndex] = { ...rules[state.editingIndex], ...rule };
  }

  try {
    await saveRules(rules);
    hideModal('#ruleModal');
    toast(state.editingIndex == null ? 'Kural eklendi' : 'Kural güncellendi', 'ok');
  } catch (err) {
    $('#ruleError').textContent = err.message;
  }
}

/* ============================== modal / çekmece ============================== */
function showModal(sel) {
  $(sel).classList.add('open');
  $(sel).setAttribute('aria-hidden', 'false');
}
function hideModal(sel) {
  $(sel).classList.remove('open');
  $(sel).setAttribute('aria-hidden', 'true');
}

function openCode(file) {
  state.codeFile = file || state.codeFile;
  $('#codeDrawer').classList.add('open');
  $('#codeDrawer').setAttribute('aria-hidden', 'false');
  $('#drawerBackdrop').classList.add('open');
  renderCodeTabs();
  loadCode(state.codeFile);
}

function closeCode() {
  $('#codeDrawer').classList.remove('open');
  $('#codeDrawer').setAttribute('aria-hidden', 'true');
  $('#drawerBackdrop').classList.remove('open');
}

const CODE_ORDER = ['engine.py', 'rules.py', 'packet.py', 'analysis.py', 'export.py', 'traffic.py', 'scenarios.py', 'pcap.py', 'quiz.py', 'server.py', 'cli.py', 'run.py', 'iptables.sh'];

function renderCodeTabs() {
  const files = CODE_ORDER.filter((f) => state.sourceFiles.includes(f))
    .concat(state.sourceFiles.filter((f) => !CODE_ORDER.includes(f)));
  $('#codeTabs').innerHTML = files
    .map((f) => `<button data-file="${esc(f)}" class="${f === state.codeFile ? 'active' : ''}">${esc(f)}</button>`)
    .join('');
  const active = $('#codeTabs button.active');
  if (active && active.scrollIntoView) active.scrollIntoView({ block: 'nearest', inline: 'center' });
}

async function loadCode(file) {
  state.codeFile = file;
  $$('#codeTabs button').forEach((b) => b.classList.toggle('active', b.dataset.file === file));
  $('#codeBody').innerHTML = '<code>Yükleniyor…</code>';
  try {
    const data = await api(`/api/source?file=${encodeURIComponent(file)}`);
    renderCode(data.code);
  } catch (err) {
    $('#codeBody').innerHTML = `<code>${esc(err.message)}</code>`;
  }
}

const KEYWORDS = new Set([
  'def', 'class', 'return', 'if', 'elif', 'else', 'for', 'while', 'in', 'not',
  'and', 'or', 'is', 'None', 'True', 'False', 'import', 'from', 'as', 'with',
  'try', 'except', 'finally', 'raise', 'lambda', 'yield', 'pass', 'continue',
  'break', 'global', 'nonlocal', 'assert', 'del', 'async', 'await', 'match', 'case',
]);

function highlight(line) {
  const re = /("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(#[^\n]*)|([A-Za-z_][A-Za-z0-9_]*)|(\b\d+(?:\.\d+)?\b)/g;
  let out = '';
  let last = 0;
  let m;
  while ((m = re.exec(line)) !== null) {
    out += esc(line.slice(last, m.index));
    const text = esc(m[0]);
    if (m[1]) out += `<span class="tok-str">${text}</span>`;
    else if (m[2]) out += `<span class="tok-cmt">${text}</span>`;
    else if (m[3]) {
      out += KEYWORDS.has(m[0]) ? `<span class="tok-kw">${text}</span>` : text;
    } else out += `<span class="tok-num">${text}</span>`;
    last = m.index + m[0].length;
  }
  out += esc(line.slice(last));
  return out;
}

function renderCode(code) {
  const lines = code.replace(/\t/g, '    ').split('\n');
  $('#codeBody').innerHTML = lines
    .map((line, i) => `<div class="code-line"><span class="ln">${i + 1}</span><span class="lc">${highlight(line)}</span></div>`)
    .join('');
}

/* ============================== istatistikler ============================== */
function updateStats(stats) {
  if (!stats) return;
  state.stats = stats;
  $('#statTotal').textContent = stats.total ?? 0;
  $('#statAllowed').textContent = stats.allowed ?? 0;
  $('#statDenied').textContent = stats.denied ?? 0;
  $('#statRate').textContent = `%${stats.block_rate ?? 0}`;
  $('#statFlood').textContent = stats.flood_blocks ?? 0;

  const history = stats.history || [];
  const key = history.map((h) => `${h.seq}${h.allowed ? 'a' : 'd'}`).join('|');
  if (key !== state.historyKey) {
    state.historyKey = key;
    $('#historyBars').innerHTML = history
      .map((h, i) => `<i class="${h.allowed ? '' : 'deny'}${i === history.length - 1 ? ' fresh' : ''}"></i>`)
      .join('');
  }

  updateRuleHits(stats.rule_hits || []);
}

function updateRuleHits(hits) {
  const maxHits = Math.max(1, ...hits);
  $$('.rule-row').forEach((row) => {
    const i = Number(row.dataset.index);
    const hit = hits[i] || 0;
    const span = row.querySelector(`[data-hits="${i}"]`);
    if (span) {
      const text = hit ? `· ${hit} eşleşme` : '';
      if (span.textContent !== text) span.textContent = text;
    }
    const bar = row.querySelector('.rule-bar');
    if (bar) {
      const width = hit ? Math.max(4, Math.min(100, (hit / maxHits) * 100)) : 0;
      bar.style.width = `${width}%`;
    }
  });
}

function flashRule(index) {
  const row = $(`.rule-row[data-index="${index}"]`);
  if (!row) return;
  row.classList.remove('matched');
  void row.offsetWidth;
  row.classList.add('matched');
  setTimeout(() => row.classList.remove('matched'), 750);
}

/* ============================== log ============================== */
function decisionToLog(d) {
  const p = d.packet;
  return {
    seq: d.seq,
    ts: d.ts,
    allowed: d.allowed,
    action: d.action,
    protocol: p.protocol,
    src_ip: p.src_ip,
    dst_ip: p.dst_ip,
    src_port: p.src_port,
    dst_port: p.dst_port,
    summary: packetText(p),
    reason: d.reason,
    rule_index: d.rule_index,
  };
}

function ingestLog(entry) {
  if (state.seen.has(entry.seq)) return;
  state.seen.add(entry.seq);
  addLogRow(entry);
  if (entry.src_ip === '127.0.0.1') {
    animateFromLog(entry);
  }
}

function addLogRow(entry) {
  const list = $('#logList');
  const row = document.createElement('div');
  row.className = `log-row ${entry.allowed ? 'allow' : 'deny'} ${entry.src_ip === '127.0.0.1' ? 'real' : ''}`;
  row.dataset.action = entry.allowed ? 'allow' : 'deny';
  row.innerHTML = `
    <span class="log-time">${fmtTime(entry.ts)}</span>
    <span class="log-badge ${entry.allowed ? 'allow' : 'deny'}">${entry.allowed ? 'ALLOW' : 'DENY'}</span>
    <span class="log-packet"><span class="proto">${esc(String(entry.protocol).toUpperCase())}</span> ${esc(packetText(entry).replace(/^\S+\s+/, ''))}</span>
    <span class="log-reason">${esc(entry.reason)}</span>
    <span class="log-rule">${entry.rule_index != null ? `#${entry.rule_index + 1}` : ''}</span>`;

  if (state.filter !== 'all' && row.dataset.action !== state.filter) row.style.display = 'none';
  list.appendChild(row);
  state.logRows += 1;
  $('#logCount').textContent = String(state.logRows);
  $('#logEmpty').style.display = 'none';

  while (list.children.length > 400) list.removeChild(list.firstChild);

  const body = $('#logBody');
  if ($('#autoScroll').checked) body.scrollTop = body.scrollHeight;
}

function clearLogView() {
  $('#logList').innerHTML = '';
  state.logRows = 0;
  $('#logCount').textContent = '0';
  $('#logEmpty').style.display = 'grid';
}

/* ============================== karar gösterimi ============================== */
function showVerdict(d) {
  const card = $('#verdictCard');
  card.classList.toggle('ok', d.allowed);
  card.classList.toggle('bad', !d.allowed);

  const badge = $('#verdictBadge');
  badge.className = `v-badge ${d.allowed ? 'ok' : 'bad'}`;
  badge.textContent = d.action.toUpperCase();

  $('#verdictText').textContent = packetText(d.packet);
  $('#verdictReason').textContent = d.reason;
  $('#traceBtn').disabled = !(d.trace && d.trace.length);
  $('#replyBtn').hidden = !(d.allowed && d.packet && d.packet.protocol !== 'icmp');
  state.lastDecision = d;
}

function resetVerdict() {
  const card = $('#verdictCard');
  card.classList.remove('ok', 'bad');
  const badge = $('#verdictBadge');
  badge.className = 'v-badge idle';
  badge.textContent = '—';
  $('#verdictText').textContent = 'Henüz karar yok';
  $('#verdictReason').textContent = 'Bir paket gönder veya saldırı başlat.';
  $('#traceBtn').disabled = true;
  $('#replyBtn').hidden = true;
  state.lastDecision = null;
}

function showBurstVerdict(label, data) {
  const card = $('#verdictCard');
  const blockedMost = data.denied >= data.allowed;
  card.classList.toggle('ok', !blockedMost);
  card.classList.toggle('bad', blockedMost);

  const badge = $('#verdictBadge');
  badge.className = `v-badge ${blockedMost ? 'bad' : 'ok'}`;
  badge.textContent = 'BURST';

  $('#verdictText').textContent = `${label} · ${data.total} paket`;
  $('#verdictReason').textContent =
    `${data.allowed} paket geçti · ${data.denied} paket engellendi` +
    (data.denied ? ' · canlı logda tümü listelenir' : '');
  $('#traceBtn').disabled = true;
  $('#replyBtn').hidden = true;
}

function openTrace() {
  const d = state.lastDecision;
  if (!d || !d.trace) return;
  $('#tracePacket').textContent = `${packetText(d.packet)}   ·   ${d.reason}`;

  $('#traceList').innerHTML = d.trace
    .map((t) => {
      const idx = t.index != null ? `#${t.index + 1}` : 'S';
      const why = t.mismatches && t.mismatches.length
        ? `<div class="trace-why">eşleşmedi: ${esc(t.mismatches.join(' · '))}</div>`
        : '';
      return `<div class="trace-item ${t.matched ? 'matched' : ''} ${t.disabled ? 'disabled' : ''}">
        <div class="trace-idx">${idx}</div>
        <div><div class="trace-rule">${esc(t.text)}</div>${why}</div>
        <div class="trace-mark ${t.matched ? 'yes' : 'no'}">${t.matched ? 'EŞLEŞTİ' : 'ATLANDI'}</div>
      </div>`;
    })
    .join('');

  $('#traceFinal').innerHTML =
    `<div class="tf ${d.allowed ? 'ok' : 'bad'}">SONUÇ: ${d.action.toUpperCase()} — ${esc(d.reason)}</div>`;
  showModal('#traceModal');
}

/* ============================== paket gönderme ============================== */
function readForm() {
  const proto = $('#proto').value;
  return {
    src_ip: $('#srcIp').value.trim(),
    dst_ip: $('#dstIp').value.trim(),
    protocol: proto,
    src_port: proto === 'icmp' ? null : num($('#srcPort').value),
    dst_port: proto === 'icmp' ? null : num($('#dstPort').value),
    flags: proto === 'tcp' ? $('#flags').value.trim().toUpperCase() : '',
    size: 64,
    payload: '',
  };
}

async function sendPacket(packetOverride = null) {
  if (state.busy) return;
  state.busy = true;
  const sendBtn = $('#sendBtn');
  if (sendBtn) sendBtn.disabled = true;
  try {
    const data = await api('/api/packet', {
      method: 'POST',
      body: JSON.stringify({ packet: packetOverride || readForm() }),
    });
    const d = data.decision;
    state.lastSeq = Math.max(state.lastSeq, d.seq);
    ingestLog(decisionToLog(d));
    animateDecision(d);
    showVerdict(d);
    updateStats(data.stats);
    if (d.rule_index != null) flashRule(d.rule_index);
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    state.busy = false;
    if (sendBtn) sendBtn.disabled = false;
  }
}

/* ============================== canlı trafik üreteci ============================== */
const rnd = (lo, hi) => lo + Math.floor(Math.random() * (hi - lo + 1));
const eph = () => rnd(32768, 60999);
const pick = (arr) => arr[rnd(0, arr.length - 1)];

/* Ağırlıklı havuz: çoğu normal trafik, arada saldırgan yoklaması. */
const AUTO_POOL = [
  [4, () => ({ src_ip: `10.0.0.${rnd(40, 60)}`, dst_ip: '10.0.0.10', protocol: 'tcp', src_port: eph(), dst_port: 443, flags: 'SYN' })],
  [3, () => ({ src_ip: `${pick([45, 91, 103, 185])}.${rnd(1, 254)}.${rnd(1, 254)}.${rnd(1, 254)}`, dst_ip: '10.0.0.10', protocol: 'tcp', src_port: eph(), dst_port: 80, flags: 'SYN' })],
  [2, () => ({ src_ip: `10.0.0.${rnd(40, 60)}`, dst_ip: '10.0.0.53', protocol: 'udp', src_port: eph(), dst_port: 53, flags: '' })],
  [2, () => ({ src_ip: `203.0.113.${rnd(2, 250)}`, dst_ip: '10.0.0.20', protocol: 'tcp', src_port: eph(), dst_port: 22, flags: 'SYN' })],
  [2, () => ({ src_ip: '198.51.100.66', dst_ip: '10.0.0.20', protocol: 'tcp', src_port: eph(), dst_port: 22, flags: 'SYN' })],
  [3, () => ({ src_ip: '198.51.100.66', dst_ip: '10.0.0.10', protocol: 'tcp', src_port: eph(), dst_port: pick([21, 23, 445, 3389, 6379, 8080, 9200]), flags: 'SYN' })],
  [1, () => ({ src_ip: '10.0.0.25', dst_ip: '10.0.0.30', protocol: 'tcp', src_port: eph(), dst_port: 3306, flags: 'SYN' })],
  [1, () => ({ src_ip: '10.0.0.10', dst_ip: '10.0.0.30', protocol: 'tcp', src_port: eph(), dst_port: 3306, flags: 'SYN' })],
  [1, () => ({ src_ip: '198.51.100.66', dst_ip: '10.0.0.10', protocol: 'icmp', src_port: null, dst_port: null, flags: '' })],
  [1, () => ({ src_ip: `10.0.0.${rnd(40, 60)}`, dst_ip: '93.184.216.34', protocol: 'tcp', src_port: eph(), dst_port: 443, flags: 'SYN' })],
];

function pickAutoPacket() {
  const total = AUTO_POOL.reduce((sum, [w]) => sum + w, 0);
  let r = Math.random() * total;
  for (const [w, make] of AUTO_POOL) {
    r -= w;
    if (r <= 0) return { ...make(), size: 64, payload: '' };
  }
  return { ...AUTO_POOL[0][1](), size: 64, payload: '' };
}

async function autoTick() {
  if (!state.auto) return;
  try {
    if (!document.hidden) {
      const data = await api('/api/packet', {
        method: 'POST',
        body: JSON.stringify({ packet: pickAutoPacket() }),
      });
      const d = data.decision;
      state.lastSeq = Math.max(state.lastSeq, d.seq);
      ingestLog(decisionToLog(d));
      animateDecision(d);
      updateStats(data.stats);
      if (d.rule_index != null) flashRule(d.rule_index);
    }
  } catch (err) {
    /* sunucu yoksa sessizce devam */
  }
  if (state.auto) state.autoTimer = setTimeout(autoTick, rnd(450, 900));
}

function setAuto(on) {
  state.auto = on;
  clearTimeout(state.autoTimer);
  if (on) {
    autoTick();
    toast('Canlı trafik açık: arka planda sürekli paket üretiliyor', 'ok');
  } else {
    toast('Canlı trafik kapatıldı', '');
  }
}

async function runBurst(kind) {
  const button = $(`.attack-btn[data-kind="${kind}"]`);
  if (button) button.disabled = true;
  try {
    const data = await api('/api/burst', {
      method: 'POST',
      body: JSON.stringify({ kind }),
    });
    const meta = state.bursts.find((b) => b.kind === kind);
    const label = meta ? meta.label : kind;

    const sample = data.sample || [];
    const step = Math.max(1, Math.ceil(sample.length / 42));
    let delay = 0;
    for (let i = 0; i < sample.length; i += step) {
      const d = sample[i];
      if (!state.seen.has(d.seq)) {
        state.seen.add(d.seq);
        addLogRow(decisionToLog(d));
      }
      animateDecision(d, delay, 2.3);
      delay += 0.022;
    }

    updateStats(data.stats);
    showBurstVerdict(label, data);
    toast(
      `${label}: ${data.denied}/${data.total} paket engellendi`,
      data.denied ? 'ok' : 'bad'
    );
  } catch (err) {
    toast(err.message, 'bad');
  } finally {
    if (button) button.disabled = false;
  }
}

/* ============================== yoklama (polling) ============================== */
let pollTimer = null;

async function poll() {
  try {
    const data = await api('/api/stats');
    updateStats(data.stats);
    if (data.last_seq > state.lastSeq) {
      const logs = await api(`/api/logs?since=${state.lastSeq}`);
      for (const entry of logs.logs || []) ingestLog(entry);
      state.lastSeq = Math.max(state.lastSeq, logs.last_seq || 0);
    }
  } catch (err) {
    /* sunucu kapanmışsa arayüzü bozma */
  }
  pollTimer = setTimeout(poll, 800);
}

/* ============================== canvas ============================== */
const canvas = $('#canvas');
const ctx = canvas.getContext('2d');
let W = 0;
let H = 0;
let DPR = 1;
const animations = [];
const particles = [];
const pulses = [];
let fwFlash = 0;
let lastFrame = performance.now();

function resizeCanvas() {
  const rect = canvas.parentElement.getBoundingClientRect();
  DPR = Math.min(2, window.devicePixelRatio || 1);
  W = Math.max(320, rect.width);
  H = Math.max(220, rect.height);
  canvas.width = Math.round(W * DPR);
  canvas.height = Math.round(H * DPR);
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
}

function layout() {
  const s = pScale();
  const leftX = Math.max(72 * s, Math.min(96 * s, W * 0.12));
  const svcX = Math.max(leftX + 230 * s, W - 84 * s);
  const fw = { x: (leftX + svcX) / 2, y: H * 0.52 };
  const services = (state.services.length ? state.services : FALLBACK_SERVICES).map((s, i) => ({
    ...s,
    x: svcX,
    y: H * [0.2, 0.42, 0.63, 0.84][i % 4],
  }));
  return {
    attacker: { x: leftX, y: H * 0.24, name: 'SALDIRGAN', ip: '198.51.100.66', color: '#f87171' },
    office: { x: leftX, y: H * 0.52, name: 'OFİS AĞI', ip: '203.0.113.0/24', color: '#fbbf24' },
    internal: { x: leftX, y: H * 0.8, name: 'İÇ AĞ', ip: '10.0.0.0/24', color: '#34d399' },
    fw,
    services,
    external: { x: W + 40, y: H * 0.28 },
  };
}

function sourceNode(ip, L) {
  if (ip.startsWith('10.')) return L.internal;
  if (ip.startsWith('203.0.113.')) return L.office;
  return L.attacker;
}

function destNode(ip, L) {
  const svc = L.services.find((s) => s.ip === ip);
  if (svc) return svc;
  if (ip.startsWith('10.')) return L.internal;
  return L.external;
}

function animateDecision(d, delay = 0, speed = 1) {
  const L = layout();
  const packet = d.packet;
  const src = sourceNode(packet.src_ip, L);
  const dst = d.allowed ? destNode(packet.dst_ip, L) : L.fw;
  animations.push({
    src,
    fw: L.fw,
    dst,
    t: 0,
    speed,
    delay,
    color: d.allowed ? '#34d399' : '#f87171',
    label: shortPort(packet),
    blocked: !d.allowed,
    trail: [],
  });
  if (animations.length > 160) animations.splice(0, animations.length - 160);
}

function animateFromLog(entry) {
  animateDecision({
    allowed: entry.allowed,
    packet: {
      src_ip: entry.src_ip,
      dst_ip: entry.dst_ip,
      protocol: entry.protocol,
      src_port: entry.src_port,
      dst_port: entry.dst_port,
      flags: entry.flags || '',
    },
  }, 0, 1.15);
}

function quad(p0, p1, p2, t) {
  const u = 1 - t;
  return {
    x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
    y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
  };
}

function packetPos(a) {
  if (a.t <= 0.5) {
    const u = a.t * 2;
    return quad(a.src, { x: (a.src.x + a.fw.x) / 2, y: a.src.y }, a.fw, u);
  }
  const u = (a.t - 0.5) * 2;
  return quad(a.fw, { x: (a.fw.x + a.dst.x) / 2, y: a.dst.y }, a.dst, u);
}

function explode(x, y, color) {
  for (let i = 0; i < 14; i += 1) {
    const angle = Math.random() * Math.PI * 2;
    const speed = 50 + Math.random() * 150;
    particles.push({
      x, y,
      vx: Math.cos(angle) * speed,
      vy: Math.sin(angle) * speed,
      life: 0.35 + Math.random() * 0.35,
      max: 0.7,
      color: Math.random() > 0.35 ? color : '#fbbf24',
      size: 1 + Math.random() * 2,
    });
  }
  pulses.push({ x, y, r: 6, life: 0.35, max: 0.35, color });
}

function updateAnimations(dt) {
  for (let i = animations.length - 1; i >= 0; i -= 1) {
    const a = animations[i];
    if (a.delay > 0) {
      a.delay -= dt;
      continue;
    }
    a.t += dt * 0.85 * a.speed;

    if (a.blocked && a.t >= 0.5) {
      const p = quad(a.src, { x: (a.src.x + a.fw.x) / 2, y: a.src.y }, a.fw, 1);
      explode(p.x, p.y, a.color);
      fwFlash = 1;
      animations.splice(i, 1);
      continue;
    }
    if (!a.blocked && a.t >= 1) {
      const p = quad(a.fw, { x: (a.fw.x + a.dst.x) / 2, y: a.dst.y }, a.dst, 1);
      pulses.push({ x: p.x, y: p.y, r: 4, life: 0.4, max: 0.4, color: a.color });
      fwFlash = Math.max(fwFlash, 0.5);
      animations.splice(i, 1);
      continue;
    }
    if (a.t > 0.05 && a.t < 0.95) {
      a.trail.push(packetPos(a));
      if (a.trail.length > 9) a.trail.shift();
    }
  }

  for (let i = particles.length - 1; i >= 0; i -= 1) {
    const p = particles[i];
    p.x += p.vx * dt;
    p.y += p.vy * dt;
    p.vx *= 0.94;
    p.vy *= 0.94;
    p.life -= dt;
    if (p.life <= 0) particles.splice(i, 1);
  }
  for (let i = pulses.length - 1; i >= 0; i -= 1) {
    const p = pulses[i];
    p.r += dt * 120;
    p.life -= dt;
    if (p.life <= 0) pulses.splice(i, 1);
  }
  fwFlash = Math.max(0, fwFlash - dt * 2.2);
}

function roundRect(x, y, w, h, r) {
  ctx.beginPath();
  if (typeof ctx.roundRect === 'function') {
    ctx.roundRect(x, y, w, h, r);
    return;
  }
  const radius = Math.min(r, w / 2, h / 2);
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + w, y, x + w, y + h, radius);
  ctx.arcTo(x + w, y + h, x, y + h, radius);
  ctx.arcTo(x, y + h, x, y, radius);
  ctx.arcTo(x, y, x + w, y, radius);
  ctx.closePath();
}

function drawSourceNode(node) {
  const s = pScale();
  const w = 128 * s;
  const h = 44 * s;
  ctx.save();
  roundRect(node.x - w / 2, node.y - h / 2, w, h, 10);
  ctx.fillStyle = 'rgba(9, 15, 25, 0.86)';
  ctx.fill();
  ctx.strokeStyle = 'rgba(30, 44, 64, 0.95)';
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(node.x - 46 * s, node.y, 10 * s, 0, Math.PI * 2);
  ctx.fillStyle = `${node.color}1f`;
  ctx.fill();
  ctx.strokeStyle = `${node.color}66`;
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(node.x - 46 * s, node.y, 3.2 * s, 0, Math.PI * 2);
  ctx.fillStyle = node.color;
  ctx.fill();

  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#dbe7f5';
  ctx.font = `700 ${(10.5 * s).toFixed(1)}px ui-sans-serif, system-ui, sans-serif`;
  ctx.fillText(node.name, node.x - 32 * s, node.y - 7 * s);
  ctx.fillStyle = '#9db0c7';
  ctx.font = `${(9 * s).toFixed(1)}px ui-monospace, Menlo, Consolas, monospace`;
  ctx.fillText(node.ip, node.x - 32 * s, node.y + 8 * s);
  ctx.restore();
}

function drawServiceNode(node) {
  const s = pScale();
  const w = 138 * s;
  const h = 42 * s;
  ctx.save();
  roundRect(node.x - w / 2, node.y - h / 2, w, h, 10);
  ctx.fillStyle = 'rgba(9, 15, 25, 0.86)';
  ctx.fill();
  ctx.strokeStyle = 'rgba(30, 44, 64, 0.95)';
  ctx.lineWidth = 1;
  ctx.stroke();

  ctx.save();
  roundRect(node.x - w / 2 + 1, node.y - h / 2 + 7 * s, 3, h - 14 * s, 2);
  ctx.fillStyle = node.color;
  ctx.fill();
  ctx.restore();

  const ports = node.ports && node.ports.length ? `:${node.ports.join('/')}` : '';
  ctx.textAlign = 'left';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#dbe7f5';
  ctx.font = `700 ${(11 * s).toFixed(1)}px ui-sans-serif, system-ui, sans-serif`;
  ctx.fillText(node.name, node.x - 54 * s, node.y - 6 * s);
  ctx.fillStyle = '#9db0c7';
  ctx.font = `${(9 * s).toFixed(1)}px ui-monospace, Menlo, Consolas, monospace`;
  ctx.fillText(`${node.ip}${ports}`, node.x - 54 * s, node.y + 9 * s);

  ctx.beginPath();
  ctx.arc(node.x + 54 * s, node.y, 3 * s, 0, Math.PI * 2);
  ctx.fillStyle = node.color;
  ctx.globalAlpha = 0.8;
  ctx.fill();
  ctx.restore();
}

function drawFirewall(L) {
  const { x, y } = L.fw;
  const s = pScale();
  const w = 64 * s;
  const h = 86 * s;
  ctx.save();

  ctx.beginPath();
  ctx.moveTo(x, y - h / 2);
  ctx.lineTo(x + w / 2, y - h / 2 + 12);
  ctx.lineTo(x + w / 2, y + h / 6);
  ctx.quadraticCurveTo(x + w / 2, y + h / 2 - 4, x, y + h / 2);
  ctx.quadraticCurveTo(x - w / 2, y + h / 2 - 4, x - w / 2, y + h / 6);
  ctx.lineTo(x - w / 2, y - h / 2 + 12);
  ctx.closePath();

  const grad = ctx.createLinearGradient(x, y - h / 2, x, y + h / 2);
  grad.addColorStop(0, 'rgba(20, 52, 66, 0.95)');
  grad.addColorStop(1, 'rgba(9, 24, 34, 0.95)');
  ctx.fillStyle = grad;
  ctx.fill();
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = `rgba(34, 211, 238, ${0.45 + fwFlash * 0.5})`;
  ctx.shadowColor = 'rgba(34, 211, 238, 0.55)';
  ctx.shadowBlur = 8 + fwFlash * 34;
  ctx.stroke();
  ctx.shadowBlur = 0;

  // İç ızgara
  ctx.save();
  ctx.beginPath();
  ctx.moveTo(x, y - h / 2);
  ctx.lineTo(x + w / 2, y - h / 2 + 12);
  ctx.lineTo(x + w / 2, y + h / 6);
  ctx.quadraticCurveTo(x + w / 2, y + h / 2 - 4, x, y + h / 2);
  ctx.quadraticCurveTo(x - w / 2, y + h / 2 - 4, x - w / 2, y + h / 6);
  ctx.lineTo(x - w / 2, y - h / 2 + 12);
  ctx.closePath();
  ctx.clip();
  ctx.strokeStyle = 'rgba(34, 211, 238, 0.13)';
  ctx.lineWidth = 1;
  for (let i = -3; i <= 3; i += 1) {
    ctx.beginPath();
    ctx.moveTo(x - w / 2, y + i * 14 * s);
    ctx.lineTo(x + w / 2, y + i * 14 * s);
    ctx.stroke();
  }
  ctx.restore();

  // Kilit anahtarı
  ctx.beginPath();
  ctx.arc(x, y - 4 * s, 7 * s, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(34, 211, 238, 0.8)';
  ctx.lineWidth = 2;
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(x, y + 3 * s);
  ctx.lineTo(x, y + 15 * s);
  ctx.stroke();

  // Politika etiketi
  const label = state.policy.toUpperCase();
  const color = state.policy === 'deny' ? '#f87171' : '#34d399';
  const badgeW = 46 * s;
  roundRect(x - badgeW / 2, y + h / 2 + 6 * s, badgeW, 16 * s, 4);
  ctx.fillStyle = `${color}1f`;
  ctx.fill();
  ctx.strokeStyle = `${color}66`;
  ctx.lineWidth = 1;
  ctx.stroke();
  ctx.fillStyle = color;
  ctx.font = `700 ${(8.5 * s).toFixed(1)}px ui-monospace, Menlo, Consolas, monospace`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(label, x, y + h / 2 + 14.5 * s);

  ctx.fillStyle = state.presentation ? '#1e293b' : '#5d6f88';
  ctx.font = `${state.presentation ? '700 ' : ''}${(8 * s).toFixed(1)}px ui-sans-serif, system-ui, sans-serif`;
  ctx.fillText('GÜVENLİK DUVARI', x, y - h / 2 - 12 * s);
  ctx.restore();
}

function drawLinks(L) {
  ctx.save();
  ctx.setLineDash([3, 5]);
  ctx.strokeStyle = 'rgba(120, 150, 180, 0.13)';
  ctx.lineWidth = 1;
  const sources = [L.attacker, L.office, L.internal];
  for (const node of sources) {
    ctx.beginPath();
    ctx.moveTo(node.x + 64, node.y);
    ctx.quadraticCurveTo((node.x + L.fw.x) / 2, node.y, L.fw.x - 34, L.fw.y);
    ctx.stroke();
  }
  for (const node of L.services) {
    ctx.beginPath();
    ctx.moveTo(L.fw.x + 34, L.fw.y);
    ctx.quadraticCurveTo((L.fw.x + node.x) / 2, node.y, node.x - 70, node.y);
    ctx.stroke();
  }
  ctx.restore();
}

function drawZones(L) {
  ctx.save();
  ctx.strokeStyle = 'rgba(120, 150, 180, 0.07)';
  ctx.lineWidth = 1;
  ctx.setLineDash([2, 6]);
  ctx.beginPath();
  ctx.moveTo(W * 0.31, 42);
  ctx.lineTo(W * 0.31, H - 26);
  ctx.moveTo(W * 0.63, 42);
  ctx.lineTo(W * 0.63, H - 26);
  ctx.stroke();
  ctx.restore();
}

function draw() {
  ctx.clearRect(0, 0, W, H);
  const L = layout();

  // Merkezi hafif ışıma
  const glow = ctx.createRadialGradient(L.fw.x, L.fw.y, 10, L.fw.x, L.fw.y, Math.max(W, H) * 0.55);
  glow.addColorStop(0, 'rgba(34, 211, 238, 0.06)');
  glow.addColorStop(1, 'rgba(34, 211, 238, 0)');
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, W, H);

  drawZones(L);
  drawLinks(L);

  drawSourceNode(L.attacker);
  drawSourceNode(L.office);
  drawSourceNode(L.internal);
  drawFirewall(L);
  for (const svc of L.services) drawServiceNode(svc);

  // Parçacıklar
  for (const p of particles) {
    ctx.globalAlpha = Math.max(0, p.life / p.max);
    ctx.fillStyle = p.color;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
    ctx.fill();
  }
  ctx.globalAlpha = 1;

  // Halkalar
  for (const p of pulses) {
    ctx.globalAlpha = Math.max(0, p.life / p.max) * 0.7;
    ctx.strokeStyle = p.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  // Paketler
  const pktScale = pScale();
  for (const a of animations) {
    if (a.delay > 0) continue;
    const pos = packetPos(a);

    for (let i = 0; i < a.trail.length; i += 1) {
      const t = a.trail[i];
      const alpha = ((i + 1) / a.trail.length) * 0.25;
      ctx.globalAlpha = alpha;
      ctx.fillStyle = a.color;
      ctx.beginPath();
      ctx.arc(t.x, t.y, 2.5 * pktScale, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1;

    ctx.save();
    ctx.shadowColor = a.color;
    ctx.shadowBlur = 16;
    ctx.fillStyle = a.color;
    ctx.beginPath();
    ctx.arc(pos.x, pos.y, 5 * pktScale, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();

    if (animations.length <= 30 && a.label) {
      ctx.fillStyle = state.presentation ? 'rgba(15, 23, 42, 0.85)' : 'rgba(220, 235, 250, 0.65)';
      ctx.font = `${state.presentation ? '700 ' : ''}${(8 * pktScale).toFixed(1)}px ui-monospace, Menlo, Consolas, monospace`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(a.label, pos.x + 8 * pktScale, pos.y - 7 * pktScale);
    }
  }
}

function frame(now) {
  const dt = Math.min(0.05, (now - lastFrame) / 1000);
  lastFrame = now;
  updateAnimations(dt);
  draw();
  requestAnimationFrame(frame);
}

/* ============================== olay bağlama ============================== */
function wire() {
  $('#packetForm').addEventListener('submit', (e) => {
    e.preventDefault();
    sendPacket();
  });

  $('#serviceChips').addEventListener('click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    $('#dstIp').value = chip.dataset.dst;
    $('#dstPort').value = chip.dataset.port;
    $('#proto').value = chip.dataset.proto;
    if (chip.dataset.proto === 'tcp') $('#flags').value = 'SYN';
  });

  $('#proto').addEventListener('change', () => {
    const icmp = $('#proto').value === 'icmp';
    $('#srcPort').disabled = icmp;
    $('#dstPort').disabled = icmp;
    $('#flags').disabled = $('#proto').value !== 'tcp';
  });

  $('#scenarioSelect').addEventListener('change', async (e) => {
    try {
      const data = await api('/api/scenario', {
        method: 'POST',
        body: JSON.stringify({ name: e.target.value }),
      });
      state.lastSeq = 0;
      state.seen.clear();
      state.historyKey = '';
      animations.length = 0;
      particles.length = 0;
      clearLogView();
      resetVerdict();
      applyState(data);
      const desc = (state.scenarios.find((s) => s.name === state.scenario) || {}).description;
      toast(desc || 'Senaryo yüklendi', 'ok');
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  $('#policySeg').addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-policy]');
    if (!btn || btn.dataset.policy === state.policy) return;
    try {
      const data = await api('/api/policy', {
        method: 'POST',
        body: JSON.stringify({ policy: btn.dataset.policy }),
      });
      applyState(data);
      toast(`Varsayılan politika: ${state.policy.toUpperCase()}`, 'ok');
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  $('#floodToggle').addEventListener('change', async (e) => {
    try {
      const data = await api('/api/flood', {
        method: 'POST',
        body: JSON.stringify({ enabled: e.target.checked, limit: state.floodDefault }),
      });
      applyState(data);
      toast(
        e.target.checked
          ? `Flood guard açık: kaynak başına saniyede en fazla ${state.floodLimit} paket`
          : 'Flood guard kapalı',
        'ok'
      );
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  $('#autoToggle').addEventListener('change', (e) => setAuto(e.target.checked));
  $('#iptablesBtn').addEventListener('click', () => openCode('iptables.sh'));

  $('#statefulToggle').addEventListener('change', async (e) => {
    try {
      const data = await api('/api/stateful', {
        method: 'POST',
        body: JSON.stringify({ enabled: e.target.checked }),
      });
      applyState(data);
      toast(
        e.target.checked
          ? 'Stateful inspection açık: oturum yanıtları hatırlanır'
          : 'Stateful inspection kapalı',
        'ok'
      );
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  $('#resetBtn').addEventListener('click', async () => {
    try {
      const data = await api('/api/reset', { method: 'POST', body: '{}' });
      applyState(data);
      clearLogView();
      resetVerdict();
      animations.length = 0;
      particles.length = 0;
      toast('Sayaçlar ve log sıfırlandı', 'ok');
    } catch (err) {
      toast(err.message, 'bad');
    }
  });

  $('#attackGrid').addEventListener('click', (e) => {
    const btn = e.target.closest('.attack-btn');
    if (btn) runBurst(btn.dataset.kind);
  });

  $('#ruleList').addEventListener('click', (e) => {
    const row = e.target.closest('.rule-row');
    if (!row) return;
    const index = Number(row.dataset.index);
    const btn = e.target.closest('.rule-btn');
    if (btn) {
      e.stopPropagation();
      onRuleAction(index, btn.dataset.act);
      return;
    }
    openRuleModal(index);
  });

  $('#addRuleBtn').addEventListener('click', () => openRuleModal(null));
  $('#closeRuleModal').addEventListener('click', () => hideModal('#ruleModal'));
  $('#cancelRule').addEventListener('click', () => hideModal('#ruleModal'));
  $('#ruleForm').addEventListener('submit', submitRule);
  ['#rAction', '#rProto', '#rSrc', '#rSport', '#rDst', '#rDport', '#rFlags', '#rComment']
    .forEach((sel) => $(sel).addEventListener('input', updatePreview));
  $('#rAction').addEventListener('change', updatePreview);
  $('#rProto').addEventListener('change', updatePreview);

  $('#deleteRuleBtn').addEventListener('click', async () => {
    if (state.editingIndex == null) return;
    const index = state.editingIndex;
    hideModal('#ruleModal');
    await onRuleAction(index, 'del');
  });

  $('#traceBtn').addEventListener('click', openTrace);
  $('#replyBtn').addEventListener('click', () => {
    const d = state.lastDecision;
    if (!d || !d.allowed) return;
    const p = d.packet;
    sendPacket({
      src_ip: p.dst_ip,
      dst_ip: p.src_ip,
      protocol: p.protocol,
      src_port: p.dst_port,
      dst_port: p.src_port,
      flags: p.protocol === 'tcp' ? 'SYN ACK' : '',
      size: 60,
      payload: '',
    });
    toast('Dönüş paketi gönderildi — stateful tablo devrede mi?', '');
  });
  $('#closeTraceModal').addEventListener('click', () => hideModal('#traceModal'));

  $$('.modal').forEach((modal) => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) hideModal(`#${modal.id}`);
    });
  });

  $('#logFilters').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-filter]');
    if (!btn) return;
    state.filter = btn.dataset.filter;
    $$('#logFilters button').forEach((b) => b.classList.toggle('active', b === btn));
    $$('.log-row').forEach((row) => {
      row.style.display = state.filter === 'all' || row.dataset.action === state.filter ? '' : 'none';
    });
  });

  $('#clearLog').addEventListener('click', clearLogView);

  $('#presentBtn').addEventListener('click', () => applyPresentation(!state.presentation));

  $('#codeBtn').addEventListener('click', () => openCode(state.codeFile));
  $('#closeCode').addEventListener('click', closeCode);
  $('#drawerBackdrop').addEventListener('click', closeCode);
  $('#codeTabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-file]');
    if (btn) loadCode(btn.dataset.file);
  });
  $('#copyCode').addEventListener('click', async () => {
    try {
      const data = await api(`/api/source?file=${encodeURIComponent(state.codeFile)}`);
      await navigator.clipboard.writeText(data.code);
      toast(`${state.codeFile} kopyalandı`, 'ok');
    } catch (err) {
      toast('Kopyalanamadı: ' + err.message, 'bad');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $$('.modal.open').forEach((m) => hideModal(`#${m.id}`));
      closeCode();
    }
  });

  window.addEventListener('resize', resizeCanvas);
  if (window.ResizeObserver) {
    new ResizeObserver(resizeCanvas).observe(canvas.parentElement);
  }
}

/* ============================== başlat ============================== */
async function boot() {
  wire();
  let savedPresentation = false;
  try {
    savedPresentation = localStorage.getItem('mfw_presentation') === '1';
  } catch (_) {
    /* özel pencere/depolama kapalı olabilir, sorun değil */
  }
  applyPresentation(savedPresentation);
  resizeCanvas();
  requestAnimationFrame(frame);

  try {
    const data = await api('/api/state');
    applyState(data);
  } catch (err) {
    toast('Sunucuya ulaşılamadı: ' + err.message, 'bad');
  }

  poll();
}

boot();
