/* ===================================================================
   NorthHarv — Core JavaScript  v3
   Toasts · request indicator · count-up · ripple · spotlight ·
   parallax tilt · staggered reveals · terminal stream · palette
   =================================================================== */

const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const COARSE  = window.matchMedia('(hover: none)').matches;

function escHtmlCore(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/* ══ Toast notifications ═══════════════════════════════════════════ */
const TOAST_ICON = { success: 'i-check', error: 'i-x', info: 'i-info' };

function toast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML =
    `<span class="t-icon"><svg class="icon"><use href="#${TOAST_ICON[type] || TOAST_ICON.info}"/></svg></span>` +
    `<span class="t-msg">${escHtmlCore(message)}</span>` +
    `<span class="t-bar"></span>`;

  const bar = el.querySelector('.t-bar');
  if (bar && !REDUCED) bar.style.animation = `toastBar ${duration}ms linear forwards`;

  const dismiss = () => {
    if (el.dataset.gone) return;
    el.dataset.gone = '1';
    el.classList.add('leaving');
    setTimeout(() => el.remove(), 320);
  };

  el.addEventListener('click', dismiss);
  container.appendChild(el);
  setTimeout(dismiss, duration);

  while (container.children.length > 5) container.firstElementChild.remove();
}
window.toast = toast;

/* ══ Global request indicator (wraps fetch) ════════════════════════ */
(function () {
  const bar = document.getElementById('nhLoadBar');
  if (!bar || !window.fetch) return;
  const original = window.fetch;
  let pending = 0;

  window.fetch = function (...args) {
    pending++;
    bar.classList.add('on');
    const done = () => {
      pending = Math.max(0, pending - 1);
      if (pending === 0) bar.classList.remove('on');
    };
    return original.apply(this, args).then(
      r => { done(); return r; },
      e => { done(); throw e; }
    );
  };
})();

/* ══ Animated counters ════════════════════════════════════════════ */
/* Any element with data-count="1234" counts up from 0.
   Optional: data-decimals="1"  data-suffix="%"                      */
function formatCount(v, dec) {
  return dec > 0 ? v.toFixed(dec) : Math.round(v).toLocaleString();
}

function animateCount(el) {
  if (el.dataset.counted) return;
  el.dataset.counted = '1';

  const target = parseFloat(el.dataset.count);
  if (!isFinite(target)) return;
  const dec = parseInt(el.dataset.decimals || '0', 10);
  const suffix = el.dataset.suffix || '';

  if (REDUCED || target === 0) {
    el.textContent = formatCount(target, dec) + suffix;
    return;
  }

  const duration = Math.min(1250, 480 + Math.log10(Math.abs(target) + 10) * 210);
  const start = performance.now();

  function tick(now) {
    const p = Math.min(1, (now - start) / duration);
    const eased = 1 - Math.pow(1 - p, 4);          // quartic ease-out
    el.textContent = formatCount(target * eased, dec) + suffix;
    if (p < 1) requestAnimationFrame(tick);
    else el.textContent = formatCount(target, dec) + suffix;
  }
  requestAnimationFrame(tick);
}

function scanCounters(root) {
  (root || document).querySelectorAll('[data-count]').forEach(animateCount);
}
window.nhCounters = scanCounters;

/* ══ Staggered reveals ════════════════════════════════════════════ */
const revealIO = ('IntersectionObserver' in window)
  ? new IntersectionObserver(entries => {
      for (const en of entries) {
        if (!en.isIntersecting) continue;
        en.target.classList.add('in');
        revealIO.unobserve(en.target);
      }
    }, { rootMargin: '220px 0px 220px 0px', threshold: 0.01 })
  : null;

function nhReveal(root) {
  const scope = (root && root.querySelectorAll) ? root : document;
  const fresh = Array.prototype.filter.call(
    scope.querySelectorAll('[data-reveal]'), el => !el.dataset.rv);
  if (!fresh.length) return;

  const seen = new Map();
  for (const el of fresh) {
    el.dataset.rv = '1';
    const parent = el.parentElement || document.body;
    const n = seen.get(parent) || 0;
    seen.set(parent, n + 1);
    el.style.setProperty('--i', String(Math.min(n, 14)));
    if (revealIO && !REDUCED) revealIO.observe(el);
    else el.classList.add('in');
  }
  // safety net — nothing stays invisible if the observer never fires
  setTimeout(() => { for (const el of fresh) el.classList.add('in'); }, 2600);
}
window.nhReveal = nhReveal;

/* ══ DOM watcher — wire up anything rendered by page scripts ══════ */
new MutationObserver(muts => {
  for (const m of muts) {
    for (const node of m.addedNodes) {
      if (node.nodeType !== 1) continue;
      if (node.hasAttribute && node.hasAttribute('data-count')) animateCount(node);
      if (node.querySelectorAll) { scanCounters(node); nhReveal(node); }
      if (node.hasAttribute && node.hasAttribute('data-reveal')) nhReveal(node.parentElement);
    }
  }
}).observe(document.documentElement, { childList: true, subtree: true });

/* ══ Button ripple ════════════════════════════════════════════════ */
document.addEventListener('pointerdown', e => {
  if (REDUCED) return;
  const btn = e.target.closest('.btn');
  if (!btn || btn.disabled) return;
  const r = btn.getBoundingClientRect();
  const d = Math.max(r.width, r.height) * 1.15;
  const span = document.createElement('span');
  span.className = 'ripple';
  span.style.width = span.style.height = d + 'px';
  span.style.left = (e.clientX - r.left - d / 2) + 'px';
  span.style.top  = (e.clientY - r.top  - d / 2) + 'px';
  btn.appendChild(span);
  setTimeout(() => span.remove(), 660);
}, { passive: true });

/* ══ Parallax tilt + cursor spotlight ════════════════════════════ */
(function () {
  if (REDUCED || COARSE) return;

  const SEL = '.card, .stat-tile, .engine-card, [data-tilt]';
  const MAX = 2.8;              // degrees — subtle, never gimmicky
  let current = null;
  let pending = null;
  let frame = 0;

  function reset(el) {
    if (!el) return;
    el.classList.remove('tilting');
    el.style.setProperty('--tx', '0deg');
    el.style.setProperty('--ty', '0deg');
  }

  function apply() {
    frame = 0;
    const e = pending;
    if (!e) return;

    const el = e.target.closest ? e.target.closest(SEL) : null;
    if (el !== current) { reset(current); current = el; }
    if (!el) return;

    const r = el.getBoundingClientRect();
    if (!r.width || !r.height) return;

    const px = (e.clientX - r.left) / r.width;      // 0 → 1
    const py = (e.clientY - r.top) / r.height;

    // spotlight position
    el.style.setProperty('--mx', (px * 100).toFixed(2) + '%');
    el.style.setProperty('--my', (py * 100).toFixed(2) + '%');

    // tilt: cursor right → rotateY positive, cursor down → rotateX negative
    el.classList.add('tilting');
    el.style.setProperty('--ty', ((px - .5) * 2 * MAX).toFixed(2) + 'deg');
    el.style.setProperty('--tx', ((.5 - py) * 2 * MAX).toFixed(2) + 'deg');
  }

  document.addEventListener('pointermove', e => {
    if (e.pointerType === 'touch') return;
    pending = e;
    if (!frame) frame = requestAnimationFrame(apply);
  }, { passive: true });

  document.addEventListener('pointerleave', () => { reset(current); current = null; }, { passive: true });
  window.addEventListener('blur', () => { reset(current); current = null; });
  document.addEventListener('scroll', () => { reset(current); current = null; }, { passive: true });
})();

/* ══ Terminal stream — typed, auto-scrolling log ═════════════════ */
class NHTerminal {
  constructor(el, opts = {}) {
    this.el      = typeof el === 'string' ? document.getElementById(el) : el;
    this.cps     = opts.cps || 900;        // characters per second
    this.maxLines = opts.maxLines || 400;
    this.queue   = [];
    this.running = false;
    this.caret   = null;
    if (this.el) this._mountCaret();
  }

  _mountCaret() {
    this.caret = document.createElement('span');
    this.caret.className = 'log-caret';
    this.el.appendChild(this.caret);
  }

  _stamp() {
    const d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  clear() {
    if (!this.el) return;
    this.el.textContent = '';
    this.queue.length = 0;
    this._mountCaret();
  }

  /* queue a line; instant:true skips the typing effect */
  write(text, cls = 'log-info', opts = {}) {
    if (!this.el) return;
    this.queue.push({ text: String(text), cls, instant: opts.instant || REDUCED });
    if (!this.running) this._pump();
  }

  _trim() {
    const lines = this.el.querySelectorAll('.log-line');
    for (let i = 0; i < lines.length - this.maxLines; i++) lines[i].remove();
  }

  _scroll() {
    this.el.scrollTop = this.el.scrollHeight;
  }

  _pump() {
    const job = this.queue.shift();
    if (!job) { this.running = false; return; }
    this.running = true;

    const line = document.createElement('span');
    line.className = 'log-line';
    const ts = document.createElement('span');
    ts.className = 'log-ts';
    ts.textContent = this._stamp();
    const body = document.createElement('span');
    body.className = job.cls;
    line.append(ts, body);
    this.el.insertBefore(line, this.caret);
    this._trim();

    if (job.instant) {
      body.textContent = job.text;
      this._scroll();
      this._pump();
      return;
    }

    const chars = job.text;
    let i = 0;
    let last = performance.now();
    const step = now => {
      const budget = Math.max(1, Math.round((now - last) / 1000 * this.cps));
      last = now;
      i = Math.min(chars.length, i + budget);
      body.textContent = chars.slice(0, i);
      this._scroll();
      if (i < chars.length) requestAnimationFrame(step);
      else this._pump();
    };
    requestAnimationFrame(step);
  }
}
window.NHTerminal = NHTerminal;

/* ══ Progress helper ═════════════════════════════════════════════ */
/* nhProgress(barEl, pct, state)  state: 'active' | 'done' | 'idle' */
function nhProgress(bar, pct, state) {
  if (typeof bar === 'string') bar = document.getElementById(bar);
  if (!bar) return;
  const wrap = bar.parentElement;
  bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
  if (!wrap) return;
  wrap.classList.toggle('active', state === 'active');
  wrap.classList.toggle('done', state === 'done');
}
window.nhProgress = nhProgress;

/* ══ Top nav search ══════════════════════════════════════════════ */
const topSearchForm = document.getElementById('topSearchForm');
if (topSearchForm) {
  topSearchForm.addEventListener('submit', e => {
    e.preventDefault();
    const q = document.getElementById('topSearchInput').value.trim();
    window.location.href = '/search?q=' + encodeURIComponent(q);
  });
}

/* ══ Active nav highlighting + sidebar stagger ═══════════════════ */
document.querySelectorAll('.sidebar-link').forEach((link, idx) => {
  link.style.setProperty('--si', String(idx));
  const href = link.getAttribute('href');
  if (href === window.location.pathname + window.location.search) link.classList.add('active');
  else if (href === window.location.pathname && !window.location.search) link.classList.add('active');
});

/* ══ Banner expand on click ══════════════════════════════════════ */
document.addEventListener('click', e => {
  const bc = e.target.closest('.banner-cell');
  if (bc) bc.classList.toggle('expanded');
});

/* ══ Tabs (data-tab driven, with legacy onclick fallback) ════════ */
window.showTab = function (id) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    const match = btn.dataset.tab
      ? btn.dataset.tab === id
      : (btn.getAttribute('onclick') || '').includes("'" + id + "'");
    btn.classList.toggle('active', match);
  });
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const panel = document.getElementById('tab-' + id);
  if (panel) {
    panel.classList.add('active');
    panel.querySelectorAll('[data-reveal]').forEach(el => el.classList.add('in'));
  }
};

/* ══ Command palette ═════════════════════════════════════════════ */
const CMDK_ITEMS = [
  { group: 'Navigate', icon: 'i-home',    label: 'Dashboard',              hint: '/',          url: '/' },
  { group: 'Navigate', icon: 'i-search',  label: 'Search',                 hint: '/search',    url: '/search' },
  { group: 'Navigate', icon: 'i-bolt',    label: 'Scan Manager',           hint: '/scan',      url: '/scan' },
  { group: 'Navigate', icon: 'i-radio',   label: 'Feed Sync',              hint: '/feeds',     url: '/feeds' },
  { group: 'Navigate', icon: 'i-scope',   label: 'Path Discovery Engine',  hint: '/wordlists', url: '/wordlists' },

  { group: 'Risk',     icon: 'i-flame',       label: 'KEV — actively exploited', hint: 'kev:true',  url: '/search?q=kev%3Atrue' },
  { group: 'Risk',     icon: 'i-alert',       label: 'Critical CVSS ≥ 9.0',      hint: 'cvss:9.0',  url: '/search?q=cvss%3A9.0' },
  { group: 'Risk',     icon: 'i-activity',    label: 'High EPSS probability',    hint: 'epss:0.9',  url: '/search?q=epss%3A0.9' },
  { group: 'Risk',     icon: 'i-certificate', label: 'Self-signed / TLS hosts',  hint: 'ssl.cn:*',  url: '/search?q=ssl.cn%3A*' },

  { group: 'Services', icon: 'i-key',        label: 'SSH (22)',        hint: 'port:22',    url: '/search?q=port%3A22' },
  { group: 'Services', icon: 'i-globe',      label: 'HTTP (80)',       hint: 'port:80',    url: '/search?q=port%3A80' },
  { group: 'Services', icon: 'i-lock',       label: 'HTTPS (443)',     hint: 'port:443',   url: '/search?q=port%3A443' },
  { group: 'Services', icon: 'i-monitor',    label: 'RDP (3389)',      hint: 'port:3389',  url: '/search?q=port%3A3389' },
  { group: 'Services', icon: 'i-database',   label: 'MySQL (3306)',    hint: 'port:3306',  url: '/search?q=port%3A3306' },
  { group: 'Services', icon: 'i-leaf',       label: 'MongoDB (27017)', hint: 'port:27017', url: '/search?q=port%3A27017' },
  { group: 'Services', icon: 'i-dot-circle', label: 'Redis (6379)',    hint: 'port:6379',  url: '/search?q=port%3A6379' },
  { group: 'Services', icon: 'i-package',    label: 'nginx',           hint: 'product:nginx', url: '/search?q=product%3Anginx' },
];

(function () {
  const overlay = document.getElementById('cmdkOverlay');
  const input   = document.getElementById('cmdkInput');
  const list    = document.getElementById('cmdkList');
  const openBtn = document.getElementById('cmdkBtn');
  if (!overlay || !input || !list) return;

  let active = 0;
  let rows = [];

  // subsequence fuzzy score — lower is better, null = no match
  function score(needle, hay) {
    if (!needle) return 0;
    const n = needle.toLowerCase(), h = hay.toLowerCase();
    const direct = h.indexOf(n);
    if (direct !== -1) return direct;
    let i = 0, gaps = 0, lastHit = -1;
    for (let j = 0; j < h.length && i < n.length; j++) {
      if (h[j] === n[i]) {
        if (lastHit !== -1) gaps += j - lastHit - 1;
        lastHit = j; i++;
      }
    }
    return i === n.length ? 60 + gaps : null;
  }

  function render(q) {
    const term = q.trim();
    const scored = [];
    CMDK_ITEMS.forEach((it, idx) => {
      const s = Math.min(
        score(term, it.label) ?? Infinity,
        score(term, it.hint)  ?? Infinity,
        score(term, it.group) ?? Infinity
      );
      if (s !== Infinity) scored.push({ it, s, idx });
    });
    scored.sort((a, b) => a.s - b.s || a.idx - b.idx);

    let entries = scored.map(x => x.it);
    if (term) {
      entries = [{
        group: 'Query', icon: 'i-search',
        label: 'Search hosts for “' + term + '”',
        hint: 'enter', url: '/search?q=' + encodeURIComponent(term),
      }].concat(entries.slice(0, 9));
    }

    if (!entries.length) {
      list.innerHTML = '<div class="cmdk-empty">Nothing matched. Press ↵ to search anyway.</div>';
      rows = [];
      return;
    }

    let html = '', lastGroup = null;
    entries.forEach((e, i) => {
      if (e.group !== lastGroup) {
        html += `<div class="cmdk-group">${escHtmlCore(e.group)}</div>`;
        lastGroup = e.group;
      }
      html += `<div class="cmdk-item" role="option" data-i="${i}" data-url="${escHtmlCore(e.url)}" aria-selected="false">
        <svg class="icon"><use href="#${e.icon}"/></svg>
        <span>${escHtmlCore(e.label)}</span>
        <span class="ci-hint">${escHtmlCore(e.hint)}</span>
      </div>`;
    });
    list.innerHTML = html;
    rows = Array.from(list.querySelectorAll('.cmdk-item'));
    active = 0;
    highlight();
  }

  function highlight() {
    rows.forEach((r, i) => r.setAttribute('aria-selected', i === active ? 'true' : 'false'));
    const el = rows[active];
    if (el) el.scrollIntoView({ block: 'nearest' });
  }

  function open() {
    overlay.classList.add('open');
    input.value = '';
    render('');
    setTimeout(() => input.focus(), 20);
  }

  function close() {
    overlay.classList.remove('open');
    input.blur();
  }

  function go(url) { if (url) window.location.href = url; }

  input.addEventListener('input', () => render(input.value));

  input.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown') { e.preventDefault(); if (rows.length) { active = (active + 1) % rows.length; highlight(); } }
    else if (e.key === 'ArrowUp') { e.preventDefault(); if (rows.length) { active = (active - 1 + rows.length) % rows.length; highlight(); } }
    else if (e.key === 'Enter') {
      e.preventDefault();
      if (rows[active]) go(rows[active].dataset.url);
      else if (input.value.trim()) go('/search?q=' + encodeURIComponent(input.value.trim()));
    } else if (e.key === 'Escape') { e.preventDefault(); close(); }
  });

  list.addEventListener('click', e => {
    const item = e.target.closest('.cmdk-item');
    if (item) go(item.dataset.url);
  });

  list.addEventListener('pointermove', e => {
    const item = e.target.closest('.cmdk-item');
    if (!item) return;
    const i = parseInt(item.dataset.i, 10);
    if (i !== active) { active = i; highlight(); }
  });

  overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
  if (openBtn) openBtn.addEventListener('click', open);

  window.nhPalette = { open, close };

  /* ── Keyboard shortcuts ──────────────────────────────────────── */
  document.addEventListener('keydown', e => {
    const typing = e.target.matches('input,textarea,select,[contenteditable]');

    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      overlay.classList.contains('open') ? close() : open();
      return;
    }

    if (e.key === '/' && !typing) {
      e.preventDefault();
      const inp = document.getElementById('heroSearch')
        || document.getElementById('searchInput')
        || document.getElementById('topSearchInput');
      if (inp) { inp.focus(); inp.select(); }
      return;
    }

    if (e.key === 'Escape') {
      if (overlay.classList.contains('open')) { close(); return; }
      if (typing) e.target.blur();
    }
  });
})();

/* ══ Boot ════════════════════════════════════════════════════════ */
scanCounters();
nhReveal();
document.addEventListener('DOMContentLoaded', () => { scanCounters(); nhReveal(); });


/* ══ Search operator autocomplete ════════════════════════════════ */
const NH_OPERATORS = [
  ['port:',        '443',              'TCP port, comma-separated for several'],
  ['product:',     'nginx',            'Product name from the service banner'],
  ['service:',     'http',             'Detected service name'],
  ['version:',     '1.18',             'Product version substring'],
  ['country:',     'US',               'Two-letter country code'],
  ['city:',        'London',           'City from geolocation'],
  ['region:',      'California',       'State or region'],
  ['org:',         'Amazon',           'Owning organisation'],
  ['isp:',         'Comcast',          'Internet service provider'],
  ['asn:',         '15169',            'Autonomous system number'],
  ['hostname:',    'example.com',      'Reverse DNS name'],
  ['domain:',      'example.com',      'Registered domain'],
  ['net:',         '10.0.0.0/8',       'CIDR network range'],
  ['ip:',          '10.0.0.0/8',       'IP address or CIDR'],
  ['os:',          'Windows',          'Operating system guess'],
  ['tech:',        'WordPress',        'Detected technology'],
  ['app:',         'Jenkins',          'Application fingerprint'],
  ['cloud:',       'AWS',              'Cloud provider'],
  ['tag:',         'database',         'Host tag'],
  ['title:',       'admin',            'HTML title contains'],
  ['server:',      'nginx',            'HTTP Server header'],
  ['http.title:',  'admin',            'HTML title contains'],
  ['http.status:', '200',              'HTTP response status code'],
  ['http.waf:',    'Cloudflare',       'Detected web application firewall'],
  ['http.body:',   'login',            'Response body contains'],
  ['header:',      'x-powered-by',     'Response header contains'],
  ['banner:',      'SSH',              'Raw banner contains'],
  ['ssl.cert.subject.cn:', '*.example.com', 'Certificate subject CN'],
  ['ssl.san:',     'example.com',      'Certificate subject alternative name'],
  ['ssl.version:', 'TLSv1.2',          'Negotiated TLS version'],
  ['ssl.alpn:',    'h2',               'ALPN protocol'],
  ['ssl.expired:', 'true',             'Certificate past its expiry date'],
  ['ssl.selfsigned:', 'true',          'Self-signed certificate'],
  ['ssl.ja3s:',    '',                 'JA3S TLS server fingerprint'],
  ['jarm:',        '',                 'JARM TLS fingerprint'],
  ['hassh:',       '',                 'SSH HASSH fingerprint'],
  ['icon_hash:',   '708578229',        'Favicon MurmurHash3 (FOFA-compatible)'],
  ['risk:',        '800',              'NorthHarv risk score, minimum'],
  ['cvss:',        '9.0',              'CVSS base score, minimum'],
  ['epss:',        '0.9',              'EPSS exploit probability, minimum'],
  ['kev:',         'true',             'Listed in the CISA KEV catalogue'],
  ['vuln:',        'CVE-2021-44228',   'Matches this CVE'],
  ['cve:',         'CVE-2021-44228',   'Matches this CVE'],
  ['has:',         'tls',              'tls · cve · kev · waf · cloud · hostname'],
  ['port.count:',  '5',                'Hosts with at least N open ports'],
  ['before:',      '2024-01-01',       'Last seen before this date'],
  ['after:',       '2023-01-01',       'Last seen after this date'],
  ['age:',         '30',               'First seen more than N days ago'],
  ['geo:',         '37.77,-122.41,50', 'Latitude, longitude, radius in km'],
];
window.NH_OPERATORS = NH_OPERATORS;

function nhAutocomplete(input) {
  if (!input || input.dataset.acReady) return;
  input.dataset.acReady = '1';

  // the input needs a positioned parent for the dropdown
  let wrap = input.parentElement;
  if (!wrap.classList.contains('ac-wrap')) {
    wrap = document.createElement('span');
    wrap.className = 'ac-wrap';
    wrap.style.flex = input.style.flex || '1 1 320px';
    wrap.style.minWidth = '0';
    input.parentElement.insertBefore(wrap, input);
    wrap.appendChild(input);
    input.style.width = '100%';
  }

  const list = document.createElement('div');
  list.className = 'ac-list';
  list.setAttribute('role', 'listbox');
  wrap.appendChild(list);

  let matches = [];
  let active = 0;

  const currentToken = () => {
    const upto = input.value.slice(0, input.selectionStart ?? input.value.length);
    const parts = upto.split(/\s+/);
    return parts[parts.length - 1] || '';
  };

  function close() { list.classList.remove('open'); matches = []; }

  function render() {
    const tok = currentToken();
    if (!tok || tok.includes(':')) { close(); return; }
    const low = tok.toLowerCase();
    matches = NH_OPERATORS
      .filter(([op]) => op.toLowerCase().startsWith(low))
      .slice(0, 9);
    if (!matches.length) { close(); return; }
    active = 0;
    list.innerHTML = matches.map(([op, ex, desc], i) => `
      <div class="ac-item" role="option" data-i="${i}" aria-selected="${i === 0}">
        <span class="ac-op">${escHtmlCore(op)}</span>
        <span class="ac-desc">${escHtmlCore(desc)}</span>
        ${ex ? `<span class="ac-ex">${escHtmlCore(ex)}</span>` : ''}
      </div>`).join('');
    list.classList.add('open');
  }

  function highlight() {
    [...list.querySelectorAll('.ac-item')].forEach((el, i) => {
      el.setAttribute('aria-selected', i === active ? 'true' : 'false');
      if (i === active) el.scrollIntoView({ block: 'nearest' });
    });
  }

  function apply(i) {
    const pick = matches[i];
    if (!pick) return;
    const pos = input.selectionStart ?? input.value.length;
    const before = input.value.slice(0, pos);
    const after = input.value.slice(pos);
    const tok = currentToken();
    const head = before.slice(0, before.length - tok.length);
    input.value = head + pick[0] + after;
    const caret = (head + pick[0]).length;
    input.focus();
    input.setSelectionRange(caret, caret);
    close();
  }

  input.addEventListener('input', render);
  input.addEventListener('focus', render);
  input.addEventListener('blur', () => setTimeout(close, 140));

  input.addEventListener('keydown', e => {
    if (!list.classList.contains('open') || !matches.length) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); active = (active + 1) % matches.length; highlight(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); active = (active - 1 + matches.length) % matches.length; highlight(); }
    else if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); apply(active); }
    else if (e.key === 'Escape') { close(); }
  });

  list.addEventListener('mousedown', e => {
    const item = e.target.closest('.ac-item');
    if (item) { e.preventDefault(); apply(parseInt(item.dataset.i, 10)); }
  });
}
window.nhAutocomplete = nhAutocomplete;

/* wire up every search box on the page */
function nhWireAutocomplete() {
  ['topSearchInput', 'heroSearch', 'searchInput'].forEach(id => {
    const el = document.getElementById(id);
    if (el) nhAutocomplete(el);
  });
}
document.addEventListener('DOMContentLoaded', nhWireAutocomplete);
nhWireAutocomplete();


/* ══ Empty index notice ══════════════════════════════════════════ */
/* Until a scan runs there are no hosts to show. Rather than let every
   page render a wall of zeros, each one says so in the same words and
   points at the two ways to fill the index. Pages that are not about
   host data — the feed sync, the wordlist engine, CVE detail — are
   left alone, since those have their own data and their own states. */
const NH_NODATA_SKIP = ['/feeds', '/wordlists', '/cve'];

async function nhEmptyNotice() {
  const main = document.querySelector('main.main-content');
  if (!main || document.getElementById('nhNoData')) return;
  const path = window.location.pathname;
  if (NH_NODATA_SKIP.some(p => path === p || path.startsWith(p + '/'))) return;

  let d = null;
  try {
    d = await fetch('/api/has-data').then(r => r.json());
  } catch (e) {
    return;                 // API down — the page's own error states handle it
  }
  if (!d || !d.empty) return;

  const running = !!d.daemon_running;
  const el = document.createElement('div');
  el.className = 'nh-nodata';
  el.id = 'nhNoData';
  el.innerHTML = `
    <span class="nh-nodata-icon">
      <svg class="icon"><use href="#${running ? 'i-activity' : 'i-database'}"/></svg>
    </span>
    <div class="nh-nodata-body">
      <h3>No data yet — run a scan to populate.</h3>
      <p>
        ${running
          ? `The continuous scanner is running and has not finished its first
             sweep yet. Hosts appear here as they are discovered.`
          : `The host index is empty. Nothing has been scanned yet — start a
             scan from the discovery engine and hosts appear here as they
             answer.`}
      </p>
      <div class="nh-nodata-actions">
        <a href="/scan" class="btn btn-primary btn-sm">
          <svg class="icon"><use href="#i-bolt"/></svg> Discovery engine
        </a>
        <a href="/feeds" class="btn btn-ghost btn-sm">
          <svg class="icon"><use href="#i-download"/></svg> Data sync
        </a>
      </div>
    </div>`;
  main.insertBefore(el, main.firstChild);
}

document.addEventListener('DOMContentLoaded', nhEmptyNotice);
if (document.readyState !== 'loading') nhEmptyNotice();
