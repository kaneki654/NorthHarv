/* ══════════════════════════════════════════════════════════════════════
   NorthHarv guided tour.

   A self-contained overlay: it builds its own DOM, owns its own styles
   (tutorial.css), and touches nothing on the host page except to read
   element positions. Dropping the stylesheet and this script into any
   page is enough to run it there.

   Each step can show a feature two ways:

     target()  a selector into the live page. When that element is
               present and on screen, the tour spotlights the real one.
     stage()   an animated miniature, used when the element is not on
               this page or is hidden behind a tab. It is labelled a
               demonstration, because it is one.

   No step describes a feature the app does not have.

   Public API:  NHTour.start([index])  .stop()  .reset()  .seen()
   ══════════════════════════════════════════════════════════════════ */
(function () {
  'use strict';

  var DONE_KEY   = 'nh.tour.done.v1';
  var RESUME_KEY = 'nh.tour.resume.v1';
  var GAP = 28;   // px between the spotlight and the step card
  var PAD = 8;    // px of breathing room around a spotlit element

  /* ════════════════════════════════════════════════════════════════
     Helpers
     ════════════════════════════════════════════════════════════════ */
  function el(tag, cls, html) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (html != null) n.innerHTML = html;
    return n;
  }
  function q(sel, root) {
    try { return (root || document).querySelector(sel); } catch (e) { return null; }
  }
  function visible(n) {
    if (!n || !n.getBoundingClientRect) return false;
    if (n.offsetParent === null && getComputedStyle(n).position !== 'fixed') return false;
    var r = n.getBoundingClientRect();
    return r.width > 4 && r.height > 4;
  }

  /* A container that rendered but has nothing in it is worse than the
     demo: pointing at an empty panel and calling it "live on this page"
     tells the user nothing. Form controls count as filled even when
     they are blank — an empty input is still the thing being shown. */
  function usable(n) {
    if (!visible(n)) return false;
    var tag = n.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' ||
        tag === 'BUTTON' || tag === 'SVG' || tag === 'TABLE') return true;
    /* A panel that rendered an empty state, a skeleton or a spinner has
       nothing to point at yet. Spotlighting "No data for this host." and
       calling it the risk gauge would be worse than showing the demo. */
    if (q('.empty-state, .skeleton, .spinner', n)) return false;
    if (n.textContent && n.textContent.trim().length > 1) return true;
    return n.children.length > 0;
  }
  function pathNow() { return location.pathname.replace(/(.)\/+$/, '$1') || '/'; }
  function flag(cc) {
    try {
      return String.fromCodePoint.apply(null, cc.toUpperCase().split('').map(function (c) {
        return 0x1F1E6 + c.charCodeAt(0) - 65;
      }));
    } catch (e) { return ''; }
  }

  /* Every stage animation registers its timers here, so moving to the
     next step can never leave one running behind the overlay. */
  function Timeline() {
    var ids = [];
    var api = {
      dead: false,
      at:   function (ms, fn) { ids.push(setTimeout(fn, ms)); return api; },
      tick: function (ms, fn) { ids.push(setInterval(fn, ms)); return api; },
      loop: function (period, fn) { fn(); ids.push(setInterval(fn, period)); return api; },
      own:  function (id) { ids.push(id); return api; },
      stop: function () {
        api.dead = true;
        ids.forEach(function (i) { clearTimeout(i); clearInterval(i); });
        ids = [];
      }
    };
    return api;
  }

  function typeInto(node, text, tl, delay, speed, after) {
    if (!node) return;
    node.textContent = '';
    tl.at(delay || 0, function () {
      var i = 0;
      var id = setInterval(function () {
        if (tl.dead) { clearInterval(id); return; }
        node.textContent = text.slice(0, ++i);
        if (i >= text.length) { clearInterval(id); if (after) after(); }
      }, speed || 58);
      tl.own(id);
    });
  }

  function countTo(node, to, tl, delay, ms, suffix) {
    if (!node) return;
    tl.at(delay || 0, function () {
      var t0 = performance.now(), dur = ms || 900;
      (function frame(now) {
        if (tl.dead || !node.isConnected) return;
        var p = Math.min(1, (now - t0) / dur);
        node.textContent = Math.round(to * (1 - Math.pow(1 - p, 3))).toLocaleString() +
                           (suffix || '');
        if (p < 1) requestAnimationFrame(frame);
      })(t0);
    });
  }

  /* ════════════════════════════════════════════════════════════════
     Stages — the animated miniatures
     ════════════════════════════════════════════════════════════════ */

  function stageDaemon(body, tl, withFeed) {
    body.innerHTML =
      '<div class="nht-daemon">' +
        '<span class="nht-live"></span>' +
        '<span>daemon <b style="color:#3fb950">sweeping</b></span>' +
        '<span class="cd" style="margin-left:auto;color:#7d8ea3">refresh in 15s</span>' +
      '</div>' +
      '<div class="nht-dgrid">' +
        '<div><span>cycle</span><b class="cyc">7</b></div>' +
        '<div><span>block</span><b class="blk" style="color:#58a6ff">203.0.113.0/24</b></div>' +
        '<div><span>found this sweep</span><b class="fnd t">0</b></div>' +
        '<div><span>next sweep</span><b class="nxt">23h 58m</b></div>' +
      '</div>' +
      (withFeed ? '<div class="nht-rows feed" style="margin-top:.65rem"></div>' : '');

    var cd = body.querySelector('.cd'), left = 15;
    tl.tick(1000, function () {
      left = left > 0 ? left - 1 : 15;
      cd.textContent = 'refresh in ' + left + 's';
      cd.style.color = left <= 3 ? '#3fb950' : '#7d8ea3';
    });

    countTo(body.querySelector('.fnd'), withFeed ? 12 : 41, tl, 300, 1400);

    if (!withFeed) {
      var blocks = ['203.0.113.0/24', '203.0.113.16/28', '198.51.100.0/24'];
      var bi = 0, blk = body.querySelector('.blk');
      tl.tick(2600, function () { blk.textContent = blocks[++bi % blocks.length]; });
      return;
    }

    var feed = body.querySelector('.feed');
    var arrivals = [
      ['203.0.113.17', '22/tcp',  'ssh · OpenSSH 8.9', '', 'n'],
      ['203.0.113.41', '443/tcp', 'https · nginx 1.18.0', 'KEV', 'r'],
      ['203.0.113.9',  '3306/tcp','mysql · 8.0.33', 'HIGH', 'o']
    ];
    var k = 0;
    tl.loop(1750, function () {
      var a = arrivals[k++ % arrivals.length];
      var row = el('div', 'nht-row nht-flash' + (a[4] === 'r' ? ' hot' : a[4] === 'o' ? ' warm' : ''));
      row.innerHTML =
        '<span class="ip">' + a[0] + '</span>' +
        '<span class="pt">' + a[1] + '</span>' +
        '<span class="sv">' + a[2] + '</span>' +
        (a[3] ? '<i class="nht-b ' + a[4] + '">' + a[3] + '</i>' : '<i class="nht-b n">new</i>');
      feed.insertBefore(row, feed.firstChild);
      while (feed.children.length > 3) feed.removeChild(feed.lastChild);
    });
  }

  function stageSearch(body, tl) {
    body.innerHTML =
      '<div class="nht-sbox"><span style="color:#7d8ea3">&#9906;</span>' +
        '<span class="q"></span><i class="nht-caret"></i></div>' +
      '<div class="nht-count">ready</div>' +
      '<div class="nht-rows"></div>';

    var box = body.querySelector('.nht-sbox');
    var qn  = body.querySelector('.q');
    var cnt = body.querySelector('.nht-count');
    var rows = body.querySelector('.nht-rows');

    var hits = [
      ['198.51.100.24', '443/tcp', 'US', 'nginx 1.18.0 · DigitalOcean', '2m', 'hot',
       '<i class="nht-b r">&#128293; KEV</i><i class="nht-b o">9.8</i>'],
      ['203.0.113.7',   '443/tcp', 'DE', 'Apache 2.4.49 · Hetzner', '11m', 'warm',
       '<i class="nht-b o">7.5</i>'],
      ['192.0.2.88',    '443/tcp', 'SG', 'Caddy 2.7.6 · Vultr', '34m', '',
       '<i class="nht-b g">clean</i>']
    ];

    tl.loop(8200, function () {
      box.classList.remove('focus');
      rows.innerHTML = '';
      cnt.textContent = 'ready';
      tl.at(260, function () { box.classList.add('focus'); });
      typeInto(qn, 'port:443', tl, 520, 78, function () {
        cnt.innerHTML = 'searching…';
        tl.at(420, function () {
          if (tl.dead) return;
          cnt.innerHTML = 'showing <b>1&#8211;3</b> of <b>1,284</b> results';
          hits.forEach(function (h, i) {
            tl.at(i * 190, function () {
              if (tl.dead) return;
              var r = el('div', 'nht-row nht-pop ' + h[5]);
              r.innerHTML =
                '<span class="ip">' + h[0] + '</span>' +
                '<span class="pt">' + h[1] + '</span>' +
                '<span class="sv">' + flag(h[2]) + ' ' + h[2] + ' &#183; ' + h[3] +
                  ' &#183; ' + h[4] + '</span>' +
                '<span style="display:flex;gap:3px">' + h[6] + '</span>';
              rows.appendChild(r);
            });
          });
        });
      });
    });
  }

  function stageHost(body, tl) {
    body.innerHTML =
      '<div class="nht-hero">' +
        '<div>' +
          '<div class="ip">198.51.100.24</div>' +
          '<div class="meta">DigitalOcean &#183; AS14061<br>' +
            flag('NL') + ' Amsterdam, NL &#183; 2 open ports</div>' +
        '</div>' +
        '<div class="nht-gauge">' +
          '<svg width="74" height="74" viewBox="0 0 74 74">' +
            '<circle class="bg" cx="37" cy="37" r="31"/>' +
            '<circle class="fg" cx="37" cy="37" r="31"/>' +
          '</svg><div class="val">0</div>' +
        '</div>' +
      '</div>' +
      '<div class="nht-tabs"></div>';

    var C = 2 * Math.PI * 31;
    var arc = body.querySelector('.fg');
    arc.style.strokeDasharray = C;
    arc.style.strokeDashoffset = C;

    var tabs = ['Overview', 'Raw Data', 'Timeline', 'Whois', 'Notes', 'Enumerate'];
    var wrap = body.querySelector('.nht-tabs');

    tl.loop(7400, function () {
      wrap.innerHTML = '';
      arc.style.strokeDashoffset = C;
      body.querySelector('.val').textContent = '0';
      tl.at(280, function () {
        if (tl.dead) return;
        arc.style.strokeDashoffset = C * (1 - 0.842);
        countTo(body.querySelector('.val'), 842, tl, 0, 1300);
      });
      tabs.forEach(function (t, i) {
        tl.at(700 + i * 130, function () {
          if (tl.dead) return;
          var b = el('span', 'nht-tab nht-pop' + (i === 0 ? ' on' : ''), t);
          wrap.appendChild(b);
        });
      });
    });
  }

  function stagePorts(body, tl) {
    body.innerHTML =
      '<div class="nht-tabs" style="margin-top:0">' +
        '<span class="nht-tab on">Overview</span><span class="nht-tab">Raw Data</span>' +
        '<span class="nht-tab">Timeline</span><span class="nht-tab">Whois</span>' +
      '</div>' +
      '<table class="nht-ptable" style="margin-top:.5rem"><thead><tr>' +
        '<th>PORT</th><th>SERVICE</th><th>BANNER</th><th></th>' +
      '</tr></thead><tbody></tbody></table>';

    var rows = [
      ['443/tcp', 'https', 'nginx/1.18.0', '<i class="nht-b g">TLS 1.3</i>'],
      ['22/tcp',  'ssh',   'OpenSSH_8.9p1 Ubuntu-3', '<i class="nht-b b">HASSH</i>'],
      ['3306/tcp','mysql', '8.0.33-0ubuntu0.22.04.2', '<i class="nht-b o">exposed</i>']
    ];
    var tb = body.querySelector('tbody');

    tl.loop(6000, function () {
      tb.innerHTML = '';
      rows.forEach(function (r, i) {
        tl.at(240 + i * 300, function () {
          if (tl.dead) return;
          var tr = el('tr', 'nht-pop');
          tr.innerHTML =
            '<td class="p">' + r[0] + '</td><td>' + r[1] + '</td>' +
            '<td class="bn">' + r[2] + '</td><td>' + r[3] + '</td>';
          tb.appendChild(tr);
        });
      });
    });
  }

  function stageCve(body, tl) {
    body.innerHTML =
      '<div style="font-size:.66rem;color:#7d8ea3;margin-bottom:.45rem">' +
        '443/tcp &#183; nginx 1.18.0 &#8212; correlated against NVD, CISA KEV and EPSS' +
      '</div><div class="cves"></div>' +
      '<div class="nht-count" style="margin-bottom:0">matched on <b>CPE</b>, not on banner text</div>';

    var cves = [
      ['CVE-2021-44228', 'crit', '10.0', '<i class="nht-b r">&#128293; KEV</i>' +
        '<i class="nht-b r">CRITICAL</i><i class="nht-b o">EPSS .975</i>'],
      ['CVE-2023-44487', '',     '7.5',  '<i class="nht-b r">&#128293; KEV</i>' +
        '<i class="nht-b o">HIGH</i><i class="nht-b n">EPSS .441</i>'],
      ['CVE-2022-41741', 'med',  '5.3',  '<i class="nht-b n">MEDIUM</i>' +
        '<i class="nht-b n">EPSS .006</i>']
    ];
    var wrap = body.querySelector('.cves');

    tl.loop(6400, function () {
      wrap.innerHTML = '';
      cves.forEach(function (c, i) {
        tl.at(220 + i * 330, function () {
          if (tl.dead) return;
          var d = el('div', 'nht-cve nht-pop ' + c[1]);
          d.innerHTML = '<span class="id">' + c[0] + '</span>' +
                        '<span style="color:#7d8ea3">CVSS ' + c[2] + '</span>' +
                        '<span class="sp">' + c[3] + '</span>';
          wrap.appendChild(d);
        });
      });
    });
  }

  function stageEnum(body, tl) {
    body.innerHTML =
      '<div style="display:flex;gap:.4rem;align-items:center;font-size:.68rem;margin-bottom:.5rem">' +
        '<span style="color:#7d8ea3">wordlist</span>' +
        '<span style="color:#58a6ff">common-paths · 4,614</span>' +
        '<span class="pct" style="margin-left:auto;color:#3fb950">0%</span>' +
      '</div>' +
      '<div class="nht-bar"><i></i></div>' +
      '<div class="hits" style="margin-top:.55rem"></div>';

    var bar = body.querySelector('.nht-bar i');
    var pct = body.querySelector('.pct');
    var hits = body.querySelector('.hits');
    var found = [
      ['200', '/admin/login', '2.1 KB'],
      ['301', '/.git/', '&#8212;'],
      ['403', '/server-status', '199 B'],
      ['200', '/api/v1/health', '41 B']
    ];

    tl.loop(7600, function () {
      bar.style.width = '0%';
      pct.textContent = '0%';
      hits.innerHTML = '';
      [18, 44, 67, 91, 100].forEach(function (p, i) {
        tl.at(400 + i * 620, function () {
          if (tl.dead) return;
          bar.style.width = p + '%';
          pct.textContent = p + '%';
        });
      });
      found.forEach(function (f, i) {
        tl.at(800 + i * 620, function () {
          if (tl.dead) return;
          var h = el('div', 'nht-hit nht-pop');
          h.innerHTML = '<span class="c' + f[0] + '">' + f[0] + '</span>' +
                        '<span class="path">' + f[1] + '</span>' +
                        '<span style="color:#7d8ea3">' + f[2] + '</span>';
          hits.appendChild(h);
        });
      });
    });
  }

  function stageScan(body, tl) {
    body.innerHTML =
      '<div class="nht-warn"><span>&#9888;</span><span>Only scan networks you own or ' +
        'have explicit written authorization to scan. Unauthorized scanning is illegal.' +
      '</span></div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem">' +
        '<div class="nht-field f1"><span>target cidr</span><div class="v1"></div></div>' +
        '<div class="nht-field f2"><span>ports</span><div class="v2"></div></div>' +
      '</div>' +
      '<div class="nht-bar" style="margin:.1rem 0 .55rem"><i></i></div>' +
      '<div class="nht-term"></div>';

    var warn = body.querySelector('.nht-warn');
    var f1 = body.querySelector('.f1'), f2 = body.querySelector('.f2');
    var v1 = body.querySelector('.v1'), v2 = body.querySelector('.v2');
    var bar = body.querySelector('.nht-bar i');
    var term = body.querySelector('.nht-term');
    var lines = [
      '<span class="i">[*]</span> round 12 opened &#183; 203.0.113.0/24',
      '<span class="i">[*]</span> 254 addresses &#215; 3 ports queued',
      '<span class="ok">[+]</span> 203.0.113.17:22 open &#183; OpenSSH_8.9p1',
      '<span class="ok">[+]</span> 203.0.113.41:443 open &#183; nginx/1.18.0',
      '<span class="w">[!]</span> 203.0.113.41 &#8594; CVE-2023-44487 (KEV)',
      '<span class="ok">[&#10003;]</span> scan complete &#183; 2 services &#183; 7.4s'
    ];

    tl.loop(10500, function () {
      warn.classList.remove('pulse');
      v1.innerHTML = ''; v2.innerHTML = '';
      f1.classList.remove('lit'); f2.classList.remove('lit');
      bar.style.width = '0%';
      term.innerHTML = '';
      void warn.offsetWidth;
      warn.classList.add('pulse');

      f1.classList.add('lit');
      typeInto(v1, '203.0.113.0/24', tl, 700, 62, function () {
        f1.classList.remove('lit'); f2.classList.add('lit');
        typeInto(v2, '80,443,22', tl, 180, 62, function () {
          f2.classList.remove('lit');
          [12, 38, 61, 84, 100].forEach(function (p, i) {
            tl.at(300 + i * 520, function () { if (!tl.dead) bar.style.width = p + '%'; });
          });
          lines.forEach(function (ln, i) {
            tl.at(320 + i * 520, function () {
              if (tl.dead) return;
              var p = el('p', 'nht-pop', ln);
              term.appendChild(p);
              term.scrollTop = term.scrollHeight;
            });
          });
        });
      });
    });
  }

  function stageDiff(body, tl) {
    body.innerHTML =
      '<table class="nht-ptable"><thead><tr>' +
        '<th>ROUND</th><th>TARGET</th><th>FOUND</th><th>STARTED</th>' +
      '</tr></thead><tbody></tbody></table>' +
      '<div style="display:flex;gap:.4rem;align-items:center;margin-top:.6rem;font-size:.68rem">' +
        '<span style="color:#7d8ea3">compare</span>' +
        '<span class="a nht-b b">#11</span><span style="color:#7d8ea3">&#8594;</span>' +
        '<span class="b nht-b b">#12</span>' +
      '</div>' +
      '<div class="nht-tiles"></div>';

    var rows = [
      ['#12', '203.0.113.0/24', '41', 'just now'],
      ['#11', '203.0.113.0/24', '38', '24h ago'],
      ['#10', '198.51.100.0/24', '17', '2d ago']
    ];
    var tb = body.querySelector('tbody');
    var tiles = body.querySelector('.nht-tiles');

    tl.loop(7200, function () {
      tb.innerHTML = '';
      tiles.innerHTML = '';
      rows.forEach(function (r, i) {
        tl.at(180 + i * 220, function () {
          if (tl.dead) return;
          var tr = el('tr', 'nht-pop');
          tr.innerHTML = '<td class="p">' + r[0] + '</td><td>' + r[1] + '</td>' +
                         '<td>' + r[2] + '</td><td class="bn">' + r[3] + '</td>';
          tb.appendChild(tr);
        });
      });
      tl.at(1150, function () {
        if (tl.dead) return;
        [['up', 'appeared', 5], ['down', 'disappeared', 2], ['chg', 'changed', 9]]
          .forEach(function (t, i) {
            var d = el('div', 'nht-tile nht-pop ' + t[0], '<b>0</b><span>' + t[1] + '</span>');
            tiles.appendChild(d);
            countTo(d.querySelector('b'), t[2], tl, 120 + i * 140, 700);
          });
      });
    });
  }

  /* ════════════════════════════════════════════════════════════════
     Steps
     ════════════════════════════════════════════════════════════════ */
  var STEPS = [
    {
      title: 'Live discovery',
      page: '/',
      target: function () { return q('#dmBody') || q('#dmDot'); },
      text: 'The daemon sweeps every authorised range on a schedule. A <b>pulsing ' +
            'green dot</b> means it is live — cycle, block and countdown sit ' +
            'beside it.',
      stage: function (b, t) { stageDaemon(b, t, true); }
    },
    {
      title: 'Searching',
      page: '/search',
      target: function () { return q('#searchInput'); },
      text: 'Field operators, not keywords: <code>port:443</code>, ' +
            '<code>kev:true</code>, <code>has:tls</code>, ' +
            '<code>domain:example.com</code> — or bare text to search the banners. ' +
            'Rows carry risk, KEV and severity badges.',
      stage: stageSearch
    },
    {
      title: 'Host detail',
      page: '/host',
      pageTest: function (p) { return p.indexOf('/host/') === 0; },
      /* the gauge only exists once a host has actually been observed, so
         its presence is the signal that this page has something to show */
      target: function () { return q('#riskGauge'); },
      text: 'The <b>risk gauge</b> is a 0–1000 score from CVSS, KEV, EPSS, exposure ' +
            'and TLS hygiene — not a copied CVSS. Six tabs sit below it.',
      stage: stageHost
    },
    {
      title: 'Overview — the open ports',
      page: '/host',
      pageTest: function (p) { return p.indexOf('/host/') === 0; },
      target: function () { return q('#portList .port-card') ? q('#portList') : null; },
      text: 'One row per port the engine actually reached — service, product and ' +
            'version from the banner, plus <b>TLS</b>, <b>JARM</b> and <b>HASSH</b> ' +
            'chips.',
      stage: stagePorts
    },
    {
      title: 'Vulnerability correlation',
      page: '/host',
      pageTest: function (p) { return p.indexOf('/host/') === 0; },
      target: null,
      text: 'Expand a port for its CVEs — matched by <b>CPE</b> against the local ' +
            'NVD mirror, then crossed with <b>KEV</b> and <b>EPSS</b>. A flame ' +
            'means exploited in the wild.',
      stage: stageCve
    },
    {
      title: 'Enumerate',
      page: '/host',
      pageTest: function (p) { return p.indexOf('/host/') === 0; },
      target: function () { return q('#hostTabs [data-tab="enumerate"]'); },
      text: 'Walks a wordlist against a web port and reports what answers: status, ' +
            'path, size. Same rule as scanning — <b>only hosts you are authorised ' +
            'to test</b>.',
      stage: stageEnum
    },
    {
      title: 'Starting a scan',
      page: '/scan',
      target: function () { return q('#scanCidr'); },
      text: 'A CIDR and a port list; blank ports means the 55 common ones. The run ' +
            'opens a new <b>scan round</b>, and anything outside your authorised ' +
            'ranges is refused.',
      stage: stageScan
    },
    {
      title: 'History and diffing',
      page: '/scan',
      target: function () { return q('#scanTable') || q('#diffA'); },
      text: 'Every sweep is kept as a numbered round. Diff two of them for what ' +
            '<b>appeared</b>, <b>disappeared</b> or <b>changed</b> — a new port, a ' +
            'bumped version, a fresh CVE.',
      stage: stageDiff
    },
    {
      title: 'Keeping it current',
      page: '/',
      target: function () { return q('#dmBody') || q('#dmDot'); },
      text: 'Continuous scanning repeats the sweep on its own schedule. Each one ' +
            'opens its own round — what the timeline and change feed compare.',
      stage: function (b, t) { stageDaemon(b, t, false); }
    }
  ];

  /* ════════════════════════════════════════════════════════════════
     Engine
     ════════════════════════════════════════════════════════════════ */
  var root, spot, ticks, link, card, stageEl;
  var idx = 0, running = false, tl = Timeline();
  var rectOf = null;

  function build() {
    if (root) return;
    root = el('div', 'nht-root');
    root.setAttribute('role', 'dialog');
    root.setAttribute('aria-label', 'NorthHarv guided tour');

    root.appendChild(el('div', 'nht-scan'));
    root.appendChild(el('div', 'nht-sweep'));

    spot = el('div', 'nht-spot');
    root.appendChild(spot);

    ticks = ['tl', 'tr', 'bl', 'br'].map(function (c) {
      var t = el('i', 'nht-tick ' + c);
      root.appendChild(t);
      return t;
    });

    link = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    link.setAttribute('class', 'nht-link');
    link.innerHTML =
      '<defs><marker id="nhtArrow" viewBox="0 0 10 10" refX="9" refY="5" ' +
      'markerWidth="4.5" markerHeight="4.5" orient="auto-start-reverse">' +
      '<path class="nht-head-tri" d="M0,0 L10,5 L0,10 z"/></marker></defs>' +
      '<path class="nht-wire" d="" marker-end="url(#nhtArrow)"/>';
    root.appendChild(link);

    card = el('div', 'nht-card');
    card.addEventListener('click', onCardClick);
    root.appendChild(card);

    document.body.appendChild(root);
    document.addEventListener('keydown', onKey, true);
    watch();
  }

  /* The spotlight has to follow its element even when nothing scrolls:
     this dashboard fills in asynchronously, so a target can be pushed
     hundreds of pixels down after the step has already been drawn.
     Scroll and resize listeners never see that. A frame loop does, and
     it only writes styles when the rectangle has actually moved. */
  var lastBox = '';
  function watch() {
    requestAnimationFrame(watch);
    if (!running || !rectOf) return;
    var r = rectOf();
    if (!r) return;
    var key = Math.round(r.left) + ':' + Math.round(r.top) + ':' +
              Math.round(r.width) + ':' + Math.round(r.height) + ':' +
              window.innerWidth + ':' + window.innerHeight;
    if (key === lastBox) return;
    lastBox = key;
    place();
  }

  function onKey(e) {
    if (!running) return;
    if (e.key === 'Escape') { e.preventDefault(); stop(false); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); next(); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); back(); }
  }

  function place() {
    if (!rectOf) return;
    var r = rectOf();
    if (!r) return;

    var vw = window.innerWidth, vh = window.innerHeight;
    var x = Math.max(4, r.left - PAD), y = Math.max(4, r.top - PAD);
    var w = Math.min(vw - x - 4, r.width + PAD * 2);
    var h = Math.min(vh - y - 4, r.height + PAD * 2);

    spot.style.top = y + 'px';
    spot.style.left = x + 'px';
    spot.style.width = w + 'px';
    spot.style.height = h + 'px';

    var corners = [[x - 2, y - 2], [x + w - 12, y - 2],
                   [x - 2, y + h - 12], [x + w - 12, y + h - 12]];
    ticks.forEach(function (t, i) {
      t.style.left = corners[i][0] + 'px';
      t.style.top = corners[i][1] + 'px';
      t.style.display = (w < 46 || h < 30) ? 'none' : '';
    });

    var cw = card.offsetWidth || 430, ch = card.offsetHeight || 250;
    var cx, cy;
    if (vw - (x + w) >= cw + GAP)      { cx = x + w + GAP;        cy = y + h / 2 - ch / 2; }
    else if (x >= cw + GAP)            { cx = x - cw - GAP;       cy = y + h / 2 - ch / 2; }
    else if (vh - (y + h) >= ch + GAP) { cx = x + w / 2 - cw / 2; cy = y + h + GAP; }
    else if (y >= ch + GAP)            { cx = x + w / 2 - cw / 2; cy = y - ch - GAP; }
    else                               { cx = vw - cw - 16;       cy = vh - ch - 16; }

    cx = Math.max(12, Math.min(cx, vw - cw - 12));
    cy = Math.max(12, Math.min(cy, vh - ch - 12));
    card.style.left = cx + 'px';
    card.style.top = cy + 'px';

    drawLink(cx, cy, cw, ch, x, y, w, h);
  }

  function drawLink(cx, cy, cw, ch, x, y, w, h) {
    /* .nht-wire, not just 'path' — the first <path> in this svg is the
       arrowhead inside <defs>, and writing the route into that one drew
       nothing at all while quietly deforming the marker. */
    var p = link.querySelector('path.nht-wire');
    var sx, sy, tx, ty;
    if (cx > x + w)       { sx = cx;          sy = cy + ch / 2; tx = x + w;     ty = y + h / 2; }
    else if (cx + cw < x) { sx = cx + cw;     sy = cy + ch / 2; tx = x;         ty = y + h / 2; }
    else if (cy > y + h)  { sx = cx + cw / 2; sy = cy;          tx = x + w / 2; ty = y + h; }
    else                  { sx = cx + cw / 2; sy = cy + ch;     tx = x + w / 2; ty = y; }

    /* The card sits one GAP away, so this arrow is deliberately short —
       long enough to read as a pointer, not so long it crosses content. */
    if (Math.hypot(sx - tx, sy - ty) < 14) { link.style.display = 'none'; return; }
    link.style.display = '';
    var mx = (sx + tx) / 2, my = (sy + ty) / 2;
    var bend = Math.min(26, Math.abs(sx - tx) / 4 + 6);
    p.setAttribute('d', 'M' + sx + ',' + sy + ' Q' + (mx + bend * 0.25) + ',' +
                        (my - bend) + ' ' + tx + ',' + ty);
  }

  function bringIntoView(n) {
    if (!n || !n.isConnected) return;
    var r = n.getBoundingClientRect();
    var vh = window.innerHeight;
    if (r.top >= 88 && r.bottom <= vh - 88) return;        // already comfortable
    if (r.height > vh - 176) {                              // taller than the gap
      if (r.top >= 0 && r.top < vh * 0.5) return;
    }
    n.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function render() {
    var step = STEPS[idx];
    tl.stop();
    tl = Timeline();
    if (stageEl) { stageEl.remove(); stageEl = null; }

    var live = null;
    try { live = step.target ? step.target() : null; } catch (e) { live = null; }
    var here = step.pageTest ? step.pageTest(pathNow()) : (!step.page || step.page === pathNow());
    var useLive = !!(live && here && usable(live));

    if (useLive) {
      bringIntoView(live);
      /* Pages here fill in from fetches. A target that was comfortably
         placed when the step opened can be shoved off screen a moment
         later, so check once more after the page has settled. */
      tl.at(800, function () { bringIntoView(live); });
      rectOf = function () { return live.getBoundingClientRect(); };
    } else {
      stageEl = el('div', 'nht-stage nht-stage-in');
      stageEl.innerHTML =
        '<div class="nht-stage-bar"><span class="nht-stage-path">' +
          (step.page || '/') + '</span>' +
          '<span class="nht-stage-tag">demonstration</span></div>' +
        '<div class="nht-stage-body"></div>';
      root.appendChild(stageEl);
      var vw = window.innerWidth, sw = Math.min(560, vw - 32);
      stageEl.style.width = sw + 'px';
      stageEl.style.left = Math.round((vw - sw) / 2) + 'px';
      stageEl.style.top = Math.max(16, Math.round(window.innerHeight * 0.15)) + 'px';
      try { step.stage(stageEl.querySelector('.nht-stage-body'), tl); } catch (e) {}
      rectOf = function () { return stageEl.getBoundingClientRect(); };
    }

    card.className = 'nht-card nht-card-in';
    card.innerHTML = cardHTML(step, useLive);
    place();
    var nx = card.querySelector('[data-act="next"]');
    if (nx) nx.focus({ preventScroll: true });
  }

  function cardHTML(step, useLive) {
    var where = '';
    if (step.page) {
      where = useLive
        ? '<span class="nht-where live">&#9679; live on this page</span>'
        : '<a class="nht-where" href="' + (step.page === '/host' ? '/search' : step.page) +
          '" data-act="goto">open ' +
          (step.page === '/host' ? '/search' : step.page) + ' &#8594;</a>';
    }
    return '' +
      '<div class="nht-head">' +
        '<span class="nht-dots"><i></i><i></i><i></i></span>' +
        '<span class="nht-crumb">northharv tour <b>' + (idx + 1) + '</b>/' + STEPS.length + '</span>' +
        '<button class="nht-x" data-act="skip">skip &#10005;</button>' +
      '</div>' +
      '<div class="nht-body">' +
        '<span class="nht-no">STEP ' + ('0' + (idx + 1)).slice(-2) + '</span>' +
        '<h3 class="nht-title">' + step.title + '</h3>' +
        '<p class="nht-text">' + step.text + '</p>' + where +
      '</div>' +
      '<div class="nht-foot">' +
        '<span class="nht-pips">' + STEPS.map(function (_, i) {
          return '<button data-go="' + i + '" title="Step ' + (i + 1) +
                 '" aria-label="Go to step ' + (i + 1) + '" class="' +
                 (i === idx ? 'now' : i < idx ? 'done' : '') + '"></button>';
        }).join('') + '</span>' +
        '<button class="nht-btn" data-act="back"' + (idx === 0 ? ' disabled' : '') +
          '>&#8592; back</button>' +
        '<button class="nht-btn go" data-act="next">' +
          (idx === STEPS.length - 1 ? 'finish &#10003;' : 'next &#8594;') +
        '</button>' +
      '</div>';
  }

  function onCardClick(e) {
    var b = e.target.closest ? e.target.closest('[data-act],[data-go]') : null;
    if (!b) return;
    if (b.dataset.go != null) { e.preventDefault(); go(+b.dataset.go); return; }
    var a = b.dataset.act;
    if (a === 'next') { e.preventDefault(); next(); }
    else if (a === 'back') { e.preventDefault(); back(); }
    else if (a === 'skip') { e.preventDefault(); stop(false); }
    else if (a === 'goto') {
      e.preventDefault();
      try { sessionStorage.setItem(RESUME_KEY, String(idx)); } catch (err) {}
      location.href = b.getAttribute('href');
    }
  }

  function go(i) { idx = Math.max(0, Math.min(STEPS.length - 1, i)); render(); }
  function next() { if (idx >= STEPS.length - 1) finish(); else go(idx + 1); }
  function back() { if (idx > 0) go(idx - 1); }

  function finish() {
    tl.stop();
    if (stageEl) { stageEl.remove(); stageEl = null; }
    rectOf = null;
    link.style.display = 'none';
    ticks.forEach(function (t) { t.style.display = 'none'; });
    spot.style.top = '50%'; spot.style.left = '50%';
    spot.style.width = '0'; spot.style.height = '0';
    card.className = 'nht-card';
    card.style.left = '-9999px';

    var done = el('div', 'nht-done',
      '<h2>You are ready.</h2>' +
      '<p>Discover, search, inspect, correlate, enumerate — and leave the daemon ' +
      'running so it stays current. Everything the tour showed runs on your own ' +
      'scans; nothing in NorthHarv is pre-populated.</p>' +
      '<div class="nht-prompt">northharv:~$ <i></i></div>' +
      '<div class="nht-done-acts">' +
        '<button class="nht-btn" data-act="again">run it again</button>' +
        '<button class="nht-btn go" data-act="close">close</button>' +
      '</div>');
    done.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('[data-act]') : null;
      if (!b) return;
      done.remove();
      if (b.dataset.act === 'again') go(0); else stop(true);
    });
    root.appendChild(done);
    markDone();
  }

  function markDone() {
    try { localStorage.setItem(DONE_KEY, String(Date.now())); } catch (e) {}
    try { sessionStorage.removeItem(RESUME_KEY); } catch (e) {}
  }

  function start(at) {
    build();
    running = true;
    idx = typeof at === 'number' ? at : 0;
    root.style.display = '';
    requestAnimationFrame(function () { root.classList.add('nht-on'); });
    render();
  }

  function stop(completed) {
    if (!root) return;
    running = false;
    tl.stop();
    root.classList.remove('nht-on');
    if (!completed) markDone();
    setTimeout(function () {
      if (running) return;
      if (stageEl) { stageEl.remove(); stageEl = null; }
      var d = root.querySelector('.nht-done');
      if (d) d.remove();
      root.style.display = 'none';
      rectOf = null;
    }, 280);
  }

  function reset() { try { localStorage.removeItem(DONE_KEY); } catch (e) {} }
  function seen() { try { return !!localStorage.getItem(DONE_KEY); } catch (e) { return false; } }

  /* ── launcher in the top bar ──────────────────────────────────── */
  function mountLauncher() {
    var bar = q('.nav-actions') || q('.topbar');
    if (!bar || q('.nht-launch')) return;
    var b = el('button', 'nht-launch',
      '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
      '<circle cx="12" cy="12" r="9"/><path d="M9.7 9.3a2.4 2.4 0 1 1 3.2 2.3' +
      'c-.6.2-.9.7-.9 1.3v.4"/><path d="M12 16.6h.01"/></svg><span>Tour</span>');
    b.type = 'button';
    b.title = 'Replay the guided tour';
    b.addEventListener('click', function () { start(0); });
    bar.insertBefore(b, bar.firstChild);
  }

  function boot() {
    mountLauncher();
    var resume = null;
    try { resume = sessionStorage.getItem(RESUME_KEY); } catch (e) {}
    if (resume != null) {
      try { sessionStorage.removeItem(RESUME_KEY); } catch (e) {}
      setTimeout(function () { start(+resume); }, 450);
      return;
    }
    /* let the page's own fetches land first: a panel still showing its
       skeleton reads as "nothing here", and the tour would open on the
       demo instead of the real thing */
    if (!seen()) setTimeout(function () { start(0); }, 1500);
  }

  window.NHTour = { start: start, stop: stop, reset: reset, seen: seen };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
