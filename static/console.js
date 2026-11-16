// Gate Console front-end: all data comes from the server API.
(function(){
  var TOKEN = localStorage.getItem('gc_token');
  if (!TOKEN) { window.location.href = '/login'; return; }
  var state = { actions: [], stats: {}, decided: [], audit: [], policy: {}, current: null };
  var esc = function(s){
    var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML;
  };

  function api(method, path, body){
    return fetch(path, {
      method: method,
      headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN},
      body: body ? JSON.stringify(body) : undefined
    }).then(function(r){
      if (r.status === 401) { window.location.href = '/login'; throw new Error('unauthorized'); }
      return r.json().then(function(j){ return {ok: r.ok, j: j}; });
    });
  }

  function pill(verdict){
    var cls = {BLOCK: 'block', REVIEW: 'review', PASS: 'pass'}[verdict] || 'pass';
    var label = {BLOCK: 'BLOCK', REVIEW: 'REVIEW', PASS: 'PASS'}[verdict];
    return '<span class="pill ' + cls + '">' + label + '</span>';
  }

  function go(id){
    document.querySelectorAll('.screen').forEach(function(s){ s.classList.remove('on'); });
    document.getElementById(id).classList.add('on');
    document.querySelectorAll('.navlink').forEach(function(n){
      n.removeAttribute('aria-current');
      if (n.dataset.go === id) n.setAttribute('aria-current', 'page');
    });
    window.scrollTo(0, 0);
  }

  function loadQueue(){
    api('GET', '/api/queue').then(function(res){
      if (!res.ok) return;
      state.actions = res.j.pending; state.decided = res.j.decided; state.stats = res.j.stats;
      var s = res.j.stats;
      document.getElementById('statcards').innerHTML =
        '<div class="stat"><div class="l">Held for review</div><div class="n">' + s.pending +
        '</div><div class="t amb">awaiting your decision</div></div>' +
        '<div class="stat"><div class="l">Blocked by the gate</div><div class="n">' + s.blocked_total +
        '</div><div class="t red">injection + policy signals</div></div>' +
        '<div class="stat"><div class="l">Passed clean</div><div class="n">' + s.auto_passed +
        '</div><div class="t grn">no flags fired</div></div>';
      var qd = document.getElementById('qdot');
      qd.hidden = s.pending === 0; qd.textContent = s.pending;
      var q = document.getElementById('qrows');
      if (!res.j.pending.length){
        q.innerHTML = '<tr class="emptyrow"><td colspan="4">Queue is clear. Nothing held.</td></tr>';
      } else {
        q.innerHTML = res.j.pending.map(function(a){
          return '<tr class="rowbtn" tabindex="0" data-id="' + a.id + '"><td><span class="mono">' + esc(a.agent) +
            '</span></td><td>' + esc(a.action) + '</td><td>' + esc(a.target) + '</td><td>' + pill(a.verdict) + '</td></tr>';
        }).join('');
        q.querySelectorAll('tr.rowbtn').forEach(function(tr){
          var open = function(){ openDetail(Number(tr.dataset.id)); };
          tr.addEventListener('click', open);
          tr.addEventListener('keydown', function(e){ if (e.key === 'Enter') open(); });
        });
      }
      var d = document.getElementById('drows');
      if (!res.j.decided.length){
        d.innerHTML = '<tr class="emptyrow"><td colspan="4">No decisions recorded yet.</td></tr>';
      } else {
        d.innerHTML = res.j.decided.map(function(a){
          return '<tr><td><span class="mono">' + esc(a.agent) + '</span></td><td>' + esc(a.action) +
            '</td><td><span class="pill ' + (a.decision === 'blocked' ? 'block' : a.decision === 'approved' ? 'pass' : 'review') +
            '">' + esc((a.decision || '').toUpperCase()) + '</span></td><td class="mut">' + esc(a.decided_at || '') + '</td></tr>';
        }).join('');
      }
    }).catch(function(){});
  }

  function loadAudit(){
    api('GET', '/api/audit').then(function(res){
      if (!res.ok) return;
      var el = document.getElementById('alog');
      if (!res.j.items.length){
        el.innerHTML = '<div class="log"><span class="mut">No entries yet.</span></div>';
      } else {
        el.innerHTML = res.j.items.map(function(i){
          var cls = {BLOCK: 'block', HOLD: 'review', AUTO: 'pass', APPROVED: 'pass', BLOCKED: 'block', ESCALATED: 'review', POLICY: 'review'}[i.kind] || 'review';
          return '<div class="log"><span class="tm">' + esc(i.logged_at) + ' UTC</span><span><span class="pill ' + cls +
            '">' + esc(i.kind) + '</span> ' + esc(i.message) + '</span></div>';
        }).join('');
      }
    }).catch(function(){});
  }

  function loadPolicy(){
    api('GET', '/api/policy').then(function(res){
      if (!res.ok) return;
      state.policy = res.j;
      document.getElementById('p_ceiling').value = res.j.wire_ceiling;
      document.getElementById('p_cooling').value = res.j.payee_cooling_days;
      setSwitch('p_docs', res.j.treat_docs_as_data);
      setSwitch('p_egress', res.j.egress_allowlist);
    }).catch(function(){});
  }

  function setSwitch(id, on){
    var el = document.getElementById(id);
    el.classList.toggle('on', !!on);
    el.setAttribute('aria-checked', on ? 'true' : 'false');
  }
  ['p_docs', 'p_egress'].forEach(function(id){
    var el = document.getElementById(id);
    var toggle = function(){
      el.classList.toggle('on');
      var on = el.classList.contains('on');
      el.setAttribute('aria-checked', on ? 'true' : 'false');
    };
    el.addEventListener('click', toggle);
    el.addEventListener('keydown', function(e){
      if (e.key === 'Enter' || e.key === ' '){ toggle(); e.preventDefault(); }
    });
  });

  function openDetail(id){
    api('GET', '/api/queue/' + id).then(function(res){
      if (!res.ok) return;
      state.current = res.j;
      var a = res.j;
      document.getElementById('d_sub').textContent = a.agent + ' · ' + a.action + ' → ' + a.target;
      var flags;
      try { flags = (a.verdict === 'PASS') ? [] : null; } catch(e){ flags = null; }
      api('GET', '/api/audit').then(function(){});
      // flags come from the saved verdict; the server re-derives detail client-side
      api('GET', '/api/policy').then(function(pr){
        var pol = pr.j || state.policy;
        var ul = document.getElementById('d_policy');
        ul.innerHTML =
          '<li>Treat retrieved content as data, never as instructions</li>' +
          '<li>Wire actions above $' + Number(pol.wire_ceiling).toLocaleString() + ' need a human signature</li>' +
          '<li>Payees younger than ' + pol.payee_cooling_days + ' day(s) are review-flagged</li>' +
          '<li>Every decision is written to the audit log</li>';
      });
      api('GET', '/api/queue/' + id + '/flags').catch(function(){}); // noop guard
      document.getElementById('d_flags').innerHTML = flagsHtmlFor(a);
      document.getElementById('d_context').innerHTML = '&quot;' + esc(a.context || '(no retrieved text submitted)') + '&quot;';
      var acts = document.getElementById('d_actions');
      if (a.status === 'pending'){
        acts.innerHTML =
          '<button class="btn ok" id="ap">Approve with sign-off</button>' +
          '<button class="btn danger" id="bl">Block ' + esc(a.agent.split('-')[0]) + '</button>' +
          '<button class="btn ghost" id="es">Escalate to security</button>';
        acts.querySelector('#ap').addEventListener('click', function(){ decide(id, 'approved'); });
        acts.querySelector('#bl').addEventListener('click', function(){ decide(id, 'blocked'); });
        acts.querySelector('#es').addEventListener('click', function(){ decide(id, 'escalated'); });
      } else {
        acts.innerHTML = '<span class="mut">Decision recorded: ' + esc((a.decision || '').toUpperCase()) +
          ' at ' + esc(a.decided_at || '') + ' UTC.</span>';
      }
      document.getElementById('verdict').textContent = '';
      go('detail');
    }).catch(function(){});
  }

  function flagsHtmlFor(a){
    if (a.verdict === 'BLOCK'){
      return '<div class="flag"><span class="ic r">⚠</span><div><b>Injected instruction in retrieved content</b>' +
        '<p>The context contains override-style directive language. Treated as untrusted content, not as an instruction.</p></div></div>' +
        '<div class="flag"><span class="ic a">⚡</span><div><b>Gate verdict: BLOCK</b><p>A hard rule fired server-side. Human decision still required to close it out.</p></div></div>';
    }
    if (a.verdict === 'REVIEW'){
      return '<div class="flag"><span class="ic a">⚡</span><div><b>Soft policy signal</b>' +
        '<p>The server-side gate flagged this against your policy (ceiling, payee cooling or egress allow-list).</p></div></div>';
    }
    return '<div class="flag"><span class="ic a">✓</span><div><b>Passed clean</b><p>No rules fired for this action.</p></div></div>';
  }

  function decide(id, decision){
    api('POST', '/api/queue/' + id + '/decide', {decision: decision}).then(function(res){
      if (!res.ok) return;
      document.getElementById('verdict').textContent = 'Recorded: ' + decision.toUpperCase() +
        '. Written to the audit log.';
      loadQueue(); loadAudit();
      setTimeout(function(){ go('overview'); }, 900);
    }).catch(function(){});
  }

  // simulate
  document.getElementById('simform').addEventListener('submit', function(e){
    e.preventDefault();
    var err = document.getElementById('simerr'), out = document.getElementById('simout');
    err.textContent = ''; out.textContent = '';
    api('POST', '/api/simulate', {
      agent: document.getElementById('s_agent').value.trim(),
      action: document.getElementById('s_action').value.trim(),
      target: document.getElementById('s_target').value.trim(),
      context: document.getElementById('s_context').value.trim()
    }).then(function(res){
      if (!res.ok){ err.textContent = res.j.error === 'rate_limited' ? 'Too many submissions; wait a bit.' : 'Check the fields and try again.'; return; }
      var v = res.j.verdict;
      out.textContent = 'Gate verdict: ' + v + (res.j.flags.length ? ' — ' + res.j.flags.length + ' flag(s) fired.' : ' — clean.') +
        ' Added to the queue.';
      loadQueue(); loadAudit();
      ['s_agent','s_action','s_target','s_context'].forEach(function(id){ document.getElementById(id).value = ''; });
    }).catch(function(){ err.textContent = 'Network error.'; });
  });

  // policy save
  document.getElementById('psave').addEventListener('click', function(){
    var out = document.getElementById('psout');
    api('PUT', '/api/policy', {
      wire_ceiling: Number(document.getElementById('p_ceiling').value),
      payee_cooling_days: Number(document.getElementById('p_cooling').value),
      treat_docs_as_data: document.getElementById('p_docs').classList.contains('on'),
      egress_allowlist: document.getElementById('p_egress').classList.contains('on')
    }).then(function(res){
      if (!res.ok){ out.textContent = 'Could not save. Check the values (ceiling 0–1,000,000; cooling 0–60 days).'; return; }
      state.policy = res.j; out.textContent = 'Policy saved. It drives the gate immediately.';
      loadAudit();
    }).catch(function(){ out.textContent = 'Network error.'; });
  });

  // account
  api('GET', '/api/auth/me').then(function(res){
    if (res.ok) {
      document.getElementById('whoami').textContent = res.j.email;
      document.getElementById('acct_sub').textContent = res.j.email + ' · member since ' + res.j.created_at;
    }
  }).catch(function(){});
  document.getElementById('logoutbtn').addEventListener('click', function(){
    localStorage.removeItem('gc_token'); window.location.href = '/login';
  });
  document.getElementById('exportbtn').addEventListener('click', function(){
    api('GET', '/api/auth/export').then(function(res){
      if (!res.ok) return;
      var blob = new Blob([JSON.stringify(res.j, null, 2)], {type: 'application/json'});
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'gate-console-export.json';
      document.body.appendChild(a); a.click(); a.remove();
    }).catch(function(){});
  });
  document.getElementById('deletebtn').addEventListener('click', function(){
    if (!window.confirm('Delete your account permanently? Your queue, audit log and policy are removed. This cannot be undone.')) return;
    api('DELETE', '/api/auth/me').then(function(){
      localStorage.removeItem('gc_token'); window.location.href = '/login';
    }).catch(function(){});
  });

  // nav
  document.querySelectorAll('.navlink').forEach(function(n){
    n.addEventListener('click', function(){
      var t = n.dataset.go;
      if (t === 'audit') loadAudit();
      if (t === 'settings') loadPolicy();
      go(t);
    });
  });
  document.querySelectorAll('[data-go]').forEach(function(el){
    if (el.classList.contains('navlink')) return;
    el.addEventListener('click', function(){
      var t = el.dataset.go;
      if (t === 'audit') loadAudit();
      if (t === 'settings') loadPolicy();
      go(t);
    });
  });

  loadQueue(); loadAudit(); loadPolicy();
})();
