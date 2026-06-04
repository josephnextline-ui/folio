// Folio app — single-page client. Vanilla JS, no framework.

const Theme = (() => {
  const KEY = 'folio.theme'; // 'auto' | 'light' | 'dark'
  function get() { return localStorage.getItem(KEY) || 'auto'; }
  function apply(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    if (mode === 'auto') {
      const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-resolved', dark ? 'dark' : 'light');
    } else {
      document.documentElement.setAttribute('data-resolved', mode);
    }
  }
  function set(mode) { localStorage.setItem(KEY, mode); apply(mode); }
  function init() {
    apply(get());
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
      if (get() === 'auto') apply('auto');
    });
  }
  return { get, set, apply, init };
})();
Theme.init();

const Folio = (() => {
  const root = document.getElementById('app');

  // ---- state ----
  const state = {
    users: [],         // [{id, slot, display_name, accent_color}]
    me: null,
    key: null,         // CryptoKey (derived from passphrase)
    salt: null,
    tab: 'chat',
    selectedSlot: null,
    setup: { user1: { accent_color: '#b8a4d4' }, user2: { accent_color: '#f4b8b8' } },
    chat: { messages: [], lastId: 0, decrypted: new Map(), pollTimer: null },
    diary: { viewing: null, entries: [], decrypted: new Map() },
  };

  // ---- helpers ----
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      ...opts,
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    if (!res.ok) {
      let err;
      try { err = await res.json(); } catch { err = { error: res.statusText }; }
      const e = new Error(err.error || 'request_failed');
      e.status = res.status;
      throw e;
    }
    return res.json();
  }

  function mount(templateId) {
    const tpl = document.getElementById(templateId);
    root.innerHTML = '';
    root.appendChild(tpl.content.cloneNode(true));
  }

  function $(sel, ctx = root) { return ctx.querySelector(sel); }
  function $$(sel, ctx = root) { return Array.from(ctx.querySelectorAll(sel)); }

  function bindInputs(target) {
    $$('[data-bind]').forEach(el => {
      const path = el.dataset.bind.split('.');
      el.addEventListener('input', () => {
        let obj = target;
        for (let i = 0; i < path.length - 1; i++) {
          obj[path[i]] = obj[path[i]] || {};
          obj = obj[path[i]];
        }
        obj[path[path.length - 1]] = el.value;
      });
    });
  }

  function setError(msg) {
    const el = $('[data-error]');
    if (el) el.textContent = msg || '';
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
    })[c]);
  }

  // ---- routing / boot ----
  async function boot() {
    const status = await api('/api/setup-status');
    if (!status.initialized) return renderSetup();
    try {
      state.me = await api('/api/me');
      state.users = await api('/api/users');
      const bundle = await api('/api/e2e-bundle');
      state.salt = bundle.salt;
      state.check = bundle.check;
      const cached = sessionStorage.getItem('folio.pass');
      if (cached) {
        const key = await FolioCrypto.verifyAndDeriveKey(cached, state.salt, state.check);
        if (key) {
          state.key = key;
          return renderMain();
        }
        sessionStorage.removeItem('folio.pass');
      }
      renderUnlock();
    } catch (e) {
      if (e.status === 401) {
        state.users = await api('/api/users');
        renderLogin();
      } else throw e;
    }
  }

  // ---- setup ----
  function renderSetup() {
    mount('tpl-setup');
    bindInputs(state.setup);
    $$('.accent-row').forEach(row => {
      const which = row.dataset.accent;
      row.querySelectorAll('button').forEach(b => {
        b.addEventListener('click', () => {
          row.querySelectorAll('button').forEach(x => x.classList.remove('selected'));
          b.classList.add('selected');
          state.setup[which].accent_color = b.dataset.color;
        });
      });
      // default-select first
      row.querySelector('button').classList.add('selected');
    });
    $('[data-action="setup"]').addEventListener('click', doSetup);
  }

  async function doSetup() {
    const s = state.setup;
    setError('');
    if (!s.user1?.display_name || !s.user2?.display_name) return setError('Both names are required.');
    if (!s.user1?.password || !s.user2?.password) return setError('Both passwords are required.');
    if (s.user1.password.length < 4 || s.user2.password.length < 4) return setError('Passwords need at least 4 characters.');
    if (!s.passphrase || s.passphrase.length < 6) return setError('The shared phrase needs at least 6 characters.');
    if (s.passphrase !== s.passphrase_confirm) return setError("The two phrases don't match.");
    try {
      const { salt, check } = await FolioCrypto.buildVerifier(s.passphrase);
      await api('/api/setup', {
        method: 'POST',
        body: {
          user1: { display_name: s.user1.display_name, password: s.user1.password, accent_color: s.user1.accent_color },
          user2: { display_name: s.user2.display_name, password: s.user2.password, accent_color: s.user2.accent_color },
          e2e_salt: salt,
          e2e_check: check,
        }
      });
      sessionStorage.setItem('folio.pass', s.passphrase);
      await boot();
    } catch (e) {
      setError('Setup failed: ' + e.message);
    }
  }

  // ---- login ----
  function renderLogin() {
    mount('tpl-login');
    const cred = { name: '', password: '' };
    bindInputs(cred);
    state._loginCred = cred;
    $('[data-action="login"]').addEventListener('click', doLogin);
    ['[data-bind="name"]', '[data-bind="password"]'].forEach(sel => {
      $(sel).addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    });
  }

  async function doLogin() {
    setError('');
    const { name, password } = state._loginCred || {};
    if (!name || !password) return setError('Enter your name and password.');
    try {
      state.me = await api('/api/login', { method: 'POST', body: { name, password } });
      await boot();
    } catch (e) {
      setError(e.status === 401 ? "That name and password don't match." : 'Login failed: ' + e.message);
    }
  }

  // ---- unlock (shared phrase) ----
  function renderUnlock() {
    mount('tpl-unlock');
    const input = $('[data-bind="passphrase"]');
    $('[data-action="unlock"]').addEventListener('click', doUnlock);
    $('[data-action="logout"]').addEventListener('click', doLogout);
    input.addEventListener('keydown', e => { if (e.key === 'Enter') doUnlock(); });
  }

  async function doUnlock() {
    setError('');
    const phrase = $('[data-bind="passphrase"]').value;
    if (!phrase) return setError('Enter the shared phrase.');
    const key = await FolioCrypto.verifyAndDeriveKey(phrase, state.salt, state.check);
    if (!key) return setError("That phrase doesn't unlock this folio.");
    state.key = key;
    sessionStorage.setItem('folio.pass', phrase);
    renderMain();
  }

  async function doLogout() {
    try { await api('/api/logout', { method: 'POST' }); } catch {}
    sessionStorage.removeItem('folio.pass');
    state.me = null;
    state.key = null;
    boot();
  }

  // ---- main shell ----
  function renderMain() {
    mount('tpl-main');
    const partner = state.users.find(u => u.id !== state.me.id);
    document.documentElement.style.setProperty('--me-accent', state.me.accent_color);
    document.documentElement.style.setProperty('--partner-accent', partner?.accent_color || '#f4b8b8');

    // paired-days footer
    const earliest = state.users.reduce((min, u) => {
      const t = new Date(u.created_at).getTime();
      return (!min || t < min) ? t : min;
    }, 0);
    const days = earliest ? Math.max(1, Math.floor((Date.now() - earliest) / 86400000)) : 0;
    const pairLabel = state.users.map(u => escapeHtml(u.display_name)).join(' & ');

    $('[data-whoami]').innerHTML = `
      <div class="pair-card">
        <div class="pair-avatars">
          ${state.users.map(u => `<span class="pair-dot" style="background:${u.accent_color}">${escapeHtml((u.display_name[0]||'?').toUpperCase())}</span>`).join('')}
        </div>
        <div class="pair-meta">
          <div class="pair-names">${pairLabel}</div>
          <div class="pair-sub">paired ${days} day${days === 1 ? '' : 's'}</div>
        </div>
      </div>
      <button class="theme-toggle" data-theme-toggle title="Toggle theme">
        <span class="th-icon">◐</span><span class="th-label">${Theme.get()}</span>
      </button>
    `;

    $('[data-theme-toggle]').addEventListener('click', () => {
      const order = ['auto', 'light', 'dark'];
      const next = order[(order.indexOf(Theme.get()) + 1) % order.length];
      Theme.set(next);
      $('[data-theme-toggle] .th-label').textContent = next;
    });

    $$('.nav-item').forEach(b => {
      b.addEventListener('click', () => switchTab(b.dataset.tab));
    });
    switchTab('chat');
  }

  function switchTab(tab) {
    state.tab = tab;
    $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    if (state.chat.pollTimer) { clearInterval(state.chat.pollTimer); state.chat.pollTimer = null; }
    const content = $('[data-content]');
    content.innerHTML = '';
    if (tab === 'chat') Chat.render(content);
    else if (tab === 'diary') Diary.render(content);
    else if (tab === 'memory') MemoryLane.render(content);
    else if (tab === 'settings') Settings.render(content);
  }

  // expose
  return {
    boot, state, api, $, $$, escapeHtml,
    switchTab, doLogout,
    setError,
  };
})();

// ===================== CHAT =====================
const Chat = (() => {
  function fmtTime(d) {
    const date = new Date(d);
    const today = new Date();
    const sameDay = date.toDateString() === today.toDateString();
    if (sameDay) return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) +
           ' · ' + date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  }

  async function decryptAll() {
    const s = Folio.state;
    for (const m of s.chat.messages) {
      if (!s.chat.decrypted.has(m.id)) {
        try {
          const pt = await FolioCrypto.decrypt(s.key, m.ciphertext, m.iv);
          s.chat.decrypted.set(m.id, pt);
        } catch {
          s.chat.decrypted.set(m.id, '[unable to decrypt]');
        }
      }
    }
  }

  async function render(container) {
    container.innerHTML = `
      <header class="content-header">
        <h2 class="page-title">Chat</h2>
        <p class="page-sub">Just the two of you. Every message is encrypted on your device.</p>
      </header>
      <div class="chat-thread" id="chat-thread"></div>
      <form class="composer" id="composer">
        <textarea id="composer-input" rows="1" placeholder="Write something tender…" autofocus></textarea>
        <button type="submit" class="send-btn" aria-label="Send">→</button>
      </form>
    `;
    const s = Folio.state;
    s.chat.messages = [];
    s.chat.lastId = 0;
    s.chat.decrypted = new Map();
    await refresh();
    s.chat.pollTimer = setInterval(refresh, 2500);

    const form = document.getElementById('composer');
    const input = document.getElementById('composer-input');
    input.addEventListener('input', () => {
      input.style.height = 'auto';
      input.style.height = Math.min(input.scrollHeight, 180) + 'px';
    });
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); }
    });
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const text = input.value.trim();
      if (!text) return;
      input.value = '';
      input.style.height = 'auto';
      const enc = await FolioCrypto.encrypt(s.key, text);
      try {
        const msg = await Folio.api('/api/messages', { method: 'POST', body: enc });
        s.chat.decrypted.set(msg.id, text);
        appendMessage(msg);
        s.chat.lastId = Math.max(s.chat.lastId, msg.id);
      } catch (err) {
        console.error(err);
      }
    });
  }

  async function refresh() {
    const s = Folio.state;
    try {
      const rows = await Folio.api(`/api/messages?since=${s.chat.lastId}`);
      if (!rows.length) return;
      for (const m of rows) {
        s.chat.messages.push(m);
        s.chat.lastId = Math.max(s.chat.lastId, m.id);
      }
      await decryptAll();
      const thread = document.getElementById('chat-thread');
      if (!thread) return;
      for (const m of rows) appendMessage(m);
    } catch (err) {
      console.warn('poll fail', err);
    }
  }

  function appendMessage(m) {
    const thread = document.getElementById('chat-thread');
    if (!thread) return;
    const s = Folio.state;
    // avoid double append
    if (thread.querySelector(`[data-mid="${m.id}"]`)) return;
    const mine = m.author_id === s.me.id;
    const author = s.users.find(u => u.id === m.author_id);
    const text = s.chat.decrypted.get(m.id) || '…';
    const row = document.createElement('div');
    row.className = 'msg-row' + (mine ? ' me' : ' them');
    row.dataset.mid = m.id;
    row.innerHTML = `
      <div class="msg-bubble" style="--bubble:${author?.accent_color || '#ddd'}">
        <div class="msg-text"></div>
        <div class="msg-meta">
          <span class="msg-time">${fmtTime(m.created_at)}</span>
          <button class="pin-btn ${m.pinned ? 'pinned' : ''}" title="${m.pinned ? 'Unpin' : 'Pin to Memory Lane'}">${m.pinned ? '✦ pinned' : '✧ pin'}</button>
        </div>
      </div>
    `;
    row.querySelector('.msg-text').textContent = text;
    const pinBtn = row.querySelector('.pin-btn');
    pinBtn.addEventListener('click', async () => {
      const isPinned = pinBtn.classList.contains('pinned');
      try {
        if (isPinned) {
          await Folio.api(`/api/messages/${m.id}/pin`, { method: 'DELETE' });
          pinBtn.classList.remove('pinned');
          pinBtn.textContent = '✧ pin';
          m.pinned = 0;
        } else {
          await Folio.api(`/api/messages/${m.id}/pin`, { method: 'POST' });
          pinBtn.classList.add('pinned');
          pinBtn.textContent = '✦ pinned';
          m.pinned = 1;
          pinBtn.animate(
            [{ transform: 'scale(1)' }, { transform: 'scale(1.3)' }, { transform: 'scale(1)' }],
            { duration: 350, easing: 'ease-out' }
          );
        }
      } catch (e) { console.error(e); }
    });
    thread.appendChild(row);
    thread.scrollTop = thread.scrollHeight;
  }

  return { render };
})();

// ===================== DIARY =====================
const Diary = (() => {
  async function render(container) {
    const s = Folio.state;
    if (s.diary.viewing == null) s.diary.viewing = s.me.id;
    container.innerHTML = `
      <header class="content-header">
        <div class="kicker-row">
          <span class="kicker">${new Date().toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' }).toUpperCase()}</span>
        </div>
        <h2 class="page-title">This week, <em>between us.</em></h2>
        <div class="pill-tabs" id="diary-tabs"></div>
      </header>
      <div class="diary-body">
        <section class="diary-write" id="diary-write" hidden>
          <p class="kicker small">Write & seal</p>
          <textarea id="diary-text" placeholder="A small thing I noticed about you…" rows="6"></textarea>
          <div class="seal-row">
            <span class="kicker small">Seal this capsule</span>
            <div class="seal-options" id="seal-options">
              <button type="button" data-seal="now" class="seal-pill active">Today</button>
              <button type="button" data-seal="3d" class="seal-pill">3 days</button>
              <button type="button" data-seal="1w" class="seal-pill">1 week</button>
              <button type="button" data-seal="custom" class="seal-pill">Pick a date</button>
            </div>
            <input type="datetime-local" id="lock-when" class="hidden-when" />
          </div>
          <div class="diary-actions">
            <button class="btn-primary small dark" id="save-entry">Seal entry</button>
          </div>
        </section>
        <section class="diary-feed" id="diary-feed"></section>
      </div>
    `;
    renderTabs();
    await load();

    // seal pill behavior
    const opts = document.getElementById('seal-options');
    const when = document.getElementById('lock-when');
    opts.addEventListener('click', e => {
      const btn = e.target.closest('.seal-pill'); if (!btn) return;
      opts.querySelectorAll('.seal-pill').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const kind = btn.dataset.seal;
      if (kind === 'custom') {
        when.classList.add('visible');
        when.focus();
        if (!when.value) {
          const d = new Date(Date.now() + 24 * 3600 * 1000);
          when.value = d.toISOString().slice(0, 16);
        }
      } else {
        when.classList.remove('visible');
      }
    });
    document.getElementById('save-entry').addEventListener('click', saveEntry);
  }

  function renderTabs() {
    const s = Folio.state;
    const partner = s.users.find(u => u.id !== s.me.id);
    const tabs = document.getElementById('diary-tabs');
    tabs.innerHTML = '';
    const items = [
      { key: s.me.id, label: 'Mine' },
      { key: 'together', label: 'Together' },
      { key: partner?.id, label: 'Theirs' },
    ];
    items.forEach(it => {
      if (it.key == null) return;
      const btn = document.createElement('button');
      btn.className = 'pill-tab' + (s.diary.viewing === it.key ? ' active' : '');
      btn.textContent = it.label;
      btn.addEventListener('click', () => {
        s.diary.viewing = it.key;
        renderTabs();
        load();
      });
      tabs.appendChild(btn);
    });
    const writeSection = document.getElementById('diary-write');
    if (writeSection) writeSection.hidden = s.diary.viewing === partner?.id; // hide composer when viewing partner only
  }

  async function load() {
    const s = Folio.state;
    const feed = document.getElementById('diary-feed');
    feed.innerHTML = '<div class="muted">Loading…</div>';
    let entries;
    if (s.diary.viewing === 'together') {
      entries = await Folio.api('/api/diary/all');
    } else {
      entries = await Folio.api(`/api/diary?author_id=${s.diary.viewing}`);
    }
    s.diary.entries = entries;
    feed.innerHTML = '';
    if (!entries.length) {
      feed.innerHTML = `<div class="empty-state">${s.diary.viewing === s.me.id ? 'Nothing here yet — write your first entry.' : (s.diary.viewing === 'together' ? "Nothing written yet from either of you." : 'No entries yet from your love.')}</div>`;
      return;
    }
    const grid = document.createElement('div');
    grid.className = 'entry-grid';
    feed.appendChild(grid);
    for (const e of entries) grid.appendChild(await renderEntry(e));
  }

  async function renderEntry(e) {
    const s = Folio.state;
    const author = s.users.find(u => u.id === e.author_id);
    const card = document.createElement('article');
    card.className = 'entry-card';
    card.style.setProperty('--accent', author?.accent_color || '#ddd');
    const date = new Date(e.created_at);
    const dayShort = date.toLocaleDateString([], { weekday: 'short' }).toUpperCase();
    const isMine = author?.id === s.me.id;
    const stateLabel = e.locked ? 'SEALED' : (e.unlock_at && new Date(e.unlock_at) > new Date() ? 'WAITING ON YOU' : 'OPEN');

    if (e.locked) {
      const unlockDate = new Date(e.unlock_at);
      card.classList.add('locked');
      card.innerHTML = `
        <header class="entry-head">
          <span class="meta-trail">${dayShort} · <span class="meta-author">${Folio.escapeHtml(author.display_name)}</span></span>
          <span class="meta-state">SEALED</span>
        </header>
        <h3 class="entry-title">Something almost told you…</h3>
        <p class="entry-preview"><span class="hand">"sealed"</span> — opens ${unlockDate.toLocaleDateString([], { month: 'short', day: 'numeric' })}</p>
        <p class="entry-countdown countdown" data-unlock="${e.unlock_at}"></p>
      `;
      updateCountdown(card.querySelector('.countdown'));
      return card;
    }

    const text = await (async () => {
      try { return await FolioCrypto.decrypt(s.key, e.ciphertext, e.iv); }
      catch { return '[unable to decrypt]'; }
    })();
    // first line as title-ish; rest as body
    const firstLine = text.split('\n')[0].slice(0, 80);
    const restRaw = text.length > firstLine.length ? text.slice(firstLine.length).trim() : '';
    const showRest = restRaw.length > 0;

    const lockNoteHtml = e.unlock_at && new Date(e.unlock_at) > new Date()
      ? `<p class="entry-countdown muted">sealed for partner until ${new Date(e.unlock_at).toLocaleString()}</p>` : '';
    const mineActions = isMine
      ? `<button class="entry-delete" data-id="${e.id}" title="Delete">×</button>` : '';

    card.innerHTML = `
      <header class="entry-head">
        <span class="meta-trail">${dayShort} · <span class="meta-author">${Folio.escapeHtml(author.display_name)}${isMine ? ' (mine)' : ''}</span></span>
        <span class="meta-state">${stateLabel}</span>
        ${mineActions}
      </header>
      <h3 class="entry-title"></h3>
      ${showRest ? '<div class="entry-body"></div>' : ''}
      ${lockNoteHtml}
    `;
    card.querySelector('.entry-title').textContent = firstLine || '·';
    if (showRest) card.querySelector('.entry-body').textContent = restRaw;

    const del = card.querySelector('.entry-delete');
    if (del) del.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      if (!confirm('Delete this entry?')) return;
      await Folio.api(`/api/diary/${e.id}`, { method: 'DELETE' });
      load();
    });

    requestAnimationFrame(() => card.classList.add('revealed'));
    return card;
  }

  function updateCountdown(el) {
    if (!el) return;
    const target = new Date(el.dataset.unlock).getTime();
    const tick = () => {
      const ms = target - Date.now();
      if (ms <= 0) { el.textContent = 'opening…'; setTimeout(() => Folio.switchTab('diary'), 800); return; }
      const s = Math.floor(ms / 1000);
      const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
      el.textContent = `opens in ${d ? d + 'd ' : ''}${h}h ${m}m`;
    };
    tick();
    const id = setInterval(() => { if (!document.body.contains(el)) clearInterval(id); else tick(); }, 30000);
  }

  async function saveEntry() {
    const s = Folio.state;
    const ta = document.getElementById('diary-text');
    const text = ta.value.trim();
    if (!text) return;
    const activePill = document.querySelector('#seal-options .seal-pill.active');
    const kind = activePill?.dataset.seal || 'now';
    let unlockISO = null;
    const now = Date.now();
    if (kind === '3d') unlockISO = new Date(now + 3 * 86400000).toISOString();
    else if (kind === '1w') unlockISO = new Date(now + 7 * 86400000).toISOString();
    else if (kind === 'custom') {
      const w = document.getElementById('lock-when').value;
      if (w) unlockISO = new Date(w).toISOString();
    }
    const enc = await FolioCrypto.encrypt(s.key, text);
    const body = { ...enc };
    if (unlockISO) body.unlock_at = unlockISO;
    await Folio.api('/api/diary', { method: 'POST', body });
    ta.value = '';
    // reset pills to today
    document.querySelectorAll('#seal-options .seal-pill').forEach(b => b.classList.toggle('active', b.dataset.seal === 'now'));
    document.getElementById('lock-when').classList.remove('visible');
    load();
  }

  return { render };
})();

// ===================== MEMORY LANE =====================
const MemoryLane = (() => {
  async function render(container) {
    const s = Folio.state;
    container.innerHTML = `
      <header class="content-header">
        <h2 class="page-title">Memory Lane</h2>
        <p class="page-sub">Every pinned message blooms on a tree. One tree per month.</p>
      </header>
      <div class="memory-wrap" id="memory-wrap"><div class="muted">Gathering memories…</div></div>
    `;
    const pinned = await Folio.api('/api/pinned');
    const decrypted = [];
    for (const m of pinned) {
      let text;
      try { text = await FolioCrypto.decrypt(s.key, m.ciphertext, m.iv); }
      catch { text = '[unable to decrypt]'; }
      decrypted.push({ ...m, text });
    }
    const grouped = groupByMonth(decrypted);
    const wrap = document.getElementById('memory-wrap');
    if (!grouped.length) {
      wrap.innerHTML = `<div class="empty-state">No memories pinned yet. Pin a chat message and watch a tree grow.</div>`;
      return;
    }
    wrap.innerHTML = '';
    for (const g of grouped) wrap.appendChild(renderTree(g));
  }

  function groupByMonth(msgs) {
    const map = new Map();
    for (const m of msgs) {
      const d = new Date(m.pinned_at || m.created_at);
      const key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
      const label = d.toLocaleDateString([], { month: 'long', year: 'numeric' });
      if (!map.has(key)) map.set(key, { key, label, items: [] });
      map.get(key).items.push(m);
    }
    return Array.from(map.values()).sort((a, b) => b.key.localeCompare(a.key));
  }

  function renderTree(group) {
    const s = Folio.state;
    const card = document.createElement('section');
    card.className = 'tree-card';
    const W = 520, H = 460;
    // distribute leaves along branches
    const leaves = group.items.map((m, i) => {
      const author = s.users.find(u => u.id === m.author_id);
      const angle = (i / Math.max(group.items.length, 1)) * Math.PI * 2;
      const radius = 110 + ((i % 3) * 24);
      const cx = W / 2 + Math.cos(angle - Math.PI / 2) * radius;
      const cy = H / 2 - 30 + Math.sin(angle - Math.PI / 2) * radius * 0.85;
      return { m, author, cx, cy, angle };
    });

    const trunk = `
      <path d="M${W/2} ${H-20} C${W/2-10} ${H-160}, ${W/2+10} ${H-220}, ${W/2} ${H-260}" stroke="#7a6a58" stroke-width="14" fill="none" stroke-linecap="round"/>
      <path d="M${W/2} ${H-180} C${W/2-60} ${H-200}, ${W/2-110} ${H-230}, ${W/2-150} ${H-220}" stroke="#7a6a58" stroke-width="7" fill="none" stroke-linecap="round"/>
      <path d="M${W/2} ${H-200} C${W/2+60} ${H-220}, ${W/2+110} ${H-250}, ${W/2+150} ${H-240}" stroke="#7a6a58" stroke-width="7" fill="none" stroke-linecap="round"/>
      <path d="M${W/2} ${H-240} C${W/2-30} ${H-260}, ${W/2-70} ${H-300}, ${W/2-90} ${H-330}" stroke="#7a6a58" stroke-width="5" fill="none" stroke-linecap="round"/>
      <path d="M${W/2} ${H-250} C${W/2+30} ${H-280}, ${W/2+70} ${H-310}, ${W/2+90} ${H-340}" stroke="#7a6a58" stroke-width="5" fill="none" stroke-linecap="round"/>
      <ellipse cx="${W/2}" cy="${H-10}" rx="160" ry="10" fill="#e8dfd0" opacity="0.6"/>
    `;

    const cloud = `
      <g opacity="0.55">
        <circle cx="${W/2 - 40}" cy="${H-260}" r="90" fill="url(#leafGrad)"/>
        <circle cx="${W/2 + 50}" cy="${H-280}" r="80" fill="url(#leafGrad)"/>
        <circle cx="${W/2}" cy="${H-320}" r="70" fill="url(#leafGrad)"/>
        <circle cx="${W/2 - 90}" cy="${H-220}" r="55" fill="url(#leafGrad)"/>
        <circle cx="${W/2 + 100}" cy="${H-230}" r="55" fill="url(#leafGrad)"/>
      </g>
    `;

    const blooms = leaves.map((l, i) => `
      <g class="bloom" data-idx="${i}" transform="translate(${l.cx} ${l.cy})">
        <circle r="11" fill="${l.author?.accent_color || '#f4b8b8'}" opacity="0.35"/>
        <circle r="7" fill="${l.author?.accent_color || '#f4b8b8'}"/>
        <circle r="2.5" fill="#fff" opacity="0.85"/>
      </g>
    `).join('');

    card.innerHTML = `
      <h3 class="tree-title">${Folio.escapeHtml(group.label)}</h3>
      <div class="tree-stage">
        <svg viewBox="0 0 ${W} ${H}" class="tree-svg">
          <defs>
            <radialGradient id="leafGrad" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="#dbe9c8"/>
              <stop offset="100%" stop-color="#a8c890"/>
            </radialGradient>
          </defs>
          ${cloud}
          ${trunk}
          ${blooms}
        </svg>
        <div class="tree-tip" id="tip-${group.key}" hidden></div>
      </div>
      <div class="tree-list"></div>
    `;

    const tip = card.querySelector('.tree-tip');
    card.querySelectorAll('.bloom').forEach(node => {
      const idx = parseInt(node.dataset.idx, 10);
      const l = leaves[idx];
      node.addEventListener('mouseenter', e => showTip(tip, l, node));
      node.addEventListener('click', e => showTip(tip, l, node, true));
      node.addEventListener('mouseleave', () => { if (!tip.dataset.sticky) tip.hidden = true; });
    });
    card.addEventListener('click', e => {
      if (!e.target.closest('.bloom') && !e.target.closest('.tree-tip')) {
        tip.hidden = true; delete tip.dataset.sticky;
      }
    });

    const list = card.querySelector('.tree-list');
    leaves.sort((a, b) => new Date(b.m.pinned_at || b.m.created_at) - new Date(a.m.pinned_at || a.m.created_at));
    leaves.forEach(l => {
      const d = new Date(l.m.pinned_at || l.m.created_at);
      const row = document.createElement('div');
      row.className = 'memory-row';
      row.style.setProperty('--accent', l.author?.accent_color || '#ddd');
      row.innerHTML = `
        <div class="memory-date">${d.toLocaleDateString([], { month: 'short', day: 'numeric' })}</div>
        <div class="memory-card">
          <div class="memory-author"><span class="dot" style="background:${l.author?.accent_color}"></span>${Folio.escapeHtml(l.author?.display_name || '?')}</div>
          <div class="memory-text"></div>
        </div>
      `;
      row.querySelector('.memory-text').textContent = l.text;
      list.appendChild(row);
    });

    return card;
  }

  function showTip(tip, leaf, node, sticky) {
    const stageRect = tip.parentElement.getBoundingClientRect();
    const r = node.getBoundingClientRect();
    const d = new Date(leaf.m.pinned_at || leaf.m.created_at);
    tip.innerHTML = `
      <div class="tip-author"><span class="dot" style="background:${leaf.author?.accent_color}"></span>${Folio.escapeHtml(leaf.author?.display_name || '?')}</div>
      <div class="tip-date">${d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })}</div>
      <div class="tip-text"></div>
    `;
    tip.querySelector('.tip-text').textContent = leaf.text;
    tip.hidden = false;
    if (sticky) tip.dataset.sticky = '1';
    // position tip near the bloom
    const left = Math.max(8, Math.min(stageRect.width - 240, r.left - stageRect.left - 110));
    const top = Math.max(8, r.top - stageRect.top - tip.offsetHeight - 12);
    tip.style.left = left + 'px';
    tip.style.top = (top < 0 ? r.bottom - stageRect.top + 12 : top) + 'px';
  }

  return { render };
})();

// ===================== SETTINGS =====================
const Settings = (() => {
  async function render(container) {
    const s = Folio.state;
    container.innerHTML = `
      <header class="content-header">
        <h2 class="page-title">Settings</h2>
        <p class="page-sub">Tune your name, accent, and password.</p>
      </header>
      <section class="settings-card">
        <h3>Your profile</h3>
        <label class="field-label">Display name</label>
        <input class="field" id="set-name" value="${Folio.escapeHtml(s.me.display_name)}" />
        <label class="field-label">Accent color</label>
        <div class="accent-row" id="set-accent">
          ${['#b8a4d4','#9bb8e0','#a8d4c4','#d4b8a4','#f4b8b8','#f4d4a8','#e8b4d4','#b4d4a8']
            .map(c => `<button type="button" data-color="${c}" style="background:${c}" class="${c === s.me.accent_color ? 'selected':''}"></button>`).join('')}
        </div>
        <button class="btn-primary small" id="save-profile">Save profile</button>
        <div class="muted" id="profile-msg"></div>
      </section>
      <section class="settings-card">
        <h3>Change password</h3>
        <input class="field" type="password" placeholder="Current password" id="cur-pw" />
        <input class="field" type="password" placeholder="New password" id="new-pw" />
        <button class="btn-primary small" id="save-pw">Update password</button>
        <div class="muted" id="pw-msg"></div>
      </section>
      <section class="settings-card">
        <h3>Appearance</h3>
        <div class="seal-options theme-row" id="theme-row">
          <button type="button" data-theme="auto" class="seal-pill">Auto</button>
          <button type="button" data-theme="light" class="seal-pill">Light</button>
          <button type="button" data-theme="dark" class="seal-pill">Dark</button>
        </div>
      </section>
      <section class="settings-card subtle">
        <h3>Session</h3>
        <button class="btn-link" id="lock-now">Lock (forget shared phrase here)</button>
        <button class="btn-link danger" id="signout">Sign out</button>
      </section>
    `;

    let chosenColor = s.me.accent_color;
    document.querySelectorAll('#set-accent button').forEach(b => {
      b.addEventListener('click', () => {
        document.querySelectorAll('#set-accent button').forEach(x => x.classList.remove('selected'));
        b.classList.add('selected');
        chosenColor = b.dataset.color;
      });
    });

    document.getElementById('save-profile').addEventListener('click', async () => {
      const name = document.getElementById('set-name').value.trim();
      try {
        await Folio.api('/api/me', { method: 'PATCH', body: { display_name: name, accent_color: chosenColor } });
        s.me.display_name = name;
        s.me.accent_color = chosenColor;
        s.users = await Folio.api('/api/users');
        document.getElementById('profile-msg').textContent = 'Saved.';
        document.documentElement.style.setProperty('--me-accent', chosenColor);
        document.querySelector('[data-whoami]').innerHTML = `<div class="me-chip"><span class="me-dot" style="background:${chosenColor}"></span><span>${Folio.escapeHtml(name)}</span></div>`;
      } catch (e) {
        document.getElementById('profile-msg').textContent = 'Save failed: ' + e.message;
      }
    });

    document.getElementById('save-pw').addEventListener('click', async () => {
      const current = document.getElementById('cur-pw').value;
      const next = document.getElementById('new-pw').value;
      if (!current || !next) return;
      try {
        await Folio.api('/api/me', { method: 'PATCH', body: { current_password: current, password: next } });
        document.getElementById('pw-msg').textContent = 'Password updated.';
        document.getElementById('cur-pw').value = '';
        document.getElementById('new-pw').value = '';
      } catch (e) {
        document.getElementById('pw-msg').textContent = e.status === 401 ? 'Current password is wrong.' : 'Update failed.';
      }
    });

    document.getElementById('lock-now').addEventListener('click', () => {
      sessionStorage.removeItem('folio.pass');
      Folio.state.key = null;
      location.reload();
    });
    document.getElementById('signout').addEventListener('click', Folio.doLogout);

    // theme pills
    const themeRow = document.getElementById('theme-row');
    const sync = () => themeRow.querySelectorAll('.seal-pill').forEach(b => b.classList.toggle('active', b.dataset.theme === Theme.get()));
    sync();
    themeRow.addEventListener('click', e => {
      const btn = e.target.closest('.seal-pill'); if (!btn) return;
      Theme.set(btn.dataset.theme);
      sync();
      const lbl = document.querySelector('[data-theme-toggle] .th-label');
      if (lbl) lbl.textContent = Theme.get();
    });
  }

  return { render };
})();

window.addEventListener('DOMContentLoaded', () => Folio.boot());
