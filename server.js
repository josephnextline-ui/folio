// Folio — server (Turso / libSQL backend)
// Server only stores ciphertext + metadata. Encryption keys live only in the
// users' browsers (derived via PBKDF2 from their shared passphrase).

const express = require('express');
const { createClient } = require('@libsql/client/web');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');

const PORT = process.env.PORT || 3000;

// Turso credentials — Mule Pages has no env-var injection, so they live here.
const TURSO_URL = 'libsql://folio-xenozbeast.aws-ap-south-1.turso.io';
const TURSO_TOKEN = 'eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODA1MTQyMjAsImlkIjoiMDE5ZThlZWEtYmYwMS03YzFmLTg5ZjctMTRmMDQ0YmRhMDc1IiwicmlkIjoiN2I1ZmNiYTgtZDFhNi00OGY3LTk2MGMtY2U0Zjg0NzRjMjA0In0.pUJhIp7-Qf_XR7V0zmkzMI0RqH0741-Z91-hXX5Mh59sHoliI0XsxQq0cs7ze_beC41IKs5V_CbtosYRYhF6Dw';

const db = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

// --- thin query wrappers ---
async function all(sql, args = []) {
  const r = await db.execute({ sql, args: args.map(a => a === undefined ? null : a) });
  return r.rows;
}
async function get(sql, args = []) {
  const rows = await all(sql, args);
  return rows[0] || null;
}
async function run(sql, args = []) {
  const r = await db.execute({ sql, args: args.map(a => a === undefined ? null : a) });
  return {
    insertId: r.lastInsertRowid != null ? Number(r.lastInsertRowid) : null,
    changes: r.rowsAffected
  };
}

// SQLite returns "YYYY-MM-DD HH:MM:SS" UTC — normalize to ISO so browsers parse correctly.
function isoStamp(s) {
  if (!s) return s;
  if (typeof s !== 'string') return s;
  if (s.endsWith('Z') || s.includes('T')) return s;
  return s.replace(' ', 'T') + 'Z';
}
function normalizeRow(row, keys) {
  const out = { ...row };
  for (const k of keys) if (k in out) out[k] = isoStamp(out[k]);
  return out;
}

const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- schema ----------
async function migrate() {
  await db.execute(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slot INTEGER UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    accent_color TEXT DEFAULT '#b8a4d4',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await db.execute(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL
  )`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    pinned INTEGER DEFAULT 0,
    pinned_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_messages_pinned ON messages(pinned)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS diary_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL,
    unlock_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_diary_author ON diary_entries(author_id)`);
  await db.execute(`CREATE INDEX IF NOT EXISTS idx_diary_created ON diary_entries(created_at)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
  )`);
}

// ---------- helpers ----------
function newToken() { return crypto.randomBytes(32).toString('hex'); }

async function getMeta(key) {
  const r = await get('SELECT v FROM meta WHERE k = ?', [key]);
  return r ? r.v : null;
}
async function setMeta(key, value) {
  await run(
    'INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v',
    [key, value]
  );
}

async function currentUser(req) {
  const token = req.cookies?.sid;
  if (!token) return null;
  const row = await get(
    `SELECT u.id, u.slot, u.username, u.display_name, u.accent_color
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`,
    [token]
  );
  return row || null;
}

function requireAuth(handler) {
  return async (req, res, next) => {
    try {
      const u = await currentUser(req);
      if (!u) return res.status(401).json({ error: 'unauthorized' });
      req.user = u;
      await handler(req, res, next);
    } catch (e) { next(e); }
  };
}

// ---------- setup ----------
app.get('/api/setup-status', async (req, res, next) => {
  try {
    const r = await get('SELECT COUNT(*) AS c FROM users');
    const hasKey = !!(await getMeta('e2e_check'));
    res.json({ initialized: r.c >= 2 && hasKey });
  } catch (e) { next(e); }
});

app.post('/api/setup', async (req, res, next) => {
  try {
    const r = await get('SELECT COUNT(*) AS c FROM users');
    if (r.c >= 2) return res.status(400).json({ error: 'already_initialized' });
    const { user1, user2, e2e_salt, e2e_check } = req.body || {};
    if (!user1 || !user2 || !e2e_salt || !e2e_check) {
      return res.status(400).json({ error: 'missing_fields' });
    }
    const h1 = await bcrypt.hash(user1.password, 10);
    const h2 = await bcrypt.hash(user2.password, 10);
    await run(
      'INSERT INTO users (slot, username, display_name, password_hash, accent_color) VALUES (?,?,?,?,?)',
      [1, 'one', user1.display_name || 'You', h1, user1.accent_color || '#b8a4d4']
    );
    await run(
      'INSERT INTO users (slot, username, display_name, password_hash, accent_color) VALUES (?,?,?,?,?)',
      [2, 'two', user2.display_name || 'Love', h2, user2.accent_color || '#f4b8b8']
    );
    await setMeta('e2e_salt', e2e_salt);
    await setMeta('e2e_check', JSON.stringify(e2e_check));
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.get('/api/users', async (req, res, next) => {
  try {
    const rows = await all('SELECT id, slot, display_name, accent_color, created_at FROM users ORDER BY slot ASC');
    res.json(rows.map(r => normalizeRow(r, ['created_at'])));
  } catch (e) { next(e); }
});

app.get('/api/e2e-bundle', async (req, res, next) => {
  try {
    const salt = await getMeta('e2e_salt');
    const check = await getMeta('e2e_check');
    if (!salt || !check) return res.status(404).json({ error: 'not_setup' });
    res.json({ salt, check: JSON.parse(check) });
  } catch (e) { next(e); }
});

// ---------- auth ----------
app.post('/api/login', async (req, res, next) => {
  try {
    const { name, password } = req.body || {};
    if (!name || !password) return res.status(400).json({ error: 'missing_fields' });
    const u = await get(
      'SELECT * FROM users WHERE LOWER(display_name) = LOWER(?) LIMIT 1',
      [String(name).trim()]
    );
    if (!u) {
      // small delay to slow brute force
      await new Promise(r => setTimeout(r, 250));
      return res.status(401).json({ error: 'invalid' });
    }
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid' });
    const token = newToken();
    await run(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+90 days'))",
      [token, u.id]
    );
    res.cookie('sid', token, { httpOnly: true, sameSite: 'lax', maxAge: 90 * 24 * 3600 * 1000 });
    res.json({ id: u.id, slot: u.slot, display_name: u.display_name, accent_color: u.accent_color });
  } catch (e) { next(e); }
});

app.post('/api/logout', requireAuth(async (req, res) => {
  await run('DELETE FROM sessions WHERE token = ?', [req.cookies.sid]);
  res.clearCookie('sid');
  res.json({ ok: true });
}));

app.get('/api/me', requireAuth(async (req, res) => res.json(req.user)));

app.patch('/api/me', requireAuth(async (req, res) => {
  const { display_name, accent_color, password, current_password } = req.body || {};
  if (display_name) {
    await run('UPDATE users SET display_name = ? WHERE id = ?', [String(display_name).slice(0, 64), req.user.id]);
  }
  if (accent_color) {
    await run('UPDATE users SET accent_color = ? WHERE id = ?', [String(accent_color).slice(0, 16), req.user.id]);
  }
  if (password) {
    if (!current_password) return res.status(400).json({ error: 'current_password_required' });
    const u = await get('SELECT password_hash FROM users WHERE id = ?', [req.user.id]);
    const ok = await bcrypt.compare(current_password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_current_password' });
    const h = await bcrypt.hash(password, 10);
    await run('UPDATE users SET password_hash = ? WHERE id = ?', [h, req.user.id]);
  }
  res.json({ ok: true });
}));

// ---------- messages ----------
app.get('/api/messages', requireAuth(async (req, res) => {
  const since = parseInt(req.query.since || '0', 10);
  const rows = await all(
    `SELECT id, author_id, ciphertext, iv, pinned, pinned_at, created_at
     FROM messages WHERE id > ? ORDER BY id ASC LIMIT 500`,
    [since]
  );
  res.json(rows.map(r => normalizeRow(r, ['created_at', 'pinned_at'])));
}));

app.post('/api/messages', requireAuth(async (req, res) => {
  const { ciphertext, iv } = req.body || {};
  if (!ciphertext || !iv) return res.status(400).json({ error: 'missing_fields' });
  const r = await run(
    'INSERT INTO messages (author_id, ciphertext, iv) VALUES (?, ?, ?)',
    [req.user.id, ciphertext, iv]
  );
  const row = await get(
    'SELECT id, author_id, ciphertext, iv, pinned, pinned_at, created_at FROM messages WHERE id = ?',
    [r.insertId]
  );
  res.json(normalizeRow(row, ['created_at', 'pinned_at']));
}));

app.post('/api/messages/:id/pin', requireAuth(async (req, res) => {
  await run("UPDATE messages SET pinned = 1, pinned_at = datetime('now') WHERE id = ?", [req.params.id]);
  res.json({ ok: true });
}));

app.delete('/api/messages/:id/pin', requireAuth(async (req, res) => {
  await run('UPDATE messages SET pinned = 0, pinned_at = NULL WHERE id = ?', [req.params.id]);
  res.json({ ok: true });
}));

app.get('/api/pinned', requireAuth(async (req, res) => {
  const rows = await all(
    `SELECT id, author_id, ciphertext, iv, pinned_at, created_at
     FROM messages WHERE pinned = 1 ORDER BY pinned_at DESC LIMIT 500`
  );
  res.json(rows.map(r => normalizeRow(r, ['created_at', 'pinned_at'])));
}));

// ---------- diary ----------
app.get('/api/diary/all', requireAuth(async (req, res) => {
  const rows = await all(
    `SELECT id, author_id, ciphertext, iv, unlock_at, created_at
     FROM diary_entries ORDER BY created_at DESC LIMIT 500`
  );
  const nowMs = Date.now();
  res.json(rows.map(r => {
    const norm = normalizeRow(r, ['created_at', 'unlock_at']);
    if (norm.author_id !== req.user.id && norm.unlock_at && new Date(norm.unlock_at).getTime() > nowMs) {
      return { id: norm.id, author_id: norm.author_id, locked: true, unlock_at: norm.unlock_at, created_at: norm.created_at };
    }
    return { ...norm, locked: false };
  }));
}));

app.get('/api/diary', requireAuth(async (req, res) => {
  const authorId = parseInt(req.query.author_id, 10);
  if (!authorId) return res.status(400).json({ error: 'author_id_required' });
  const rows = await all(
    `SELECT id, author_id, ciphertext, iv, unlock_at, created_at
     FROM diary_entries WHERE author_id = ? ORDER BY created_at DESC LIMIT 500`,
    [authorId]
  );
  const nowMs = Date.now();
  const result = rows.map(r => {
    const norm = normalizeRow(r, ['created_at', 'unlock_at']);
    if (norm.author_id !== req.user.id && norm.unlock_at && new Date(norm.unlock_at).getTime() > nowMs) {
      return { id: norm.id, author_id: norm.author_id, locked: true, unlock_at: norm.unlock_at, created_at: norm.created_at };
    }
    return { ...norm, locked: false };
  });
  res.json(result);
}));

app.post('/api/diary', requireAuth(async (req, res) => {
  const { ciphertext, iv, unlock_at } = req.body || {};
  if (!ciphertext || !iv) return res.status(400).json({ error: 'missing_fields' });
  let ua = null;
  if (unlock_at) {
    const d = new Date(unlock_at);
    if (!isNaN(d.getTime())) ua = d.toISOString().slice(0, 19).replace('T', ' ');
  }
  const r = await run(
    'INSERT INTO diary_entries (author_id, ciphertext, iv, unlock_at) VALUES (?, ?, ?, ?)',
    [req.user.id, ciphertext, iv, ua]
  );
  res.json({ id: r.insertId });
}));

app.delete('/api/diary/:id', requireAuth(async (req, res) => {
  await run('DELETE FROM diary_entries WHERE id = ? AND author_id = ?', [req.params.id, req.user.id]);
  res.json({ ok: true });
}));

// ---------- error handler ----------
app.use((err, req, res, next) => {
  console.error('ERR', err);
  res.status(500).json({ error: 'server_error', detail: String(err.message || err) });
});

// ---------- start ----------
(async () => {
  try {
    await migrate();
    app.listen(PORT, '0.0.0.0', () => console.log(`Folio on ${PORT}`));
  } catch (e) {
    console.error('startup failed', e);
    process.exit(1);
  }
})();
