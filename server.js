'use strict';
// Good Form server. No dependencies, Node 18+.
//   node server.js                     start at http://localhost:3000 (set PORT to change)
//   node server.js make-pro <email>    give an account Pro (can upload)
//   node server.js remove-pro <email>  take Pro away
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');

const ROOT = __dirname, DATA = path.join(ROOT, 'data'), UPLOADS = path.join(DATA, 'uploads'), DB_FILE = path.join(DATA, 'db.json');
const PORT = +process.env.PORT || 3000, MAX_FILE = 5 * 1024 * 1024, MAX_PER_USER = 100, SESSION_DAYS = 30;
// The only account that can open the admin panel. Admin rights come from this email, not from Pro, so revoking your own Pro can't lock you out.
const ADMIN_EMAIL = 'ferdinandbodmann@gmail.com';
fs.mkdirSync(UPLOADS, { recursive: true });

// shortcut: the whole database is one JSON file rewritten on every change; fine for hundreds of users, move to SQLite/Postgres before real traffic.
function load() {
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { if (e.code === 'ENOENT') return { users: [], sessions: {}, uploads: [] }; throw e; } // a corrupt file stops the server instead of being overwritten
}
let db = load();
function save() { const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db, null, 1)); fs.renameSync(tmp, DB_FILE); }

// ---- admin CLI ----
const [cmd, arg] = process.argv.slice(2);
if (cmd) {
  if (cmd !== 'make-pro' && cmd !== 'remove-pro') { console.error('Usage: node server.js [make-pro|remove-pro <email>]'); process.exit(1); }
  const u = db.users.find(u => u.email === String(arg || '').trim().toLowerCase());
  if (!u) { console.error(`No account with email ${arg}`); process.exit(1); }
  u.pro = cmd === 'make-pro'; save();
  console.log(`${u.email} is now ${u.pro ? 'Pro' : 'Free'}.`);
  process.exit(0);
}
// pick up changes the CLI makes while the server is running
fs.watchFile(DB_FILE, { interval: 1000 }, () => { try { db = load(); } catch (e) { console.error('db.json unreadable, keeping the in-memory copy:', e.message); } });

// ---- helpers ----
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => `${salt}:${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
const checkPw = (pw, stored) => { const [salt, h] = stored.split(':'); return crypto.timingSafeEqual(Buffer.from(h, 'hex'), crypto.scryptSync(pw, salt, 64)); };
const DUMMY_HASH = hashPw(crypto.randomBytes(8).toString('hex'));
const pub = u => ({ id: u.id, name: u.name, email: u.email, pro: !!u.pro });
const isAdmin = u => !!u && String(u.email).trim().toLowerCase() === ADMIN_EMAIL;
const self = u => ({ ...pub(u), admin: isAdmin(u) }); // what the signed-in user learns about themselves
const requireAdmin = u => { if (!u) throw fail(401, 'Please sign in.'); if (!isAdmin(u)) throw fail(403, 'Admins only.'); };
const fail = (status, msg) => Object.assign(new Error(msg), { status });
const strip = ({ uid, ...rest }) => rest; // never send owner ids to the browser

function send(res, status, obj, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0])
    .map(([k, ...v]) => { try { return [k, decodeURIComponent(v.join('='))]; } catch { return [k, '']; } }));
}
function currentUser(req) {
  const t = cookies(req).gf_session; if (!t) return null;
  const s = db.sessions[sha(t)];
  if (!s || s.exp < Date.now()) return null;
  return db.users.find(u => u.id === s.uid) || null;
}
function startSession(req, u) {
  const t = crypto.randomBytes(32).toString('hex'), now = Date.now();
  for (const [k, s] of Object.entries(db.sessions)) if (s.exp < now) delete db.sessions[k];
  db.sessions[sha(t)] = { uid: u.id, exp: now + SESSION_DAYS * 864e5 }; // only the hash is stored, so a leaked db.json can't log anyone in
  save();
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `gf_session=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`;
}
function readJSON(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0, tooBig = false;
    req.on('data', c => { n += c.length; if (n > limit) tooBig = true; else chunks.push(c); });
    req.on('end', () => {
      if (tooBig) return reject(fail(413, 'That file is too large (max 5 MB).'));
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(fail(400, 'Invalid JSON.')); }
    });
    req.on('error', reject);
  });
}
// login throttle: 8 failed tries per email+IP, then a 15-minute wait
const attempts = new Map();
const throttled = k => { const a = attempts.get(k); return a && a.n >= 8 && a.until > Date.now(); };
const noteFail = k => { const a = attempts.get(k), fresh = !a || a.until < Date.now(); attempts.set(k, { n: fresh ? 1 : a.n + 1, until: Date.now() + 15 * 60e3 }); };

// allowed uploads, checked by content, not just by extension
const TYPES = {
  png:  { mime: 'image/png',     check: b => b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) },
  jpg:  { mime: 'image/jpeg',    check: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  webp: { mime: 'image/webp',    check: b => b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP' },
  svg:  { mime: 'image/svg+xml', check: b => /<svg[\s>]/i.test(b.subarray(0, 4000).toString()) },
  css:  { mime: 'text/css; charset=utf-8', check: b => !b.includes(0) },
};
const STATIC = { '/': 'index.html', '/index.html': 'index.html', '/logo.svg': 'logo.svg' };
const STATIC_MIME = { '.html': 'text/html; charset=utf-8', '.svg': 'image/svg+xml' };

// ---- routes ----
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost'), p = url.pathname, m = req.method;
  let match;

  if (m === 'GET' && STATIC[p]) {
    const f = path.join(ROOT, STATIC[p]);
    if (!fs.existsSync(f)) throw fail(404, 'Not found.');
    res.writeHead(200, { 'Content-Type': STATIC_MIME[path.extname(f)], 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-cache' });
    return fs.createReadStream(f).pipe(res);
  }
  if (m === 'GET' && (match = p.match(/^\/uploads\/([a-f0-9]{24})\.(png|jpg|webp|svg|css)$/))) {
    const f = path.join(UPLOADS, `${match[1]}.${match[2]}`);
    if (!fs.existsSync(f)) throw fail(404, 'Not found.');
    // sandboxed: an uploaded SVG opened directly can't run scripts on this site
    res.writeHead(200, { 'Content-Type': TYPES[match[2]].mime, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox", 'Cache-Control': 'public, max-age=86400' });
    return fs.createReadStream(f).pipe(res);
  }
  if (!p.startsWith('/api/')) throw fail(404, 'Not found.');
  // JSON-only writes: a form on another site can't send this content type without a CORS preflight, which is never approved
  if (m !== 'GET' && !(req.headers['content-type'] || '').startsWith('application/json')) throw fail(415, 'Send JSON.');
  const user = currentUser(req);

  if (m === 'GET' && p === '/api/me') return send(res, 200, { user: user && self(user) });

  if (m === 'GET' && p === '/api/admin/users') {
    requireAdmin(user);
    const q = String(url.searchParams.get('q') || '').trim().toLowerCase();
    const users = db.users.filter(u => !q || u.name.toLowerCase().includes(q) || u.email.includes(q))
      .sort((a, b) => b.created - a.created).map(u => ({ ...pub(u), created: u.created }));
    return send(res, 200, { users });
  }
  if (m === 'POST' && (match = p.match(/^\/api\/admin\/users\/([a-f0-9]{24})\/pro$/))) {
    requireAdmin(user);
    const b = await readJSON(req, 1e3);
    if (typeof b.pro !== 'boolean') throw fail(400, 'Send { "pro": true } or { "pro": false }.');
    const target = db.users.find(u => u.id === match[1]);
    if (!target) throw fail(404, 'No account with that id.');
    const changed = !!target.pro !== b.pro;
    if (changed) { target.pro = b.pro; save(); } // setting the status it already has is a harmless no-op
    return send(res, 200, { user: { ...pub(target), created: target.created }, changed });
  }

  if (m === 'POST' && p === '/api/signup') {
    const b = await readJSON(req, 1e4);
    const email = String(b.email || '').trim().toLowerCase(), name = String(b.name || '').trim().slice(0, 40), pw = String(b.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 200) throw fail(400, 'Please enter a valid email.');
    if (!name) throw fail(400, 'Please enter your name.');
    if (pw.length < 8 || pw.length > 200) throw fail(400, 'Your password needs at least 8 characters.');
    if (db.users.some(u => u.email === email)) throw fail(409, 'An account with that email already exists.');
    const u = { id: crypto.randomBytes(12).toString('hex'), email, name, pw: hashPw(pw), pro: false, created: Date.now() };
    db.users.push(u);
    return send(res, 201, { user: self(u) }, { 'Set-Cookie': startSession(req, u) });
  }
  if (m === 'POST' && p === '/api/login') {
    const b = await readJSON(req, 1e4);
    const email = String(b.email || '').trim().toLowerCase(), key = `${email}|${req.socket.remoteAddress}`;
    if (throttled(key)) throw fail(429, 'Too many attempts. Try again in 15 minutes.');
    const u = db.users.find(u => u.email === email);
    const ok = checkPw(String(b.password || ''), u ? u.pw : DUMMY_HASH) && !!u; // same work whether or not the email exists
    if (!ok) { noteFail(key); throw fail(401, 'Wrong email or password.'); }
    attempts.delete(key);
    return send(res, 200, { user: self(u) }, { 'Set-Cookie': startSession(req, u) });
  }
  if (m === 'POST' && p === '/api/logout') {
    const t = cookies(req).gf_session;
    if (t && db.sessions[sha(t)]) { delete db.sessions[sha(t)]; save(); }
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'gf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }

  if (m === 'GET' && p === '/api/uploads') {
    const mine = url.searchParams.get('mine') === '1';
    if (mine && !user) throw fail(401, 'Please sign in.');
    const list = db.uploads.filter(u => !mine || u.uid === user.id).slice(-200).reverse().map(strip);
    return send(res, 200, { uploads: list });
  }
  if (m === 'POST' && p === '/api/uploads') {
    if (!user) throw fail(401, 'Please sign in.');
    if (!user.pro) throw fail(403, 'Uploads are a Pro feature.');
    const b = await readJSON(req, Math.ceil(MAX_FILE * 4 / 3) + 1e4);
    let ext = String(b.filename || '').toLowerCase().split('.').pop(); if (ext === 'jpeg') ext = 'jpg';
    const type = Object.hasOwn(TYPES, ext) && TYPES[ext];
    if (!type) throw fail(400, 'Allowed files: PNG, JPG, WebP, SVG or CSS.');
    const buf = Buffer.from(String(b.data || ''), 'base64');
    if (!buf.length) throw fail(400, 'That file is empty.');
    if (buf.length > MAX_FILE) throw fail(413, 'That file is too large (max 5 MB).');
    if (!type.check(buf)) throw fail(400, `That doesn’t look like a real .${ext} file.`);
    if (db.uploads.filter(u => u.uid === user.id).length >= MAX_PER_USER) throw fail(400, `You’ve reached the limit of ${MAX_PER_USER} uploads.`);
    const id = crypto.randomBytes(12).toString('hex'), title = String(b.title || '').trim().slice(0, 80) || 'Untitled';
    fs.writeFileSync(path.join(UPLOADS, `${id}.${ext}`), buf);
    const up = { id, uid: user.id, author: user.name, title, ext, file: `${id}.${ext}`, kind: ext === 'css' ? 'css' : 'image', size: buf.length, created: Date.now() };
    db.uploads.push(up); save();
    return send(res, 201, { upload: strip(up) });
  }
  if (m === 'DELETE' && (match = p.match(/^\/api\/uploads\/([a-f0-9]{24})$/))) {
    if (!user) throw fail(401, 'Please sign in.');
    const i = db.uploads.findIndex(u => u.id === match[1]);
    if (i < 0) throw fail(404, 'Not found.');
    if (db.uploads[i].uid !== user.id) throw fail(403, 'That isn’t your upload.');
    fs.rmSync(path.join(UPLOADS, db.uploads[i].file), { force: true });
    db.uploads.splice(i, 1); save();
    return send(res, 200, { ok: true });
  }
  throw fail(404, 'Not found.');
}

http.createServer(async (req, res) => {
  try { await handle(req, res); }
  catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'Something went wrong on the server.' });
    else res.end();
  }
}).listen(PORT, () => console.log(`Good Form running at http://localhost:${PORT}`));
