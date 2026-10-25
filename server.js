const express = require('express'), Database = require('better-sqlite3'), nodemailer = require('nodemailer'), crypto = require('crypto'), path = require('path');
const E = process.env, db = new Database(E.DB_PATH || 'devx.db'), app = express();
const ADMIN = (E.ADMIN_EMAIL || '').trim().toLowerCase();
db.exec(`
create table if not exists users(id integer primary key,email text unique,username text unique,pw text,badge text default '',role text default 'user',banned int default 0,warning text default '',created int);
create table if not exists sessions(token text primary key,uid int,exp int);
create table if not exists codes(email text primary key,hash text,exp int,tries int default 0,purpose text,data text);
create table if not exists posts(id integer primary key,uid int,parent int,body text,created int);
create table if not exists likes(uid int,pid int,primary key(uid,pid));`);

const h = s => crypto.createHash('sha256').update(s).digest('hex');
const norm = e => String(e || '').trim().toLowerCase();
const hashPw = p => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const checkPw = (p, st) => { const [s, k] = st.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(p, s, 64), Buffer.from(k, 'hex')); };
const mail = E.SMTP_USER && nodemailer.createTransport({ host: E.SMTP_HOST || 'smtp.gmail.com', port: 465, secure: true, auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } });

async function sendCode(email, purpose, data) {
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  db.prepare('insert or replace into codes values(?,?,?,0,?,?)').run(email, h(code), Date.now() + 6e5, purpose, data || '');
  if (mail) await mail.sendMail({ from: `DevX <${E.SMTP_USER}>`, to: email, subject: 'Your DevX code: ' + code, text: `Your DevX verification code is ${code}. It expires in 10 minutes. If this was not you, ignore this email.` });
  else console.log('[DEV MODE - no SMTP set] code for', email, '=', code);
}

const hits = new Map();
const limit = n => (q, s, nx) => { const k = q.ip + q.path, t = Date.now(), a = (hits.get(k) || []).filter(x => t - x < 6e5); if (a.length >= n) return s.status(429).json({ error: 'Too many tries, wait a few minutes' }); a.push(t); hits.set(k, a); nx(); };
const auth = (q, s, nx) => {
  const t = (q.headers.cookie || '').match(/sid=([a-f0-9]+)/)?.[1];
  const u = t && db.prepare('select u.* from sessions s join users u on u.id=s.uid where s.token=? and s.exp>?').get(h(t), Date.now());
  if (!u || u.banned) return s.status(401).json({ error: 'Not logged in' });
  q.u = u; q.tok = h(t); nx();
};
const admin = (q, s, nx) => q.u.role === 'admin' ? nx() : s.status(403).json({ error: 'Admins only' });

app.use((q, s, nx) => {
  s.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; script-src 'self' 'unsafe-inline'" });
  nx();
});
app.use(express.json({ limit: '10kb' }));
const PUB = ['index.html', 'logo.png', 'icon-192.png', 'icon-512.png', 'manifest.json', 'sw.js'];
app.get('/', (q, s) => s.sendFile(path.join(__dirname, 'index.html')));
app.get('/:f', (q, s, nx) => PUB.includes(q.params.f) ? s.sendFile(path.join(__dirname, q.params.f)) : nx());

// ---- auth: every login needs an emailed code ----
app.post('/api/register', limit(10), async (q, s) => {
  const email = norm(q.body.email), username = String(q.body.username || ''), pw = String(q.body.password || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || !/^[A-Za-z0-9_]{3,15}$/.test(username) || pw.length < 8 || pw.length > 100)
    return s.status(400).json({ error: 'Check your email, username (3-15 letters/numbers/_) and password (8+)' });
  if (db.prepare('select 1 from users where email=? or username=? collate nocase').get(email, username)) return s.status(409).json({ error: 'Email or username already taken' });
  try { await sendCode(email, 'register', JSON.stringify({ username, pw: hashPw(pw) })); s.json({ ok: 1 }); }
  catch (e) { console.error(e); s.status(500).json({ error: 'Could not send the email' }); }
});
app.post('/api/login', limit(10), async (q, s) => {
  const email = norm(q.body.email), u = db.prepare('select * from users where email=?').get(email);
  if (!u || !checkPw(String(q.body.password || ''), u.pw)) return s.status(401).json({ error: 'Wrong email or password' });
  if (u.banned) return s.status(403).json({ error: 'This account is banned' });
  try { await sendCode(email, 'login'); s.json({ ok: 1 }); }
  catch (e) { console.error(e); s.status(500).json({ error: 'Could not send the email' }); }
});
app.post('/api/verify', limit(15), (q, s) => {
  const email = norm(q.body.email), c = db.prepare('select * from codes where email=?').get(email);
  if (!c || c.exp < Date.now() || c.tries >= 5) return s.status(400).json({ error: 'Code expired, start again' });
  if (h(String(q.body.code || '')) !== c.hash) { db.prepare('update codes set tries=tries+1 where email=?').run(email); return s.status(400).json({ error: 'Wrong code' }); }
  db.prepare('delete from codes where email=?').run(email);
  let u = db.prepare('select * from users where email=?').get(email);
  if (c.purpose === 'register' && !u) {
    const d = JSON.parse(c.data);
    try { const r = db.prepare('insert into users(email,username,pw,role,created) values(?,?,?,?,?)').run(email, d.username, d.pw, email === ADMIN ? 'admin' : 'user', Date.now()); u = db.prepare('select * from users where id=?').get(r.lastInsertRowid); }
    catch { return s.status(409).json({ error: 'Email or username already taken' }); }
  }
  if (!u || u.banned) return s.status(403).json({ error: 'Account unavailable' });
  if (email === ADMIN && u.role !== 'admin') db.prepare("update users set role='admin' where id=?").run(u.id);
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('insert into sessions values(?,?,?)').run(h(t), u.id, Date.now() + 2592e6);
  s.setHeader('Set-Cookie', `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000` + (E.NODE_ENV === 'production' ? '; Secure' : ''));
  s.json({ ok: 1 });
});
app.post('/api/logout', auth, (q, s) => { db.prepare('delete from sessions where token=?').run(q.tok); s.setHeader('Set-Cookie', 'sid=; Max-Age=0; Path=/'); s.json({ ok: 1 }); });
app.get('/api/me', auth, (q, s) => { const { id, username, badge, role, warning } = q.u; s.json({ id, username, badge, role, warning }); });
app.post('/api/ack', auth, (q, s) => { db.prepare("update users set warning='' where id=?").run(q.u.id); s.json({ ok: 1 }); });

// ---- posts ----
const POSTS = `select p.id,p.body,p.created,p.parent,u.username,u.badge,u.role,
(select count(*) from likes where pid=p.id) likes,
exists(select 1 from likes where pid=p.id and uid=?) liked,
(select count(*) from posts where parent=p.id) replies
from posts p join users u on u.id=p.uid `;
app.get('/api/posts', auth, (q, s) => s.json(db.prepare(POSTS + 'where p.parent is ? order by p.id desc limit 100').all(q.u.id, +q.query.parent || null)));
app.get('/api/posts/:id', auth, (q, s) => { const p = db.prepare(POSTS + 'where p.id=?').get(q.u.id, +q.params.id); p ? s.json(p) : s.status(404).json({ error: 'Not found' }); });
app.post('/api/posts', auth, limit(60), (q, s) => {
  const body = String(q.body.body || '').trim(), parent = +q.body.parent || null;
  if (!body || body.length > 280) return s.status(400).json({ error: 'Posts must be 1-280 characters' });
  if (parent && !db.prepare('select 1 from posts where id=?').get(parent)) return s.status(404).json({ error: 'Not found' });
  db.prepare('insert into posts(uid,parent,body,created) values(?,?,?,?)').run(q.u.id, parent, body, Date.now()); s.json({ ok: 1 });
});
app.delete('/api/posts/:id', auth, (q, s) => {
  const p = db.prepare('select * from posts where id=?').get(+q.params.id);
  if (!p || (p.uid !== q.u.id && q.u.role !== 'admin')) return s.status(403).json({ error: 'Not allowed' });
  db.prepare('delete from posts where id=? or parent=?').run(p.id, p.id); db.prepare('delete from likes where pid=?').run(p.id); s.json({ ok: 1 });
});
app.post('/api/like/:id', auth, (q, s) => {
  const r = db.prepare('delete from likes where uid=? and pid=?').run(q.u.id, +q.params.id);
  if (!r.changes) db.prepare('insert or ignore into likes values(?,?)').run(q.u.id, +q.params.id); s.json({ ok: 1 });
});

// ---- admin (checked on the server, never trusts the browser) ----
app.get('/api/admin/users', auth, admin, (q, s) => s.json(db.prepare('select id,email,username,badge,role,banned,warning from users order by id desc').all()));
app.post('/api/admin/users/:id', auth, admin, (q, s) => {
  const t = db.prepare('select * from users where id=?').get(+q.params.id);
  if (!t || t.role === 'admin') return s.status(400).json({ error: 'Not allowed' });
  const { action, value } = q.body;
  if (action === 'badge' && ['', 'blue', 'gold'].includes(value)) db.prepare('update users set badge=? where id=?').run(value, t.id);
  else if (action === 'warn') db.prepare('update users set warning=? where id=?').run(String(value || 'Please follow the rules.').slice(0, 200), t.id);
  else if (action === 'kick') db.prepare('delete from sessions where uid=?').run(t.id);
  else if (action === 'ban' || action === 'unban') { db.prepare('update users set banned=? where id=?').run(action === 'ban' ? 1 : 0, t.id); db.prepare('delete from sessions where uid=?').run(t.id); }
  else return s.status(400).json({ error: 'Bad action' });
  s.json({ ok: 1 });
});

app.listen(E.PORT || 3000, () => console.log('DevX running on http://localhost:' + (E.PORT || 3000)));
