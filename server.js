'use strict';
/*
  AROGYA.Q backend: appointments, queue, login with limited attempts.
  Zero dependencies. Needs Node.js 22.13 or newer (uses the built-in node:sqlite).

  Run:   node server.js
  Env:   PORT=3000  DEMO_MODE=1  STAFF_ID=...  STAFF_PIN=...  APP_SECRET=...  SMS_WEBHOOK_URL=...
         CORS_ORIGIN=https://your-frontend  TRUST_PROXY=1  DB_FILE=./arogya.db
*/
process.env.TZ = process.env.TZ || 'Asia/Kolkata';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = +process.env.PORT || 3000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'arogya.db');
const DEMO = process.env.DEMO_MODE === '1';
const SECRET = process.env.APP_SECRET || crypto.randomBytes(32).toString('hex');
const CORS = process.env.CORS_ORIGIN || '';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const FRONTEND = path.join(__dirname, 'AROGYA.Q.html');

/* ---------- clinic setup ---------- */
const DOCTORS = [
  { id: 'rao', name: 'Dr. Ananya Rao', dept: 'General Medicine', code: 'GM', rn: 4, avg: 10 },
  { id: 'khan', name: 'Dr. Sameer Khan', dept: 'Paediatrics', code: 'PD', rn: 7, avg: 12 },
  { id: 'reddy', name: 'Dr. Lakshmi Reddy', dept: 'Gynaecology', code: 'GY', rn: 9, avg: 15 },
  { id: 'iyer', name: 'Dr. Meera Iyer', dept: 'Cardiology', code: 'CD', rn: 12, avg: 15 },
  { id: 'sethi', name: 'Dr. Vikram Sethi', dept: 'Orthopaedics', code: 'OR', rn: 15, avg: 12 },
  { id: 'verma', name: 'Dr. Rahul Verma', dept: 'Dermatology', code: 'DM', rn: 18, avg: 8 },
];
const SESSIONS = [[540, 780], [840, 1020]]; // 9:00-13:00 and 14:00-17:00
const SLOT = 15;
const ACTIVE = ['booked', 'checked_in', 'in_consult', 'done'];
const LOCK_MS = 5 * 60 * 1000;
const OTP_MS = 5 * 60 * 1000;
const MAX_UPCOMING = 5;

/* ---------- small helpers ---------- */
const pad = (n) => String(n).padStart(2, '0');
const pad3 = (n) => String(n).padStart(3, '0');
const dstr = (d) => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
const todayStr = () => dstr(new Date());
const addDays = (n) => { const d = new Date(); return dstr(new Date(d.getFullYear(), d.getMonth(), d.getDate() + n)); };
const nowHHMM = () => { const d = new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()); };
const docOf = (id) => DOCTORS.find((d) => d.id === id);
const toMin = (s) => { const p = s.split(':'); return +p[0] * 60 + +p[1]; };
const tsOf = (date, slot) => { const d = date.split('-').map(Number), t = slot.split(':').map(Number); return new Date(d[0], d[1] - 1, d[2], t[0], t[1]).getTime(); };
const slotsOf = () => { const out = []; SESSIONS.forEach((s) => { for (let m = s[0]; m < s[1]; m += SLOT) out.push(pad(Math.floor(m / 60)) + ':' + pad(m % 60)); }); return out; };
const ALL_SLOTS = slotsOf();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
function normPhone(v) { let d = String(v || '').replace(/\D/g, ''); if (d.length === 12 && d.startsWith('91')) d = d.slice(2); return d.length === 10 ? d : null; }
function newId() { const al = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s = ''; for (let i = 0; i < 5; i++) s += al[crypto.randomInt(al.length)]; return 'AQ-' + s; }
const mean = (a) => (a.length ? a.reduce((s, x) => s + x, 0) / a.length : null);
class HttpError extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra || {}; } }

/* ---------- database ---------- */
const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS appts(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL DEFAULT '', age INTEGER, reason TEXT NOT NULL DEFAULT '',
  doctor_id TEXT NOT NULL, date TEXT NOT NULL, slot TEXT NOT NULL, channel TEXT NOT NULL DEFAULT 'sms',
  status TEXT NOT NULL, emergency INTEGER NOT NULL DEFAULT 0, emergency_at INTEGER, walkin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL, checked_in_at INTEGER, called_at INTEGER, done_at INTEGER, rating INTEGER, via TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_booking_per_slot ON appts(doctor_id,date,slot)
  WHERE walkin=0 AND status IN ('booked','checked_in','in_consult','done');
CREATE INDEX IF NOT EXISTS appts_day ON appts(date,doctor_id);
CREATE INDEX IF NOT EXISTS appts_phone ON appts(phone);
CREATE TABLE IF NOT EXISTS staff(id TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS otps(phone TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, subject TEXT NOT NULL, expires INTEGER NOT NULL);
`);
const Q = {
  apptGet: db.prepare('SELECT * FROM appts WHERE id=?'),
  day: db.prepare('SELECT * FROM appts WHERE doctor_id=? AND date=?'),
  dayAll: db.prepare('SELECT * FROM appts WHERE date=?'),
};
const toApi = (r) => r && ({
  id: r.id, name: r.name, phone: r.phone, age: r.age, reason: r.reason, doctorId: r.doctor_id, date: r.date, slot: r.slot,
  channel: r.channel, status: r.status, emergency: !!r.emergency, emergencyAt: r.emergency_at, walkin: !!r.walkin,
  createdAt: r.created_at, checkedInAt: r.checked_in_at, calledAt: r.called_at, doneAt: r.done_at, rating: r.rating, via: r.via,
});
function tx(fn) { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; } }
function slotErr(e) { if (/UNIQUE/i.test(String(e && e.message))) throw new HttpError(409, 'That time was just taken. Pick another slot.'); throw e; }

/* ---------- attempt limits (kept in the database, not the browser) ---------- */
function limStatus(key, max) {
  const r = db.prepare('SELECT n,until FROM limits WHERE key=?').get(key), now = Date.now();
  if (!r) return { locked: false, remainMs: 0, left: max };
  if (r.until && r.until <= now) { db.prepare('DELETE FROM limits WHERE key=?').run(key); return { locked: false, remainMs: 0, left: max }; }
  return { locked: r.until > now, remainMs: Math.max(0, r.until - now), left: Math.max(0, max - r.n) };
}
function limFail(key, max, lockMs) {
  const r = db.prepare('SELECT n FROM limits WHERE key=?').get(key), n = (r ? r.n : 0) + 1;
  db.prepare('INSERT OR REPLACE INTO limits(key,n,until) VALUES(?,?,?)').run(key, n, n >= max ? Date.now() + lockMs : 0);
  return limStatus(key, max);
}
const limReset = (key) => db.prepare('DELETE FROM limits WHERE key=?').run(key);
function mustNotBeLocked(st, what) { if (st.locked) throw new HttpError(429, what, { retryAfterSec: Math.ceil(st.remainMs / 1000) }); }

/* ---------- sessions ---------- */
function createSession(role, subject, ttlMs) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions(token_hash,role,subject,expires) VALUES(?,?,?,?)').run(sha(token), role, subject, Date.now() + ttlMs);
  return token;
}
function authOf(req) {
  const h = req.headers.authorization || '', m = /^Bearer ([a-f0-9]{64})$/.exec(h);
  if (!m) return null;
  const r = db.prepare('SELECT role,subject,expires FROM sessions WHERE token_hash=?').get(sha(m[1]));
  if (!r || r.expires < Date.now()) return null;
  return { role: r.role, subject: r.subject, token: m[1] };
}
setInterval(() => { const n = Date.now(); db.prepare('DELETE FROM sessions WHERE expires<?').run(n); db.prepare('DELETE FROM otps WHERE expires<?').run(n); db.prepare('DELETE FROM limits WHERE until>0 AND until<?').run(n); }, 60000).unref();

/* ---------- staff accounts ---------- */
function hashPin(pin, salt) { return crypto.scryptSync(String(pin), salt, 32).toString('hex'); }
function seedStaff() {
  let id = process.env.STAFF_ID, pin = process.env.STAFF_PIN;
  if (!id || !pin) { if (DEMO) { id = 'STAFF01'; pin = '2468'; } else { if (!db.prepare('SELECT 1 FROM staff LIMIT 1').get()) console.warn('No staff account yet. Set STAFF_ID and STAFF_PIN, then restart.'); return; } }
  id = String(id).trim().toUpperCase();
  const salt = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT OR REPLACE INTO staff(id,salt,hash) VALUES(?,?,?)').run(id, salt, hashPin(pin, salt));
}
seedStaff();

/* ---------- SMS ---------- */
async function sendSms(phone, text) {
  if (process.env.SMS_WEBHOOK_URL) {            // plug in Twilio / MSG91 / any gateway behind this webhook
    const r = await fetch(process.env.SMS_WEBHOOK_URL, { method: 'POST', headers: { 'content-type': 'application/json', authorization: process.env.SMS_WEBHOOK_AUTH || '' }, body: JSON.stringify({ to: '+91' + phone, text }) });
    if (!r.ok) throw new HttpError(502, 'Could not send the SMS. Try again.');
    return;
  }
  if (DEMO) { console.log('[demo sms to ' + phone + '] ' + text); return; }
  throw new HttpError(503, 'SMS is not configured on the server.');
}

/* ---------- queue logic (same rules as the app) ---------- */
const effTs = (a) => Math.max(a.slot ? tsOf(a.date, a.slot) : 0, a.checkedInAt || 0);
function cmpQueue(x, y) {
  if (!!x.emergency !== !!y.emergency) return x.emergency ? -1 : 1;
  if (x.emergency && y.emergency) return (x.emergencyAt || 0) - (y.emergencyAt || 0) || x.id.localeCompare(y.id);
  return effTs(x) - effTs(y) || (x.checkedInAt || 0) - (y.checkedInAt || 0) || x.id.localeCompare(y.id);
}
function queueOf(doctorId, date) {
  const list = Q.day.all(doctorId, date).map(toApi);
  return { list, waiting: list.filter((a) => a.status === 'checked_in').sort(cmpQueue), serving: list.find((a) => a.status === 'in_consult') || null };
}
function tokenOf(a) {
  if (!a || !a.checkedInAt) return null;
  const arrived = Q.day.all(a.doctorId, a.date).map(toApi).filter((x) => x.checkedInAt).sort((x, y) => x.checkedInAt - y.checkedInAt || x.id.localeCompare(y.id));
  return docOf(a.doctorId).code + '-' + pad3(arrived.findIndex((x) => x.id === a.id) + 1);
}
function queueInfo(a) {
  const q = queueOf(a.doctorId, a.date), idx = q.waiting.findIndex((x) => x.id === a.id);
  if (idx < 0) return null;
  return { ahead: idx, estMin: Math.round((idx + (q.serving ? 0.5 : 0)) * docOf(a.doctorId).avg / 5) * 5, nowServing: q.serving ? tokenOf(q.serving) : null, next: idx === 0 && !q.serving };
}
const withQueue = (a) => Object.assign({}, a, { token: tokenOf(a), queue: a.status === 'checked_in' ? queueInfo(a) : null });
function freeSlots(doctorId, date, exceptId) {
  const now = Date.now(), taken = new Set(Q.day.all(doctorId, date).filter((a) => !a.walkin && ACTIVE.includes(a.status) && a.id !== exceptId).map((a) => a.slot));
  return ALL_SLOTS.filter((s) => tsOf(date, s) > now && !taken.has(s));
}
function validateSlot(doctorId, date, slot, exceptId) {
  if (!docOf(doctorId)) throw new HttpError(400, 'Unknown doctor.');
  if (![0, 1, 2, 3, 4, 5, 6].map(addDays).includes(date)) throw new HttpError(400, 'Pick a day within the next 7 days.');
  if (!ALL_SLOTS.includes(slot)) throw new HttpError(400, 'Pick a valid time slot.');
  if (tsOf(date, slot) <= Date.now()) throw new HttpError(400, 'That time has already passed.');
  if (!freeSlots(doctorId, date, exceptId).includes(slot)) throw new HttpError(409, 'That time was just taken. Pick another slot.');
}

/* ---------- live updates (server-sent events) ---------- */
const clients = new Set();
function broadcast() { for (const r of clients) r.write('event: change\ndata: {}\n\n'); }
setInterval(() => { for (const r of clients) r.write(': ping\n\n'); }, 25000).unref();

/* ---------- router ---------- */
const routes = [];
function add(method, p, role, fn) { const keys = []; const re = new RegExp('^' + p.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$'); routes.push({ method, re, keys, role, fn }); }
function send(res, status, obj, extra) { const b = JSON.stringify(obj); res.writeHead(status, Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }, extra || {})); res.end(b); }
function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', (c) => { n += c.length; if (n > 20000) { no(new HttpError(413, 'Request too large.')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { if (!ch.length) return ok({}); try { const j = JSON.parse(Buffer.concat(ch).toString('utf8')); ok(j && typeof j === 'object' ? j : {}); } catch (_) { no(new HttpError(400, 'Invalid JSON.')); } });
    req.on('error', no);
  });
}
const clientIp = (req) => (TRUST_PROXY && req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';
const own = (ctx, id) => { const a = Q.apptGet.get(String(id)); if (!a || a.phone !== ctx.auth.subject) throw new HttpError(404, 'Booking not found.'); return toApi(a); };
const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);

/* ===== public ===== */
add('GET', '/api/health', null, () => ({ ok: true, demo: DEMO }));
add('GET', '/api/doctors', null, () => DOCTORS.map((d) => ({ id: d.id, name: d.name, dept: d.dept, room: d.rn })));
add('GET', '/api/slots', null, (c) => {
  const doctor = c.query.get('doctor'), date = c.query.get('date');
  if (!docOf(doctor) || !/^\d{4}-\d{2}-\d{2}$/.test(date || '')) throw new HttpError(400, 'doctor and date are required.');
  return { doctor, date, free: freeSlots(doctor, date) };
});
add('GET', '/api/board', null, () => DOCTORS.map((d) => {
  const q = queueOf(d.id, todayStr());
  return { doctorId: d.id, name: d.name, dept: d.dept, room: d.rn, nowServing: q.serving ? tokenOf(q.serving) : null, waiting: q.waiting.length, estMin: Math.round((q.waiting.length + (q.serving ? 0.5 : 0)) * d.avg / 5) * 5 };
})); // tokens only, never patient names

/* ===== patient login: mobile number + one-time code ===== */
add('POST', '/api/patient/send-code', null, async (c) => {
  const phone = normPhone(c.body.phone); if (!phone) throw new HttpError(400, 'Enter a 10-digit mobile number.');
  mustNotBeLocked(limStatus('otpverify:' + phone, 3), 'Sign-in is locked for this number. Try again later.');
  mustNotBeLocked(limStatus('otpsend:' + phone, 3), 'Too many codes requested. Try again later.');
  mustNotBeLocked(limStatus('otpsendip:' + c.ip, 10), 'Too many codes requested. Try again later.');
  const code = DEMO && phone === '1234567890' ? '1234' : String(crypto.randomInt(1000, 10000));
  db.prepare('INSERT OR REPLACE INTO otps(phone,code_hash,expires) VALUES(?,?,?)').run(phone, sha(SECRET + phone + code), Date.now() + OTP_MS);
  limFail('otpsend:' + phone, 3, LOCK_MS); limFail('otpsendip:' + c.ip, 10, LOCK_MS);
  await sendSms(phone, 'Your AROGYA.Q code is ' + code + '. It works for 5 minutes. Do not share it.');
  return Object.assign({ ok: true, expiresInSec: OTP_MS / 1000 }, DEMO ? { devCode: code } : {});
});
add('POST', '/api/patient/verify-code', null, (c) => {
  const phone = normPhone(c.body.phone), code = str(c.body.code, 8);
  if (!phone || !/^\d{4}$/.test(code)) throw new HttpError(400, 'Enter your number and the 4-digit code.');
  mustNotBeLocked(limStatus('otpverify:' + phone, 3), 'Too many wrong codes. Sign-in is locked.');
  mustNotBeLocked(limStatus('otpverifyip:' + c.ip, 10), 'Too many wrong codes. Sign-in is locked.');
  const row = db.prepare('SELECT code_hash,expires FROM otps WHERE phone=?').get(phone);
  if (!row || row.expires < Date.now()) throw new HttpError(400, 'That code has expired. Ask for a new one.');
  if (!safeEq(sha(SECRET + phone + code), row.code_hash)) {
    const r = limFail('otpverify:' + phone, 3, LOCK_MS); limFail('otpverifyip:' + c.ip, 10, LOCK_MS);
    if (r.locked) db.prepare('DELETE FROM otps WHERE phone=?').run(phone);
    throw new HttpError(401, r.locked ? 'Too many wrong codes. Sign-in is locked for 5 minutes.' : 'Wrong code.', { triesLeft: r.left });
  }
  limReset('otpverify:' + phone); limReset('otpsend:' + phone); db.prepare('DELETE FROM otps WHERE phone=?').run(phone);
  return { token: createSession('patient', phone, 12 * 3600e3), phone };
});
add('POST', '/api/logout', 'any', (c) => { db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(c.auth.token)); return { ok: true }; });

/* ===== patient (needs patient token) ===== */
add('GET', '/api/my/appointments', 'patient', (c) => ({ appointments: db.prepare('SELECT * FROM appts WHERE phone=? ORDER BY date DESC,slot DESC').all(c.auth.subject).map(toApi).map(withQueue) }));
add('POST', '/api/appointments', 'patient', (c) => {
  const b = c.body, name = str(b.name, 80), reason = str(b.reason, 200), channel = b.channel === 'whatsapp' ? 'whatsapp' : 'sms';
  const age = b.age === '' || b.age == null ? null : +b.age;
  if (name.length < 2) throw new HttpError(400, "Enter the patient's full name.");
  if (age != null && !(Number.isInteger(age) && age >= 0 && age <= 120)) throw new HttpError(400, 'Enter a valid age.');
  return tx(() => {
    const open = db.prepare("SELECT COUNT(*) n FROM appts WHERE phone=? AND status='booked' AND date>=?").get(c.auth.subject, todayStr()).n;
    if (open >= MAX_UPCOMING) throw new HttpError(429, 'You already have ' + MAX_UPCOMING + ' upcoming bookings. Cancel one first.');
    validateSlot(b.doctorId, b.date, b.slot);
    const id = newId();
    try { db.prepare("INSERT INTO appts(id,name,phone,age,reason,doctor_id,date,slot,channel,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'booked',?)").run(id, name, c.auth.subject, age, reason, b.doctorId, b.date, b.slot, channel, Date.now()); } catch (e) { slotErr(e); }
    c.changed = true; return withQueue(toApi(Q.apptGet.get(id)));
  });
});
add('POST', '/api/appointments/:id/reschedule', 'patient', (c) => tx(() => {
  const a = own(c, c.params.id); if (a.status !== 'booked') throw new HttpError(409, 'Only a booked visit can be moved.');
  validateSlot(a.doctorId, c.body.date, c.body.slot, a.id);
  try { db.prepare('UPDATE appts SET date=?,slot=? WHERE id=?').run(c.body.date, c.body.slot, a.id); } catch (e) { slotErr(e); }
  c.changed = true; return withQueue(toApi(Q.apptGet.get(a.id)));
}));
add('POST', '/api/appointments/:id/cancel', 'patient', (c) => {
  const a = own(c, c.params.id); if (a.status !== 'booked') throw new HttpError(409, 'Only a booked visit can be cancelled.');
  db.prepare("UPDATE appts SET status='cancelled' WHERE id=?").run(a.id); c.changed = true; return { ok: true };
});
add('POST', '/api/appointments/:id/checkin', 'patient', (c) => {
  const a = own(c, c.params.id);
  if (a.status !== 'booked') throw new HttpError(409, 'This visit cannot be checked in.');
  if (a.date !== todayStr()) throw new HttpError(409, 'Check-in opens on the day of the visit.');
  db.prepare("UPDATE appts SET status='checked_in',checked_in_at=?,via='app' WHERE id=?").run(Date.now(), a.id); c.changed = true;
  return withQueue(toApi(Q.apptGet.get(a.id)));
});
add('POST', '/api/appointments/:id/rate', 'patient', (c) => {
  const a = own(c, c.params.id), r = +c.body.rating;
  if (a.status !== 'done') throw new HttpError(409, 'You can rate a visit after it is done.');
  if (!Number.isInteger(r) || r < 1 || r > 5) throw new HttpError(400, 'Rating must be 1 to 5.');
  db.prepare('UPDATE appts SET rating=? WHERE id=?').run(r, a.id); c.changed = true; return { ok: true };
});

/* ===== staff login with limited attempts ===== */
add('POST', '/api/staff/login', null, (c) => {
  const id = str(c.body.id, 40).toUpperCase(), pin = String(c.body.pin || '').slice(0, 64);
  const k1 = 'staff:' + c.ip, k2 = 'staffid:' + id;
  mustNotBeLocked(limStatus(k1, 3), 'Too many wrong attempts. Sign-in is locked.');
  mustNotBeLocked(limStatus(k2, 6), 'Too many wrong attempts. Sign-in is locked.');
  const s = db.prepare('SELECT salt,hash FROM staff WHERE id=?').get(id);
  const ok = s ? safeEq(hashPin(pin, s.salt), s.hash) : (hashPin(pin, 'x'.repeat(32)), false); // same work either way
  if (!ok) { const r = limFail(k1, 3, LOCK_MS); limFail(k2, 6, LOCK_MS); throw new HttpError(401, r.locked ? 'Too many wrong attempts. Sign-in is locked for 5 minutes.' : 'Wrong staff ID or PIN.', { triesLeft: r.left }); }
  limReset(k1); limReset(k2);
  return { token: createSession('staff', id, 8 * 3600e3), id };
});

/* ===== staff (needs staff token) ===== */
add('GET', '/api/staff/appointments', 'staff', (c) => {
  const date = c.query.get('date') || todayStr(), doc = c.query.get('doctor');
  return { date, appointments: Q.dayAll.all(date).map(toApi).filter((a) => !doc || a.doctorId === doc).map(withQueue) };
});
add('POST', '/api/staff/appointments/:id/checkin', 'staff', (c) => {
  const a = toApi(Q.apptGet.get(c.params.id)); if (!a) throw new HttpError(404, 'Not found.');
  if (a.status !== 'booked') throw new HttpError(409, 'This visit cannot be checked in.');
  db.prepare("UPDATE appts SET status='checked_in',checked_in_at=?,via='desk' WHERE id=?").run(Date.now(), a.id); c.changed = true; return withQueue(toApi(Q.apptGet.get(a.id)));
});
add('POST', '/api/staff/doctors/:id/call-next', 'staff', (c) => tx(() => {
  if (!docOf(c.params.id)) throw new HttpError(404, 'Unknown doctor.');
  const q = queueOf(c.params.id, todayStr());
  if (q.serving) throw new HttpError(409, 'Finish the current visit first.');
  if (!q.waiting.length) throw new HttpError(409, 'Nobody is waiting.');
  db.prepare("UPDATE appts SET status='in_consult',called_at=? WHERE id=?").run(Date.now(), q.waiting[0].id); c.changed = true;
  return withQueue(toApi(Q.apptGet.get(q.waiting[0].id)));
}));
add('POST', '/api/staff/appointments/:id/complete', 'staff', (c) => {
  const a = toApi(Q.apptGet.get(c.params.id)); if (!a) throw new HttpError(404, 'Not found.');
  if (a.status !== 'in_consult') throw new HttpError(409, 'This patient is not in consultation.');
  db.prepare("UPDATE appts SET status='done',done_at=? WHERE id=?").run(Date.now(), a.id); c.changed = true; return { ok: true };
});
add('POST', '/api/staff/appointments/:id/no-show', 'staff', (c) => {
  const a = toApi(Q.apptGet.get(c.params.id)); if (!a) throw new HttpError(404, 'Not found.');
  if (!['booked', 'in_consult'].includes(a.status)) throw new HttpError(409, 'Cannot mark this visit as a no-show.');
  db.prepare("UPDATE appts SET status='no_show' WHERE id=?").run(a.id); c.changed = true; return { ok: true };
});
add('POST', '/api/staff/appointments/:id/emergency', 'staff', (c) => {
  const a = toApi(Q.apptGet.get(c.params.id)); if (!a) throw new HttpError(404, 'Not found.');
  if (!['booked', 'checked_in'].includes(a.status)) throw new HttpError(409, 'Priority can only change before the consultation.');
  const on = c.body.on !== false;
  db.prepare('UPDATE appts SET emergency=?,emergency_at=? WHERE id=?').run(on ? 1 : 0, on ? Date.now() : null, a.id); c.changed = true; return { ok: true };
});
add('POST', '/api/staff/walkin', 'staff', (c) => {
  const b = c.body, name = str(b.name, 80), age = b.age === '' || b.age == null ? null : +b.age;
  if (name.length < 2) throw new HttpError(400, "Enter the patient's name.");
  if (!docOf(b.doctorId)) throw new HttpError(400, 'Choose a doctor.');
  if (age != null && !(Number.isInteger(age) && age >= 0 && age <= 120)) throw new HttpError(400, 'Enter a valid age.');
  const now = Date.now(), id = newId();
  db.prepare("INSERT INTO appts(id,name,phone,age,reason,doctor_id,date,slot,channel,status,emergency,emergency_at,walkin,created_at,checked_in_at,via) VALUES(?,?,?,?,?,?,?,?,?,'checked_in',1,?,1,?,?,'desk')")
    .run(id, name, '', age, str(b.reason, 200) || 'Emergency', b.doctorId, todayStr(), nowHHMM(), 'sms', now, now, now);
  c.changed = true; return withQueue(toApi(Q.apptGet.get(id)));
});
add('GET', '/api/staff/insights', 'staff', (c) => {
  const date = c.query.get('date') || todayStr(), nowTs = Date.now();
  const list = Q.dayAll.all(date).map(toApi).filter((a) => a.status !== 'cancelled');
  const done = list.filter((a) => a.status === 'done').length, noShow = list.filter((a) => a.status === 'no_show').length;
  const full = SESSIONS.reduce((s, x) => s + (x[1] - x[0]), 0), today = todayStr(), nd = new Date(nowTs), nm = nd.getHours() * 60 + nd.getMinutes();
  const elapsed = date < today ? full : date > today ? 0 : SESSIONS.reduce((s, x) => s + Math.max(0, Math.min(nm, x[1]) - x[0]), 0);
  const waits = (l) => l.filter((a) => a.checkedInAt && a.calledAt).map((a) => (a.calledAt - a.checkedInAt) / 60000);
  const perDoc = DOCTORS.map((d) => {
    const l = list.filter((a) => a.doctorId === d.id);
    const care = l.filter((a) => a.calledAt).reduce((s, a) => s + ((a.doneAt || nowTs) - a.calledAt) / 60000, 0);
    return { doctorId: d.id, name: d.name, total: l.length, seen: l.filter((a) => a.status === 'done').length, waiting: l.filter((a) => a.status === 'checked_in').length, avgWaitMin: mean(waits(l)), utilisation: elapsed ? Math.min(1, care / elapsed) : null };
  });
  const rated = list.filter((a) => a.rating), ev = [], hours = {};
  list.forEach((a) => { if (a.checkedInAt) { ev.push([a.checkedInAt, 1], [a.calledAt || (a.status === 'checked_in' ? nowTs : a.checkedInAt), -1]); const h = new Date(a.checkedInAt).getHours(); hours[h] = (hours[h] || 0) + 1; } });
  ev.sort((x, y) => x[0] - y[0] || x[1] - y[1]); let cur = 0, peak = 0; ev.forEach((e) => { cur += e[1]; if (cur > peak) peak = cur; });
  const util = mean(perDoc.filter((p) => p.total > 0 && p.utilisation != null).map((p) => p.utilisation));
  return { date, total: list.length, done, noShow, noShowRate: done + noShow ? noShow / (done + noShow) : null, avgWaitMin: mean(waits(list)), utilisation: util, satisfaction: mean(rated.map((a) => a.rating)), ratedCount: rated.length, peakWaiting: peak, waitingNow: list.filter((a) => a.status === 'checked_in').length, arrivalsByHour: hours, perDoctor: perDoc };
});

/* ---------- server ---------- */
const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x'), ip = clientIp(req);
  if (CORS) { res.setHeader('access-control-allow-origin', CORS); res.setHeader('access-control-allow-headers', 'content-type,authorization'); res.setHeader('access-control-allow-methods', 'GET,POST,OPTIONS'); res.setHeader('vary', 'origin'); }
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  if (u.pathname === '/api/events' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' }); res.write(': hello\n\n');
    clients.add(res); req.on('close', () => clients.delete(res)); return;
  }
  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/AROGYA.Q.html') && fs.existsSync(FRONTEND)) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'x-content-type-options': 'nosniff' }); return fs.createReadStream(FRONTEND).pipe(res);
  }
  if (!u.pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found.' });
  try {
    let hit = null, params = {};
    for (const r of routes) { const m = r.re.exec(u.pathname); if (m && r.method === req.method) { hit = r; r.keys.forEach((k, i) => { params[k] = decodeURIComponent(m[i + 1]); }); break; } }
    if (!hit) throw new HttpError(404, 'Not found.');
    const auth = authOf(req);
    if (hit.role === 'patient' && (!auth || auth.role !== 'patient')) throw new HttpError(401, 'Please sign in.');
    if (hit.role === 'staff' && (!auth || auth.role !== 'staff')) throw new HttpError(401, 'Staff sign-in required.');
    if (hit.role === 'any' && !auth) throw new HttpError(401, 'Please sign in.');
    const ctx = { req, res, ip, params, auth, query: u.searchParams, body: req.method === 'POST' ? await readBody(req) : {}, changed: false };
    const out = await hit.fn(ctx);
    send(res, 200, out); if (ctx.changed) broadcast();
  } catch (e) {
    if (e instanceof HttpError) send(res, e.status, Object.assign({ error: e.message }, e.extra), e.status === 429 && e.extra.retryAfterSec ? { 'retry-after': String(e.extra.retryAfterSec) } : {});
    else { console.error(e); send(res, 500, { error: 'Something went wrong on the server.' }); }
  }
});
server.listen(PORT, () => console.log('AROGYA.Q backend on http://localhost:' + PORT + (DEMO ? '  [DEMO_MODE: demo number 1234567890 / code 1234, staff STAFF01 / 2468]' : '')));
