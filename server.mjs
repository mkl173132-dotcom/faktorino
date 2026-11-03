import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';

const app = express();
const PORT = Number(process.env.PORT || 3000);
const RP_NAME = process.env.RP_NAME || 'فاکتورینو';
const ORIGIN = process.env.ORIGIN;
const RP_ID = process.env.RP_ID;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean);
const DATA_DIR = process.env.DATA_DIR || path.dirname(fileURLToPath(import.meta.url));
const DB_FILE = path.join(DATA_DIR, 'webauthn-db.json');

if (!ORIGIN || !RP_ID || !ALLOWED_ORIGINS.length) {
  console.error('تنظیم ORIGIN، RP_ID و ALLOWED_ORIGINS الزامی است.');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true });

// CORS محدود به دامنه فرانت‌اند فاکتورینو
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(origin && !ALLOWED_ORIGINS.includes(origin) ? 403 : 204);
  if (origin && !ALLOWED_ORIGINS.includes(origin)) return res.status(403).json({ error: 'این دامنه اجازه اتصال به سرور را ندارد.' });
  next();
});
app.use(express.json({ limit: '256kb' }));
app.use((_req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });

let db = { users: {} };
try { if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('Database read error:', e); }
const challenges = new Map();
const attempts = new Map();
const b64 = value => Buffer.from(value).toString('base64url');
const key = (id, kind) => `${kind}:${id}`;
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
function userRecord(id) { db.users[id] ||= { credentials: [] }; return db.users[id]; }
function fail(res, e) { console.error(e); return res.status(400).json({ error: e.message || 'درخواست نامعتبر است.' }); }
function validUserId(value) { return typeof value === 'string' && value.length > 0 && value.length <= 128; }
function rateLimit(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const now = Date.now(); const entry = attempts.get(ip) || { start: now, count: 0 };
  if (now - entry.start > 60_000) { entry.start = now; entry.count = 0; }
  entry.count++; attempts.set(ip, entry);
  if (entry.count > 40) return res.status(429).json({ error: 'تعداد درخواست‌ها زیاد است؛ یک دقیقه بعد دوباره تلاش کن.' });
  next();
}
app.use('/api/', rateLimit);
app.get('/health', (_req, res) => res.json({ ok: true, service: 'faktorino-webauthn', rpId: RP_ID }));

app.post('/api/webauthn/registration-options', async (req, res) => {
  try {
    const { userId, username, displayName } = req.body || {};
    if (!validUserId(String(userId || '')) || !username || String(username).length > 128) return res.status(400).json({ error: 'اطلاعات حساب ناقص یا نامعتبر است.' });
    const id = String(userId); const u = userRecord(id);
    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID, userID: Buffer.from(id),
      userName: String(username), userDisplayName: String(displayName || username),
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      excludeCredentials: u.credentials.map(c => ({ id: c.id, transports: c.transports }))
    });
    challenges.set(key(id, 'reg'), { challenge: options.challenge, expires: Date.now() + 5 * 60_000 });
    res.json(options);
  } catch (e) { fail(res, e); }
});

app.post('/api/webauthn/registration-verify', async (req, res) => {
  try {
    const { userId, response } = req.body || {}; const id = String(userId || '');
    const pending = challenges.get(key(id, 'reg'));
    if (!validUserId(id) || !pending || pending.expires < Date.now()) return res.status(400).json({ error: 'درخواست ثبت منقضی شده است؛ دوباره تلاش کن.' });
    const verification = await verifyRegistrationResponse({ response, expectedChallenge: pending.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID, requireUserVerification: true });
    challenges.delete(key(id, 'reg'));
    if (verification.verified && verification.registrationInfo) {
      const info = verification.registrationInfo;
      const credential = info.credential || { id: b64(info.credentialID), publicKey: info.credentialPublicKey, counter: info.counter, transports: response.response?.transports || [] };
      const u = userRecord(id);
      u.credentials = u.credentials.filter(c => c.id !== credential.id);
      u.credentials.push({ id: credential.id, publicKey: b64(credential.publicKey), counter: credential.counter, transports: credential.transports || [] });
      save();
    }
    res.json({ verified: verification.verified });
  } catch (e) { fail(res, e); }
});

app.post('/api/webauthn/authentication-options', async (req, res) => {
  try {
    const { userId } = req.body || {}; const id = String(userId || '');
    if (!validUserId(id)) return res.status(400).json({ error: 'شناسه حساب نامعتبر است.' });
    const u = db.users[id];
    if (!u?.credentials?.length) return res.status(404).json({ error: 'برای این حساب Passkey ثبت نشده است.' });
    const options = await generateAuthenticationOptions({ rpID: RP_ID, allowCredentials: u.credentials.map(c => ({ id: c.id, transports: c.transports })), userVerification: 'required' });
    challenges.set(key(id, 'auth'), { challenge: options.challenge, expires: Date.now() + 5 * 60_000 });
    res.json(options);
  } catch (e) { fail(res, e); }
});

app.post('/api/webauthn/authentication-verify', async (req, res) => {
  try {
    const { userId, response } = req.body || {}; const id = String(userId || '');
    const pending = challenges.get(key(id, 'auth')); const u = db.users[id];
    if (!pending || pending.expires < Date.now() || !u) return res.status(400).json({ error: 'درخواست ورود منقضی شده یا حساب پیدا نشد.' });
    const stored = u.credentials.find(c => c.id === response?.id);
    if (!stored) return res.status(400).json({ error: 'این Passkey برای حساب ثبت نشده است.' });
    const verification = await verifyAuthenticationResponse({ response, expectedChallenge: pending.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID, requireUserVerification: true, credential: { id: stored.id, publicKey: Buffer.from(stored.publicKey, 'base64url'), counter: stored.counter, transports: stored.transports } });
    challenges.delete(key(id, 'auth'));
    if (verification.verified) { stored.counter = verification.authenticationInfo.newCounter; save(); }
    res.json({ verified: verification.verified });
  } catch (e) { fail(res, e); }
});

app.post('/api/webauthn/remove', (req, res) => {
  const id = String(req.body?.userId || '');
  if (!validUserId(id)) return res.status(400).json({ error: 'شناسه حساب لازم است.' });
  if (db.users[id]) { db.users[id].credentials = []; save(); }
  res.json({ ok: true });
});

app.listen(PORT, '0.0.0.0', () => console.log(`Faktorino WebAuthn API listening on ${PORT}; RP_ID=${RP_ID}`));
