import express from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';

const app = express();
// Render sits behind a trusted reverse proxy. Do not trust arbitrary X-Forwarded-For headers.
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 3000);
const RP_NAME = process.env.RP_NAME || 'فاکتورینو';
const ORIGIN = process.env.ORIGIN;
const RP_ID = process.env.RP_ID;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ORIGIN || '').split(',').map(x => x.trim()).filter(Boolean);
const DATA_DIR = process.env.DATA_DIR || path.join(path.dirname(fileURLToPath(import.meta.url)), 'data');
const DB_FILE = path.join(DATA_DIR, 'webauthn-db.json');

if (!ORIGIN || !RP_ID || !ALLOWED_ORIGINS.length) {
  console.error('تنظیم ORIGIN، RP_ID و ALLOWED_ORIGINS الزامی است.');
  process.exit(1);
}
fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

// Security headers and strict CORS allow-list.
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Cache-Control', 'no-store');
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
app.use(express.json({ limit: '128kb', strict: true }));

let db = { users: {} };
try {
  if (fs.existsSync(DB_FILE)) {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (parsed && parsed.users && typeof parsed.users === 'object') db = parsed;
    else throw new Error('ساختار پایگاه داده معتبر نیست.');
  }
} catch (e) {
  console.error('Database read error:', e);
  // Fail closed: never silently overwrite a damaged database with an empty one.
  process.exit(1);
}
const challenges = new Map();
const attempts = new Map();
const key = (id, kind) => `${kind}:${id}`;
const b64 = value => Buffer.from(value).toString('base64url');
function save() {
  const tmp = DB_FILE + '.tmp';
  const fd = fs.openSync(tmp, 'w', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(db)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, DB_FILE);
}
function validUserId(value) { return typeof value === 'string' && value.length > 0 && value.length <= 128; }
function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = attempts.get(ip) || { start: now, count: 0 };
  if (now - entry.start > 60_000) entry = { start: now, count: 0 };
  entry.count++; attempts.set(ip, entry);
  if (attempts.size > 10000) for (const [k, v] of attempts) if (now - v.start > 120_000) attempts.delete(k);
  if (entry.count > 30) return res.status(429).json({ error: 'تعداد درخواست‌ها زیاد است؛ کمی بعد دوباره تلاش کن.' });
  next();
}
app.use('/api/', rateLimit);
app.get('/health', (_req, res) => res.json({ ok: true, service: 'faktorino-webauthn', rpId: RP_ID }));

// Enrollment/removal intentionally remain disabled until the product has a real,
// server-authenticated account session. A client-supplied userId is NOT proof of ownership.
app.post('/api/webauthn/registration-options', (_req, res) =>
  res.status(503).json({ error: 'ثبت Passkey تا زمان اتصال ورود حساب به نشست امن سرور موقتاً غیرفعال است.' }));
app.post('/api/webauthn/registration-verify', (_req, res) =>
  res.status(503).json({ error: 'ثبت Passkey تا زمان اتصال ورود حساب به نشست امن سرور موقتاً غیرفعال است.' }));
app.post('/api/webauthn/remove', (_req, res) =>
  res.status(503).json({ error: 'حذف Passkey از سرور تا زمان فعال‌شدن نشست احراز هویت‌شده غیرفعال است.' }));

app.post('/api/webauthn/authentication-options', async (req, res) => {
  try {
    const id = String(req.body?.userId || '');
    if (!validUserId(id)) return res.status(400).json({ error: 'شناسه حساب نامعتبر است.' });
    const credentials = db.users[id]?.credentials;
    if (!Array.isArray(credentials) || !credentials.length) return res.status(404).json({ error: 'برای این حساب Passkey ثبت نشده است.' });
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: credentials.map(c => ({ id: c.id, transports: c.transports })),
      userVerification: 'required'
    });
    challenges.set(key(id, 'auth'), { challenge: options.challenge, expires: Date.now() + 3 * 60_000 });
    res.json(options);
  } catch (e) {
    console.error('Authentication options error:', e);
    res.status(400).json({ error: 'ساخت درخواست ورود امن انجام نشد.' });
  }
});

app.post('/api/webauthn/authentication-verify', async (req, res) => {
  try {
    const id = String(req.body?.userId || '');
    const pending = challenges.get(key(id, 'auth'));
    const user = db.users[id];
    if (!validUserId(id) || !pending || pending.expires < Date.now() || !user) {
      challenges.delete(key(id, 'auth'));
      return res.status(400).json({ error: 'درخواست ورود منقضی شده یا حساب پیدا نشد.' });
    }
    const response = req.body?.response;
    const stored = user.credentials.find(c => c.id === response?.id);
    if (!stored) return res.status(400).json({ error: 'این Passkey برای حساب ثبت نشده است.' });
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: stored.id,
        publicKey: Buffer.from(stored.publicKey, 'base64url'),
        counter: stored.counter,
        transports: stored.transports
      }
    });
    challenges.delete(key(id, 'auth'));
    if (verification.verified) {
      stored.counter = verification.authenticationInfo.newCounter;
      save();
    }
    res.json({ verified: verification.verified });
  } catch (e) {
    console.error('Authentication verification error:', e);
    res.status(400).json({ error: 'تأیید ورود امن انجام نشد.' });
  }
});

// Expire abandoned challenges and rate-limit records without allowing unbounded growth.
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k);
  for (const [k, v] of attempts) if (now - v.start > 120_000) attempts.delete(k);
}, 60_000).unref();

app.listen(PORT, '0.0.0.0', () => console.log(`Faktorino WebAuthn API listening on ${PORT}; RP_ID=${RP_ID}`));
