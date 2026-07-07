"use strict";
/**
 * پروتکل آیرون — بک‌اند فاز ۱ (نسخه‌ی تک‌فایلی)
 * عمداً همه‌چیز در یک فایل است تا آپلود دستی از موبایل (بدون ساختار پوشه)
 * ممکن باشد. منطق و رفتار دقیقاً همان نسخه‌ی ماژولار قبلی است.
 */
const http = require("http");
const url = require("url");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

/* ================= تنظیمات (env) ================= */
function readEnvFile() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, "utf8").split("\n");
  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;
    const idx = trimmed.indexOf("=");
    if (idx === -1) return;
    const key = trimmed.slice(0, idx).trim();
    const val = trimmed.slice(idx + 1).trim();
    if (!(key in process.env)) process.env[key] = val;
  });
}
readEnvFile();
const env = {
  PORT: Number(process.env.PORT || 4000),
  JWT_ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || "dev-access-secret-change-me",
  JWT_REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || "dev-refresh-secret-change-me",
  ACCESS_TOKEN_TTL: Number(process.env.ACCESS_TOKEN_TTL || 15 * 60),
  REFRESH_TOKEN_TTL: Number(process.env.REFRESH_TOKEN_TTL || 30 * 24 * 60 * 60),
  NODE_ENV: process.env.NODE_ENV || "development",
  CORS_ORIGIN: process.env.CORS_ORIGIN || "*",
  STORAGE_DIR: process.env.STORAGE_DIR || null,
  // ایمیل‌هایی که با ورود، خودکار نقش ادمین می‌گیرن (با کاما جدا کن)
  ADMIN_EMAILS: (process.env.ADMIN_EMAILS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
  USDT_WALLET_ADDRESS: process.env.USDT_WALLET_ADDRESS || "",
  USDT_WALLET_NETWORK: process.env.USDT_WALLET_NETWORK || "TRC20",
  ZARINPAL_MERCHANT_ID: process.env.ZARINPAL_MERCHANT_ID || "",
  FRONTEND_URL: process.env.FRONTEND_URL || "",
  MONGODB_URI: process.env.MONGODB_URI || "",
  MONGODB_DB: process.env.MONGODB_DB || "iron_protocol",
};

/* ================= لاگر ================= */
function ts() { return new Date().toISOString(); }
const logInfo = (...a) => console.log(`[${ts()}] ℹ️`, ...a);
const logError = (...a) => console.error(`[${ts()}] ❌`, ...a);

/* ================= JWT سبک (بدون وابستگی خارجی) ================= */
function base64url(input) {
  return Buffer.from(input).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64urlDecode(input) {
  input = input.replace(/-/g, "+").replace(/_/g, "/");
  while (input.length % 4) input += "=";
  return Buffer.from(input, "base64").toString("utf8");
}
function jwtSign(payload, secret, { expiresInSeconds = 3600 } = {}) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = Object.assign({ iat: now, exp: now + expiresInSeconds }, payload);
  const data = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(fullPayload))}`;
  const signature = crypto.createHmac("sha256", secret).update(data).digest("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${data}.${signature}`;
}
function jwtVerify(token, secret) {
  if (!token || typeof token !== "string") throw new Error("توکن نامعتبر است");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("توکن نامعتبر است");
  const [encodedHeader, encodedPayload, signature] = parts;
  const data = `${encodedHeader}.${encodedPayload}`;
  const expectedSig = crypto.createHmac("sha256", secret).update(data).digest("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const sigBuf = Buffer.from(signature), expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) throw new Error("امضای توکن نامعتبر است");
  const payload = JSON.parse(base64urlDecode(encodedPayload));
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) throw new Error("توکن منقضی شده است");
  return payload;
}

/* ================= هش رمز عبور (scrypt داخلی) ================= */
const KEY_LEN = 64;
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.scryptSync(plain, salt, KEY_LEN);
  return `${salt}:${derivedKey.toString("hex")}`;
}
function verifyPassword(plain, stored) {
  if (!stored || !stored.includes(":")) return false;
  const [salt, key] = stored.split(":");
  const derivedKey = crypto.scryptSync(plain, salt, KEY_LEN);
  const keyBuf = Buffer.from(key, "hex");
  if (keyBuf.length !== derivedKey.length) return false;
  return crypto.timingSafeEqual(keyBuf, derivedKey);
}
const isStrongPassword = (pw) => typeof pw === "string" && pw.length >= 8;

/* ================= اعتبارسنجی ================= */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const IRAN_PHONE_RE = /^09\d{9}$/;
const isValidEmail = (v) => typeof v === "string" && EMAIL_RE.test(v);
const isValidIranPhone = (v) => typeof v === "string" && IRAN_PHONE_RE.test(v);
const isNonEmptyString = (v) => typeof v === "string" && v.trim().length > 0;
const isNumberInRange = (v, min, max) => { const n = Number(v); return !Number.isNaN(n) && n >= min && n <= max; };

/* ================= پارسر multipart/form-data (آپلود عکس) ================= */
function getBoundary(contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
  return match ? (match[1] || match[2]) : null;
}
function parseMultipart(buffer, contentType) {
  const boundary = getBoundary(contentType);
  const body = {}, files = {};
  if (!boundary) return { body, files };
  const boundaryBuf = Buffer.from(`--${boundary}`);
  const parts = [];
  let start = buffer.indexOf(boundaryBuf);
  while (start !== -1) {
    const next = buffer.indexOf(boundaryBuf, start + boundaryBuf.length);
    if (next === -1) break;
    parts.push(buffer.slice(start + boundaryBuf.length, next));
    start = next;
  }
  parts.forEach((part) => {
    let p = part;
    if (p.slice(0, 2).toString() === "--") return;
    if (p.slice(0, 2).toString("utf8") === "\r\n") p = p.slice(2);
    const headerEnd = p.indexOf("\r\n\r\n");
    if (headerEnd === -1) return;
    const rawHeaders = p.slice(0, headerEnd).toString("utf8");
    let content = p.slice(headerEnd + 4);
    if (content.slice(-2).toString("utf8") === "\r\n") content = content.slice(0, -2);
    const nameMatch = /name="([^"]+)"/i.exec(rawHeaders);
    const filenameMatch = /filename="([^"]*)"/i.exec(rawHeaders);
    const typeMatch = /Content-Type:\s*([^\r\n]+)/i.exec(rawHeaders);
    if (!nameMatch) return;
    const fieldName = nameMatch[1];
    if (filenameMatch && filenameMatch[1]) {
      files[fieldName] = { filename: filenameMatch[1], mimeType: typeMatch ? typeMatch[1].trim() : "application/octet-stream", buffer: content, size: content.length };
    } else {
      body[fieldName] = content.toString("utf8");
    }
  });
  return { body, files };
}

/* ================= ذخیره‌سازی فایل‌محور (JSON store) ================= */
const DATA_DIR = env.STORAGE_DIR ? path.join(env.STORAGE_DIR, "data") : path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const _cache = new Map();
function _filePathFor(name) { return path.join(DATA_DIR, `${name}.json`); }
function _load(name) {
  if (_cache.has(name)) return _cache.get(name);
  const fp = _filePathFor(name);
  let rows = [];
  if (fs.existsSync(fp)) { try { rows = JSON.parse(fs.readFileSync(fp, "utf8")); } catch (e) { rows = []; } }
  _cache.set(name, rows);
  return rows;
}

/* ---------- لایه‌ی MongoDB (اختیاری) — رفع باگ بحرانیِ از دست رفتن داده روی Render -----------
   مشکل ریشه‌ای: بدون MONGODB_URI، داده‌ها فقط روی دیسک ephemeral کانتینر Render ذخیره می‌شن
   و با هر redeploy/restart از بین می‌رن. اگه MONGODB_URI تنظیم بشه، هر تغییر همزمان (async،
   بدون کند کردن پاسخ به کاربر) روی MongoDB هم منعکس می‌شه و در startup از همونجا بارگذاری
   می‌شه — یعنی داده‌ها دیگه هیچ‌وقت با دیپلوی یا ری‌استارت پاک نمی‌شن.
   طراحی عمداً ساده نگه داشته شده (بدون تغییر در بقیه‌ی کد سرویس‌ها/کنترلرها) تا ریسک
   خرابی منطق فعلی که تست شده صفر بمونه. */
let _mongoClient = null, _mongoDb = null, _mongoReady = false;
const ALL_COLLECTION_NAMES = ["users", "sessions", "verification_tokens", "security_events", "outbox_emails", "outbox_sms", "body_stats", "personal_records", "vip_codes", "vip_plans", "discount_codes", "payment_transactions", "ai_usage_daily"];
function stripMongoId(doc) { if (!doc) return doc; const { _id, ...rest } = doc; return rest; }
async function initStorage() {
  if (!env.MONGODB_URI) {
    logInfo("⚠️ حالت ذخیره‌سازی: فقط فایل محلی (بدون MONGODB_URI). روی Render این یعنی داده‌ها با هر دیپلوی/ری‌استارت پاک می‌شن. برای رفع دائمی، MONGODB_URI رو تنظیم کن.");
    return;
  }
  try {
    const { MongoClient } = require("mongodb");
    _mongoClient = new MongoClient(env.MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
    await _mongoClient.connect();
    _mongoDb = _mongoClient.db(env.MONGODB_DB);
    for (const name of ALL_COLLECTION_NAMES) {
      const docs = await _mongoDb.collection(name).find({}).toArray();
      _cache.set(name, docs.map(stripMongoId));
    }
    _mongoReady = true;
    logInfo("✅ به MongoDB وصل شد — داده‌ها دائمی هستن و با دیپلوی/ری‌استارت پاک نمی‌شن.");
  } catch (e) {
    _mongoReady = false;
    logError("❌ اتصال به MongoDB ناموفق بود، برگشت موقت به فایل محلی (ناپایدار روی Render):", e.message);
  }
}
function _persist(name) {
  const rows = _cache.get(name) || [];
  const fp = _filePathFor(name);
  const tmp = `${fp}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify(rows, null, 2), "utf8");
    fs.renameSync(tmp, fp);
  } catch (e) { logError("نوشتن فایل محلی ناموفق بود برای " + name + ":", e.message); }
  if (_mongoReady) {
    const snapshot = rows.slice();
    const coll = _mongoDb.collection(name);
    coll.deleteMany({})
      .then(() => (snapshot.length ? coll.insertMany(snapshot) : null))
      .catch((e) => logError("همگام‌سازی با MongoDB ناموفق بود برای " + name + ":", e.message));
  }
}
function collection(name) {
  return {
    all() { return _load(name).slice(); },
    findById(id) { return _load(name).find((r) => r.id === id) || null; },
    findOne(pred) { return _load(name).find(pred) || null; },
    findMany(pred) { return _load(name).filter(pred); },
    insert(doc) {
      const rows = _load(name);
      const record = Object.assign({ id: crypto.randomUUID(), createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }, doc);
      rows.push(record); _persist(name);
      return record;
    },
    update(id, patch) {
      const rows = _load(name);
      const idx = rows.findIndex((r) => r.id === id);
      if (idx === -1) return null;
      rows[idx] = Object.assign({}, rows[idx], patch, { updatedAt: new Date().toISOString() });
      _persist(name);
      return rows[idx];
    },
    remove(id) {
      const rows = _load(name);
      const idx = rows.findIndex((r) => r.id === id);
      if (idx === -1) return false;
      rows.splice(idx, 1); _persist(name);
      return true;
    },
  };
}

/* ================= ریپازیتوری‌ها ================= */
const _users = collection("users");
const UserRepo = {
  create: (data) => _users.insert(data),
  findById: (id) => _users.findById(id),
  findByEmail: (email) => email ? _users.findOne((u) => u.email && u.email.toLowerCase() === email.toLowerCase()) : null,
  findByPhone: (phone) => phone ? _users.findOne((u) => u.phone === phone) : null,
  update: (id, patch) => _users.update(id, patch),
  remove: (id) => _users.remove(id),
  all: () => _users.all(),
};
const _sessions = collection("sessions");
const SessionRepo = {
  create: ({ userId, refreshToken, userAgent, ip, expiresAt }) => _sessions.insert({ userId, refreshToken, userAgent, ip, expiresAt, revoked: false }),
  findByToken: (refreshToken) => _sessions.findOne((s) => s.refreshToken === refreshToken && !s.revoked),
  revoke: (refreshToken) => { const s = _sessions.findOne((x) => x.refreshToken === refreshToken); if (!s) return false; _sessions.update(s.id, { revoked: true }); return true; },
  revokeAllForUser: (userId) => { const rows = _sessions.findMany((s) => s.userId === userId && !s.revoked); rows.forEach((s) => _sessions.update(s.id, { revoked: true })); return rows.length; },
};
const _tokens = collection("verification_tokens");
const TokenRepo = {
  create: ({ userId, type, code, expiresAt }) => _tokens.insert({ userId, type, code, expiresAt, used: false }),
  findValid: ({ userId, type, code }) => { const now = Date.now(); return _tokens.findOne((t) => t.userId === userId && t.type === type && t.code === code && !t.used && new Date(t.expiresAt).getTime() > now); },
  markUsed: (id) => _tokens.update(id, { used: true }),
  invalidateAllForUser: (userId, type) => { _tokens.findMany((t) => t.userId === userId && t.type === type && !t.used).forEach((t) => _tokens.update(t.id, { used: true })); },
};
const _secEvents = collection("security_events");
const SecurityLog = { log: ({ userId = null, type, ip = null, meta = {} }) => _secEvents.insert({ userId, type, ip, meta }) };

/* ================= ایمیل و پیامک (شبیه‌سازی؛ برای اتصال واقعی جایگزین کنید) ================= */
const _outboxEmail = collection("outbox_emails");
async function mailerSend({ to, subject, body }) {
  const usingResend = !!process.env.RESEND_API_KEY;
  const record = _outboxEmail.insert({ to, subject, body, provider: usingResend ? "resend" : "console-stub" });
  if (usingResend) {
    try {
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${process.env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: process.env.RESEND_FROM_EMAIL || "onboarding@resend.dev",
          to: [to],
          subject,
          text: body,
        }),
      });
      if (!res.ok) {
        const errText = await res.text();
        logError("ارسال ایمیل با Resend ناموفق بود:", res.status, errText);
      }
    } catch (e) {
      logError("خطای اتصال به Resend:", e.message);
    }
  }
  console.log(`\n📧 [ایمیل${usingResend ? "" : " شبیه‌سازی‌شده"}] به: ${to}\nموضوع: ${subject}\n${body}\n`);
  return record;
}
const _outboxSms = collection("outbox_sms");
async function smsSend({ to, text }) {
  const record = _outboxSms.insert({ to, text, provider: "console-stub" });
  console.log(`\n📱 [پیامک شبیه‌سازی‌شده] به: ${to}\n${text}\n`);
  return record;
}

/* ================= میان‌افزارها ================= */
function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) { const err = new Error("توکن ارسال نشده است"); err.status = 401; return next(err); }
  try {
    const payload = jwtVerify(token, env.JWT_ACCESS_SECRET);
    req.userId = payload.sub;
    next();
  } catch (e) {
    const err = new Error("توکن نامعتبر یا منقضی شده است"); err.status = 401; next(err);
  }
}
const _rlBuckets = new Map();
function rateLimit({ windowMs = 60000, max = 10, keyPrefix = "" } = {}) {
  return (req, res, next) => {
    const ip = req.socket.remoteAddress || "unknown";
    const key = keyPrefix + ":" + ip;
    const now = Date.now();
    let entry = _rlBuckets.get(key);
    if (!entry || now - entry.start > windowMs) entry = { start: now, count: 0 };
    entry.count += 1;
    _rlBuckets.set(key, entry);
    if (entry.count > max) { const err = new Error("درخواست‌های زیاد؛ کمی بعد دوباره تلاش کن"); err.status = 429; return next(err); }
    next();
  };
}

/* ================= روتر سبک (Express-like) ================= */
function matchRoute(routePath, actualPath) {
  const routeParts = routePath.split("/").filter(Boolean);
  const actualParts = actualPath.split("/").filter(Boolean);
  if (routeParts.length !== actualParts.length) return null;
  const params = {};
  for (let i = 0; i < routeParts.length; i++) {
    const rp = routeParts[i], ap = actualParts[i];
    if (rp.startsWith(":")) params[rp.slice(1)] = decodeURIComponent(ap);
    else if (rp !== ap) return null;
  }
  return params;
}
class Router {
  constructor() { this.routes = []; this.globalMiddlewares = []; }
  use(mw) { this.globalMiddlewares.push(mw); return this; }
  _add(method, path_, handlers) { this.routes.push({ method, path: path_, handlers }); return this; }
  get(p, ...h) { return this._add("GET", p, h); }
  post(p, ...h) { return this._add("POST", p, h); }
  put(p, ...h) { return this._add("PUT", p, h); }
  patch(p, ...h) { return this._add("PATCH", p, h); }
  delete(p, ...h) { return this._add("DELETE", p, h); }
  mount(prefix, subRouter) {
    subRouter.routes.forEach((r) => {
      const handlers = [...subRouter.globalMiddlewares, ...r.handlers];
      this.routes.push({ method: r.method, path: (prefix + r.path).replace(/\/+$/, "") || "/", handlers });
    });
    return this;
  }
  async _readBody(req) {
    const contentType = req.headers["content-type"] || "";
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks);
    if (contentType.includes("application/json")) {
      if (raw.length === 0) return { body: {}, files: {} };
      try { return { body: JSON.parse(raw.toString("utf8")), files: {} }; }
      catch (e) { throw Object.assign(new Error("بدنه‌ی JSON نامعتبر است"), { status: 400 }); }
    }
    if (contentType.includes("multipart/form-data")) return parseMultipart(raw, contentType);
    if (contentType.includes("application/x-www-form-urlencoded")) {
      const params = new url.URLSearchParams(raw.toString("utf8"));
      const body = {}; for (const [k, v] of params) body[k] = v;
      return { body, files: {} };
    }
    return { body: {}, files: {} };
  }
  handler() {
    return async (req, res) => {
      const parsed = url.parse(req.url, true);
      req.query = parsed.query;
      res.status = (code) => { res.statusCode = code; return res; };
      res.json = (data) => { res.setHeader("Content-Type", "application/json; charset=utf-8"); res.end(JSON.stringify(data)); };
      res.sendFile = (buffer, contentType) => { res.setHeader("Content-Type", contentType || "application/octet-stream"); res.end(buffer); };
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");
      res.setHeader("Referrer-Policy", "no-referrer");
      res.setHeader("Access-Control-Allow-Origin", env.CORS_ORIGIN);
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
      if (req.method === "OPTIONS") { res.statusCode = 204; return res.end(); }
      try {
        if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
          const { body, files } = await this._readBody(req);
          req.body = body; req.files = files;
        } else { req.body = {}; req.files = {}; }
        const pathname = parsed.pathname;
        const match = this.routes.find((r) => r.method === req.method && matchRoute(r.path, pathname));
        if (!match) { res.status(404).json({ error: "مسیر یافت نشد" }); return; }
        req.params = matchRoute(match.path, pathname) || {};
        const chain = [...this.globalMiddlewares, ...match.handlers];
        let i = 0;
        const next = (err) => {
          if (err) return this._handleError(err, res);
          const fn = chain[i++];
          if (!fn) return;
          Promise.resolve(fn(req, res, next)).catch((e) => this._handleError(e, res));
        };
        next();
      } catch (e) { this._handleError(e, res); }
    };
  }
  _handleError(err, res) {
    const status = err.status || 500;
    if (status >= 500) console.error(err);
    if (!res.headersSent) {
      const payload = Object.assign({ error: err.publicMessage || err.message || "خطای سرور" }, err.publicData || {});
      res.status(status).json(payload);
    }
  }
  listen(port, cb) { const server = http.createServer(this.handler()); server.listen(port, cb); return server; }
}

/* ================= سرویس حساب کاربری ================= */
function httpError(status, message) { const e = new Error(message); e.status = status; e.publicMessage = message; return e; }
function issueTokenPair(user, { userAgent, ip } = {}) {
  const accessToken = jwtSign({ sub: user.id, role: user.role || "user" }, env.JWT_ACCESS_SECRET, { expiresInSeconds: env.ACCESS_TOKEN_TTL });
  const refreshToken = crypto.randomBytes(48).toString("hex");
  const expiresAt = new Date(Date.now() + env.REFRESH_TOKEN_TTL * 1000).toISOString();
  SessionRepo.create({ userId: user.id, refreshToken, userAgent, ip, expiresAt });
  return { accessToken, refreshToken, expiresIn: env.ACCESS_TOKEN_TTL };
}
function publicUser(user) { if (!user) return null; const { passwordHash, ...rest } = user; return rest; }

function maybePromoteAdmin(user) {
  if (!user || !user.email) return user;
  if (env.ADMIN_EMAILS.includes(user.email.toLowerCase()) && user.role !== "admin") {
    return UserRepo.update(user.id, { role: "admin" });
  }
  return user;
}
function isVipActive(user) {
  if (!user || !user.vip || !user.vip.active) return false;
  if (user.vip.expiresAt && new Date(user.vip.expiresAt).getTime() < Date.now()) return false;
  return true;
}
function withFreshVipState(user) {
  // انقضای تنبل: اگه تاریخ گذشته بود، همینجا غیرفعالش می‌کنیم
  if (user && user.vip && user.vip.active && user.vip.expiresAt && new Date(user.vip.expiresAt).getTime() < Date.now()) {
    return UserRepo.update(user.id, { vip: Object.assign({}, user.vip, { active: false }) });
  }
  return user;
}

async function sendVerificationCode(user, method) {
  const code = String(crypto.randomInt(100000, 999999));
  TokenRepo.invalidateAllForUser(user.id, "contact_verify");
  TokenRepo.create({ userId: user.id, type: "contact_verify", code, expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString() });
  if (method === "email") {
    await mailerSend({ to: user.email, subject: "کد تایید حساب - پروتکل آیرون", body: `کد تایید حساب شما: ${code}\nاین کد تا ۱۰ دقیقه معتبر است.` });
  } else {
    await smsSend({ to: user.phone, text: `کد تایید حساب پروتکل آیرون: ${code} (تا ۱۰ دقیقه معتبر است)` });
  }
}

const AuthService = {
  async register({ name, email, phone, password }, ctx = {}) {
    if (!isNonEmptyString(name)) throw httpError(400, "نام الزامی است");
    if (!email && !phone) throw httpError(400, "ایمیل یا شماره موبایل الزامی است");
    if (email && !isValidEmail(email)) throw httpError(400, "ایمیل نامعتبر است");
    if (phone && !isValidIranPhone(phone)) throw httpError(400, "شماره موبایل نامعتبر است (فرمت 09xxxxxxxxx)");
    if (!isStrongPassword(password)) throw httpError(400, "رمز عبور باید حداقل ۸ کاراکتر باشد");
    if (email && UserRepo.findByEmail(email)) throw httpError(409, "این ایمیل قبلاً ثبت شده است");
    if (phone && UserRepo.findByPhone(phone)) throw httpError(409, "این شماره موبایل قبلاً ثبت شده است");
    const user = UserRepo.create({
      name: name.trim(), email: email ? email.toLowerCase() : null, phone: phone || null,
      passwordHash: hashPassword(password), role: "user", emailVerified: false, phoneVerified: false, avatarUrl: null,
      profile: { age: null, height: null, weight: null, gender: null, trainingGoal: null, trainingLevel: null, trainingHistory: null },
      vip: { active: false, plan: null, expiresAt: null },
    });
    SecurityLog.log({ userId: user.id, type: "register", ip: ctx.ip, meta: { email, phone } });
    const method = email ? "email" : "phone";
    await sendVerificationCode(user, method);
    return { userId: user.id, method, needsVerification: true };
  },
  async resendVerification({ userId }, ctx = {}) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const method = user.email ? "email" : "phone";
    await sendVerificationCode(user, method);
    SecurityLog.log({ userId, type: "verification_resent", ip: ctx.ip });
    return { sent: true, method };
  },
  async verifyRegistration({ userId, code }, ctx = {}) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const valid = TokenRepo.findValid({ userId, type: "contact_verify", code });
    if (!valid) throw httpError(400, "کد وارد شده نامعتبر یا منقضی شده است");
    TokenRepo.markUsed(valid.id);
    const patch = user.email ? { emailVerified: true } : { phoneVerified: true };
    const updated = UserRepo.update(userId, patch);
    SecurityLog.log({ userId, type: "account_verified", ip: ctx.ip });
    const fresh = withFreshVipState(maybePromoteAdmin(updated));
    return { user: publicUser(fresh), ...issueTokenPair(fresh, ctx) };
  },
  async login({ email, phone, password }, ctx = {}) {
    if (!password) throw httpError(400, "رمز عبور الزامی است");
    const user = email ? UserRepo.findByEmail(email) : UserRepo.findByPhone(phone);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      SecurityLog.log({ type: "login_failed", ip: ctx.ip, meta: { email, phone } });
      throw httpError(401, "ایمیل/شماره یا رمز عبور اشتباه است");
    }
    if (!user.emailVerified && !user.phoneVerified) {
      const method = user.email ? "email" : "phone";
      await sendVerificationCode(user, method);
      throw Object.assign(httpError(403, "حساب هنوز تایید نشده؛ کد جدید ارسال شد"), { publicData: { userId: user.id, method, needsVerification: true } });
    }
    SecurityLog.log({ userId: user.id, type: "login_success", ip: ctx.ip });
    const freshUser = withFreshVipState(maybePromoteAdmin(user));
    return { user: publicUser(freshUser), ...issueTokenPair(freshUser, ctx) };
  },
  async requestPhoneOtp({ phone }, ctx = {}) {
    if (!isValidIranPhone(phone)) throw httpError(400, "شماره موبایل نامعتبر است");
    let user = UserRepo.findByPhone(phone);
    if (!user) {
      user = UserRepo.create({
        name: "کاربر جدید", email: null, phone, passwordHash: null, role: "user", emailVerified: false, phoneVerified: false, avatarUrl: null,
        profile: { age: null, height: null, weight: null, gender: null, trainingGoal: null, trainingLevel: null, trainingHistory: null },
        vip: { active: false, plan: null, expiresAt: null },
      });
    }
    const code = String(crypto.randomInt(100000, 999999));
    TokenRepo.invalidateAllForUser(user.id, "phone_otp");
    TokenRepo.create({ userId: user.id, type: "phone_otp", code, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
    await smsSend({ to: phone, text: `کد ورود شما به پروتکل آیرون: ${code} (تا ۵ دقیقه معتبر است)` });
    SecurityLog.log({ userId: user.id, type: "otp_requested", ip: ctx.ip });
    return { sent: true };
  },
  async verifyPhoneOtp({ phone, code }, ctx = {}) {
    const user = UserRepo.findByPhone(phone);
    if (!user) throw httpError(404, "کاربری با این شماره پیدا نشد");
    const valid = TokenRepo.findValid({ userId: user.id, type: "phone_otp", code });
    if (!valid) throw httpError(400, "کد وارد شده نامعتبر یا منقضی شده است");
    TokenRepo.markUsed(valid.id);
    SecurityLog.log({ userId: user.id, type: "otp_login_success", ip: ctx.ip });
    const fresh = withFreshVipState(maybePromoteAdmin(user));
    return { user: publicUser(fresh), ...issueTokenPair(fresh, ctx) };
  },
  async refresh({ refreshToken }) {
    if (!refreshToken) throw httpError(400, "توکن رفرش ارسال نشده است");
    const session = SessionRepo.findByToken(refreshToken);
    if (!session || new Date(session.expiresAt).getTime() < Date.now()) throw httpError(401, "نشست منقضی شده؛ دوباره وارد شوید");
    const user = UserRepo.findById(session.userId);
    if (!user) throw httpError(401, "کاربر یافت نشد");
    SessionRepo.revoke(refreshToken);
    const fresh = withFreshVipState(maybePromoteAdmin(user));
    return { user: publicUser(fresh), ...issueTokenPair(fresh) };
  },
  async logout({ refreshToken }) { if (refreshToken) SessionRepo.revoke(refreshToken); return { ok: true }; },
  async logoutAllDevices(userId) {
    const count = SessionRepo.revokeAllForUser(userId);
    SecurityLog.log({ userId, type: "logout_all_devices", meta: { revoked: count } });
    return { ok: true, revoked: count };
  },
  async forgotPassword({ email }, ctx = {}) {
    if (!isValidEmail(email)) throw httpError(400, "ایمیل نامعتبر است");
    const user = UserRepo.findByEmail(email);
    if (!user) return { sent: true };
    const code = crypto.randomBytes(24).toString("hex");
    TokenRepo.invalidateAllForUser(user.id, "password_reset");
    TokenRepo.create({ userId: user.id, type: "password_reset", code, expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() });
    const resetLink = `https://YOUR-FRONTEND-DOMAIN/reset-password?uid=${user.id}&code=${code}`;
    await mailerSend({ to: email, subject: "بازیابی رمز عبور - پروتکل آیرون", body: `برای بازیابی رمز عبور روی این لینک بزن (تا ۱ ساعت معتبر است):\n${resetLink}` });
    SecurityLog.log({ userId: user.id, type: "password_reset_requested", ip: ctx.ip });
    return { sent: true };
  },
  async resetPassword({ userId, code, newPassword }, ctx = {}) {
    if (!isStrongPassword(newPassword)) throw httpError(400, "رمز عبور باید حداقل ۸ کاراکتر باشد");
    const valid = TokenRepo.findValid({ userId, type: "password_reset", code });
    if (!valid) throw httpError(400, "لینک بازیابی نامعتبر یا منقضی شده است");
    TokenRepo.markUsed(valid.id);
    UserRepo.update(userId, { passwordHash: hashPassword(newPassword) });
    SessionRepo.revokeAllForUser(userId);
    SecurityLog.log({ userId, type: "password_reset_completed", ip: ctx.ip });
    return { ok: true };
  },
};

/* ================= سرویس پروفایل کاربر ================= */
const UPLOAD_DIR = env.STORAGE_DIR ? path.join(env.STORAGE_DIR, "uploads") : path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const ALLOWED_AVATAR_MIME = ["image/png", "image/jpeg", "image/webp"];
const MAX_AVATAR_BYTES = 3 * 1024 * 1024;
const _bodyStats = collection("body_stats");
const _personalRecords = collection("personal_records");

const UsersService = {
  getMe(userId) {
    let user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    user = withFreshVipState(maybePromoteAdmin(user));
    return publicUser(user);
  },
  updateMe(userId, patch) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const topPatch = {};
    if (patch.name !== undefined) topPatch.name = patch.name;
    if (topPatch.name !== undefined && !isNonEmptyString(topPatch.name)) throw httpError(400, "نام نامعتبر است");
    const profilePatch = Object.assign({}, user.profile);
    ["age", "height", "weight", "gender", "trainingGoal", "trainingLevel", "trainingHistory"].forEach((k) => { if (patch[k] !== undefined) profilePatch[k] = patch[k]; });
    if (profilePatch.age !== undefined && profilePatch.age !== null && !isNumberInRange(profilePatch.age, 10, 100)) throw httpError(400, "سن نامعتبر است");
    if (profilePatch.height !== undefined && profilePatch.height !== null && !isNumberInRange(profilePatch.height, 100, 250)) throw httpError(400, "قد نامعتبر است");
    if (profilePatch.weight !== undefined && profilePatch.weight !== null && !isNumberInRange(profilePatch.weight, 25, 300)) throw httpError(400, "وزن نامعتبر است");
    const updated = UserRepo.update(userId, Object.assign({}, topPatch, { profile: profilePatch }));
    return publicUser(updated);
  },
  uploadAvatar(userId, file) {
    if (!file) throw httpError(400, "فایلی ارسال نشده است");
    if (!ALLOWED_AVATAR_MIME.includes(file.mimeType)) throw httpError(400, "فقط فرمت‌های png، jpg و webp مجاز است");
    if (file.size > MAX_AVATAR_BYTES) throw httpError(400, "حجم عکس نباید بیشتر از ۳ مگابایت باشد");
    const ext = file.mimeType === "image/png" ? "png" : file.mimeType === "image/webp" ? "webp" : "jpg";
    const filename = `${userId}_${crypto.randomBytes(6).toString("hex")}.${ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
    const updated = UserRepo.update(userId, { avatarUrl: `/uploads/${filename}` });
    return publicUser(updated);
  },
  deleteAccount(userId, password) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    if (user.passwordHash && !verifyPassword(password || "", user.passwordHash)) throw httpError(401, "رمز عبور اشتباه است");
    SessionRepo.revokeAllForUser(userId);
    UserRepo.remove(userId);
    SecurityLog.log({ userId, type: "account_deleted" });
    return { ok: true };
  },
  addBodyStat(userId, { weight, waist, arm, chest, thigh, date }) {
    return _bodyStats.insert({ userId, weight, waist, arm, chest, thigh, date: date || new Date().toISOString() });
  },
  listBodyStats(userId) { return _bodyStats.findMany((s) => s.userId === userId).sort((a, b) => new Date(a.date) - new Date(b.date)); },
  addPersonalRecord(userId, { exerciseName, weight, reps, date }) {
    if (!isNonEmptyString(exerciseName)) throw httpError(400, "نام حرکت الزامی است");
    return _personalRecords.insert({ userId, exerciseName, weight, reps: reps || null, date: date || new Date().toISOString() });
  },
  listPersonalRecords(userId) { return _personalRecords.findMany((p) => p.userId === userId).sort((a, b) => (b.weight || 0) - (a.weight || 0)); },
};

/* ================= سرویس اشتراک VIP (فقط کد، بدون درگاه پرداخت) ================= */
const _vipCodes = collection("vip_codes");
function genVipCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 8; i++) s += chars[crypto.randomInt(0, chars.length)];
  return "IRON-" + s;
}
const VipService = {
  redeem(userId, rawCode) {
    if (!isNonEmptyString(rawCode)) throw httpError(400, "کد رو وارد کن");
    const code = rawCode.trim().toUpperCase();
    const rec = _vipCodes.findOne((c) => c.code === code);
    if (!rec || !rec.isActive) throw httpError(404, "کد نامعتبره یا غیرفعال شده");
    if (rec.expiresAt && new Date(rec.expiresAt).getTime() < Date.now()) throw httpError(400, "این کد منقضی شده");
    if (rec.maxUses !== null && rec.usedCount >= rec.maxUses) throw httpError(400, "ظرفیت استفاده از این کد تموم شده");
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const now = Date.now();
    const baseTime = user.vip && user.vip.active && user.vip.expiresAt && new Date(user.vip.expiresAt).getTime() > now
      ? new Date(user.vip.expiresAt).getTime() : now;
    const newExpiresAt = new Date(baseTime + rec.durationDays * 86400000).toISOString();
    const updated = UserRepo.update(userId, { vip: { active: true, plan: rec.planLabel || "هدیه", expiresAt: newExpiresAt } });
    _vipCodes.update(rec.id, { usedCount: rec.usedCount + 1 });
    SecurityLog.log({ userId, type: "vip_redeemed", meta: { code } });
    return { ok: true, vip: updated.vip };
  },
  status(userId) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const fresh = withFreshVipState(user);
    return { vip: fresh.vip || { active: false, plan: null, expiresAt: null } };
  },
};

/* ================= پلن‌های اشتراک ================= */
const _plans = collection("vip_plans");
function ensureDefaultPlans() {
  if (_plans.all().length > 0) return;
  [
    { code: "monthly", title: "یک ماهه", durationDays: 30, priceToman: 159000, priceUsdt: 4, isActive: true },
    { code: "quarterly", title: "سه ماهه", durationDays: 90, priceToman: 369000, priceUsdt: 9, isActive: true },
    { code: "semiannual", title: "شش ماهه", durationDays: 180, priceToman: 699000, priceUsdt: 17, isActive: true },
  ].forEach((p) => _plans.insert(p));
}
const PlanService = {
  listPublic() { return _plans.all().filter((p) => p.isActive); },
  listAll(adminId) { requireAdminUser(adminId); return _plans.all(); },
  update(adminId, id, patch) {
    requireAdminUser(adminId);
    const allowed = {};
    ["title", "priceToman", "priceUsdt", "durationDays", "isActive"].forEach((k) => { if (patch[k] !== undefined) allowed[k] = patch[k]; });
    const updated = _plans.update(id, allowed);
    if (!updated) throw httpError(404, "پلن یافت نشد");
    return updated;
  },
};
function grantVipDaysToUser(userId, days, planLabel) {
  const user = UserRepo.findById(userId);
  if (!user) throw httpError(404, "کاربر یافت نشد");
  const now = Date.now();
  const baseTime = user.vip && user.vip.active && user.vip.expiresAt && new Date(user.vip.expiresAt).getTime() > now
    ? new Date(user.vip.expiresAt).getTime() : now;
  const expiresAt = new Date(baseTime + days * 86400000).toISOString();
  return UserRepo.update(userId, { vip: { active: true, plan: planLabel || "اشتراک", expiresAt } });
}

/* ================= کدهای تخفیف (برای پرداخت، نه فعال‌سازی مستقیم) ================= */
const _discountCodes = collection("discount_codes");
const DiscountService = {
  listAll(adminId) { requireAdminUser(adminId); return _discountCodes.all(); },
  create(adminId, { code, percentOff, amountOff, maxUses, expiresAt }) {
    requireAdminUser(adminId);
    if (!percentOff && !amountOff) throw httpError(400, "درصد یا مقدار تخفیف رو مشخص کن");
    const finalCode = (code && code.trim()) ? code.trim().toUpperCase() : "SALE-" + crypto.randomBytes(3).toString("hex").toUpperCase();
    if (_discountCodes.findOne((c) => c.code === finalCode)) throw httpError(409, "این کد قبلاً وجود دارد");
    return _discountCodes.insert({
      code: finalCode, percentOff: percentOff ? Number(percentOff) : null, amountOff: amountOff ? Number(amountOff) : null,
      maxUses: maxUses ? Number(maxUses) : null, usedCount: 0, expiresAt: expiresAt || null, isActive: true,
    });
  },
  toggle(adminId, id, isActive) {
    requireAdminUser(adminId);
    const updated = _discountCodes.update(id, { isActive: !!isActive });
    if (!updated) throw httpError(404, "کد یافت نشد");
    return updated;
  },
  validateAndCompute(rawCode, baseAmount) {
    if (!rawCode) return { discountCode: null, finalAmount: baseAmount };
    const code = rawCode.trim().toUpperCase();
    const rec = _discountCodes.findOne((c) => c.code === code);
    if (!rec || !rec.isActive) throw httpError(404, "کد تخفیف نامعتبره");
    if (rec.expiresAt && new Date(rec.expiresAt).getTime() < Date.now()) throw httpError(400, "کد تخفیف منقضی شده");
    if (rec.maxUses !== null && rec.usedCount >= rec.maxUses) throw httpError(400, "ظرفیت این کد تخفیف تموم شده");
    let finalAmount = baseAmount;
    if (rec.percentOff) finalAmount = Math.round(baseAmount * (1 - rec.percentOff / 100));
    if (rec.amountOff) finalAmount = Math.max(0, finalAmount - rec.amountOff);
    return { discountCode: rec, finalAmount };
  },
  markUsed(rec) { if (rec) _discountCodes.update(rec.id, { usedCount: rec.usedCount + 1 }); },
};

/* ================= پرداخت‌ها ================= */
const _payments = collection("payment_transactions");
const PaymentService = {
  walletInfo() {
    return { address: env.USDT_WALLET_ADDRESS || null, network: env.USDT_WALLET_NETWORK, gatewayEnabled: !!env.ZARINPAL_MERCHANT_ID };
  },
  submitUsdt(userId, { planId, txHash, amountUsdt, discountCode }) {
    const plan = _plans.findById(planId);
    if (!plan || !plan.isActive) throw httpError(404, "پلن نامعتبره");
    if (!env.USDT_WALLET_ADDRESS) throw httpError(400, "پرداخت تتری فعلاً فعال نشده");
    if (!isNonEmptyString(txHash)) throw httpError(400, "شناسه‌ی تراکنش (Tx Hash) رو وارد کن");
    let expectedAmount = plan.priceUsdt;
    let discRec = null;
    if (discountCode) {
      const r = DiscountService.validateAndCompute(discountCode, plan.priceUsdt);
      discRec = r.discountCode; expectedAmount = r.finalAmount;
    }
    const rec = _payments.insert({
      userId, planId, provider: "usdt_wallet", providerRef: txHash.trim(), amountToman: null, amountUsdt: Number(amountUsdt) || null,
      expectedAmountUsdt: expectedAmount, status: "pending", discountCode: discountCode || null, receiptCode: null, paidAt: null,
    });
    if (discRec) DiscountService.markUsed(discRec);
    SecurityLog.log({ userId, type: "usdt_payment_submitted", meta: { planId, txHash } });
    return rec;
  },
  mine(userId) { return _payments.findMany((p) => p.userId === userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); },
  listPending(adminId) { requireAdminUser(adminId); return _payments.findMany((p) => p.status === "pending").sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)); },
  listAll(adminId) { requireAdminUser(adminId); return _payments.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 200); },
  approve(adminId, paymentId) {
    requireAdminUser(adminId);
    const p = _payments.findById(paymentId);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    if (p.status !== "pending") throw httpError(400, "این تراکنش قبلاً بررسی شده");
    const plan = _plans.findById(p.planId);
    if (!plan) throw httpError(404, "پلن این تراکنش یافت نشد");
    grantVipDaysToUser(p.userId, plan.durationDays, plan.title);
    const updated = _payments.update(paymentId, { status: "success", paidAt: new Date().toISOString() });
    SecurityLog.log({ userId: adminId, type: "payment_approved", meta: { paymentId, targetUser: p.userId } });
    return updated;
  },
  reject(adminId, paymentId, reason) {
    requireAdminUser(adminId);
    const p = _payments.findById(paymentId);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    const updated = _payments.update(paymentId, { status: "rejected", rejectReason: reason || null });
    SecurityLog.log({ userId: adminId, type: "payment_rejected", meta: { paymentId } });
    return updated;
  },
  async zarinpalRequest(userId, { planId, discountCode }) {
    if (!env.ZARINPAL_MERCHANT_ID) throw httpError(400, "این روش پرداخت فعلاً فعال نشده");
    const plan = _plans.findById(planId);
    if (!plan || !plan.isActive) throw httpError(404, "پلن نامعتبره");
    let amount = plan.priceToman;
    let discRec = null;
    if (discountCode) {
      const r = DiscountService.validateAndCompute(discountCode, plan.priceToman);
      discRec = r.discountCode; amount = r.finalAmount;
    }
    const callbackUrl = (env.FRONTEND_URL || "") + "/#/payment-callback";
    const res = await fetch("https://api.zarinpal.com/pg/v4/payment/request.json", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ merchant_id: env.ZARINPAL_MERCHANT_ID, amount: amount * 10, callback_url: callbackUrl, description: "خرید اشتراک VIP - " + plan.title }),
    });
    const data = await res.json();
    if (!data.data || !data.data.authority) throw httpError(502, "درگاه پرداخت پاسخ نداد");
    _payments.insert({
      userId, planId, provider: "zarinpal", providerRef: data.data.authority, amountToman: amount, amountUsdt: null,
      status: "pending", discountCode: discountCode || null, receiptCode: null, paidAt: null,
    });
    if (discRec) DiscountService.markUsed(discRec);
    return { paymentUrl: "https://www.zarinpal.com/pg/StartPay/" + data.data.authority };
  },
  async zarinpalCallback({ Authority, Status }) {
    const p = _payments.findOne((x) => x.provider === "zarinpal" && x.providerRef === Authority);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    if (Status !== "OK") { _payments.update(p.id, { status: "failed" }); return { ok: false }; }
    const res = await fetch("https://api.zarinpal.com/pg/v4/payment/verify.json", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ merchant_id: env.ZARINPAL_MERCHANT_ID, amount: p.amountToman * 10, authority: Authority }),
    });
    const data = await res.json();
    if (data.data && (data.data.code === 100 || data.data.code === 101)) {
      const plan = _plans.findById(p.planId);
      grantVipDaysToUser(p.userId, plan.durationDays, plan.title);
      _payments.update(p.id, { status: "success", paidAt: new Date().toISOString(), receiptCode: String(data.data.ref_id || "") });
      return { ok: true };
    }
    _payments.update(p.id, { status: "failed" });
    return { ok: false };
  },
};

/* ================= محدودیت پیام روزانه‌ی مربی هوشمند (۵ پیام رایگان، VIP نامحدود) ================= */
const _aiUsage = collection("ai_usage_daily");
const FREE_DAILY_AI_LIMIT = 5;
const AiService = {
  checkAndIncrement(userId) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    if (isVipActive(withFreshVipState(user))) return { allowed: true, remaining: null, unlimited: true };
    const today = new Date().toISOString().slice(0, 10);
    let rec = _aiUsage.findOne((r) => r.userId === userId && r.date === today);
    if (!rec) rec = _aiUsage.insert({ userId, date: today, count: 0 });
    if (rec.count >= FREE_DAILY_AI_LIMIT) return { allowed: false, remaining: 0, unlimited: false };
    const updated = _aiUsage.update(rec.id, { count: rec.count + 1 });
    return { allowed: true, remaining: FREE_DAILY_AI_LIMIT - updated.count, unlimited: false };
  },
  status(userId) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    if (isVipActive(withFreshVipState(user))) return { remaining: null, unlimited: true, limit: null };
    const today = new Date().toISOString().slice(0, 10);
    const rec = _aiUsage.findOne((r) => r.userId === userId && r.date === today);
    const used = rec ? rec.count : 0;
    return { remaining: Math.max(0, FREE_DAILY_AI_LIMIT - used), unlimited: false, limit: FREE_DAILY_AI_LIMIT };
  },
};

/* ================= سرویس پنل مدیریت ================= */
function requireAdminUser(userId) {
  const user = UserRepo.findById(userId);
  if (!user || user.role !== "admin") throw httpError(403, "دسترسی نداری");
  return user;
}
const AdminService = {
  stats(adminId) {
    requireAdminUser(adminId);
    const all = UserRepo.all();
    const now = Date.now();
    const vipCount = all.filter((u) => u.vip && u.vip.active && (!u.vip.expiresAt || new Date(u.vip.expiresAt).getTime() > now)).length;
    const todayKey = new Date().toISOString().slice(0, 10);
    const signupsToday = all.filter((u) => (u.createdAt || "").slice(0, 10) === todayKey).length;
    return { totalUsers: all.length, vipUsers: vipCount, signupsToday, totalVipCodes: _vipCodes.all().length };
  },
  listUsers(adminId, search) {
    requireAdminUser(adminId);
    let all = UserRepo.all().map(publicUser).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    if (search) {
      const q = search.toLowerCase();
      all = all.filter((u) => (u.name || "").toLowerCase().includes(q) || (u.email || "").toLowerCase().includes(q) || (u.phone || "").includes(q));
    }
    return all.slice(0, 200);
  },
  setUserVip(adminId, userId, { active, days }) {
    requireAdminUser(adminId);
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    if (active === false) {
      const updated = UserRepo.update(userId, { vip: { active: false, plan: null, expiresAt: null } });
      SecurityLog.log({ userId: adminId, type: "admin_vip_revoked", meta: { targetUser: userId } });
      return publicUser(updated);
    }
    const d = Number(days) || 30;
    const now = Date.now();
    const baseTime = user.vip && user.vip.active && user.vip.expiresAt && new Date(user.vip.expiresAt).getTime() > now
      ? new Date(user.vip.expiresAt).getTime() : now;
    const expiresAt = new Date(baseTime + d * 86400000).toISOString();
    const updated = UserRepo.update(userId, { vip: { active: true, plan: "هدیه‌ی مدیر", expiresAt } });
    SecurityLog.log({ userId: adminId, type: "admin_vip_granted", meta: { targetUser: userId, days: d } });
    return publicUser(updated);
  },
  listVipCodes(adminId) {
    requireAdminUser(adminId);
    return _vipCodes.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  },
  createVipCode(adminId, { code, durationDays, maxUses, expiresAt, planLabel }) {
    requireAdminUser(adminId);
    const d = Number(durationDays);
    if (!d || d <= 0) throw httpError(400, "مدت اعتبار (روز) الزامی است");
    const finalCode = (code && code.trim()) ? code.trim().toUpperCase() : genVipCode();
    if (_vipCodes.findOne((c) => c.code === finalCode)) throw httpError(409, "این کد قبلاً ساخته شده");
    return _vipCodes.insert({
      code: finalCode, durationDays: d,
      maxUses: maxUses !== undefined && maxUses !== null && maxUses !== "" ? Number(maxUses) : null,
      usedCount: 0, expiresAt: expiresAt || null, isActive: true, planLabel: planLabel || "هدیه",
    });
  },
  toggleVipCode(adminId, codeId, isActive) {
    requireAdminUser(adminId);
    const updated = _vipCodes.update(codeId, { isActive: !!isActive });
    if (!updated) throw httpError(404, "کد یافت نشد");
    return updated;
  },
};


/* ================= کنترلرها ================= */
function ctxFrom(req) { return { ip: req.socket.remoteAddress, userAgent: req.headers["user-agent"] }; }
const AuthController = {
  register: (req, res, next) => AuthService.register(req.body, ctxFrom(req)).then((r) => res.status(201).json(r)).catch(next),
  verifyRegistration: (req, res, next) => AuthService.verifyRegistration(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  resendVerification: (req, res, next) => AuthService.resendVerification(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  login: (req, res, next) => AuthService.login(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  requestOtp: (req, res, next) => AuthService.requestPhoneOtp(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  verifyOtp: (req, res, next) => AuthService.verifyPhoneOtp(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  refresh: (req, res, next) => AuthService.refresh(req.body).then((r) => res.status(200).json(r)).catch(next),
  logout: (req, res, next) => AuthService.logout(req.body).then((r) => res.status(200).json(r)).catch(next),
  logoutAll: (req, res, next) => AuthService.logoutAllDevices(req.userId).then((r) => res.status(200).json(r)).catch(next),
  forgotPassword: (req, res, next) => AuthService.forgotPassword(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
  resetPassword: (req, res, next) => AuthService.resetPassword(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
};
const UsersController = {
  me: (req, res, next) => { try { res.json(UsersService.getMe(req.userId)); } catch (e) { next(e); } },
  updateMe: (req, res, next) => { try { res.json(UsersService.updateMe(req.userId, req.body)); } catch (e) { next(e); } },
  uploadAvatar: (req, res, next) => { try { res.json(UsersService.uploadAvatar(req.userId, req.files.avatar)); } catch (e) { next(e); } },
  deleteAccount: (req, res, next) => { try { res.json(UsersService.deleteAccount(req.userId, req.body.password)); } catch (e) { next(e); } },
  addBodyStat: (req, res, next) => { try { res.status(201).json(UsersService.addBodyStat(req.userId, req.body)); } catch (e) { next(e); } },
  listBodyStats: (req, res, next) => { try { res.json(UsersService.listBodyStats(req.userId)); } catch (e) { next(e); } },
  addPr: (req, res, next) => { try { res.status(201).json(UsersService.addPersonalRecord(req.userId, req.body)); } catch (e) { next(e); } },
  listPrs: (req, res, next) => { try { res.json(UsersService.listPersonalRecords(req.userId)); } catch (e) { next(e); } },
};

const VipController = {
  redeem: (req, res, next) => { try { res.json(VipService.redeem(req.userId, req.body.code)); } catch (e) { next(e); } },
  status: (req, res, next) => { try { res.json(VipService.status(req.userId)); } catch (e) { next(e); } },
  plans: (req, res, next) => { try { res.json(PlanService.listPublic()); } catch (e) { next(e); } },
  walletInfo: (req, res, next) => { try { res.json(PaymentService.walletInfo()); } catch (e) { next(e); } },
};
const PaymentController = {
  submitUsdt: (req, res, next) => { try { res.status(201).json(PaymentService.submitUsdt(req.userId, req.body)); } catch (e) { next(e); } },
  mine: (req, res, next) => { try { res.json(PaymentService.mine(req.userId)); } catch (e) { next(e); } },
  zarinpalRequest: (req, res, next) => { PaymentService.zarinpalRequest(req.userId, req.body).then((r) => res.json(r)).catch(next); },
  zarinpalCallback: (req, res, next) => {
    PaymentService.zarinpalCallback(req.query).then((r) => {
      const target = (env.FRONTEND_URL || "/") + (r.ok ? "#/payment-success" : "#/payment-failed");
      res.statusCode = 302; res.setHeader("Location", target); res.end();
    }).catch(next);
  },
};
const AdminController = {
  stats: (req, res, next) => { try { res.json(AdminService.stats(req.userId)); } catch (e) { next(e); } },
  listUsers: (req, res, next) => { try { res.json(AdminService.listUsers(req.userId, req.query.search)); } catch (e) { next(e); } },
  setUserVip: (req, res, next) => { try { res.json(AdminService.setUserVip(req.userId, req.params.id, req.body)); } catch (e) { next(e); } },
  listVipCodes: (req, res, next) => { try { res.json(AdminService.listVipCodes(req.userId)); } catch (e) { next(e); } },
  createVipCode: (req, res, next) => { try { res.status(201).json(AdminService.createVipCode(req.userId, req.body)); } catch (e) { next(e); } },
  toggleVipCode: (req, res, next) => { try { res.json(AdminService.toggleVipCode(req.userId, req.params.id, req.body.isActive)); } catch (e) { next(e); } },
  listPlans: (req, res, next) => { try { res.json(PlanService.listAll(req.userId)); } catch (e) { next(e); } },
  updatePlan: (req, res, next) => { try { res.json(PlanService.update(req.userId, req.params.id, req.body)); } catch (e) { next(e); } },
  listDiscountCodes: (req, res, next) => { try { res.json(DiscountService.listAll(req.userId)); } catch (e) { next(e); } },
  createDiscountCode: (req, res, next) => { try { res.status(201).json(DiscountService.create(req.userId, req.body)); } catch (e) { next(e); } },
  toggleDiscountCode: (req, res, next) => { try { res.json(DiscountService.toggle(req.userId, req.params.id, req.body.isActive)); } catch (e) { next(e); } },
  listPendingPayments: (req, res, next) => { try { res.json(PaymentService.listPending(req.userId)); } catch (e) { next(e); } },
  listAllPayments: (req, res, next) => { try { res.json(PaymentService.listAll(req.userId)); } catch (e) { next(e); } },
  approvePayment: (req, res, next) => { try { res.json(PaymentService.approve(req.userId, req.params.id)); } catch (e) { next(e); } },
  rejectPayment: (req, res, next) => { try { res.json(PaymentService.reject(req.userId, req.params.id, req.body.reason)); } catch (e) { next(e); } },
};

const AiController = {
  check: (req, res, next) => { try { res.json(AiService.checkAndIncrement(req.userId)); } catch (e) { next(e); } },
  status: (req, res, next) => { try { res.json(AiService.status(req.userId)); } catch (e) { next(e); } },
};

/* ================= مسیرها ================= */
const authRoutes = new Router();
authRoutes.post("/register", rateLimit({ windowMs: 60000, max: 8, keyPrefix: "register" }), AuthController.register);
authRoutes.post("/verify-registration", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "verify-reg" }), AuthController.verifyRegistration);
authRoutes.post("/resend-verification", rateLimit({ windowMs: 60000, max: 5, keyPrefix: "resend-verify" }), AuthController.resendVerification);
authRoutes.post("/login", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "login" }), AuthController.login);
authRoutes.post("/otp/request", rateLimit({ windowMs: 60000, max: 5, keyPrefix: "otp-req" }), AuthController.requestOtp);
authRoutes.post("/otp/verify", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "otp-verify" }), AuthController.verifyOtp);
authRoutes.post("/refresh", AuthController.refresh);
authRoutes.post("/logout", AuthController.logout);
authRoutes.post("/logout-all", requireAuth, AuthController.logoutAll);
authRoutes.post("/forgot-password", rateLimit({ windowMs: 60000, max: 5, keyPrefix: "forgot" }), AuthController.forgotPassword);
authRoutes.post("/reset-password", rateLimit({ windowMs: 60000, max: 8, keyPrefix: "reset" }), AuthController.resetPassword);

const usersRoutes = new Router();
usersRoutes.use(requireAuth);
usersRoutes.get("/me", UsersController.me);
usersRoutes.put("/me", UsersController.updateMe);
usersRoutes.post("/me/avatar", UsersController.uploadAvatar);
usersRoutes.delete("/me", UsersController.deleteAccount);
usersRoutes.post("/me/body-stats", UsersController.addBodyStat);
usersRoutes.get("/me/body-stats", UsersController.listBodyStats);
usersRoutes.post("/me/prs", UsersController.addPr);
usersRoutes.get("/me/prs", UsersController.listPrs);

const vipRoutes = new Router();
vipRoutes.use(requireAuth);
vipRoutes.post("/redeem", rateLimit({ windowMs: 60000, max: 15, keyPrefix: "vip-redeem" }), VipController.redeem);
vipRoutes.get("/status", VipController.status);

const paymentRoutes = new Router();
paymentRoutes.use(requireAuth);
paymentRoutes.post("/usdt/submit", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "usdt-submit" }), PaymentController.submitUsdt);
paymentRoutes.get("/mine", PaymentController.mine);
paymentRoutes.post("/zarinpal/request", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "zp-req" }), PaymentController.zarinpalRequest);

const aiRoutes = new Router();
aiRoutes.use(requireAuth);
aiRoutes.post("/check", rateLimit({ windowMs: 60000, max: 30, keyPrefix: "ai-check" }), AiController.check);
aiRoutes.get("/status", AiController.status);

const adminRoutes = new Router();
adminRoutes.use(requireAuth);
adminRoutes.get("/stats", AdminController.stats);
adminRoutes.get("/users", AdminController.listUsers);
adminRoutes.put("/users/:id/vip", AdminController.setUserVip);
adminRoutes.get("/vip-codes", AdminController.listVipCodes);
adminRoutes.post("/vip-codes", AdminController.createVipCode);
adminRoutes.put("/vip-codes/:id/toggle", AdminController.toggleVipCode);
adminRoutes.get("/plans", AdminController.listPlans);
adminRoutes.put("/plans/:id", AdminController.updatePlan);
adminRoutes.get("/discount-codes", AdminController.listDiscountCodes);
adminRoutes.post("/discount-codes", AdminController.createDiscountCode);
adminRoutes.put("/discount-codes/:id/toggle", AdminController.toggleDiscountCode);
adminRoutes.get("/payments/pending", AdminController.listPendingPayments);
adminRoutes.get("/payments", AdminController.listAllPayments);
adminRoutes.put("/payments/:id/approve", AdminController.approvePayment);
adminRoutes.put("/payments/:id/reject", AdminController.rejectPayment);

/* ================= پنل مدیریت (صفحه‌ی وب ساده، بدون نیاز به دیپلوی جدا) ================= */
const ADMIN_PAGE_HTML = `<!DOCTYPE html>
<html dir="rtl" lang="fa"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل مدیریت | پروتکل آیرون</title>
<style>
body{font-family:Tahoma,Vazirmatn,sans-serif;background:#0A0B09;color:#F3EEDD;margin:0;padding:16px;}
.panel{background:#131913;border:1px solid rgba(76,122,82,.3);border-radius:10px;padding:16px;margin-bottom:14px;}
input,select{background:#0A0B09;color:#F3EEDD;border:1px solid rgba(76,122,82,.4);border-radius:6px;padding:8px;margin:4px 0;width:100%;box-sizing:border-box;}
button{background:#D8AE52;color:#1A140B;border:none;border-radius:6px;padding:8px 14px;font-weight:700;cursor:pointer;margin:4px 2px;}
button.danger{background:#FF5252;color:#1A0E0C;}
button.outline{background:transparent;border:1px solid #D8AE52;color:#D8AE52;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th,td{padding:6px;text-align:right;border-bottom:1px solid rgba(255,255,255,.08);}
.statgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}
.statcard{background:rgba(216,174,82,.08);border:1px solid rgba(216,174,82,.3);border-radius:8px;padding:12px;text-align:center;}
.statnum{font-size:22px;font-weight:800;color:#F2CE7A;}
.err{color:#FF5252;font-size:12px;margin-top:6px;}
.badge{font-size:10px;padding:2px 6px;border-radius:10px;}
.badge.on{background:rgba(61,220,116,.2);color:#3DDC74;}
.badge.off{background:rgba(255,82,82,.15);color:#FF5252;}
h2{font-size:16px;} h3{font-size:14px;color:#D8AE52;}
</style></head>
<body>
<div id="app">در حال بارگذاری...</div>
<script>
const T={access:null};
async function api(path,opts={}){
  const headers={"Content-Type":"application/json"};
  if(T.access) headers.Authorization="Bearer "+T.access;
  const res=await fetch(path,Object.assign({headers},opts));
  const data=await res.json().catch(()=>null);
  if(!res.ok) throw new Error((data&&data.error)||"خطا");
  return data;
}
let me=null, err="";
function render(){
  const app=document.getElementById("app");
  if(!me){
    app.innerHTML='<div class="panel" style="max-width:360px;margin:60px auto;">'+
      '<h2>ورود مدیر</h2>'+
      '<input id="email" placeholder="ایمیل مدیر">'+
      '<input id="password" type="password" placeholder="رمز عبور">'+
      (err?'<div class="err">'+err+'</div>':'')+
      '<button onclick="doLogin()">ورود</button>'+
    '</div>';
    return;
  }
  app.innerHTML='<div style="max-width:900px;margin:0 auto;">'+
    '<div style="display:flex;justify-content:space-between;align-items:center;"><h2>پنل مدیریت پروتکل آیرون</h2><button class="outline" onclick="logout()">خروج</button></div>'+
    '<div class="panel"><div class="statgrid" id="stats">...</div></div>'+
    '<div class="panel"><h3>کاربران</h3><input id="search" placeholder="جستجو (نام/ایمیل/موبایل)" oninput="loadUsers()"><div id="usersTable">...</div></div>'+
    '<div class="panel"><h3>ساخت کد VIP جدید</h3>'+
      '<input id="codeCustom" placeholder="کد دلخواه (خالی=خودکار)">'+
      '<input id="codeDays" type="number" placeholder="مدت اعتبار (روز) مثلاً 30">'+
      '<input id="codeMax" type="number" placeholder="حداکثر تعداد استفاده (خالی=نامحدود)">'+
      '<button onclick="createCode()">ساخت کد</button>'+
      '<div id="codeErr" class="err"></div>'+
    '</div>'+
    '<div class="panel"><h3>کدهای VIP</h3><div id="codesTable">...</div></div>'+
    '<div class="panel"><h3>پلن‌های اشتراک</h3><div id="plansTable">...</div></div>'+
    '<div class="panel"><h3>ساخت کد تخفیف</h3>'+
      '<input id="discCustom" placeholder="کد دلخواه (خالی=خودکار)">'+
      '<input id="discPercent" type="number" placeholder="درصد تخفیف (مثلاً 20)">'+
      '<input id="discAmount" type="number" placeholder="یا مبلغ ثابت تخفیف">'+
      '<input id="discMax" type="number" placeholder="حداکثر تعداد استفاده (خالی=نامحدود)">'+
      '<button onclick="createDiscount()">ساخت کد تخفیف</button>'+
      '<div id="discErr" class="err"></div>'+
    '</div>'+
    '<div class="panel"><h3>کدهای تخفیف</h3><div id="discTable">...</div></div>'+
    '<div class="panel"><h3>💰 پرداخت‌های در انتظار تایید (تتر/کارت)</h3><div id="paymentsTable">...</div></div>'+
  '</div>';
  loadStats(); loadUsers(); loadCodes(); loadPlans(); loadDiscounts(); loadPayments();
}
async function loadPlans(){
  try{
    const plans=await api("/api/admin/plans");
    let html='<table><tr><th>پلن</th><th>قیمت تومان</th><th>قیمت تتر</th><th>روز</th><th>وضعیت</th><th></th></tr>';
    plans.forEach(function(p){
      html+='<tr><td>'+esc(p.title)+'</td>'+
        '<td><input style="width:90px;display:inline-block;" value="'+p.priceToman+'" id="pt_'+p.id+'"></td>'+
        '<td><input style="width:60px;display:inline-block;" value="'+p.priceUsdt+'" id="pu_'+p.id+'"></td>'+
        '<td>'+p.durationDays+'</td>'+
        '<td><span class="badge '+(p.isActive?"on":"off")+'">'+(p.isActive?"فعال":"غیرفعال")+'</span></td>'+
        '<td><button onclick="savePlan(\\''+p.id+'\\')">ذخیره</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("plansTable").innerHTML=html;
  }catch(e){}
}
async function savePlan(id){
  try{
    const priceToman=Number(document.getElementById("pt_"+id).value);
    const priceUsdt=Number(document.getElementById("pu_"+id).value);
    await api("/api/admin/plans/"+id,{method:"PUT",body:JSON.stringify({priceToman,priceUsdt})});
    alert("ذخیره شد");
  }catch(e){ alert(e.message); }
}
async function loadDiscounts(){
  try{
    const codes=await api("/api/admin/discount-codes");
    let html='<table><tr><th>کد</th><th>تخفیف</th><th>استفاده</th><th>وضعیت</th><th></th></tr>';
    codes.forEach(function(c){
      const disc=c.percentOff?c.percentOff+"٪":(c.amountOff?c.amountOff+" تومان":"-");
      html+='<tr><td class="mono">'+c.code+'</td><td>'+disc+'</td><td>'+c.usedCount+' / '+(c.maxUses===null?"∞":c.maxUses)+'</td>'+
        '<td><span class="badge '+(c.isActive?"on":"off")+'">'+(c.isActive?"فعال":"غیرفعال")+'</span></td>'+
        '<td><button class="outline" onclick="toggleDiscount(\\''+c.id+'\\','+(!c.isActive)+')">'+(c.isActive?"غیرفعال کن":"فعال کن")+'</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("discTable").innerHTML=html;
  }catch(e){}
}
async function createDiscount(){
  document.getElementById("discErr").textContent="";
  try{
    const code=document.getElementById("discCustom").value;
    const percentOff=document.getElementById("discPercent").value;
    const amountOff=document.getElementById("discAmount").value;
    const maxUses=document.getElementById("discMax").value;
    const created=await api("/api/admin/discount-codes",{method:"POST",body:JSON.stringify({code,percentOff,amountOff,maxUses})});
    alert("کد تخفیف ساخته شد: "+created.code);
    loadDiscounts();
  }catch(e){ document.getElementById("discErr").textContent=e.message; }
}
async function toggleDiscount(id,val){
  try{ await api("/api/admin/discount-codes/"+id+"/toggle",{method:"PUT",body:JSON.stringify({isActive:val})}); loadDiscounts(); }
  catch(e){ alert(e.message); }
}
async function loadPayments(){
  try{
    const payments=await api("/api/admin/payments/pending");
    let html='<table><tr><th>کاربر</th><th>روش</th><th>مبلغ</th><th>کد تراکنش</th><th>عملیات</th></tr>';
    if(payments.length===0) html+='<tr><td colspan="5" style="text-align:center;color:#9A9484;">هیچ پرداخت در انتظاری نیست</td></tr>';
    payments.forEach(function(p){
      html+='<tr><td class="mono" style="font-size:10px;">'+p.userId.slice(0,8)+'</td><td>'+(p.provider==="usdt_wallet"?"تتر":"درگاه")+'</td>'+
        '<td>'+(p.amountUsdt?p.amountUsdt+" USDT":(p.amountToman?p.amountToman+" ت":"-"))+'</td>'+
        '<td style="font-size:10px;">'+esc(p.providerRef||"")+'</td>'+
        '<td><button onclick="approvePayment(\\''+p.id+'\\')">تایید</button><button class="danger" onclick="rejectPayment(\\''+p.id+'\\')">رد</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("paymentsTable").innerHTML=html;
  }catch(e){}
}
async function approvePayment(id){
  if(!confirm("تایید بشه و VIP کاربر فعال بشه؟")) return;
  try{ await api("/api/admin/payments/"+id+"/approve",{method:"PUT"}); loadPayments(); loadStats(); }
  catch(e){ alert(e.message); }
}
async function rejectPayment(id){
  const reason=prompt("دلیل رد (اختیاری)","");
  try{ await api("/api/admin/payments/"+id+"/reject",{method:"PUT",body:JSON.stringify({reason})}); loadPayments(); }
  catch(e){ alert(e.message); }
}
async function doLogin(){
  err="";
  try{
    const email=document.getElementById("email").value.trim();
    const password=document.getElementById("password").value;
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email,password})});
    if(res.user.role!=="admin"){ err="این حساب دسترسی مدیریت نداره"; render(); return; }
    T.access=res.accessToken;
    me=res.user;
    render();
  }catch(e){ err=e.message; render(); }
}
function logout(){ me=null; T.access=null; render(); }
async function loadStats(){
  try{
    const s=await api("/api/admin/stats");
    document.getElementById("stats").innerHTML=
      '<div class="statcard"><div class="statnum">'+s.totalUsers+'</div>کل کاربران</div>'+
      '<div class="statcard"><div class="statnum">'+s.vipUsers+'</div>کاربر VIP</div>'+
      '<div class="statcard"><div class="statnum">'+s.signupsToday+'</div>ثبت‌نام امروز</div>'+
      '<div class="statcard"><div class="statnum">'+s.totalVipCodes+'</div>کد VIP ساخته‌شده</div>';
  }catch(e){}
}
async function loadUsers(){
  try{
    const q=document.getElementById("search").value;
    const users=await api("/api/admin/users?search="+encodeURIComponent(q));
    let html='<table><tr><th>نام</th><th>ایمیل/موبایل</th><th>نقش</th><th>VIP</th><th>عملیات</th></tr>';
    users.forEach(function(u){
      const vipOn=u.vip&&u.vip.active;
      html+='<tr><td>'+esc(u.name)+'</td><td>'+esc(u.email||u.phone||"")+'</td><td>'+u.role+'</td>'+
        '<td><span class="badge '+(vipOn?"on":"off")+'">'+(vipOn?"فعال":"ندارد")+'</span></td>'+
        '<td><button onclick="giftVip(\\''+u.id+'\\')">هدیه VIP</button>'+
        (vipOn?'<button class="danger" onclick="revokeVip(\\''+u.id+'\\')">لغو</button>':'')+
        '</td></tr>';
    });
    html+='</table>';
    document.getElementById("usersTable").innerHTML=html;
  }catch(e){}
}
async function giftVip(userId){
  const days=prompt("چند روز VIP هدیه بدم؟","30");
  if(!days) return;
  try{ await api("/api/admin/users/"+userId+"/vip",{method:"PUT",body:JSON.stringify({active:true,days:Number(days)})}); loadUsers(); }
  catch(e){ alert(e.message); }
}
async function revokeVip(userId){
  if(!confirm("مطمئنی VIP این کاربر لغو بشه؟")) return;
  try{ await api("/api/admin/users/"+userId+"/vip",{method:"PUT",body:JSON.stringify({active:false})}); loadUsers(); }
  catch(e){ alert(e.message); }
}
async function loadCodes(){
  try{
    const codes=await api("/api/admin/vip-codes");
    let html='<table><tr><th>کد</th><th>مدت</th><th>استفاده</th><th>وضعیت</th><th>عملیات</th></tr>';
    codes.forEach(function(c){
      html+='<tr><td class="mono">'+c.code+'</td><td>'+c.durationDays+' روز</td><td>'+c.usedCount+' / '+(c.maxUses===null?"∞":c.maxUses)+'</td>'+
        '<td><span class="badge '+(c.isActive?"on":"off")+'">'+(c.isActive?"فعال":"غیرفعال")+'</span></td>'+
        '<td><button class="outline" onclick="toggleCode(\\''+c.id+'\\','+(!c.isActive)+')">'+(c.isActive?"غیرفعال کن":"فعال کن")+'</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("codesTable").innerHTML=html;
  }catch(e){}
}
async function createCode(){
  document.getElementById("codeErr").textContent="";
  try{
    const code=document.getElementById("codeCustom").value;
    const durationDays=document.getElementById("codeDays").value;
    const maxUses=document.getElementById("codeMax").value;
    const created=await api("/api/admin/vip-codes",{method:"POST",body:JSON.stringify({code,durationDays,maxUses})});
    alert("کد ساخته شد: "+created.code);
    document.getElementById("codeCustom").value="";
    document.getElementById("codeDays").value="";
    document.getElementById("codeMax").value="";
    loadCodes();
  }catch(e){ document.getElementById("codeErr").textContent=e.message; }
}
async function toggleCode(id,val){
  try{ await api("/api/admin/vip-codes/"+id+"/toggle",{method:"PUT",body:JSON.stringify({isActive:val})}); loadCodes(); }
  catch(e){ alert(e.message); }
}
function esc(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
render();
</script>
</body></html>`;


const app = new Router();
app.get("/health", (req, res) => res.json({ ok: true, env: env.NODE_ENV, time: new Date().toISOString(), storage: _mongoReady ? "mongodb" : "local-file (ephemeral on Render!)" }));
app.get("/admin", (req, res) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); res.end(ADMIN_PAGE_HTML); });
app.mount("/api/auth", authRoutes);
app.mount("/api/users", usersRoutes);
app.mount("/api/vip", vipRoutes);
app.mount("/api/payments", paymentRoutes);
app.mount("/api/ai", aiRoutes);
app.mount("/api/admin", adminRoutes);
app.get("/api/vip/plans", VipController.plans);
app.get("/api/vip/wallet-info", VipController.walletInfo);
app.get("/api/payments/zarinpal/callback", PaymentController.zarinpalCallback);
app.get("/uploads/:filename", (req, res, next) => {
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  if (!filePath.startsWith(UPLOAD_DIR) || !fs.existsSync(filePath)) { const err = new Error("فایل یافت نشد"); err.status = 404; return next(err); }
  const ext = path.extname(filePath).slice(1);
  const mime = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp" }[ext] || "application/octet-stream";
  res.sendFile(fs.readFileSync(filePath), mime);
});

if (require.main === module) {
  initStorage().then(() => {
    ensureDefaultPlans();
    app.listen(env.PORT, () => logInfo(`سرور پروتکل آیرون در حال اجرا روی پورت ${env.PORT} (${env.NODE_ENV}) — ذخیره‌سازی: ${_mongoReady ? "MongoDB (دائمی)" : "فایل محلی (موقت)"}`));
  });
}
module.exports = app;
