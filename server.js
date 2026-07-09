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
  GEMINI_API_KEY: process.env.GEMINI_API_KEY || "",
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

/* ================= مربی هوشمند (Gemini واقعی + تنظیمات از پنل مدیریت) ================= */
const _aiUsage = collection("ai_usage_daily");
const _aiSettings = collection("app_settings");
const _aiMessages = collection("ai_messages");
const DEFAULT_AI_MODEL = "gemini-2.5-flash";
const DEFAULT_FREE_LIMIT = 5;

function getAiSettings() {
  const rec = _aiSettings.findOne((s) => s.key === "ai");
  return Object.assign({ enabled: true, freeDailyLimit: DEFAULT_FREE_LIMIT, model: DEFAULT_AI_MODEL }, rec ? rec.value : {});
}
function saveAiSettings(patch) {
  const current = getAiSettings();
  const merged = Object.assign({}, current, patch);
  const rec = _aiSettings.findOne((s) => s.key === "ai");
  if (rec) _aiSettings.update(rec.id, { value: merged });
  else _aiSettings.insert({ key: "ai", value: merged });
  return merged;
}

function buildSystemPrompt(user) {
  const p = user.profile || {};
  const goalLabel = { cut: "کات (خشک کردن)", bulk: "افزایش حجم", fatloss: "چربی‌سوزی", recomp: "نگهداری/ترکیب بدنی" }[p.trainingGoal] || "نامشخص";
  const levelLabel = { amateur: "آماتور", beginner: "مبتدی", pro: "حرفه‌ای" }[p.trainingLevel] || "نامشخص";
  return "تو «مربی آیرون» هستی، دستیار هوشمند اپلیکیشن تناسب‌اندام «پروتکل آیرون». به فارسی، صمیمی، مختصر و کاربردی جواب بده.\n" +
    "اطلاعات کاربر: نام: " + (user.name || "کاربر") + "، جنسیت: " + (p.gender === "female" ? "زن" : "مرد") + "، سن: " + (p.age || "نامشخص") +
    "، قد: " + (p.height || "نامشخص") + " سانتی‌متر، وزن: " + (p.weight || "نامشخص") + " کیلوگرم، هدف: " + goalLabel + "، سطح تمرینی: " + levelLabel + ".\n" +
    "قوانین مهم: هیچ‌وقت خودتو جای پزشک یا متخصص تغذیه‌ی واقعی نذار؛ برای مسائل پزشکی/آسیب‌دیدگی همیشه توصیه کن با پزشک مشورت کنه. پاسخ‌ها رو کوتاه و عملی نگه دار (حداکثر چند پاراگراف کوتاه).";
}
async function callGemini(apiKey, model, systemPrompt, history, userMessage) {
  const contents = history.map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
  contents.push({ role: "user", parts: [{ text: userMessage }] });
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents,
      systemInstruction: { parts: [{ text: systemPrompt }] },
      generationConfig: { temperature: 0.7, maxOutputTokens: 700 },
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    const msg = (data && data.error && data.error.message) || "خطای نامشخص از سرویس هوش مصنوعی";
    throw httpError(502, msg);
  }
  const text = data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts
    ? data.candidates[0].content.parts.map((p) => p.text || "").join("") : "";
  const usage = data.usageMetadata || {};
  return { text: text || "متاسفم، نتونستم جواب بدم. دوباره امتحان کن.", promptTokens: usage.promptTokenCount || 0, completionTokens: usage.candidatesTokenCount || 0 };
}

const AiService = {
  checkAndIncrement(userId) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const settings = getAiSettings();
    if (isVipActive(withFreshVipState(user))) return { allowed: true, remaining: null, unlimited: true, limit: null };
    const today = new Date().toISOString().slice(0, 10);
    let rec = _aiUsage.findOne((r) => r.userId === userId && r.date === today);
    if (!rec) rec = _aiUsage.insert({ userId, date: today, count: 0 });
    if (rec.count >= settings.freeDailyLimit) return { allowed: false, remaining: 0, unlimited: false, limit: settings.freeDailyLimit };
    const updated = _aiUsage.update(rec.id, { count: rec.count + 1 });
    return { allowed: true, remaining: settings.freeDailyLimit - updated.count, unlimited: false, limit: settings.freeDailyLimit };
  },
  status(userId) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const settings = getAiSettings();
    if (isVipActive(withFreshVipState(user))) return { remaining: null, unlimited: true, limit: null, enabled: settings.enabled };
    const today = new Date().toISOString().slice(0, 10);
    const rec = _aiUsage.findOne((r) => r.userId === userId && r.date === today);
    const used = rec ? rec.count : 0;
    return { remaining: Math.max(0, settings.freeDailyLimit - used), unlimited: false, limit: settings.freeDailyLimit, enabled: settings.enabled };
  },
  async chat(userId, message) {
    if (!isNonEmptyString(message)) throw httpError(400, "پیام خالیه");
    const settings = getAiSettings();
    if (!settings.enabled) throw httpError(503, "مربی هوشمند فعلاً توسط مدیر غیرفعال شده");
    if (!env.GEMINI_API_KEY) throw httpError(503, "هنوز کلید هوش مصنوعی تنظیم نشده");
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const gate = this.checkAndIncrement(userId);
    if (!gate.allowed) throw Object.assign(httpError(429, "سقف پیام رایگان امروزت تموم شده"), { publicData: { remaining: 0 } });

    const vip = isVipActive(withFreshVipState(user));
    // حافظه‌ی بلندمدت فقط برای کاربران VIP (طبق طراحی)
    const history = vip ? _aiMessages.findMany((m) => m.userId === userId).slice(-10).map((m) => ({ role: m.role, content: m.content })) : [];
    const systemPrompt = buildSystemPrompt(user);
    const t0 = Date.now();
    const result = await callGemini(env.GEMINI_API_KEY, settings.model, systemPrompt, history, message);
    const responseMs = Date.now() - t0;

    _aiMessages.insert({ userId, role: "user", content: message, model: settings.model });
    _aiMessages.insert({ userId, role: "assistant", content: result.text, model: settings.model, promptTokens: result.promptTokens, completionTokens: result.completionTokens, responseMs });

    return { reply: result.text, remaining: gate.remaining, unlimited: gate.unlimited };
  },
  history(userId, limit) {
    return _aiMessages.findMany((m) => m.userId === userId).slice(-(limit || 30));
  },
};

const AiAdminService = {
  getSettings(adminId) { requireAdminUser(adminId); return getAiSettings(); },
  updateSettings(adminId, patch) {
    requireAdminUser(adminId);
    const clean = {};
    if (patch.enabled !== undefined) clean.enabled = !!patch.enabled;
    if (patch.freeDailyLimit !== undefined) clean.freeDailyLimit = Math.max(0, Number(patch.freeDailyLimit) || DEFAULT_FREE_LIMIT);
    if (patch.model !== undefined && isNonEmptyString(patch.model)) clean.model = patch.model.trim();
    return saveAiSettings(clean);
  },
  stats(adminId) {
    requireAdminUser(adminId);
    const allMsgs = _aiMessages.all();
    const userMsgs = allMsgs.filter((m) => m.role === "user");
    const distinctUsers = new Set(userMsgs.map((m) => m.userId)).size;
    const today = new Date().toISOString().slice(0, 10);
    const todayMsgs = userMsgs.filter((m) => (m.createdAt || "").slice(0, 10) === today).length;
    const totalTokens = allMsgs.reduce((sum, m) => sum + (m.promptTokens || 0) + (m.completionTokens || 0), 0);
    return { totalMessages: userMsgs.length, distinctUsers, todayMessages: todayMsgs, totalTokens, hasApiKey: !!env.GEMINI_API_KEY, settings: getAiSettings() };
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
  chat: (req, res, next) => { AiService.chat(req.userId, req.body.message).then((r) => res.json(r)).catch(next); },
  history: (req, res, next) => { try { res.json(AiService.history(req.userId)); } catch (e) { next(e); } },
};
const AiAdminController = {
  getSettings: (req, res, next) => { try { res.json(AiAdminService.getSettings(req.userId)); } catch (e) { next(e); } },
  updateSettings: (req, res, next) => { try { res.json(AiAdminService.updateSettings(req.userId, req.body)); } catch (e) { next(e); } },
  stats: (req, res, next) => { try { res.json(AiAdminService.stats(req.userId)); } catch (e) { next(e); } },
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
aiRoutes.post("/chat", rateLimit({ windowMs: 60000, max: 20, keyPrefix: "ai-chat" }), AiController.chat);
aiRoutes.get("/history", AiController.history);

const adminRoutes = new Router();
adminRoutes.use(requireAuth);
adminRoutes.get("/ai-settings", AiAdminController.getSettings);
adminRoutes.put("/ai-settings", AiAdminController.updateSettings);
adminRoutes.get("/ai-stats", AiAdminController.stats);
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
<html dir="rtl" lang="fa">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>پنل مدیریت | پروتکل آیرون</title>
<style>
:root{
--bg:#0A0B09;--panel:#131913;--panel2:#1a221a;--border:rgba(76,122,82,.3);
--brass:#D8AE52;--brass2:#F2CE7A;--green:#1F9D55;--green2:#3DDC74;
--ink:#C23B3B;--ink2:#FF5252;--text:#F3EEDD;--muted:#9A9484;
--sidebar-w:240px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:Tahoma,'Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;}
.mono{font-family:'Courier New',monospace;}
/* Sidebar */
.sidebar{position:fixed;top:0;right:0;width:var(--sidebar-w);height:100vh;background:var(--panel);border-left:1px solid var(--border);overflow-y:auto;z-index:100;transition:transform .3s;}
.sidebar.collapsed{transform:translateX(100%);}
.sidebar-header{padding:20px 16px;border-bottom:1px solid var(--border);}
.sidebar-header h1{font-size:18px;color:var(--brass);font-weight:800;}
.sidebar-header small{font-size:11px;color:var(--muted);}
.nav-item{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;border:none;background:none;color:var(--muted);font-family:inherit;font-size:13px;width:100%;text-align:right;transition:all .2s;}
.nav-item:hover{background:rgba(216,174,82,.06);color:var(--text);}
.nav-item.active{background:rgba(216,174,82,.1);color:var(--brass);border-right:3px solid var(--brass);}
.nav-item .ic{font-size:18px;width:24px;text-align:center;flex-shrink:0;}
.nav-section{padding:8px 16px 4px;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;}
/* Main */
.main{margin-right:var(--sidebar-w);padding:16px;transition:margin .3s;}
.main.full{margin-right:0;}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;}
.topbar button.menu-toggle{display:none;font-size:24px;background:none;border:none;color:var(--text);cursor:pointer;}
/* Cards */
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;margin-bottom:14px;}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:16px;}
.stat-card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center;}
.stat-num{font-size:28px;font-weight:800;}
.stat-label{font-size:11px;color:var(--muted);margin-top:4px;}
.stat-card.green .stat-num{color:var(--green2);}
.stat-card.brass .stat-num{color:var(--brass2);}
.stat-card.ink .stat-num{color:var(--ink2);}
.stat-card.purple .stat-num{color:#B79CFF;}
/* Tables */
table{width:100%;border-collapse:collapse;font-size:12px;}
th{text-align:right;padding:8px;color:var(--muted);border-bottom:2px solid var(--border);font-size:11px;}
td{padding:8px;border-bottom:1px solid rgba(255,255,255,.05);}
tr:hover td{background:rgba(255,255,255,.02);}
/* Inputs */
input,select,textarea{background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:8px 12px;font-family:inherit;font-size:13px;width:100%;}
input:focus{outline:none;border-color:var(--brass);}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-family:inherit;font-size:13px;font-weight:700;transition:all .2s;}
.btn-primary{background:var(--brass);color:#1A140B;}
.btn-success{background:var(--green);color:#fff;}
.btn-danger{background:var(--ink);color:#fff;}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text);}
.btn-sm{padding:4px 10px;font-size:11px;}
/* Badge */
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:700;}
.badge.on{background:rgba(61,220,116,.15);color:var(--green2);}
.badge.off{background:rgba(255,82,82,.15);color:var(--ink2);}
.badge.vip{background:rgba(216,174,82,.15);color:var(--brass2);}
.badge.free{background:rgba(255,255,255,.05);color:var(--muted);}
/* Toggle */
.toggle{position:relative;width:42px;height:22px;background:var(--border);border-radius:11px;cursor:pointer;transition:background .2s;flex-shrink:0;}
.toggle.on{background:var(--green);}
.toggle::after{content:'';position:absolute;top:2px;right:2px;width:18px;height:18px;background:#fff;border-radius:50%;transition:transform .2s;}
.toggle.on::after{transform:translateX(-20px);}
/* Sections */
.section{display:none;}
.section.active{display:block;}
.section-title{font-size:16px;font-weight:800;margin-bottom:12px;display:flex;align-items:center;gap:8px;}
/* Search */
.search-box{display:flex;gap:8px;margin-bottom:12px;}
.search-box input{flex:1;}
/* Scroll */
.scroll-table{max-height:500px;overflow-y:auto;}
::-webkit-scrollbar{width:6px;height:6px;}
::-webkit-scrollbar-thumb{background:#2c5238;border-radius:4px;}
/* Login */
.login-wrap{max-width:360px;margin:80px auto;padding:24px;}
.login-wrap h2{text-align:center;margin-bottom:16px;}
.err{color:var(--ink2);font-size:12px;margin-top:8px;}
.empty{text-align:center;color:var(--muted);padding:24px;font-size:13px;}
/* Mobile */
@media(max-width:768px){
.sidebar{transform:translateX(100%);}
.sidebar.show{transform:translateX(0);}
.main{margin-right:0;padding:12px;}
.topbar button.menu-toggle{display:block;}
.stat-grid{grid-template-columns:1fr 1fr;}
.scroll-table{max-height:300px;}
}
/* Loading */
.loading{text-align:center;padding:20px;color:var(--muted);}
.spinner{display:inline-block;width:24px;height:24px;border:3px solid var(--border);border-top-color:var(--brass);border-radius:50%;animation:spin .8s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
</style>
</head>
<body>
<div id="app"><div class="loading"><div class="spinner"></div><div style="margin-top:8px;">در حال بارگذاری...</div></div></div>
<script>
var T={access:null};
async function api(path,opts){
  opts=opts||{};
  var headers={"Content-Type":"application/json"};
  if(T.access) headers["Authorization"]="Bearer "+T.access;
  try{
    var res=await fetch(path,Object.assign({headers:headers},opts));
    var data=await res.json().catch(function(){return null;});
    if(!res.ok) throw new Error((data&&data.error)||("خطای سرور: "+res.status));
    return data;
  }catch(e){
    if(e.message&&e.message.indexOf("Failed to fetch")!==-1) throw new Error("ارتباط با سرور برقرار نشد");
    throw e;
  }
}
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function toFa(n){return String(n||0).replace(/[0-9]/g,function(d){return "۰۱۲۳۴۵۶۷۸۹"[d];});}

var me=null, err="", currentSection="dashboard";

function render(){
  var app=document.getElementById("app");
  if(!me){
    app.innerHTML='<div class="login-wrap card">'+
      '<h2>🔐 ورود به پنل مدیریت</h2>'+
      '<div style="margin-bottom:12px;"><input id="email" placeholder="ایمیل مدیر" onkeydown="if(event.key===\'Enter\')document.getElementById(\'password\').focus()"></div>'+
      '<div style="margin-bottom:12px;"><input id="password" type="password" placeholder="رمز عبور" onkeydown="if(event.key===\'Enter\')doLogin()"></div>'+
      (err?'<div class="err">'+esc(err)+'</div>':'')+
      '<button class="btn btn-primary" style="width:100%;" onclick="doLogin()">ورود</button>'+
      '<div style="text-align:center;margin-top:12px;font-size:11px;color:var(--muted);">پروتکل آیرون — پنل مدیریت</div>'+
    '</div>';
    return;
  }
  var nav=[
    {section:"dashboard",icon:"📊",label:"داشبورد"},
    {section:"users",icon:"👥",label:"کاربران"},
    {section:"payments",icon:"💰",label:"پرداخت‌ها"},
    {section:"vip",icon:"🎟️",label:"کدهای VIP"},
    {section:"plans",icon:"📋",label:"پلن‌ها"},
    {section:"discounts",icon:"🏷️",label:"تخفیف"},
    {section:"ai",icon:"🤖",label:"هوش مصنوعی"},
  ];
  app.innerHTML=
    '<div class="sidebar" id="sidebar">'+
      '<div class="sidebar-header"><h1>🏋️ آیرون</h1><small>پنل مدیریت نسخه ۱.۰</small></div>'+
      nav.map(function(n){
        return '<button class="nav-item '+(currentSection===n.section?'active':'')+'" onclick="goSection(\''+n.section+'\')">'+
          '<span class="ic">'+n.icon+'</span><span>'+n.label+'</span></button>';
      }).join('')+
      '<div style="padding:12px 16px;border-top:1px solid var(--border);margin-top:auto;">'+
        '<div style="font-size:11px;color:var(--muted);margin-bottom:4px;">'+esc(me.name||me.email||'مدیر')+'</div>'+
        '<button class="nav-item" onclick="logout()" style="color:var(--ink2);"><span class="ic">🚪</span><span>خروج</span></button>'+
      '</div>'+
    '</div>'+
    '<div class="main" id="main">'+
      '<div class="topbar">'+
        '<button class="menu-toggle" onclick="toggleSidebar()">☰</button>'+
        '<div style="font-size:14px;font-weight:700;">'+nav.find(function(n){return n.section===currentSection;}).label+'</div>'+
        '<div style="font-size:11px;color:var(--muted);">'+new Date().toLocaleDateString('fa-IR')+'</div>'+
      '</div>'+
      '<div id="sectionContent"><div class="loading"><div class="spinner"></div></div></div>'+
    '</div>';
  loadSection(currentSection);
}

function toggleSidebar(){document.getElementById('sidebar').classList.toggle('show');}
function goSection(s){currentSection=s;document.getElementById('sidebar').classList.remove('show');render();}

// === LOGIN ===
async function doLogin(){
  err="";
  var email=document.getElementById("email").value.trim();
  var password=document.getElementById("password").value;
  if(!email||!password){err="ایمیل و رمز رو وارد کن";render();return;}
  try{
    var res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email:email,password:password})});
    if(res.user.role!=="admin"){err="این حساب دسترسی مدیریت نداره";render();return;}
    T.access=res.accessToken;
    me=res.user;
    render();
  }catch(e){err=e.message;render();}
}
function logout(){me=null;T.access=null;render();}

// === DASHBOARD ===
async function loadDashboard(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var s=await api("/api/admin/stats");
    var aiS;
    try{aiS=await api("/api/admin/ai-stats");}catch(e){aiS={todayMessages:0,totalMessages:0,distinctUsers:0,totalTokens:0,settings:{enabled:false}};}
    el.innerHTML=
      '<div class="stat-grid">'+
        statCard(s.totalUsers,"کل کاربران","green")+
        statCard(s.vipUsers,"کاربران VIP","brass")+
        statCard(s.signupsToday,"ثبت‌نام امروز","purple")+
        statCard(aiS.todayMessages||0,"پیام AI امروز","ink")+
      '</div>'+
      '<div class="stat-grid">'+
        statCard(aiS.totalMessages||0,"کل پیام‌های AI","green")+
        statCard(aiS.distinctUsers||0,"کاربران فعال AI","brass")+
        statCard(aiS.totalTokens||0,"توکن مصرفی","purple")+
        statCard(s.totalVipCodes||0,"کدهای VIP","ink")+
      '</div>'+
      '<div class="card">'+
        '<div class="section-title">🤖 وضعیت هوش مصنوعی</div>'+
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;">'+
          '<span style="font-size:13px;">مدل: <b>'+(aiS.settings.model||"-")+'</b></span>'+
          '<span class="badge '+(aiS.settings.enabled?'on':'off')+'">'+(aiS.settings.enabled?'فعال':'غیرفعال')+'</span>'+
        '</div>'+
        '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-top:1px solid var(--border);">'+
          '<span style="font-size:13px;">محدودیت روزانه رایگان: <b>'+toFa(aiS.settings.freeDailyLimit||0)+'</b></span>'+
          '<span style="font-size:13px;color:'+(aiS.hasApiKey?'var(--green2)':'var(--ink2)')+';">'+(aiS.hasApiKey?'کلید API ✓':'کلید API ✗')+'</span>'+
        '</div>'+
      '</div>'+
      '<div class="card">'+
        '<div class="section-title">⚡ میانبرها</div>'+
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">'+
          '<button class="btn btn-outline" onclick="goSection(\'users\')">👥 مدیریت کاربران</button>'+
          '<button class="btn btn-outline" onclick="goSection(\'payments\')">💰 پرداخت‌ها</button>'+
          '<button class="btn btn-outline" onclick="goSection(\'vip\')">🎟️ ساخت کد VIP</button>'+
          '<button class="btn btn-outline" onclick="goSection(\'ai\')">🤖 تنظیمات AI</button>'+
        '</div>'+
      '</div>';
  }catch(e){el.innerHTML='<div class="card err">خطا: '+esc(e.message)+'</div>';}
}
function statCard(num,label,color){return '<div class="stat-card '+color+'"><div class="stat-num">'+toFa(num)+'</div><div class="stat-label">'+label+'</div></div>';}

// === USERS ===
var userSearchTimer=null;
async function loadUsers(search){
  var el=document.getElementById("usersTable");
  if(!el) return;
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var q=document.getElementById("userSearch").value;
    var users=await api("/api/admin/users?search="+encodeURIComponent(q));
    if(!users.length){el.innerHTML='<div class="empty">کاربری پیدا نشد</div>';return;}
    var html='<div class="scroll-table"><table><thead><tr><th>نام</th><th>ایمیل/موبایل</th><th>نقش</th><th>VIP</th><th>عملیات</th></tr></thead><tbody>';
    users.forEach(function(u){
      var vipOn=u.vip&&u.vip.active;
      html+='<tr><td>'+esc(u.name)+'</td><td style="font-size:11px;">'+esc(u.email||u.phone||"-")+'</td>'+
        '<td><span class="badge '+(u.role==='admin'?'vip':'free')+'">'+esc(u.role)+'</span></td>'+
        '<td><span class="badge '+(vipOn?'on':'off')+'">'+(vipOn?'فعال':'-')+'</span></td>'+
        '<td><button class="btn btn-sm '+(vipOn?'btn-danger':'btn-success')+'" onclick="'+(vipOn?'revokeVip':'giftVip')+'(\''+u.id+'\')">'+(vipOn?'لغو VIP':'هدیه VIP')+'</button></td></tr>';
    });
    html+='</tbody></table></div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<div class="err">'+esc(e.message)+'</div>';}
}
async function giftVip(id){
  var days=prompt("چند روز VIP هدیه بدم؟","30");
  if(!days) return;
  try{await api("/api/admin/users/"+id+"/vip",{method:"PUT",body:JSON.stringify({active:true,days:Number(days)})});loadUsers();}
  catch(e){alert(e.message);}
}
async function revokeVip(id){
  if(!confirm("مطمئنی؟")) return;
  try{await api("/api/admin/users/"+id+"/vip",{method:"PUT",body:JSON.stringify({active:false})});loadUsers();}
  catch(e){alert(e.message);}
}

// === PAYMENTS ===
async function loadPayments(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var payments=await api("/api/admin/payments/pending");
    var html='<div class="card"><div class="section-title">💰 پرداخت‌های در انتظار</div>';
    if(!payments.length){html+='<div class="empty">هیچ پرداخت در انتظاری نیست ✅</div>';}
    else{
      html+='<div class="scroll-table"><table><thead><tr><th>کاربر</th><th>روش</th><th>مبلغ</th><th>کد تراکنش</th><th>عملیات</th></tr></thead><tbody>';
      payments.forEach(function(p){
        html+='<tr><td class="mono" style="font-size:10px;">'+(p.userId||"").slice(0,8)+'</td>'+
          '<td>'+(p.provider==='usdt_wallet'?'تتر':'درگاه')+'</td>'+
          '<td>'+(p.amountUsdt?p.amountUsdt+' USDT':(p.amountToman?toFa(p.amountToman)+' ت':'-'))+'</td>'+
          '<td style="font-size:10px;">'+esc(p.providerRef||"-")+'</td>'+
          '<td><button class="btn btn-sm btn-success" onclick="approvePay(\''+p.id+'\')">تایید</button> <button class="btn btn-sm btn-danger" onclick="rejectPay(\''+p.id+'\')">رد</button></td></tr>';
      });
      html+='</tbody></table></div>';
    }
    html+='</div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<div class="card err">'+esc(e.message)+'</div>';}
}
async function approvePay(id){
  if(!confirm("تایید بشه؟")) return;
  try{await api("/api/admin/payments/"+id+"/approve",{method:"PUT"});loadPayments();}catch(e){alert(e.message);}
}
async function rejectPay(id){
  var reason=prompt("دلیل رد:","");
  try{await api("/api/admin/payments/"+id+"/reject",{method:"PUT",body:JSON.stringify({reason:reason||""})});loadPayments();}catch(e){alert(e.message);}
}

// === VIP CODES ===
async function loadVip(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var codes=await api("/api/admin/vip-codes");
    var html='<div class="card"><div class="section-title">🎟️ ساخت کد VIP</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">'+
        '<input id="vipCode" placeholder="کد دلخواه (خالی=خودکار)">'+
        '<input id="vipDays" type="number" placeholder="مدت (روز) مثلا 30">'+
        '<input id="vipMax" type="number" placeholder="حداکثر استفاده (خالی=نامحدود)">'+
      '</div>'+
      '<button class="btn btn-primary" onclick="createVip()">ساخت کد</button>'+
      '<div id="vipErr" class="err"></div></div>'+
      '<div class="card"><div class="section-title">کدهای VIP ('+toFa(codes.length)+')</div>';
    if(!codes.length){html+='<div class="empty">کدی ساخته نشده</div>';}
    else{
      html+='<div class="scroll-table"><table><thead><tr><th>کد</th><th>مدت</th><th>استفاده</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>';
      codes.forEach(function(c){
        html+='<tr><td class="mono" style="font-size:13px;font-weight:700;color:var(--brass2);">'+esc(c.code)+'</td>'+
          '<td>'+toFa(c.durationDays)+' روز</td>'+
          '<td>'+toFa(c.usedCount)+' / '+(c.maxUses===null?'∞':toFa(c.maxUses))+'</td>'+
          '<td><span class="badge '+(c.isActive?'on':'off')+'">'+(c.isActive?'فعال':'غیرفعال')+'</span></td>'+
          '<td><button class="btn btn-sm btn-outline" onclick="toggleVip(\''+c.id+'\','+(!c.isActive)+')">'+(c.isActive?'غیرفعال':'فعال')+'</button></td></tr>';
      });
      html+='</tbody></table></div>';
    }
    html+='</div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<div class="card err">'+esc(e.message)+'</div>';}
}
async function createVip(){
  var code=document.getElementById("vipCode").value;
  var days=document.getElementById("vipDays").value;
  var maxUses=document.getElementById("vipMax").value;
  try{
    var r=await api("/api/admin/vip-codes",{method:"POST",body:JSON.stringify({code:code,durationDays:Number(days),maxUses:maxUses?Number(maxUses):null})});
    alert("کد ساخته شد: "+r.code);
    loadVip();
  }catch(e){document.getElementById("vipErr").textContent=e.message;}
}
async function toggleVip(id,val){
  try{await api("/api/admin/vip-codes/"+id+"/toggle",{method:"PUT",body:JSON.stringify({isActive:val})});loadVip();}catch(e){alert(e.message);}
}

// === PLANS ===
async function loadPlans(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var plans=await api("/api/admin/plans");
    var html='<div class="card"><div class="section-title">📋 پلن‌های اشتراک</div>';
    if(!plans.length){html+='<div class="empty">پلنی وجود نداره</div>';}
    else{
      html+='<table><thead><tr><th>پلن</th><th>تومان</th><th>تتر</th><th>روز</th><th>وضعیت</th><th></th></tr></thead><tbody>';
      plans.forEach(function(p){
        html+='<tr><td>'+esc(p.title)+'</td>'+
          '<td><input style="width:80px;" value="'+p.priceToman+'" id="pt_'+p.id+'"></td>'+
          '<td><input style="width:60px;" value="'+p.priceUsdt+'" id="pu_'+p.id+'"></td>'+
          '<td>'+toFa(p.durationDays)+'</td>'+
          '<td><span class="badge '+(p.isActive?'on':'off')+'">'+(p.isActive?'فعال':'غیرفعال')+'</span></td>'+
          '<td><button class="btn btn-sm btn-primary" onclick="savePlan(\''+p.id+'\')">ذخیره</button></td></tr>';
      });
      html+='</tbody></table>';
    }
    html+='</div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<div class="card err">'+esc(e.message)+'</div>';}
}
async function savePlan(id){
  try{
    var pt=Number(document.getElementById("pt_"+id).value);
    var pu=Number(document.getElementById("pu_"+id).value);
    await api("/api/admin/plans/"+id,{method:"PUT",body:JSON.stringify({priceToman:pt,priceUsdt:pu})});
    alert("ذخیره شد ✅");
  }catch(e){alert(e.message);}
}

// === DISCOUNTS ===
async function loadDiscounts(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var codes=await api("/api/admin/discount-codes");
    var html='<div class="card"><div class="section-title">🏷️ ساخت کد تخفیف</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">'+
        '<input id="discCode" placeholder="کد (خالی=خودکار)">'+
        '<input id="discPercent" type="number" placeholder="درصد تخفیف (مثلا 20)">'+
        '<input id="discAmount" type="number" placeholder="یا مبلغ ثابت">'+
        '<input id="discMax" type="number" placeholder="حداکثر استفاده">'+
      '</div><button class="btn btn-primary" onclick="createDisc()">ساخت</button>'+
      '<div id="discErr" class="err"></div></div>'+
      '<div class="card"><div class="section-title">کدهای تخفیف</div>';
    if(!codes.length){html+='<div class="empty">کدی نیست</div>';}
    else{
      html+='<table><thead><tr><th>کد</th><th>تخفیف</th><th>استفاده</th><th>وضعیت</th><th></th></tr></thead><tbody>';
      codes.forEach(function(c){
        var d=c.percentOff?toFa(c.percentOff)+'%':(c.amountOff?toFa(c.amountOff)+' ت':'-');
        html+='<tr><td class="mono">'+esc(c.code)+'</td><td>'+d+'</td>'+
          '<td>'+toFa(c.usedCount)+' / '+(c.maxUses===null?'∞':toFa(c.maxUses))+'</td>'+
          '<td><span class="badge '+(c.isActive?'on':'off')+'">'+(c.isActive?'فعال':'غیر')+'</span></td>'+
          '<td><button class="btn btn-sm btn-outline" onclick="toggleDisc(\''+c.id+'\','+(!c.isActive)+')">تبدیل</button></td></tr>';
      });
      html+='</tbody></table>';
    }
    html+='</div>';
    el.innerHTML=html;
  }catch(e){el.innerHTML='<div class="card err">'+esc(e.message)+'</div>';}
}
async function createDisc(){
  try{
    var r=await api("/api/admin/discount-codes",{method:"POST",body:JSON.stringify({
      code:document.getElementById("discCode").value,
      percentOff:Number(document.getElementById("discPercent").value)||null,
      amountOff:Number(document.getElementById("discAmount").value)||null,
      maxUses:Number(document.getElementById("discMax").value)||null
    })});
    alert("ساخته شد: "+r.code);
    loadDiscounts();
  }catch(e){document.getElementById("discErr").textContent=e.message;}
}
async function toggleDisc(id,val){
  try{await api("/api/admin/discount-codes/"+id+"/toggle",{method:"PUT",body:JSON.stringify({isActive:val})});loadDiscounts();}catch(e){alert(e.message);}
}

// === AI ===
async function loadAi(){
  var el=document.getElementById("sectionContent");
  el.innerHTML='<div class="loading"><div class="spinner"></div></div>';
  try{
    var s=await api("/api/admin/ai-stats");
    el.innerHTML=
      '<div class="card"><div class="section-title">🤖 تنظیمات هوش مصنوعی</div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;margin-bottom:8px;">'+
        '<span>کلید API:</span><span class="badge '+(s.hasApiKey?'on':'off')+'">'+(s.hasApiKey?'تنظیم شده ✓':'تنظیم نشده ✗')+'</span>'+
      '</div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;margin-bottom:8px;">'+
        '<span>فعال‌سازی:</span><div class="toggle '+(s.settings.enabled?'on':'')+'" id="aiToggle" onclick="this.classList.toggle(\'on\')"></div>'+
      '</div>'+
      '<div style="margin-bottom:8px;"><label style="font-size:12px;color:var(--muted);">مدل AI</label><input id="aiModel" value="'+esc(s.settings.model||'')+'" placeholder="مثلا gemini-2.5-flash"></div>'+
      '<div style="margin-bottom:12px;"><label style="font-size:12px;color:var(--muted);">محدودیت پیام رایگان روزانه</label><input id="aiLimit" type="number" value="'+(s.settings.freeDailyLimit||5)+'"></div>'+
      '<button class="btn btn-primary" onclick="saveAi()">💾 ذخیره تنظیمات</button>'+
      '</div>'+
      '<div class="card"><div class="section-title">📊 آمار مصرف</div>'+
      '<div class="stat-grid">'+
        statCard(s.todayMessages||0,"پیام امروز","green")+
        statCard(s.totalMessages||0,"کل پیام‌ها","brass")+
        statCard(s.distinctUsers||0,"کاربران فعال","purple")+
        statCard(s.totalTokens||0,"کل توکن","ink")+
      '</div></div>';
  }catch(e){el.innerHTML='<div class="card err">'+esc(e.message)+'</div>';}
}
async function saveAi(){
  try{
    var enabled=document.getElementById("aiToggle").classList.contains('on');
    var model=document.getElementById("aiModel").value;
    var limit=Number(document.getElementById("aiLimit").value);
    await api("/api/admin/ai-settings",{method:"PUT",body:JSON.stringify({enabled:enabled,model:model,freeDailyLimit:limit})});
    alert("ذخیره شد ✅");
    loadAi();
  }catch(e){alert(e.message);}
}

// === ROUTER ===
function loadSection(s){
  if(s==='dashboard') loadDashboard();
  else if(s==='users'){
    document.getElementById("sectionContent").innerHTML='<div class="card"><div class="search-box"><input id="userSearch" placeholder="🔍 جستجوی نام/ایمیل/موبایل..." oninput="clearTimeout(userSearchTimer);userSearchTimer=setTimeout(loadUsers,300)"></div><div id="usersTable"><div class="loading"><div class="spinner"></div></div></div></div>';
    loadUsers();
  }
  else if(s==='payments') loadPayments();
  else if(s==='vip') loadVip();
  else if(s==='plans') loadPlans();
  else if(s==='discounts') loadDiscounts();
  else if(s==='ai') loadAi();
}

render();
</script>
</body>
</html>`;


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
