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

/* ================= ریپازیتوری‌های مربیان (Coach System) ================= */
const _coaches = collection("coaches");
const CoachRepo = {
  create: (data) => _coaches.insert(data),
  findById: (id) => _coaches.findById(id),
  findByUserId: (userId) => _coaches.findOne((c) => c.userId === userId),
  findApproved: () => _coaches.findMany((c) => c.status === "approved"),
  findPending: () => _coaches.findMany((c) => c.status === "pending"),
  all: () => _coaches.all(),
  update: (id, patch) => _coaches.update(id, patch),
  remove: (id) => _coaches.remove(id),
};

const _coachRatings = collection("coach_ratings");
const CoachRatingRepo = {
  create: (data) => _coachRatings.insert(data),
  findByCoach: (coachId) => _coachRatings.findMany((r) => r.coachId === coachId),
  findByUser: (userId, coachId) => _coachRatings.findOne((r) => r.userId === userId && r.coachId === coachId),
  update: (id, patch) => _coachRatings.update(id, patch),
  all: () => _coachRatings.all(),
};

function computeCoachRanking(coachId) {
  const ratings = CoachRatingRepo.findByCoach(coachId);
  const coach = CoachRepo.findById(coachId);
  if (!coach) return { rank: "🥉 Bronze", score: 0, avgRating: 0, totalRatings: 0, totalStudents: 0 };
  const totalRatings = ratings.length;
  const avgRating = totalRatings > 0 ? (ratings.reduce((s, r) => s + (r.score || 0), 0) / totalRatings) : 0;
  const totalStudents = coach.studentIds ? coach.studentIds.length : 0;
  let score = avgRating * 20 + totalStudents * 5 + (coach.totalSales || 0) * 3;
  let rank = "🥉 Bronze Coach";
  if (score >= 200) rank = "👑 Elite Coach";
  else if (score >= 120) rank = "💎 Platinum Coach";
  else if (score >= 70) rank = "🥇 Gold Coach";
  else if (score >= 30) rank = "🥈 Silver Coach";
  return { rank, score: Math.round(score), avgRating: Math.round(avgRating * 10) / 10, totalRatings, totalStudents };
}


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
      try { await sendVerificationCode(user, method); } catch (e) {}
      const freshUser = withFreshVipState(maybePromoteAdmin(user));
      return { user: publicUser(freshUser), verificationNeeded: true, verificationUserId: user.id, ...issueTokenPair(freshUser, ctx) };
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
  return Object.assign({ enabled: true, freeDailyLimit: DEFAULT_FREE_LIMIT, model: DEFAULT_AI_MODEL, personality: "motivational", customPrompt: "" }, rec ? rec.value : {});
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
  if (patch.personality !== undefined) clean.personality = String(patch.personality).slice(0, 50);
  if (patch.customPrompt !== undefined) clean.customPrompt = String(patch.customPrompt).slice(0, 2000);
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
    '<div class="panel"><h3>🧠 تنظیمات مربی هوشمند</h3>'+
      '<div id="aiStatsBox" style="font-size:12px;color:#9A9484;margin-bottom:10px;">...</div>'+
      '<label style="font-size:12px;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="aiEnabled"> مربی هوشمند فعال باشه</label>'+
      '<input id="aiFreeLimit" type="number" placeholder="تعداد پیام رایگان روزانه (مثلاً 5)">'+
      '<input id="aiModel" placeholder="مدل (مثلاً gemini-2.5-flash)">'+
      '<button onclick="saveAiSettings()">ذخیره تنظیمات</button>'+
      '<div id="aiSettingsErr" class="err"></div>'+
    '</div>'+
    '<div class="panel"><h3>🧑‍🏫 مدیریت مربیان</h3>'+
      '<div id="coachStats" style="font-size:12px;color:#9A9484;margin-bottom:10px;">در حال بارگذاری...</div>'+
      '<button onclick="loadPendingCoaches()">📋 درخواست‌های در انتظار</button>'+
      '<div id="pendingCoaches" style="margin-top:8px;"></div>'+
    '</div>'+
    '<div class="panel"><h3>📝 شخصیت و Prompt مربی</h3>'+
      '<div style="font-size:12px;color:#9A9484;margin-bottom:6px;">شخصیت فعلی مربی رو انتخاب کن. این روی لحن جواب‌های AI تأثیر می‌ذاره.</div>'+
      '<div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px;">'+
        '<button class="chip" id="perso_motiv" onclick="setPersonality(\\'motivational\\')" style="padding:6px 10px;font-size:11px;border:1px solid #2c5238;border-radius:6px;background:transparent;color:#F3EEDD;">🔥 انگیزشی</button>'+
        '<button class="chip" id="perso_friendly" onclick="setPersonality(\\'friendly\\')" style="padding:6px 10px;font-size:11px;border:1px solid #2c5238;border-radius:6px;background:transparent;color:#F3EEDD;">🤝 دوستانه</button>'+
        '<button class="chip" id="perso_formal" onclick="setPersonality(\\'formal\\')" style="padding:6px 10px;font-size:11px;border:1px solid #2c5238;border-radius:6px;background:transparent;color:#F3EEDD;">🎯 رسمی</button>'+
        '<button class="chip" id="perso_strict" onclick="setPersonality(\\'strict\\')" style="padding:6px 10px;font-size:11px;border:1px solid #2c5238;border-radius:6px;background:transparent;color:#F3EEDD;">⚡ سختگیر</button>'+
        '<button class="chip" id="perso_humorous" onclick="setPersonality(\\'humorous\\')" style="padding:6px 10px;font-size:11px;border:1px solid #2c5238;border-radius:6px;background:transparent;color:#F3EEDD;">😄 شوخ</button>'+
      '</div>'+
      '<input id="aiPrompt" placeholder="Prompt سفارشی مربی (اختیاری)..." style="margin-bottom:6px;">'+
      '<div style="font-size:11px;color:#9A9484;">اگه خالی باشه، از Prompt پیش‌فرض استفاده می‌شه.</div>'+
      '<button onclick="savePrompt()">💾 ذخیره Prompt</button>'+
      '<div id="promptMsg" style="font-size:12px;margin-top:6px;"></div>'+
    '</div>'+
    '<div class="panel"><h3>📊 نمودار مصرف AI (۷ روز اخیر)</h3>'+
      '<div id="aiChart" style="text-align:center;color:#9A9484;font-size:12px;">در حال بارگذاری...</div>'+
    '</div>'+
  '</div>';
  loadStats(); loadUsers(); loadCodes(); loadPlans(); loadDiscounts(); loadPayments(); loadAiSettings();
}
async function loadAiSettings(){
  try{
    const stats=await api("/api/admin/ai-stats");
    document.getElementById("aiStatsBox").innerHTML=
      "کلید API: "+(stats.hasApiKey?'<span class="badge on">تنظیم شده</span>':'<span class="badge off">تنظیم نشده</span>')+
      " · پیام‌های امروز: "+stats.todayMessages+" · کل پیام‌ها: "+stats.totalMessages+
      " · کاربران فعال: "+stats.distinctUsers+" · کل توکن مصرفی: "+stats.totalTokens;
    document.getElementById("aiEnabled").checked=!!stats.settings.enabled;
    document.getElementById("aiFreeLimit").value=stats.settings.freeDailyLimit;
    document.getElementById("aiModel").value=stats.settings.model;
  }catch(e){}
}
async function saveAiSettings(){
  document.getElementById("aiSettingsErr").textContent="";
  try{
    const enabled=document.getElementById("aiEnabled").checked;
    const freeDailyLimit=document.getElementById("aiFreeLimit").value;
    const model=document.getElementById("aiModel").value;
    await api("/api/admin/ai-settings",{method:"PUT",body:JSON.stringify({enabled,freeDailyLimit,model})});
    loadAiChart();
    alert("ذخیره شد");
    loadAiSettings();
  }catch(e){ document.getElementById("aiSettingsErr").textContent=e.message; }
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
    // بارگذاری نمودار
    loadAiChart();
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
// === توابع جدید ===
async function loadAiChart(){
  var el=document.getElementById("aiChart");
  if(!el) return;
  try{
    var s=await api("/api/admin/ai-stats");
    // نمودار ساده SVG
    var msgs=s.todayMessages||0;
    var total=s.totalMessages||0;
    var users=s.distinctUsers||0;
    var tokens=s.totalTokens||0;
    el.innerHTML="<div style=display:flex;gap:12px;flex-wrap:wrap;justify-content:center>"+
      "<div style=text-align:center><div style=font-size:24px;font-weight:800;color:#3DDC74>"+msgs+"</div><div style=font-size:10px;color:#9A9484>پیام امروز</div></div>"+
      "<div style=text-align:center><div style=font-size:24px;font-weight:800;color:#D8AE52>"+total+"</div><div style=font-size:10px;color:#9A9484>کل پیام‌ها</div></div>"+
      "<div style=text-align:center><div style=font-size:24px;font-weight:800;color:#B79CFF>"+users+"</div><div style=font-size:10px;color:#9A9484>کاربران فعال</div></div>"+
      "<div style=text-align:center><div style=font-size:24px;font-weight:800;color:#FF5252>"+tokens+"</div><div style=font-size:10px;color:#9A9484>توکن مصرفی</div></div>"+
      "</div>"+
      "<div style=margin-top:12px;font-size:11px;color:#9A9484;text-align:center>"+
      "میانگین توکن هر پیام: "+(total>0?Math.round(tokens/total):0)+" · "+
      "میانگین پیام هر کاربر: "+(users>0?Math.round(total/users):0)+
      "</div>";
  }catch(e){ el.innerHTML="<div style=color:#FF5252>خطا در بارگذاری</div>"; }
}
function setPersonality(key){
  var keys=["motivational","friendly","formal","strict","humorous"];
  keys.forEach(function(k){
    var el=document.getElementById("perso_"+k.substring(0,5));
    if(el){
      if(k===key){ el.style.background="rgba(61,220,116,.15)"; el.style.borderColor="#3DDC74"; el.style.color="#3DDC74"; }
      else{ el.style.background="transparent"; el.style.borderColor="#2c5238"; el.style.color="#F3EEDD"; }
    }
  });
  // ذخیره تو تنظیمات
  savePersonality(key);
}
async function savePersonality(key){
  try{
    await api("/api/admin/ai-settings",{method:"PUT",body:JSON.stringify({personality:key})});
    var msg=document.getElementById("promptMsg");
    if(msg){ msg.innerHTML="<span style=color:#3DDC74>✅ شخصیت تغییر کرد</span>"; }
  }catch(e){
    var msg=document.getElementById("promptMsg");
    if(msg){ msg.innerHTML="<span style=color:#FF5252>⚠️ "+esc(e.message)+"</span>"; }
  }
}
async function savePrompt(){
  var msg=document.getElementById("promptMsg");
  var prompt=document.getElementById("aiPrompt").value;
  if(msg) msg.innerHTML="<span style=color:#9A9484>در حال ذخیره...</span>";
  try{
    await api("/api/admin/ai-settings",{method:"PUT",body:JSON.stringify({customPrompt:prompt})});
    if(msg) msg.innerHTML="<span style=color:#3DDC74>✅ ذخیره شد</span>";
  }catch(e){
    if(msg) msg.innerHTML="<span style=color:#FF5252>⚠️ "+esc(e.message)+"</span>";
  }
}
// بارگذاری شخصیت فعلی
async function loadPersonality(){
  try{
    var s=await api("/api/admin/ai-stats");
    var p=s.settings.personality||"motivational";
    setPersonality(p);
    if(s.settings.customPrompt){
      var inp=document.getElementById("aiPrompt");
      if(inp) inp.value=s.settings.customPrompt;
    }
  }catch(e){}
}
// فراخوانی اولیه
setTimeout(loadPersonality,1000);

async function loadCoachStats(){
  try{
    const s=await api("/api/admin/coaches/stats");
    document.getElementById("coachStats").innerHTML=
      "کل مربیان: "+s.totalCoaches+" · تایید شده: "+s.approved+
      " · در انتظار: "+s.pending+" · تیک آبی: "+s.verified+
      " · اشتراک فعال: "+s.activeSubscriptions;
  }catch(e){}
}
async function loadPendingCoaches(){
  try{
    const list=await api("/api/admin/coaches/pending");
    let html="";
    if(!list.length) html="<div style='text-align:center;color:#9A9484;padding:12px;'>درخواست در انتظاری نیست ✅</div>";
    list.forEach(function(c){
      html+="<div style='padding:10px;border:1px solid rgba(255,255,255,.08);border-radius:6px;margin-bottom:6px;'>"+
        "<div><b>"+esc(c.name||"-")+"</b> - "+esc(c.specialty||"-")+" - "+esc(c.city||"-")+"</div>"+
        "<div style='font-size:11px;color:#9A9484;margin-top:4px;'>"+esc(c.bio||"").substring(0,100)+"</div>"+
        "<div style='margin-top:6px;'>"+
        "<button onclick=approveCoach(\\""+c.id+"\\")>✅ تایید</button>"+
        "<button class='danger' onclick=rejectCoach(\\""+c.id+"\\")>❌ رد</button>"+
        "</div></div>";
    });
    document.getElementById("pendingCoaches").innerHTML=html;
  }catch(e){document.getElementById("pendingCoaches").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function approveCoach(id){
  if(!confirm("تایید بشه؟"))return;
  try{await api("/api/admin/coaches/"+id+"/approve",{method:"PUT"});alert("تایید شد ✅");loadPendingCoaches();loadCoachStats();}catch(e){alert(e.message);}
}
async function rejectCoach(id){
  if(!confirm("رد بشه؟"))return;
  try{await api("/api/admin/coaches/"+id+"/reject",{method:"PUT"});alert("رد شد");loadPendingCoaches();loadCoachStats();}catch(e){alert(e.message);}
}
setTimeout(loadCoachStats,1500);
render();
</script>
</body></html>`;



/* ================= API مربیان ================= */
const CoachController = {
  // تبدیل شدن به مربی (درخواست)
  requestCoach: (req, res, next) => {
    try {
      const userId = req.userId;
      const existing = CoachRepo.findByUserId(userId);
      if (existing) {
        if (existing.status === "approved") throw httpError(400, "شما قبلا مربی تایید شده هستید");
        if (existing.status === "pending") throw httpError(400, "درخواست شما در حال بررسی است");
      }
      const body = req.body || {};
      const required = ["specialty", "city", "bio"];
      for (const f of required) {
        if (!body[f] || !String(body[f]).trim()) throw httpError(400, "فیلد " + f + " الزامی است");
      }
      const coach = CoachRepo.create({
        userId,
        name: body.name || "",
        specialty: String(body.specialty).slice(0, 200),
        city: String(body.city).slice(0, 100),
        country: String(body.country || "ایران").slice(0, 100),
        bio: String(body.bio).slice(0, 1000),
        experience: Number(body.experience) || 0,
        languages: Array.isArray(body.languages) ? body.languages : ["فارسی"],
        pricePerSession: Number(body.pricePerSession) || 0,
        onlineSessions: !!body.onlineSessions,
        avatarUrl: body.avatarUrl || null,
        status: "pending",
        verified: false,
        subscription: "none",
        studentIds: [],
        totalSales: 0,
      });
      SecurityLog.log({ userId, type: "coach_request", meta: { coachId: coach.id } });
      res.status(201).json(coach);
    } catch (e) { next(e); }
  },
  // دریافت پروفایل مربی خودم
  myProfile: (req, res, next) => {
    try {
      const coach = CoachRepo.findByUserId(req.userId);
      if (!coach) throw httpError(404, "شما مربی نیستید");
      const ranking = computeCoachRanking(coach.id);
      res.json(Object.assign({}, coach, { ranking }));
    } catch (e) { next(e); }
  },
  // ویرایش پروفایل مربی
  updateProfile: (req, res, next) => {
    try {
      const coach = CoachRepo.findByUserId(req.userId);
      if (!coach) throw httpError(404, "شما مربی نیستید");
      const allowed = ["specialty", "city", "country", "bio", "experience", "languages", "pricePerSession", "onlineSessions", "name"];
      const patch = {};
      allowed.forEach((f) => { if (req.body[f] !== undefined) patch[f] = req.body[f]; });
      res.json(CoachRepo.update(coach.id, patch));
    } catch (e) { next(e); }
  },
  // لیست مربیان تایید شده (برای جستجو)
  listApproved: (req, res, next) => {
    try {
      const { specialty, city, minRating, maxPrice, verifiedOnly, lang } = req.query;
      let coaches = CoachRepo.findApproved();
      if (specialty) coaches = coaches.filter((c) => c.specialty && c.specialty.indexOf(specialty) !== -1);
      if (city) coaches = coaches.filter((c) => c.city && c.city.indexOf(city) !== -1);
      if (lang) coaches = coaches.filter((c) => c.languages && c.languages.indexOf(lang) !== -1);
      if (verifiedOnly === "true") coaches = coaches.filter((c) => c.verified);
      const result = coaches.map((c) => {
        const ranking = computeCoachRanking(c.id);
        const user = UserRepo.findById(c.userId);
        return {
          id: c.id,
          name: c.name || (user ? user.name : "مربی"),
          specialty: c.specialty,
          city: c.city,
          country: c.country,
          bio: c.bio,
          avatarUrl: c.avatarUrl || (user ? user.avatarUrl : null),
          verified: c.verified,
          subscription: c.subscription,
          onlineSessions: c.onlineSessions,
          pricePerSession: c.pricePerSession,
          languages: c.languages,
          experience: c.experience,
          ranking,
        };
      }).filter((c) => {
        if (maxPrice && c.pricePerSession > Number(maxPrice)) return false;
        if (minRating && c.ranking.avgRating < Number(minRating)) return false;
        return true;
      });
      res.json(result);
    } catch (e) { next(e); }
  },
  // دریافت پروفایل یه مربی خاص
  getCoach: (req, res, next) => {
    try {
      const coach = CoachRepo.findById(req.params.id);
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      const ranking = computeCoachRanking(coach.id);
      const user = UserRepo.findById(coach.userId);
      res.json(Object.assign({}, coach, { ranking, userInfo: user ? { name: user.name, avatarUrl: user.avatarUrl } : null }));
    } catch (e) { next(e); }
  },
  // ثبت امتیاز برای مربی
  rateCoach: (req, res, next) => {
    try {
      const { coachId, score, comment } = req.body;
      if (!coachId || !score) throw httpError(400, "coachId و score الزامی است");
      if (score < 1 || score > 5) throw httpError(400, "امتیاز باید بین ۱ تا ۵ باشد");
      const coach = CoachRepo.findById(coachId);
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      const existing = CoachRatingRepo.findByUser(req.userId, coachId);
      if (existing) {
        CoachRatingRepo.update(existing.id, { score: Number(score), comment: String(comment || "").slice(0, 500) });
      } else {
        CoachRatingRepo.create({ coachId, userId: req.userId, score: Number(score), comment: String(comment || "").slice(0, 500) });
      }
      res.json({ ok: true, ranking: computeCoachRanking(coachId) });
    } catch (e) { next(e); }
  },
};

const coachRoutes = new Router();
coachRoutes.use(requireAuth);
coachRoutes.post("/request", CoachController.requestCoach);
coachRoutes.get("/me", CoachController.myProfile);
coachRoutes.put("/me", CoachController.updateProfile);
coachRoutes.get("/list", CoachController.listApproved);
coachRoutes.get("/:id", CoachController.getCoach);
coachRoutes.post("/rate", CoachController.rateCoach);

// === Admin Coach Routes ===
const AdminCoachController = {
  listPending: (req, res, next) => {
    try { requireAdminUser(req.userId); res.json(CoachRepo.findPending()); } catch (e) { next(e); }
  },
  listAll: (req, res, next) => {
    try { requireAdminUser(req.userId); res.json(CoachRepo.all()); } catch (e) { next(e); }
  },
  approve: (req, res, next) => {
    try {
      requireAdminUser(req.userId);
      const coach = CoachRepo.update(req.params.id, { status: "approved", verified: true });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      SecurityLog.log({ userId: req.userId, type: "coach_approved", meta: { coachId: req.params.id } });
      res.json(coach);
    } catch (e) { next(e); }
  },
  reject: (req, res, next) => {
    try {
      requireAdminUser(req.userId);
      const coach = CoachRepo.update(req.params.id, { status: "rejected" });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      SecurityLog.log({ userId: req.userId, type: "coach_rejected", meta: { coachId: req.params.id } });
      res.json(coach);
    } catch (e) { next(e); }
  },
  setVerified: (req, res, next) => {
    try {
      requireAdminUser(req.userId);
      const coach = CoachRepo.update(req.params.id, { verified: !!req.body.verified });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      res.json(coach);
    } catch (e) { next(e); }
  },
  setSubscription: (req, res, next) => {
    try {
      requireAdminUser(req.userId);
      const { subscription } = req.body;
      const coach = CoachRepo.update(req.params.id, { subscription });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      res.json(coach);
    } catch (e) { next(e); }
  },
  stats: (req, res, next) => {
    try {
      requireAdminUser(req.userId);
      const all = CoachRepo.all();
      res.json({
        totalCoaches: all.length,
        approved: all.filter((c) => c.status === "approved").length,
        pending: all.filter((c) => c.status === "pending").length,
        verified: all.filter((c) => c.verified).length,
        activeSubscriptions: all.filter((c) => c.subscription !== "none").length,
      });
    } catch (e) { next(e); }
  },
};

adminRoutes.get("/coaches/pending", AdminCoachController.listPending);
adminRoutes.get("/coaches/all", AdminCoachController.listAll);
adminRoutes.put("/coaches/:id/approve", AdminCoachController.approve);
adminRoutes.put("/coaches/:id/reject", AdminCoachController.reject);
adminRoutes.put("/coaches/:id/verify", AdminCoachController.setVerified);
adminRoutes.put("/coaches/:id/subscription", AdminCoachController.setSubscription);
adminRoutes.get("/coaches/stats", AdminCoachController.stats);


const app = new Router();
app.get("/health", (req, res) => res.json({ ok: true, env: env.NODE_ENV, time: new Date().toISOString(), storage: _mongoReady ? "mongodb" : "local-file (ephemeral on Render!)" }));
// سرو کردن پنل مدیریت
app.get("/admin", (req, res) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); res.end(ADMIN_PAGE_HTML); });

// سرو کردن اپلیکیشن اصلی (index.html)
app.get("/", (req, res) => {
  const indexPath = path.join(__dirname, "index.html");
  if (fs.existsSync(indexPath)) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(fs.readFileSync(indexPath, "utf8"));
  } else {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end('<html><body style="font-family:Tahoma;background:#0A0B09;color:#F3EEDD;text-align:center;padding:40px;"><h1>🏋️ پروتکل آیرون</h1><p>سرور فعال است ✅</p><p>اپلیکیشن: فایل index.html رو آپلود کنید</p><p style="margin-top:20px;font-size:12px;color:#9A9484;"><a href="/admin" style="color:#D8AE52;">پنل مدیریت →</a></p></body></html>');
  }
});
app.get("/index.html", (req, res) => {
  const indexPath = path.join(__dirname, "index.html");
  if (fs.existsSync(indexPath)) {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(fs.readFileSync(indexPath, "utf8"));
  } else {
    res.statusCode = 404;
    res.end("Not found");
  }
});
app.mount("/api/auth", authRoutes);
app.mount("/api/users", usersRoutes);
app.mount("/api/vip", vipRoutes);
app.mount("/api/payments", paymentRoutes);
app.mount("/api/ai", aiRoutes);
coachRoutes.get("/recommend", async (req, res, next) => {
  try {
    const user = UserRepo.findById(req.userId);
    const profile = user && user.profile ? user.profile : {};
    const allCoaches = CoachRepo.findApproved();
    if (!allCoaches.length) return res.json([]);

    // امتیازدهی به هر مربی بر اساس تطابق با کاربر
    const scored = allCoaches.map((coach) => {
      let score = 0;
      const ranking = computeCoachRanking(coach.id);
      score += ranking.avgRating * 10;
      score += ranking.totalStudents * 2;
      if (coach.verified) score += 20;
      if (coach.specialty && profile.trainingGoal) {
        const goals = { bulk: "حجم", cut: "کات", fatloss: "چربی", recomp: "ترکیب" };
        const userGoal = goals[profile.trainingGoal] || "";
        if (coach.specialty.indexOf(userGoal) !== -1) score += 30;
      }
      if (coach.onlineSessions) score += 5;
      return { coach, score, ranking };
    });
    scored.sort((a, b) => b.score - a.score);
    res.json(scored.slice(0, 5).map((s) => {
      const u = UserRepo.findById(s.coach.userId);
      return {
        id: s.coach.id,
        name: s.coach.name || (u ? u.name : "مربی"),
        specialty: s.coach.specialty,
        city: s.coach.city,
        avatarUrl: s.coach.avatarUrl || (u ? u.avatarUrl : null),
        verified: s.coach.verified,
        ranking: s.ranking,
        matchScore: Math.round(s.score),
      };
    }));
  } catch (e) { next(e); }
});

// === مرحله ۳: اشتراک مربیان ===
const COACH_PLANS = [
  { id: "starter", name: "Starter Coach", durationDays: 30, priceToman: 150000, priceUsdt: 5, maxStudents: 20, features: ["ثبت پروفایل", "حداکثر ۲۰ شاگرد", "ساخت برنامه", "چت با شاگردان"] },
  { id: "professional", name: "Professional Coach", durationDays: 90, priceToman: 350000, priceUsdt: 12, maxStudents: null, features: ["شاگرد نامحدود", "فروش برنامه", "فروش رژیم", "دریافت رزرو", "گزارشات کامل", "آنالیز درآمد", "اولویت نمایش"] },
  { id: "elite", name: "Elite Coach", durationDays: 365, priceToman: 1200000, priceUsdt: 40, maxStudents: null, features: ["تمام امکانات Professional", "تیک آبی تایید شده", "تبلیغ رایگان", "نشان مربی برتر", "پشتیبانی اختصاصی", "ابزارهای AI"] },
];

coachRoutes.get("/plans", (req, res) => res.json(COACH_PLANS));

coachRoutes.post("/subscribe", async (req, res, next) => {
  try {
    const { planId } = req.body;
    const plan = COACH_PLANS.find((p) => p.id === planId);
    if (!plan) throw httpError(400, "پلن نامعتبر است");
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "ابتدا باید مربی شوید");

    // ثبت پرداخت (در انتظار تایید)
    const payment = PaymentRepo.create({
      userId: req.userId,
      amountToman: plan.priceToman,
      amountUsdt: plan.priceUsdt,
      provider: "coach_subscription",
      status: "pending",
      providerRef: "coach_" + planId,
      meta: { type: "coach_subscription", planId, coachId: coach.id },
    });

    res.status(201).json({ paymentId: payment.id, plan, walletAddress: env.USDT_WALLET_ADDRESS || "", network: env.USDT_WALLET_NETWORK || "TRC20" });
  } catch (e) { next(e); }
});

// === مرحله ۳: کیف پول مربی ===
const _coachWallet = collection("coach_wallets");
const CoachWalletRepo = {
  getOrCreate: (coachId) => {
    let w = _coachWallet.findOne((x) => x.coachId === coachId);
    if (!w) w = _coachWallet.insert({ coachId, balance: 0, totalEarnings: 0, totalCommission: 0, transactions: [] });
    return w;
  },
  addTransaction: (coachId, type, amount, desc) => {
    const w = CoachWalletRepo.getOrCreate(coachId);
    const tx = { id: crypto.randomUUID(), type, amount: Number(amount), desc: String(desc || "").slice(0, 200), date: new Date().toISOString() };
    w.transactions = (w.transactions || []).concat([tx]).slice(-100);
    if (type === "earning") { w.balance += Number(amount); w.totalEarnings += Number(amount); }
    else if (type === "commission") { w.balance -= Number(amount); w.totalCommission += Number(amount); }
    else if (type === "withdrawal") { w.balance -= Number(amount); }
    _coachWallet.update(w.id, { balance: w.balance, totalEarnings: w.totalEarnings, totalCommission: w.totalCommission, transactions: w.transactions });
    return w;
  },
  requestWithdrawal: (coachId, amount, method) => {
    const w = CoachWalletRepo.getOrCreate(coachId);
    if (w.balance < amount) throw httpError(400, "موجودی کافی نیست");
    return CoachWalletRepo.addTransaction(coachId, "withdrawal", amount, "درخواست برداشت - " + method);
  },
};

coachRoutes.get("/wallet", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(CoachWalletRepo.getOrCreate(coach.id));
  } catch (e) { next(e); }
});

coachRoutes.post("/wallet/withdraw", (req, res, next) => {
  try {
    const { amount, method } = req.body;
    if (!amount || amount <= 0) throw httpError(400, "مبلغ نامعتبر است");
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const result = CoachWalletRepo.requestWithdrawal(coach.id, Number(amount), method || "bank");
    res.json({ ok: true, balance: result.balance });
  } catch (e) { next(e); }
});

// === مرحله ۴: فروش برنامه توسط مربی ===
const _coachPrograms = collection("coach_programs");
const CoachProgramRepo = {
  create: (data) => _coachPrograms.insert(data),
  findByCoach: (coachId) => _coachPrograms.findMany((p) => p.coachId === coachId),
  findApproved: () => _coachPrograms.findMany((p) => p.status === "approved"),
  findById: (id) => _coachPrograms.findById(id),
  update: (id, patch) => _coachPrograms.update(id, patch),
};

coachRoutes.post("/program", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const { title, description, type, priceToman, priceUsdt, content } = req.body;
    if (!title || !type) throw httpError(400, "عنوان و نوع الزامی است");
    const prog = CoachProgramRepo.create({
      coachId: coach.id, title: String(title).slice(0, 200),
      description: String(description || "").slice(0, 2000),
      type: String(type), priceToman: Number(priceToman) || 0,
      priceUsdt: Number(priceUsdt) || 0, content: content || null,
      status: "approved", salesCount: 0,
    });
    res.status(201).json(prog);
  } catch (e) { next(e); }
});

coachRoutes.get("/programs", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(CoachProgramRepo.findByCoach(coach.id));
  } catch (e) { next(e); }
});

coachRoutes.get("/programs/market", (req, res) => {
  res.json(CoachProgramRepo.findApproved());
});

coachRoutes.post("/programs/:id/buy", async (req, res, next) => {
  try {
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "برنامه پیدا نشد");
    const coach = CoachRepo.findById(prog.coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");

    // ثبت پرداخت
    const payment = PaymentRepo.create({
      userId: req.userId, amountToman: prog.priceToman, amountUsdt: prog.priceUsdt,
      provider: "coach_program", status: "pending", providerRef: "prog_" + prog.id,
      meta: { type: "coach_program", programId: prog.id, coachId: coach.id },
    });

    res.status(201).json({ paymentId: payment.id, program: prog, walletAddress: env.USDT_WALLET_ADDRESS || "" });
  } catch (e) { next(e); }
});

// === مرحله ۴: آنالیز مربی ===
coachRoutes.get("/analytics", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const ranking = computeCoachRanking(coach.id);
    const wallet = CoachWalletRepo.getOrCreate(coach.id);
    const programs = CoachProgramRepo.findByCoach(coach.id);
    const totalSales = programs.reduce((s, p) => s + (p.salesCount || 0), 0);
    res.json({
      ranking,
      wallet: { balance: wallet.balance, totalEarnings: wallet.totalEarnings, totalCommission: wallet.totalCommission },
      programs: { total: programs.length, totalSales },
      students: coach.studentIds ? coach.studentIds.length : 0,
      subscription: coach.subscription || "none",
    });
  } catch (e) { next(e); }
});

// تایید پرداخت مربی توسط ادمین — هنگام approve پرداخت
const _origApprove = AdminController.approvePayment;
AdminController.approvePayment = function(adminId, paymentId) {
  requireAdminUser(adminId);
  const p = PaymentRepo.findById(paymentId);
  if (!p) throw httpError(404, "پرداخت پیدا نشد");
  PaymentRepo.update(paymentId, { status: "approved", approvedAt: new Date().toISOString() });

  // اگه پرداخت مربیانه
  if (p.meta && p.meta.type === "coach_subscription" && p.meta.coachId) {
    const plan = COACH_PLANS.find((pl) => pl.id === p.meta.planId);
    if (plan) {
      const expiresAt = new Date(Date.now() + plan.durationDays * 86400000).toISOString();
      CoachRepo.update(p.meta.coachId, { subscription: plan.id, subscriptionExpiresAt: expiresAt });
    }
  }
  if (p.meta && p.meta.type === "coach_program" && p.meta.coachId) {
    const commission = Math.round((p.amountToman || 0) * 0.1);
    const earning = (p.amountToman || 0) - commission;
    CoachWalletRepo.addTransaction(p.meta.coachId, "earning", earning, "فروش برنامه");
    if (commission > 0) CoachWalletRepo.addTransaction(p.meta.coachId, "commission", commission, "کمیسیون اپ");
    const coach = CoachRepo.findById(p.meta.coachId);
    if (coach) CoachRepo.update(p.meta.coachId, { totalSales: (coach.totalSales || 0) + 1 });
    if (p.meta.programId) {
      const prog = CoachProgramRepo.findById(p.meta.programId);
      if (prog) CoachProgramRepo.update(p.meta.programId, { salesCount: (prog.salesCount || 0) + 1 });
    }
  }

  SecurityLog.log({ userId: adminId, type: "payment_approved", meta: { paymentId, targetUser: p.userId } });
  return PaymentRepo.findById(paymentId);
};

app.mount("/api/coach", coachRoutes);
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
