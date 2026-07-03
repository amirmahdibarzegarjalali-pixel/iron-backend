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
function _persist(name) {
  const rows = _cache.get(name) || [];
  const fp = _filePathFor(name);
  const tmp = `${fp}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(rows, null, 2), "utf8");
  fs.renameSync(tmp, fp);
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
    return { user: publicUser(updated), ...issueTokenPair(updated, ctx) };
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
    return { user: publicUser(user), ...issueTokenPair(user, ctx) };
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
    return { user: publicUser(user), ...issueTokenPair(user, ctx) };
  },
  async refresh({ refreshToken }) {
    if (!refreshToken) throw httpError(400, "توکن رفرش ارسال نشده است");
    const session = SessionRepo.findByToken(refreshToken);
    if (!session || new Date(session.expiresAt).getTime() < Date.now()) throw httpError(401, "نشست منقضی شده؛ دوباره وارد شوید");
    const user = UserRepo.findById(session.userId);
    if (!user) throw httpError(401, "کاربر یافت نشد");
    SessionRepo.revoke(refreshToken);
    return { user: publicUser(user), ...issueTokenPair(user) };
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
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
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

/* ================= بوت‌استرپ سرور ================= */
const app = new Router();
app.get("/health", (req, res) => res.json({ ok: true, env: env.NODE_ENV, time: new Date().toISOString() }));
app.mount("/api/auth", authRoutes);
app.mount("/api/users", usersRoutes);
app.get("/uploads/:filename", (req, res, next) => {
  const filePath = path.join(UPLOAD_DIR, req.params.filename);
  if (!filePath.startsWith(UPLOAD_DIR) || !fs.existsSync(filePath)) { const err = new Error("فایل یافت نشد"); err.status = 404; return next(err); }
  const ext = path.extname(filePath).slice(1);
  const mime = { png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", webp: "image/webp" }[ext] || "application/octet-stream";
  res.sendFile(fs.readFileSync(filePath), mime);
});

if (require.main === module) {
  app.listen(env.PORT, () => logInfo(`سرور پروتکل آیرون در حال اجرا روی پورت ${env.PORT} (${env.NODE_ENV})`));
}
module.exports = app;
