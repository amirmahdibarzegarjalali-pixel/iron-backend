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
const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const isValidUsername = (v) => typeof v === "string" && USERNAME_RE.test(v);
const _encKey = crypto.createHash("sha256").update(env.JWT_ACCESS_SECRET + ":enc").digest();
function encryptSensitive(text) {
  if (!text) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", _encKey, iv);
  const enc = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return iv.toString("base64") + "." + enc.toString("base64") + "." + tag.toString("base64");
}
function decryptSensitive(payload) {
  if (!payload) return null;
  try {
    const [ivB64, encB64, tagB64] = payload.split(".");
    const decipher = crypto.createDecipheriv("aes-256-gcm", _encKey, Buffer.from(ivB64, "base64"));
    decipher.setAuthTag(Buffer.from(tagB64, "base64"));
    const dec = Buffer.concat([decipher.update(Buffer.from(encB64, "base64")), decipher.final()]);
    return dec.toString("utf8");
  } catch (e) { return null; }
}
function maskBankNumber(v) {
  if (!v) return null;
  const s = String(v);
  return s.length > 4 ? ("•".repeat(Math.max(0, s.length - 4)) + s.slice(-4)) : s;
}
function decryptedWithdrawal(wr) {
  return Object.assign({}, wr, {
    bankInfo: Object.assign({}, wr.bankInfo, {
      cardNumber: decryptSensitive(wr.bankInfo.cardNumber),
      sheba: decryptSensitive(wr.bankInfo.sheba),
    }),
  });
}
function generateReferralCode(username) {
  const base = (username || "user").toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
  let code;
  do { code = base + Math.floor(1000 + Math.random() * 9000); } while (UserRepo.findByReferralCode(code));
  return code;
}
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
const ALL_COLLECTION_NAMES = ["users", "sessions", "verification_tokens", "security_events", "outbox_emails", "outbox_sms", "body_stats", "personal_records", "vip_codes", "vip_plans", "discount_codes", "payment_transactions", "ai_usage_daily", "coaches", "coach_ratings", "coach_wallets", "coach_programs", "coach_students", "coach_messages", "coach_bookings", "coach_reports", "coach_notices", "app_settings", "ai_messages", "tickets", "ticket_messages", "ticket_quick_replies", "notifications", "content_posts", "ad_banners", "coach_withdrawals", "daily_logs", "activity_events", "gamification", "product_reviews", "product_purchases", "referral_commissions", "reports", "equipment_products", "equipment_orders"];
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
  findByUsername: (username) => username ? _users.findOne((u) => u.username && u.username.toLowerCase() === username.toLowerCase()) : null,
  findByReferralCode: (code) => code ? _users.findOne((u) => u.referralCode && u.referralCode.toLowerCase() === String(code).toLowerCase()) : null,
  update: (id, patch) => _users.update(id, patch),
  remove: (id) => _users.remove(id),
  all: () => _users.all(),
};
const _sessions = collection("sessions");
const SessionRepo = {
  create: ({ userId, refreshToken, userAgent, ip, expiresAt }) => _sessions.insert({ userId, refreshToken, userAgent, ip, expiresAt, revoked: false }),
  findByToken: (refreshToken) => _sessions.findOne((s) => s.refreshToken === refreshToken && !s.revoked),
  findById: (id) => _sessions.findById(id),
  findActiveForUser: (userId) => _sessions.findMany((s) => s.userId === userId && !s.revoked).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)),
  revoke: (refreshToken) => { const s = _sessions.findOne((x) => x.refreshToken === refreshToken); if (!s) return false; _sessions.update(s.id, { revoked: true }); return true; },
  revokeById: (id) => { const s = _sessions.findById(id); if (!s) return false; _sessions.update(id, { revoked: true }); return true; },
  revokeAllForUser: (userId) => { const rows = _sessions.findMany((s) => s.userId === userId && !s.revoked); rows.forEach((s) => _sessions.update(s.id, { revoked: true })); return rows.length; },
  revokeAllExcept: (userId, keepToken) => { const rows = _sessions.findMany((s) => s.userId === userId && !s.revoked && s.refreshToken !== keepToken); rows.forEach((s) => _sessions.update(s.id, { revoked: true })); return rows.length; },
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
  if (!coach) return { rank: "🥉 Bronze Coach", score: 0, avgRating: 0, totalRatings: 0, totalStudents: 0 };
  const totalRatings = ratings.length;
  const avgRating = totalRatings > 0 ? (ratings.reduce((s, r) => s + (r.score || 0), 0) / totalRatings) : 0;
  const totalStudents = CoachStudentRepo.findByCoach(coachId).filter((s) => s.status === "active").length;
  let score = avgRating * 20 + totalStudents * 5 + (coach.totalSales || 0) * 3;
  let rank = "🥉 Bronze Coach";
  if (score >= 200) rank = "👑 Elite Coach";
  else if (score >= 120) rank = "💎 Platinum Coach";
  else if (score >= 70) rank = "🥇 Gold Coach";
  else if (score >= 30) rank = "🥈 Silver Coach";
  if (coach.rankOverride) {
    const overrideMap = {
      bronze: { rank: "🥉 Bronze Coach", min: 0 },
      silver: { rank: "🥈 Silver Coach", min: 30 },
      gold: { rank: "🥇 Gold Coach", min: 70 },
      platinum: { rank: "💎 Platinum Coach", min: 120 },
      elite: { rank: "👑 Elite Coach", min: 200 },
    };
    const ov = overrideMap[coach.rankOverride];
    if (ov) { rank = ov.rank; score = Math.max(ov.min, Math.round(score)); }
  }
  return { rank, score: Math.round(score), avgRating: Math.round(avgRating * 10) / 10, totalRatings, totalStudents, rankOverride: coach.rankOverride || null };
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
const _onlinePresence = new Map(); // userId -> lastSeen timestamp (in-memory only, no disk writes)
function requireAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) { const err = new Error("توکن ارسال نشده است"); err.status = 401; return next(err); }
  try {
    const payload = jwtVerify(token, env.JWT_ACCESS_SECRET);
    const u = UserRepo.findById(payload.sub);
    if (u && u.blocked) { const err = new Error("حساب شما مسدود شده است. با پشتیبانی تماس بگیر."); err.status = 403; return next(err); }
    req.userId = payload.sub;
    _onlinePresence.set(payload.sub, Date.now());
    next();
  } catch (e) {
    const err = new Error("توکن نامعتبر یا منقضی شده است"); err.status = 401; next(err);
  }
}
function countOnlineUsers(windowMs) {
  const cutoff = Date.now() - (windowMs || 5 * 60000);
  let count = 0;
  _onlinePresence.forEach((ts) => { if (ts >= cutoff) count++; });
  return count;
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
async function send2FACode(user) {
  const code = String(crypto.randomInt(100000, 999999));
  TokenRepo.invalidateAllForUser(user.id, "2fa_login");
  TokenRepo.create({ userId: user.id, type: "2fa_login", code, expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString() });
  if (user.email) await mailerSend({ to: user.email, subject: "کد ورود دومرحله‌ای - پروتکل آیرون", body: `کد ورود شما: ${code}\nاین کد تا ۵ دقیقه معتبر است. اگه خودت درخواست ورود ندادی، رمزتو عوض کن.` });
  else await smsSend({ to: user.phone, text: `کد ورود دومرحله‌ای پروتکل آیرون: ${code} (تا ۵ دقیقه معتبر)` });
}

const AuthService = {
  async register({ name, username, email, phone, password, refCode }, ctx = {}) {
    if (!isNonEmptyString(name)) throw httpError(400, "نام الزامی است");
    if (!isValidUsername(username)) throw httpError(400, "نام کاربری باید ۳ تا ۲۰ کاراکتر و فقط شامل حروف انگلیسی، عدد و _ باشد");
    if (UserRepo.findByUsername(username)) throw httpError(409, "این نام کاربری قبلاً گرفته شده؛ یکی دیگه امتحان کن");
    if (!email && !phone) throw httpError(400, "ایمیل یا شماره موبایل الزامی است");
    if (email && !isValidEmail(email)) throw httpError(400, "ایمیل نامعتبر است");
    if (phone && !isValidIranPhone(phone)) throw httpError(400, "شماره موبایل نامعتبر است (فرمت 09xxxxxxxxx)");
    if (!isStrongPassword(password)) throw httpError(400, "رمز عبور باید حداقل ۸ کاراکتر باشد");
    if (email && UserRepo.findByEmail(email)) throw httpError(409, "این ایمیل قبلاً ثبت شده است");
    if (phone && UserRepo.findByPhone(phone)) throw httpError(409, "این شماره موبایل قبلاً ثبت شده است");
    let referredBy = null;
    if (refCode) {
      const referrer = UserRepo.findByReferralCode(refCode);
      if (referrer) referredBy = referrer.id;
    }
    const user = UserRepo.create({
      name: name.trim(), username: username.trim(), email: email ? email.toLowerCase() : null, phone: phone || null,
      passwordHash: hashPassword(password), role: "user", emailVerified: false, phoneVerified: false, avatarUrl: null,
      profile: { age: null, height: null, weight: null, gender: null, trainingGoal: null, trainingLevel: null, trainingHistory: null },
      vip: { active: false, plan: null, expiresAt: null },
      referralCode: generateReferralCode(username), referredBy,
    });
    SecurityLog.log({ userId: user.id, type: "register", ip: ctx.ip, meta: { email, phone, username, referredBy } });
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
    if (user.referredBy) ReferralService.awardSignupReward(user.referredBy, user.id);
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
    if (user.blocked) { SecurityLog.log({ userId: user.id, type: "login_blocked", ip: ctx.ip }); throw httpError(403, "حساب شما مسدود شده است. با پشتیبانی تماس بگیر."); }
    if (user.twoFactorEnabled) {
      await send2FACode(user);
      SecurityLog.log({ userId: user.id, type: "2fa_code_sent", ip: ctx.ip });
      return { needs2fa: true, userId: user.id };
    }
    SecurityLog.log({ userId: user.id, type: "login_success", ip: ctx.ip });
    const freshUser = withFreshVipState(maybePromoteAdmin(user));
    return { user: publicUser(freshUser), ...issueTokenPair(freshUser, ctx) };
  },
  async verify2FA({ userId, code }, ctx = {}) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر پیدا نشد");
    const token = TokenRepo.findValid({ userId, type: "2fa_login", code });
    if (!token) throw httpError(400, "کد نامعتبر یا منقضی شده است");
    TokenRepo.markUsed(token.id);
    SecurityLog.log({ userId: user.id, type: "login_success_2fa", ip: ctx.ip });
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
const _dailyLogs = collection("daily_logs");
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
    if (patch.username !== undefined && !user.username) {
      // فقط برای حساب‌های قدیمی که هنوز نام کاربری ندارن (یه‌بار قابل تنظیم؛ تغییرش بعداً نیاز به ادمین داره)
      if (!isValidUsername(patch.username)) throw httpError(400, "نام کاربری باید ۳ تا ۲۰ کاراکتر و فقط شامل حروف انگلیسی، عدد و _ باشد");
      if (UserRepo.findByUsername(patch.username)) throw httpError(409, "این نام کاربری قبلاً گرفته شده؛ یکی دیگه امتحان کن");
      topPatch.username = patch.username.trim();
    }
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
  addBodyStat(userId, { weight, waist, arm, chest, thigh, bodyFat, date }) {
    return _bodyStats.insert({ userId, weight, waist, arm, chest, thigh, bodyFat: bodyFat || null, date: date || new Date().toISOString() });
  },
  listBodyStats(userId) { return _bodyStats.findMany((s) => s.userId === userId).sort((a, b) => new Date(a.date) - new Date(b.date)); },
  logDaily(userId, { water, sleep, date }) {
    const day = (date || new Date().toISOString()).slice(0, 10);
    const existing = _dailyLogs.findOne((d) => d.userId === userId && d.date === day);
    if (existing) {
      const patch = {};
      if (water !== undefined) patch.water = Number(water);
      if (sleep !== undefined) patch.sleep = Number(sleep);
      return _dailyLogs.update(existing.id, patch);
    }
    return _dailyLogs.insert({ userId, date: day, water: water !== undefined ? Number(water) : 0, sleep: sleep !== undefined ? Number(sleep) : null });
  },
  listDailyLogs(userId, days) {
    const n = Math.min(90, Math.max(7, Number(days) || 30));
    const cutoff = new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);
    return _dailyLogs.findMany((d) => d.userId === userId && d.date >= cutoff).sort((a, b) => a.date.localeCompare(b.date));
  },
  addPersonalRecord(userId, { exerciseName, weight, reps, date }) {
    if (!isNonEmptyString(exerciseName)) throw httpError(400, "نام حرکت الزامی است");
    return _personalRecords.insert({ userId, exerciseName, weight, reps: reps || null, date: date || new Date().toISOString() });
  },
  listPersonalRecords(userId) { return _personalRecords.findMany((p) => p.userId === userId).sort((a, b) => (b.weight || 0) - (a.weight || 0)); },
  toggleTwoFactor(userId, enable, password) {
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر پیدا نشد");
    if (!verifyPassword(password, user.passwordHash)) throw httpError(401, "رمز عبور اشتباه است");
    const updated = UserRepo.update(userId, { twoFactorEnabled: !!enable });
    SecurityLog.log({ userId, type: enable ? "2fa_enabled" : "2fa_disabled" });
    return publicUser(updated);
  },
};

/* ================= معرفی دوستان و همکاری در فروش (Referral / Affiliate) ================= */
const _referralCommissions = collection("referral_commissions");
const REFERRAL_SETTINGS_KEY = "referral_settings";
function getReferralSettings() {
  const s = _aiSettings.findOne((x) => x.key === REFERRAL_SETTINGS_KEY);
  return s ? s.value : { signupRewardDays: 3, commissionPercent: 10 };
}
const ReferralService = {
  setSettings(adminId, { signupRewardDays, commissionPercent }) {
    requireAdminUser(adminId, "payments");
    const value = {
      signupRewardDays: Math.max(0, Math.min(30, Number(signupRewardDays) || 0)),
      commissionPercent: Math.max(0, Math.min(50, Number(commissionPercent) || 0)),
    };
    const existing = _aiSettings.findOne((x) => x.key === REFERRAL_SETTINGS_KEY);
    if (existing) _aiSettings.update(existing.id, { value });
    else _aiSettings.insert({ key: REFERRAL_SETTINGS_KEY, value });
    return value;
  },
  awardSignupReward(referrerId, referredUserId) {
    const settings = getReferralSettings();
    if (settings.signupRewardDays > 0) grantVipDaysToUser(referrerId, settings.signupRewardDays, "هدیه‌ی دعوت دوست");
    _referralCommissions.insert({ referrerUserId: referrerId, referredUserId, sourceType: "signup", amountToman: 0, paymentId: null, status: "paid" });
    notifyCoachUser(referrerId, "🎁 دوستت عضو شد!", "به‌خاطر دعوتت، " + settings.signupRewardDays + " روز VIP رایگان گرفتی.");
  },
  awardPurchaseCommission(payment) {
    const referred = UserRepo.findById(payment.userId);
    if (!referred || !referred.referredBy) return;
    const settings = getReferralSettings();
    if (settings.commissionPercent <= 0) return;
    const amount = Math.round((payment.amountToman || 0) * (settings.commissionPercent / 100));
    if (amount <= 0) return;
    _referralCommissions.insert({ referrerUserId: referred.referredBy, referredUserId: referred.id, sourceType: "purchase", amountToman: amount, paymentId: payment.id, status: "pending" });
    notifyCoachUser(referred.referredBy, "💰 پورسانت جدید!", "دوستی که دعوت کردی خرید انجام داد و " + amount.toLocaleString("fa-IR") + " تومان پورسانت برات ثبت شد.");
  },
  myStats(userId) {
    const user = UserRepo.findById(userId);
    const commissions = _referralCommissions.findMany((c) => c.referrerUserId === userId);
    const referredCount = _users.findMany((u) => u.referredBy === userId).length;
    return {
      referralCode: user.referralCode,
      totalReferred: referredCount,
      pendingToman: commissions.filter((c) => c.status === "pending").reduce((s, c) => s + c.amountToman, 0),
      paidToman: commissions.filter((c) => c.status === "paid").reduce((s, c) => s + c.amountToman, 0),
      cancelledToman: commissions.filter((c) => c.status === "cancelled").reduce((s, c) => s + c.amountToman, 0),
      history: commissions.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50),
    };
  },
  adminList(adminId, status) {
    requireAdminUser(adminId, "payments");
    let list = _referralCommissions.all();
    if (status) list = list.filter((c) => c.status === status);
    return list.map((c) => {
      const referrer = UserRepo.findById(c.referrerUserId);
      const referred = UserRepo.findById(c.referredUserId);
      return Object.assign({}, c, { referrerName: referrer ? referrer.name : "-", referredName: referred ? referred.name : "-" });
    }).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  },
  markPaid(adminId, id) {
    requireAdminUser(adminId, "payments");
    const c = _referralCommissions.findById(id);
    if (!c) throw httpError(404, "پورسانت پیدا نشد");
    if (c.status !== "pending") throw httpError(400, "قبلاً بررسی شده");
    const updated = _referralCommissions.update(id, { status: "paid" });
    SecurityLog.log({ userId: adminId, type: "referral_commission_paid", meta: { id, referrer: c.referrerUserId, amount: c.amountToman } });
    notifyCoachUser(c.referrerUserId, "✅ پورسانت پرداخت شد", Number(c.amountToman).toLocaleString("fa-IR") + " تومان پورسانتت پرداخت شد.");
    return updated;
  },
  cancel(adminId, id, reason) {
    requireAdminUser(adminId, "payments");
    const c = _referralCommissions.findById(id);
    if (!c) throw httpError(404, "پورسانت پیدا نشد");
    if (c.status !== "pending") throw httpError(400, "قبلاً بررسی شده");
    const updated = _referralCommissions.update(id, { status: "cancelled", cancelReason: reason || null });
    SecurityLog.log({ userId: adminId, type: "referral_commission_cancelled", meta: { id, referrer: c.referrerUserId, reason } });
    return updated;
  },
};
const _activityEvents = collection("activity_events");
const _gamification = collection("gamification");
const XP_VALUES = { workout_done: 20, water_goal_met: 5, stat_logged: 10, pr_added: 15, nutrition_logged: 5, sleep_logged: 5 };
const ACTIVITY_TYPES = Object.keys(XP_VALUES);
const BADGE_DEFS = [
  { id: "first_step", emoji: "🔥", title: "شروع قدرتمند", desc: "اولین فعالیتت رو ثبت کردی", check: (s) => s.totalDays >= 1 },
  { id: "week_streak", emoji: "🗓️", title: "یک هفته پیوسته", desc: "۷ روز متوالی فعالیت", check: (s) => s.bestStreak >= 7 },
  { id: "month_streak", emoji: "⚡", title: "استریک ۳۰ روزه", desc: "۳۰ روز متوالی بدون وقفه", check: (s) => s.bestStreak >= 30 },
  { id: "legend_streak", emoji: "👑", title: "افسانه", desc: "۱۰۰ روز متوالی — تسلیم‌ناپذیر", check: (s) => s.bestStreak >= 100 },
  { id: "marathon", emoji: "💪", title: "ماراتن‌کار", desc: "۳۰ روز فعالیت (نه لزوماً پشت‌سرهم)", check: (s) => s.totalDays >= 30 },
  { id: "veteran", emoji: "🏋️", title: "کهنه‌کار", desc: "۱۰۰ روز فعالیت در طول زمان", check: (s) => s.totalDays >= 100 },
  { id: "first_pr", emoji: "🏆", title: "اولین رکورد", desc: "یه وزنه رو به‌عنوان رکورد ثبت کردی", check: (s) => s.counts.pr_added >= 1 },
  { id: "pr_hunter", emoji: "🥇", title: "شکارچی رکورد", desc: "۵ رکورد شخصی ثبت کردی", check: (s) => s.counts.pr_added >= 5 },
  { id: "tracker", emoji: "📏", title: "پیگیر پیشرفت", desc: "۳ بار اندازه‌گیری بدن ثبت کردی", check: (s) => s.counts.stat_logged >= 3 },
  { id: "hydrated", emoji: "💧", title: "آب‌دوست", desc: "۱۰ روز به هدف آب رسیدی", check: (s) => s.counts.water_goal_met >= 10 },
  { id: "level10", emoji: "⭐", title: "سطح ۱۰", desc: "به سطح ۱۰ رسیدی", check: (s) => s.level >= 10 },
  { id: "level25", emoji: "🌟", title: "سطح ۲۵", desc: "به سطح ۲۵ رسیدی — یه ورزشکار واقعی", check: (s) => s.level >= 25 },
];
function xpForLevel(level) { return level * 100; } // مقدار XP لازم برای رسیدن از سطح level به level+1
function levelFromXp(xp) {
  let level = 1, remaining = xp;
  while (remaining >= xpForLevel(level)) { remaining -= xpForLevel(level); level++; }
  return { level, xpIntoLevel: remaining, xpForNext: xpForLevel(level) };
}
function isoWeekKey(d) {
  const date = new Date(d);
  date.setHours(0, 0, 0, 0);
  date.setDate(date.getDate() + 3 - ((date.getDay() + 6) % 7));
  const week1 = new Date(date.getFullYear(), 0, 4);
  const weekNo = 1 + Math.round(((date - week1) / 86400000 - 3 + ((week1.getDay() + 6) % 7)) / 7);
  return date.getFullYear() + "-W" + weekNo;
}
function computeActivityStats(userId) {
  const events = _activityEvents.findMany((e) => e.userId === userId);
  const days = Array.from(new Set(events.map((e) => e.date))).sort();
  let bestStreak = 0, curStreak = 0, prevDay = null;
  days.forEach((d) => {
    if (prevDay) {
      const diff = (new Date(d) - new Date(prevDay)) / 86400000;
      curStreak = diff === 1 ? curStreak + 1 : 1;
    } else curStreak = 1;
    bestStreak = Math.max(bestStreak, curStreak);
    prevDay = d;
  });
  // استریک فعلی: آیا امروز یا دیروز فعالیتی بوده
  const todayStr = new Date().toISOString().slice(0, 10);
  const yesterdayStr = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  let currentStreak = 0;
  if (days.includes(todayStr) || days.includes(yesterdayStr)) {
    currentStreak = curStreak;
  }
  const counts = {};
  ACTIVITY_TYPES.forEach((t) => { counts[t] = events.filter((e) => e.type === t).length; });
  return { totalDays: days.length, bestStreak, currentStreak, counts, days };
}
function getOrCreateGamification(userId) {
  let g = _gamification.findOne((x) => x.userId === userId);
  if (!g) g = _gamification.insert({ userId, xp: 0, badges: [], claimedMissions: [] });
  return g;
}
const GamificationService = {
  logActivity(userId, type) {
    if (!ACTIVITY_TYPES.includes(type)) throw httpError(400, "نوع فعالیت نامعتبر است");
    const day = new Date().toISOString().slice(0, 10);
    const already = _activityEvents.findOne((e) => e.userId === userId && e.type === type && e.date === day);
    let xpGained = 0;
    if (!already) {
      _activityEvents.insert({ userId, type, date: day });
      xpGained = XP_VALUES[type];
    }
    const g = getOrCreateGamification(userId);
    const stats = computeActivityStats(userId);
    const newXp = g.xp + xpGained;
    const { level } = levelFromXp(newXp);
    const prevLevel = levelFromXp(g.xp).level;
    const statsForBadges = Object.assign({}, stats, { level });
    const newBadges = [];
    BADGE_DEFS.forEach((b) => {
      if (!g.badges.includes(b.id) && b.check(statsForBadges)) newBadges.push(b.id);
    });
    const updated = _gamification.update(g.id, { xp: newXp, badges: g.badges.concat(newBadges) });
    return {
      xp: updated.xp, level, xpIntoLevel: levelFromXp(updated.xp).xpIntoLevel, xpForNext: levelFromXp(updated.xp).xpForNext,
      xpGained, leveledUp: level > prevLevel, newBadges: newBadges.map((id) => BADGE_DEFS.find((b) => b.id === id)),
      streak: stats.currentStreak,
    };
  },
  getProfile(userId) {
    const g = getOrCreateGamification(userId);
    const stats = computeActivityStats(userId);
    const { level, xpIntoLevel, xpForNext } = levelFromXp(g.xp);
    const badges = BADGE_DEFS.map((b) => ({ id: b.id, emoji: b.emoji, title: b.title, desc: b.desc, earned: g.badges.includes(b.id) }));
    return { xp: g.xp, level, xpIntoLevel, xpForNext, badges, streak: stats.currentStreak, bestStreak: stats.bestStreak, totalDays: stats.totalDays };
  },
  getMissions(userId) {
    const g = getOrCreateGamification(userId);
    const events = _activityEvents.findMany((e) => e.userId === userId);
    const todayStr = new Date().toISOString().slice(0, 10);
    const weekKey = isoWeekKey(new Date());
    const monthKey = todayStr.slice(0, 7);
    const todayCount = events.filter((e) => e.date === todayStr).length;
    const weekDays = new Set(events.filter((e) => isoWeekKey(new Date(e.date)) === weekKey).map((e) => e.date)).size;
    const monthDays = new Set(events.filter((e) => e.date.slice(0, 7) === monthKey).map((e) => e.date)).size;
    const defs = [
      { id: "daily:" + todayStr, scope: "daily", title: "فعالیت امروز", desc: "حداقل یه فعالیت (تمرین، وعده، آب) امروز ثبت کن", target: 1, progress: Math.min(todayCount, 1), reward: 10 },
      { id: "weekly:" + weekKey, scope: "weekly", title: "۴ روز فعال این هفته", desc: "این هفته حداقل ۴ روز فعالیت داشته باش", target: 4, progress: Math.min(weekDays, 4), reward: 40 },
      { id: "weekly2:" + weekKey, scope: "weekly", title: "هفتهٔ کامل", desc: "این هفته هر ۷ روز فعالیت داشته باش", target: 7, progress: Math.min(weekDays, 7), reward: 80 },
      { id: "monthly:" + monthKey, scope: "monthly", title: "۱۵ روز فعال این ماه", desc: "این ماه حداقل ۱۵ روز فعالیت داشته باش", target: 15, progress: Math.min(monthDays, 15), reward: 150 },
    ];
    return defs.map((m) => Object.assign({}, m, { done: m.progress >= m.target, claimed: g.claimedMissions.includes(m.id) }));
  },
  claimMission(userId, missionId) {
    const missions = GamificationService.getMissions(userId);
    const m = missions.find((x) => x.id === missionId);
    if (!m) throw httpError(404, "ماموریت پیدا نشد");
    if (!m.done) throw httpError(400, "این ماموریت هنوز کامل نشده");
    const g = getOrCreateGamification(userId);
    if (g.claimedMissions.includes(missionId)) throw httpError(400, "قبلاً جایزه‌ش رو گرفتی");
    const newXp = g.xp + m.reward;
    const updated = _gamification.update(g.id, { xp: newXp, claimedMissions: g.claimedMissions.concat([missionId]) });
    const { level, xpIntoLevel, xpForNext } = levelFromXp(updated.xp);
    return { ok: true, reward: m.reward, xp: updated.xp, level, xpIntoLevel, xpForNext };
  },
  leaderboard(limit) {
    const all = _gamification.all();
    const rows = all.map((g) => {
      const u = UserRepo.findById(g.userId);
      const { level } = levelFromXp(g.xp);
      return { name: u ? u.name : "کاربر", username: u ? u.username : null, xp: g.xp, level, avatarUrl: u ? u.avatarUrl : null };
    }).sort((a, b) => b.xp - a.xp).slice(0, Math.min(100, Number(limit) || 20));
    return rows;
  },
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
  listAll(adminId) { requireAdminUser(adminId, "payments"); return _plans.all(); },
  update(adminId, id, patch) {
    requireAdminUser(adminId, "payments");
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
  listAll(adminId) { requireAdminUser(adminId, "payments"); return _discountCodes.all(); },
  create(adminId, { code, percentOff, amountOff, maxUses, expiresAt }) {
    requireAdminUser(adminId, "payments");
    if (!percentOff && !amountOff) throw httpError(400, "درصد یا مقدار تخفیف رو مشخص کن");
    const finalCode = (code && code.trim()) ? code.trim().toUpperCase() : "SALE-" + crypto.randomBytes(3).toString("hex").toUpperCase();
    if (_discountCodes.findOne((c) => c.code === finalCode)) throw httpError(409, "این کد قبلاً وجود دارد");
    return _discountCodes.insert({
      code: finalCode, percentOff: percentOff ? Number(percentOff) : null, amountOff: amountOff ? Number(amountOff) : null,
      maxUses: maxUses ? Number(maxUses) : null, usedCount: 0, expiresAt: expiresAt || null, isActive: true,
    });
  },
  toggle(adminId, id, isActive) {
    requireAdminUser(adminId, "payments");
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
const PaymentRepo = {
  create: (data) => _payments.insert(data),
  findById: (id) => _payments.findById(id),
  update: (id, patch) => _payments.update(id, patch),
};
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
  listPending(adminId) { requireAdminUser(adminId, "payments"); return _payments.findMany((p) => p.status === "pending").sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)); },
  listAll(adminId) { requireAdminUser(adminId, "payments"); return _payments.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 200); },
  approve(adminId, paymentId) {
    requireAdminUser(adminId, "payments");
    const p = _payments.findById(paymentId);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    if (p.status !== "pending") throw httpError(400, "این تراکنش قبلاً بررسی شده");
    const metaType = p.meta && p.meta.type;
    if (!metaType) {
      // پرداخت اشتراک VIP معمولی
      const plan = _plans.findById(p.planId);
      if (!plan) throw httpError(404, "پلن این تراکنش یافت نشد");
      grantVipDaysToUser(p.userId, plan.durationDays, plan.title);
    } else if (metaType === "coach_subscription" && p.meta.coachId) {
      const plan = getCoachPlans().find((pl) => pl.id === p.meta.planId);
      if (plan) {
        const expiresAt = new Date(Date.now() + plan.durationDays * 86400000).toISOString();
        CoachRepo.update(p.meta.coachId, { subscription: plan.id, subscriptionExpiresAt: expiresAt });
      }
    } else if (metaType === "coach_program" && p.meta.coachId) {
      const commission = Math.round((p.amountToman || 0) * getCoachCommissionRate());
      const earning = (p.amountToman || 0) - commission;
      CoachWalletRepo.addTransaction(p.meta.coachId, "earning", earning, "فروش برنامه");
      if (commission > 0) CoachWalletRepo.addTransaction(p.meta.coachId, "commission", commission, "کمیسیون اپ");
      const coach = CoachRepo.findById(p.meta.coachId);
      if (coach) CoachRepo.update(p.meta.coachId, { totalSales: (coach.totalSales || 0) + 1 });
      if (p.meta.programId) {
        const prog = CoachProgramRepo.findById(p.meta.programId);
        if (prog) CoachProgramRepo.update(p.meta.programId, { salesCount: (prog.salesCount || 0) + 1 });
        ProductPurchaseRepo.create({ userId: p.userId, productId: p.meta.programId, paymentId: p.id, purchasedAt: new Date().toISOString() });
      }
      const existingRel = CoachStudentRepo.findByCoachAndUser(p.meta.coachId, p.userId);
      if (!existingRel) CoachStudentRepo.create({ coachId: p.meta.coachId, userId: p.userId, status: "active" });
      else if (existingRel.status !== "active") CoachStudentRepo.update(existingRel.id, { status: "active" });
    } else if (metaType === "coach_booking" && p.meta.coachId) {
      const commission = Math.round((p.amountToman || 0) * getCoachCommissionRate());
      const earning = (p.amountToman || 0) - commission;
      CoachWalletRepo.addTransaction(p.meta.coachId, "earning", earning, "رزرو مشاوره (" + (BOOKING_TYPES[p.meta.bookingType] || p.meta.bookingType) + ")");
      if (commission > 0) CoachWalletRepo.addTransaction(p.meta.coachId, "commission", commission, "کمیسیون اپ");
      CoachBookingRepo.create({
        coachId: p.meta.coachId, userId: p.userId, type: p.meta.bookingType,
        requestedTime: p.meta.requestedTime, note: p.meta.note || "", status: "confirmed", paymentId: p.id,
      });
      const existingRel2 = CoachStudentRepo.findByCoachAndUser(p.meta.coachId, p.userId);
      if (!existingRel2) CoachStudentRepo.create({ coachId: p.meta.coachId, userId: p.userId, status: "active" });
      else if (existingRel2.status !== "active") CoachStudentRepo.update(existingRel2.id, { status: "active" });
    } else if (metaType === "equipment_order" && p.meta.orderId) {
      const order = EquipOrderRepo.findById(p.meta.orderId);
      if (order && order.status === "pending_payment") EquipOrderRepo.update(order.id, { status: "paid" });
    }
    const updated = _payments.update(paymentId, { status: "success", paidAt: new Date().toISOString() });
    ReferralService.awardPurchaseCommission(updated);
    SecurityLog.log({ userId: adminId, type: "payment_approved", meta: { paymentId, targetUser: p.userId, kind: metaType || "vip" } });
    return updated;
  },
  refund(adminId, paymentId, reason) {
    requireAdminUser(adminId);
    const p = _payments.findById(paymentId);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    if (p.status !== "success") throw httpError(400, "فقط تراکنش‌های موفق قابل بازپرداختن");
    const updated = _payments.update(paymentId, { status: "refunded", refundReason: reason || null, refundedAt: new Date().toISOString() });
    SecurityLog.log({ userId: adminId, type: "payment_refunded", meta: { paymentId, targetUser: p.userId, reason: reason || null } });
    return updated;
  },
  manualCreate(adminId, { userId, amountToman, amountUsdt, note }) {
    requireAdminUser(adminId);
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const rec = _payments.insert({
      userId, planId: null, provider: "manual_admin", providerRef: null,
      amountToman: amountToman ? Number(amountToman) : null, amountUsdt: amountUsdt ? Number(amountUsdt) : null,
      status: "success", paidAt: new Date().toISOString(), meta: { type: "manual", note: (note || "").slice(0, 300), recordedBy: adminId },
    });
    SecurityLog.log({ userId: adminId, type: "payment_manual_entry", meta: { paymentId: rec.id, targetUser: userId, amountToman, amountUsdt } });
    return rec;
  },
  reject(adminId, paymentId, reason) {
    requireAdminUser(adminId, "payments");
    const p = _payments.findById(paymentId);
    if (!p) throw httpError(404, "تراکنش یافت نشد");
    const updated = _payments.update(paymentId, { status: "rejected", rejectReason: reason || null });
    if (p.meta && p.meta.type === "equipment_order" && p.meta.orderId) {
      const order = EquipOrderRepo.findById(p.meta.orderId);
      if (order && order.status === "pending_payment") {
        order.items.forEach((it) => { const prod = EquipProductRepo.findById(it.productId); if (prod) EquipProductRepo.update(prod.id, { stock: prod.stock + it.qty }); });
        EquipOrderRepo.update(order.id, { status: "cancelled" });
      }
    }
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
      const updated = _payments.update(p.id, { status: "success", paidAt: new Date().toISOString(), receiptCode: String(data.data.ref_id || "") });
      ReferralService.awardPurchaseCommission(updated);
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
function getCoachCommissionRate() {
  const rec = _aiSettings.findOne((s) => s.key === "coach_commission");
  const rate = rec && rec.value && typeof rec.value.rate === "number" ? rec.value.rate : 0.1;
  return Math.min(0.9, Math.max(0, rate));
}
function setCoachCommissionRate(rate) {
  const clean = Math.min(0.9, Math.max(0, Number(rate) || 0));
  const rec = _aiSettings.findOne((s) => s.key === "coach_commission");
  if (rec) _aiSettings.update(rec.id, { value: { rate: clean } });
  else _aiSettings.insert({ key: "coach_commission", value: { rate: clean } });
  return clean;
}

function buildSystemPrompt(user) {
  const p = user.profile || {};
  const goalLabel = { cut: "کات (خشک کردن)", bulk: "افزایش حجم", fatloss: "چربی‌سوزی", recomp: "نگهداری/ترکیب بدنی" }[p.trainingGoal] || "نامشخص";
  const levelLabel = { amateur: "آماتور", beginner: "مبتدی", pro: "حرفه‌ای" }[p.trainingLevel] || "نامشخص";
  return "تو «مربی آیرون» هستی، دستیار هوشمند اپلیکیشن تناسب‌اندام «پروتکل آیرون». به فارسی، صمیمی، مختصر و کاربردی جواب بده.\n" +
    "اطلاعات کاربر: نام: " + (user.name || "کاربر") + "، جنسیت: " + (p.gender === "female" ? "زن" : "مرد") + "، سن: " + (p.age || "نامشخص") +
    "، قد: " + (p.height || "نامشخص") + " سانتی‌متر، وزن: " + (p.weight || "نامشخص") + " کیلوگرم، هدف: " + goalLabel + "، سطح تمرینی: " + levelLabel + ".\n" +
    "قوانین مهم: هیچ‌وقت خودتو جای پزشک یا متخصص تغذیه‌ی واقعی نذار؛ برای مسائل پزشکی/آسیب‌دیدگی همیشه توصیه کن با پزشک مشورت کنه. جواب رو کامل و جمع‌بندی‌شده بده؛ در عین حال مختصر و عملی باش و معمولاً بیشتر از ۲۵۰ کلمه ننویس مگر واقعاً لازم باشه.";
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
      generationConfig: { temperature: 0.7, maxOutputTokens: 2048, thinkingConfig: { thinkingBudget: 0 } },
    }),
  });
  const data = await res.json();
  if (!res.ok) {
    const msg = (data && data.error && data.error.message) || "خطای نامشخص از سرویس هوش مصنوعی";
    throw httpError(502, msg);
  }
  const text = data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts
    ? data.candidates[0].content.parts.map((p) => p.text || "").join("") : "";
  const finishReason = data.candidates && data.candidates[0] && data.candidates[0].finishReason;
  const usage = data.usageMetadata || {};
  let finalText = text || "متاسفم، نتونستم جواب بدم. دوباره امتحان کن.";
  if (finishReason === "MAX_TOKENS" && text) finalText += "\n\n(پاسخ طولانی بود و کوتاه شد؛ اگه خواستی ادامه‌شو بپرس)";
  return { text: finalText, promptTokens: usage.promptTokenCount || 0, completionTokens: usage.candidatesTokenCount || 0 };
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
  getSettings(adminId) { requireAdminUser(adminId, "ai"); return getAiSettings(); },
  updateSettings(adminId, patch) {
    requireAdminUser(adminId, "ai");
    const clean = {};
    if (patch.enabled !== undefined) clean.enabled = !!patch.enabled;
    if (patch.freeDailyLimit !== undefined) clean.freeDailyLimit = Math.max(0, Number(patch.freeDailyLimit) || DEFAULT_FREE_LIMIT);
  if (patch.personality !== undefined) clean.personality = String(patch.personality).slice(0, 50);
  if (patch.customPrompt !== undefined) clean.customPrompt = String(patch.customPrompt).slice(0, 2000);
    if (patch.model !== undefined && isNonEmptyString(patch.model)) clean.model = patch.model.trim();
    return saveAiSettings(clean);
  },
  stats(adminId) {
    requireAdminUser(adminId, "ai");
    const allMsgs = _aiMessages.all();
    const userMsgs = allMsgs.filter((m) => m.role === "user");
    const distinctUsers = new Set(userMsgs.map((m) => m.userId)).size;
    const today = new Date().toISOString().slice(0, 10);
    const todayMsgs = userMsgs.filter((m) => (m.createdAt || "").slice(0, 10) === today).length;
    const totalTokens = allMsgs.reduce((sum, m) => sum + (m.promptTokens || 0) + (m.completionTokens || 0), 0);
    return { totalMessages: userMsgs.length, distinctUsers, todayMessages: todayMsgs, totalTokens, hasApiKey: !!env.GEMINI_API_KEY, settings: getAiSettings() };
  },
};

/* ================= سرویس پنل مدیریت (RBAC) ================= */
// نقش‌ها: admin (دسترسی کامل) < moderator/support (محدود به PERMISSIONS خودشون)
const ADMIN_PERMISSIONS = ["users", "coaches", "payments", "tickets", "ai", "content"];
const ROLE_DEFAULT_PERMISSIONS = {
  moderator: ["coaches", "content", "tickets"],
  support: ["tickets", "users"],
};
function requireAdminUser(userId, permission) {
  const user = UserRepo.findById(userId);
  if (!user) throw httpError(403, "دسترسی نداری");
  if (user.role === "admin") return user; // دسترسی کامل
  if ((user.role === "moderator" || user.role === "support") && permission) {
    const perms = user.permissions || ROLE_DEFAULT_PERMISSIONS[user.role] || [];
    if (perms.includes(permission)) return user;
  }
  throw httpError(403, "دسترسی نداری");
}
const AdminService = {
  stats(adminId) {
    requireAdminUser(adminId);
    const all = UserRepo.all();
    const now = Date.now();
    const vipCount = all.filter((u) => u.vip && u.vip.active && (!u.vip.expiresAt || new Date(u.vip.expiresAt).getTime() > now)).length;
    const todayKey = new Date().toISOString().slice(0, 10);
    const signupsToday = all.filter((u) => (u.createdAt || "").slice(0, 10) === todayKey).length;
    const approvedPayments = _payments.findMany((p) => p.status === "success");
    const revenueToman = approvedPayments.reduce((s, p) => s + (p.amountToman || 0), 0);
    const revenueUsdt = approvedPayments.reduce((s, p) => s + (p.amountUsdt || 0), 0);
    const trend = [];
    for (let i = 6; i >= 0; i--) {
      const day = new Date(now - i * 86400000).toISOString().slice(0, 10);
      trend.push({ date: day, signups: all.filter((u) => (u.createdAt || "").slice(0, 10) === day).length });
    }
    return {
      totalUsers: all.length, vipUsers: vipCount, signupsToday, totalVipCodes: _vipCodes.all().length,
      revenueToman, revenueUsdt, pendingPayments: _payments.findMany((p) => p.status === "pending").length,
      totalCoaches: _coaches.findMany((c) => c.status === "approved").length,
      pendingCoaches: _coaches.findMany((c) => c.status === "pending").length,
      openTickets: _tickets.findMany((t) => t.status !== "closed").length,
      signupTrend: trend,
    };
  },
  auditLog(adminId, { type, search, page, limit } = {}) {
    requireAdminUser(adminId);
    let events = _secEvents.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    if (type) events = events.filter((e) => e.type === type);
    if (search) {
      const q = search.toLowerCase();
      events = events.filter((e) => JSON.stringify(e.meta || {}).toLowerCase().includes(q) || (e.userId || "").includes(q));
    }
    const pg = Math.max(1, Number(page) || 1);
    const lim = Math.min(100, Math.max(10, Number(limit) || 40));
    const total = events.length;
    const slice = events.slice((pg - 1) * lim, pg * lim).map((e) => {
      const u = e.userId ? UserRepo.findById(e.userId) : null;
      return Object.assign({}, e, { userName: u ? u.name : null, userEmail: u ? u.email : null });
    });
    return { total, page: pg, limit: lim, items: slice };
  },
  listUsers(adminId, search) {
    requireAdminUser(adminId, "users");
    let all = UserRepo.all().map(publicUser).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    if (search) {
      const q = search.toLowerCase();
      all = all.filter((u) => (u.name || "").toLowerCase().includes(q) || (u.email || "").toLowerCase().includes(q) || (u.phone || "").includes(q) || (u.username || "").toLowerCase().includes(q));
    }
    return all.slice(0, 200);
  },
  userDetail(adminId, userId) {
    requireAdminUser(adminId, "users");
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const stats = _bodyStats.findMany((s) => s.userId === userId).sort((a, b) => new Date(b.date || b.createdAt) - new Date(a.date || a.createdAt)).slice(0, 10);
    const records = _personalRecords.findMany((r) => r.userId === userId);
    const payments = _payments.findMany((p) => p.userId === userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 20);
    const aiUsage = _aiUsage.findMany((a) => a.userId === userId).sort((a, b) => (b.date || "").localeCompare(a.date || "")).slice(0, 14);
    const events = _secEvents.findMany((e) => e.userId === userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 30);
    const coachProfile = _coaches.findOne((c) => c.userId === userId);
    return { user: publicUser(user), stats, records, payments, aiUsage, events, coachProfile: coachProfile || null };
  },
  updateUserProfile(adminId, userId, patch) {
    requireAdminUser(adminId, "users");
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    const clean = {};
    ["name", "email", "phone"].forEach((k) => { if (patch[k] !== undefined) clean[k] = patch[k]; });
    if (patch.username !== undefined && patch.username !== user.username) {
      if (!isValidUsername(patch.username)) throw httpError(400, "نام کاربری نامعتبر است");
      const existing = UserRepo.findByUsername(patch.username);
      if (existing && existing.id !== userId) throw httpError(409, "این نام کاربری قبلاً گرفته شده");
      clean.username = patch.username.trim();
    }
    const profilePatch = {};
    ["age", "height", "weight", "gender", "trainingGoal", "trainingLevel"].forEach((k) => { if (patch[k] !== undefined) profilePatch[k] = patch[k]; });
    if (Object.keys(profilePatch).length) clean.profile = Object.assign({}, user.profile, profilePatch);
    const updated = UserRepo.update(userId, clean);
    SecurityLog.log({ userId: adminId, type: "admin_user_edited", meta: { targetUser: userId, fields: Object.keys(patch) } });
    return publicUser(updated);
  },
  setUserBlocked(adminId, userId, blocked) {
    requireAdminUser(adminId, "users");
    const updated = UserRepo.update(userId, { blocked: !!blocked });
    if (!updated) throw httpError(404, "کاربر یافت نشد");
    SecurityLog.log({ userId: adminId, type: blocked ? "admin_user_blocked" : "admin_user_unblocked", meta: { targetUser: userId } });
    return publicUser(updated);
  },
  deleteUser(adminId, userId) {
    const admin = requireAdminUser(adminId);
    if (userId === adminId) throw httpError(400, "نمی‌تونی حساب خودت رو حذف کنی");
    const user = UserRepo.findById(userId);
    if (!user) throw httpError(404, "کاربر یافت نشد");
    _users.remove(userId);
    SecurityLog.log({ userId: adminId, type: "admin_user_deleted", meta: { targetUser: userId, targetEmail: user.email } });
    return { ok: true };
  },
  setUserVip(adminId, userId, { active, days }) {
    requireAdminUser(adminId, "users");
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
  // === مدیریت تیم ادمین (فقط برای admin کامل) ===
  listTeam(adminId) {
    const admin = requireAdminUser(adminId);
    if (admin.role !== "admin") throw httpError(403, "فقط مدیر کامل به مدیریت تیم دسترسی داره");
    return UserRepo.all().filter((u) => ["admin", "moderator", "support"].includes(u.role)).map((u) => publicUser(u));
  },
  setTeamRole(adminId, userId, { role, permissions }) {
    const admin = requireAdminUser(adminId);
    if (admin.role !== "admin") throw httpError(403, "فقط مدیر کامل به مدیریت تیم دسترسی داره");
    if (!["user", "coach", "support", "moderator", "admin"].includes(role)) throw httpError(400, "نقش نامعتبر است");
    if (userId === adminId && role !== "admin") throw httpError(400, "نمی‌تونی نقش خودت رو پایین بیاری");
    const cleanPerms = Array.isArray(permissions) ? permissions.filter((p) => ADMIN_PERMISSIONS.includes(p)) : undefined;
    const patch = { role };
    if (cleanPerms) patch.permissions = cleanPerms;
    const updated = UserRepo.update(userId, patch);
    if (!updated) throw httpError(404, "کاربر یافت نشد");
    SecurityLog.log({ userId: adminId, type: "admin_role_changed", meta: { targetUser: userId, role, permissions: cleanPerms || null } });
    return publicUser(updated);
  },
  listVipCodes(adminId) {
    requireAdminUser(adminId, "payments");
    return _vipCodes.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  },
  createVipCode(adminId, { code, durationDays, maxUses, expiresAt, planLabel }) {
    requireAdminUser(adminId, "payments");
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
    requireAdminUser(adminId, "payments");
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
  verify2FA: (req, res, next) => AuthService.verify2FA(req.body, ctxFrom(req)).then((r) => res.status(200).json(r)).catch(next),
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
  addBodyStat: (req, res, next) => { try { const r = UsersService.addBodyStat(req.userId, req.body); GamificationService.logActivity(req.userId, "stat_logged"); res.status(201).json(r); } catch (e) { next(e); } },
  listBodyStats: (req, res, next) => { try { res.json(UsersService.listBodyStats(req.userId)); } catch (e) { next(e); } },
  logDaily: (req, res, next) => {
    try {
      const r = UsersService.logDaily(req.userId, req.body);
      if (req.body.sleep !== undefined) GamificationService.logActivity(req.userId, "sleep_logged");
      if (req.body.water !== undefined && Number(req.body.water) >= 2000) GamificationService.logActivity(req.userId, "water_goal_met");
      res.json(r);
    } catch (e) { next(e); }
  },
  listDailyLogs: (req, res, next) => { try { res.json(UsersService.listDailyLogs(req.userId, req.query.days)); } catch (e) { next(e); } },
  addPr: (req, res, next) => { try { const r = UsersService.addPersonalRecord(req.userId, req.body); GamificationService.logActivity(req.userId, "pr_added"); res.status(201).json(r); } catch (e) { next(e); } },
  listPrs: (req, res, next) => { try { res.json(UsersService.listPersonalRecords(req.userId)); } catch (e) { next(e); } },
  logActivity: (req, res, next) => { try { res.json(GamificationService.logActivity(req.userId, req.body.type)); } catch (e) { next(e); } },
  gamificationProfile: (req, res, next) => { try { res.json(GamificationService.getProfile(req.userId)); } catch (e) { next(e); } },
  gamificationMissions: (req, res, next) => { try { res.json(GamificationService.getMissions(req.userId)); } catch (e) { next(e); } },
  claimMission: (req, res, next) => { try { res.json(GamificationService.claimMission(req.userId, req.body.missionId)); } catch (e) { next(e); } },
  leaderboard: (req, res, next) => { try { res.json(GamificationService.leaderboard(req.query.limit)); } catch (e) { next(e); } },
  myReferral: (req, res, next) => { try { res.json(ReferralService.myStats(req.userId)); } catch (e) { next(e); } },
  mySessions: (req, res, next) => {
    try {
      const sessions = SessionRepo.findActiveForUser(req.userId).map((s) => ({ id: s.id, userAgent: s.userAgent, ip: s.ip, createdAt: s.createdAt, expiresAt: s.expiresAt }));
      res.json(sessions);
    } catch (e) { next(e); }
  },
  revokeSession: (req, res, next) => {
    try {
      const s = SessionRepo.findById(req.params.id);
      if (!s || s.userId !== req.userId) throw httpError(404, "نشست پیدا نشد");
      SessionRepo.revokeById(s.id);
      SecurityLog.log({ userId: req.userId, type: "session_revoked_by_user", meta: { sessionId: s.id } });
      res.json({ ok: true });
    } catch (e) { next(e); }
  },
  revokeOtherSessions: (req, res, next) => {
    try {
      const count = SessionRepo.revokeAllExcept(req.userId, req.body.currentRefreshToken || "");
      SecurityLog.log({ userId: req.userId, type: "sessions_revoked_bulk", meta: { count } });
      res.json({ ok: true, revoked: count });
    } catch (e) { next(e); }
  },
  toggleTwoFactor: (req, res, next) => { try { res.json(UsersService.toggleTwoFactor(req.userId, req.body.enable, req.body.password)); } catch (e) { next(e); } },
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
  auditLog: (req, res, next) => { try { res.json(AdminService.auditLog(req.userId, req.query)); } catch (e) { next(e); } },
  listUsers: (req, res, next) => { try { res.json(AdminService.listUsers(req.userId, req.query.search)); } catch (e) { next(e); } },
  userDetail: (req, res, next) => { try { res.json(AdminService.userDetail(req.userId, req.params.id)); } catch (e) { next(e); } },
  updateUserProfile: (req, res, next) => { try { res.json(AdminService.updateUserProfile(req.userId, req.params.id, req.body)); } catch (e) { next(e); } },
  setUserBlocked: (req, res, next) => { try { res.json(AdminService.setUserBlocked(req.userId, req.params.id, req.body.blocked)); } catch (e) { next(e); } },
  deleteUser: (req, res, next) => { try { res.json(AdminService.deleteUser(req.userId, req.params.id)); } catch (e) { next(e); } },
  listTeam: (req, res, next) => { try { res.json(AdminService.listTeam(req.userId)); } catch (e) { next(e); } },
  setTeamRole: (req, res, next) => { try { res.json(AdminService.setTeamRole(req.userId, req.params.id, req.body)); } catch (e) { next(e); } },
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
  refundPayment: (req, res, next) => { try { res.json(PaymentService.refund(req.userId, req.params.id, req.body.reason)); } catch (e) { next(e); } },
  manualPayment: (req, res, next) => { try { res.json(PaymentService.manualCreate(req.userId, req.body)); } catch (e) { next(e); } },
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
authRoutes.post("/verify-2fa", rateLimit({ windowMs: 60000, max: 10, keyPrefix: "verify-2fa" }), AuthController.verify2FA);
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
usersRoutes.post("/me/daily-log", UsersController.logDaily);
usersRoutes.get("/me/daily-log", UsersController.listDailyLogs);
usersRoutes.post("/me/prs", UsersController.addPr);
usersRoutes.get("/me/prs", UsersController.listPrs);
usersRoutes.post("/me/activity", UsersController.logActivity);
usersRoutes.get("/me/gamification", UsersController.gamificationProfile);
usersRoutes.get("/me/missions", UsersController.gamificationMissions);
usersRoutes.post("/me/missions/claim", UsersController.claimMission);
usersRoutes.get("/leaderboard", UsersController.leaderboard);
usersRoutes.get("/me/referral", UsersController.myReferral);
usersRoutes.get("/me/sessions", UsersController.mySessions);
usersRoutes.delete("/me/sessions/:id", UsersController.revokeSession);
usersRoutes.post("/me/sessions/revoke-others", UsersController.revokeOtherSessions);
usersRoutes.put("/me/two-factor", UsersController.toggleTwoFactor);

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
adminRoutes.get("/backup/export", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const dump = { exportedAt: new Date().toISOString(), collections: {} };
    ALL_COLLECTION_NAMES.forEach((name) => { dump.collections[name] = _load(name); });
    SecurityLog.log({ userId: req.userId, type: "backup_exported" });
    res.setHeader("Content-Disposition", "attachment; filename=iron-protocol-backup-" + new Date().toISOString().slice(0, 10) + ".json");
    res.json(dump);
  } catch (e) { next(e); }
});
adminRoutes.post("/backup/restore", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    if (req.body.confirm !== true) throw httpError(400, "برای بازیابی باید confirm=true بفرستی — این کار همه‌ی داده‌های فعلی رو جایگزین می‌کنه");
    const collections = req.body.collections;
    if (!collections || typeof collections !== "object") throw httpError(400, "فایل بکاپ نامعتبره");
    let restoredCount = 0;
    ALL_COLLECTION_NAMES.forEach((name) => {
      if (Array.isArray(collections[name])) { _cache.set(name, collections[name]); _persist(name); restoredCount++; }
    });
    SecurityLog.log({ userId: req.userId, type: "backup_restored", meta: { restoredCount } });
    res.json({ ok: true, restoredCollections: restoredCount });
  } catch (e) { next(e); }
});
adminRoutes.get("/live-dashboard", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const monthStr = todayStr.slice(0, 7);
    const payments = _payments.all().filter((p) => p.status === "success");
    const todayRevenue = payments.filter((p) => (p.paidAt || "").slice(0, 10) === todayStr).reduce((s, p) => s + (p.amountToman || 0), 0);
    const monthRevenue = payments.filter((p) => (p.paidAt || "").slice(0, 7) === monthStr).reduce((s, p) => s + (p.amountToman || 0), 0);
    const todaySalesCount = payments.filter((p) => (p.paidAt || "").slice(0, 10) === todayStr).length;
    const coachEarningsTotal = _coachWallet.all().reduce((s, w) => s + (w.totalEarnings || 0), 0);
    const coachCommissionTotal = _coachWallet.all().reduce((s, w) => s + (w.totalCommission || 0), 0);
    const ads = _adBanners ? _adBanners.all() : [];
    const adImpressionsTotal = ads.reduce((s, a) => s + (a.impressions || 0), 0);
    const adClicksTotal = ads.reduce((s, a) => s + (a.clicks || 0), 0);
    const aiCallsToday = _aiUsage.findMany((r) => r.date === todayStr).reduce((s, r) => s + (r.count || 0), 0);
    const mem = process.memoryUsage();
    res.json({
      onlineUsers: countOnlineUsers(5 * 60000),
      onlineUsers15m: countOnlineUsers(15 * 60000),
      revenue: { today: todayRevenue, month: monthRevenue, todaySalesCount },
      coach: { totalEarnings: coachEarningsTotal, platformCommission: coachCommissionTotal, activeCoaches: CoachRepo.all().filter((c) => c.status === "approved").length },
      ads: { totalBanners: ads.length, impressionsTotal: adImpressionsTotal, clicksTotal: adClicksTotal },
      api: { aiCallsToday },
      system: {
        uptimeSeconds: Math.round(process.uptime()),
        memoryUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
        memoryTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
        nodeVersion: process.version,
      },
      health: {
        database: env.MONGODB_URI ? (_mongoReady ? "connected" : "configured_not_connected") : "local_file_only",
        email: process.env.RESEND_API_KEY ? "configured" : "not_configured",
        paymentGateway: env.ZARINPAL_MERCHANT_ID ? "configured" : "not_configured",
        usdtWallet: env.USDT_WALLET_ADDRESS ? "configured" : "not_configured",
        backup: env.MONGODB_URI ? "mirrored_to_mongodb" : "local_only_no_auto_backup",
      },
      totals: { users: _users.all().length, coaches: CoachRepo.all().length, products: CoachProgramRepo.all().length, tickets: _tickets.all().length },
    });
  } catch (e) { next(e); }
});
adminRoutes.get("/audit-log", AdminController.auditLog);
adminRoutes.get("/users", AdminController.listUsers);
adminRoutes.get("/users/:id", AdminController.userDetail);
adminRoutes.put("/users/:id", AdminController.updateUserProfile);
adminRoutes.put("/users/:id/block", AdminController.setUserBlocked);
adminRoutes.delete("/users/:id", AdminController.deleteUser);
adminRoutes.put("/users/:id/vip", AdminController.setUserVip);
adminRoutes.get("/team", AdminController.listTeam);
adminRoutes.get("/referrals", (req, res, next) => { try { res.json(ReferralService.adminList(req.userId, req.query.status)); } catch (e) { next(e); } });
adminRoutes.put("/referrals/:id/pay", (req, res, next) => { try { res.json(ReferralService.markPaid(req.userId, req.params.id)); } catch (e) { next(e); } });
adminRoutes.put("/referrals/:id/cancel", (req, res, next) => { try { res.json(ReferralService.cancel(req.userId, req.params.id, req.body.reason)); } catch (e) { next(e); } });
adminRoutes.put("/referrals/settings", (req, res, next) => { try { res.json(ReferralService.setSettings(req.userId, req.body)); } catch (e) { next(e); } });
adminRoutes.get("/referrals/settings", (req, res, next) => { try { requireAdminUser(req.userId, "payments"); res.json(getReferralSettings()); } catch (e) { next(e); } });
adminRoutes.put("/team/:id/role", AdminController.setTeamRole);
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
adminRoutes.put("/payments/:id/refund", AdminController.refundPayment);
adminRoutes.post("/payments/manual", AdminController.manualPayment);

/* ================= پنل مدیریت (صفحه‌ی وب ساده، بدون نیاز به دیپلوی جدا) ================= */
const ADMIN_PAGE_HTML = `<!DOCTYPE html>
<html dir="rtl" lang="fa"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل مدیریت | پروتکل آیرون</title>
<style>
*{box-sizing:border-box;}
body{font-family:Tahoma,Vazirmatn,sans-serif;background:linear-gradient(160deg,#0A0B09 0%,#0D1210 100%);color:#F3EEDD;margin:0;padding:0 16px 40px;min-height:100vh;}
.topbar{position:sticky;top:0;z-index:10;background:linear-gradient(135deg,#171310,#0A0B09);margin:0 -16px 16px;padding:16px;border-bottom:2px solid rgba(216,174,82,.35);box-shadow:0 6px 20px rgba(0,0,0,.4);}
.topbar h1{margin:0;font-size:17px;background:linear-gradient(90deg,#F2CE7A,#D8AE52);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:800;}
.topbar .sub{font-size:11px;color:#9A9484;margin-top:2px;}
.panel{background:linear-gradient(160deg,#141912,#101410);border:1px solid rgba(76,122,82,.28);border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 4px 14px rgba(0,0,0,.25);}
input,select,textarea{background:#0A0B09;color:#F3EEDD;border:1px solid rgba(76,122,82,.4);border-radius:8px;padding:9px 10px;margin:4px 0;width:100%;box-sizing:border-box;font-family:inherit;transition:border-color .15s;}
input:focus,select:focus,textarea:focus{outline:none;border-color:#D8AE52;}
button{background:linear-gradient(135deg,#F2CE7A,#D8AE52);color:#1A140B;border:none;border-radius:8px;padding:9px 15px;font-weight:800;cursor:pointer;margin:4px 2px;transition:transform .1s,box-shadow .15s;box-shadow:0 2px 8px rgba(216,174,82,.25);}
button:hover{transform:translateY(-1px);box-shadow:0 4px 12px rgba(216,174,82,.4);}
button:active{transform:translateY(0);}
button.danger{background:linear-gradient(135deg,#FF6B6B,#E14848);color:#2A0A0A;}
button.outline{background:transparent;border:1.5px solid #D8AE52;color:#D8AE52;box-shadow:none;}
button.outline:hover{background:rgba(216,174,82,.1);}
button.small{padding:5px 10px;font-size:11px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{padding:8px 6px;text-align:right;color:#D8AE52;font-size:11px;border-bottom:2px solid rgba(216,174,82,.25);}
td{padding:8px 6px;text-align:right;border-bottom:1px solid rgba(255,255,255,.06);}
tr:hover td{background:rgba(255,255,255,.02);}
.statgrid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}
.tabbtn{flex-shrink:0;padding:9px 16px;border-radius:10px;border:1.5px solid var(--border,#333);background:rgba(255,255,255,.04);color:inherit;font-size:12.5px;font-weight:700;cursor:pointer;white-space:nowrap;}
.tabpage{animation:fadein .15s ease;}
@keyframes fadein{from{opacity:0;}to{opacity:1;}}
.statcard{background:linear-gradient(160deg,rgba(216,174,82,.12),rgba(216,174,82,.03));border:1px solid rgba(216,174,82,.3);border-radius:12px;padding:14px;text-align:center;}
.statnum{font-size:24px;font-weight:800;color:#F2CE7A;}
.err{color:#FF6B6B;font-size:12px;margin-top:6px;}
.badge{font-size:10px;padding:3px 9px;border-radius:20px;font-weight:700;display:inline-block;}
.badge.on{background:rgba(61,220,116,.18);color:#3DDC74;border:1px solid rgba(61,220,116,.35);}
.badge.off{background:rgba(255,82,82,.15);color:#FF5252;border:1px solid rgba(255,82,82,.3);}
.badge.warn{background:rgba(242,206,122,.15);color:#F2CE7A;border:1px solid rgba(242,206,122,.35);}
h2{font-size:17px;} h3{font-size:14.5px;color:#D8AE52;margin-top:0;display:flex;align-items:center;gap:6px;}
.thumb{width:60px;height:60px;object-fit:cover;border-radius:8px;border:1px solid rgba(255,255,255,.15);cursor:pointer;}
.evidence-row{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0;}
.report-card{border:1px solid rgba(255,255,255,.08);border-radius:10px;padding:12px;margin-bottom:8px;background:rgba(255,255,255,.015);}
.section-divider{border:none;border-top:1px dashed rgba(216,174,82,.2);margin:18px 0;}
select.tier-select{width:auto;display:inline-block;}
</style></head>
<body>
<div class="topbar" id="topbar" style="display:none;"><h1>🛡️ پنل مدیریت پروتکل آیرون</h1><div class="sub">مدیریت کاربران، مربیان، پرداخت‌ها و محتوا</div></div>
<div id="app">در حال بارگذاری...</div>
<script>
const T={access:null};
async function downloadBackup(){
  try{
    const data=await api("/api/admin/backup/export");
    const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url; a.download="iron-protocol-backup-"+new Date().toISOString().slice(0,10)+".json";
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }catch(e){ alert(e.message); }
}
async function restoreBackup(){
  const msg=document.getElementById("backupMsg");
  const fileInput=document.getElementById("restoreFile");
  if(!fileInput.files.length){ msg.textContent="اول یه فایل بکاپ انتخاب کن"; msg.style.color="#FF5252"; return; }
  if(!confirm("این کار همه‌ی داده‌های فعلی رو با محتوای فایل جایگزین می‌کنه و برگشت‌پذیر نیست. مطمئنی؟"))return;
  try{
    const text=await fileInput.files[0].text();
    const parsed=JSON.parse(text);
    const result=await api("/api/admin/backup/restore",{method:"POST",body:JSON.stringify({confirm:true,collections:parsed.collections})});
    msg.textContent="بازیابی شد ✅ ("+result.restoredCollections+" بخش) — صفحه رو رفرش کن"; msg.style.color="#8FD19E";
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
async function api(path,opts={}){
  const headers={"Content-Type":"application/json"};
  if(T.access) headers.Authorization="Bearer "+T.access;
  const res=await fetch(path,Object.assign({headers},opts));
  const data=await res.json().catch(()=>null);
  if(!res.ok) throw new Error((data&&data.error)||"خطا");
  return data;
}
async function apiUpload(path,formData){
  const headers={};
  if(T.access) headers.Authorization="Bearer "+T.access;
  const res=await fetch(path,{method:"POST",headers,body:formData});
  const data=await res.json().catch(()=>null);
  if(!res.ok) throw new Error((data&&data.error)||"خطا");
  return data;
}
let me=null, err="";
function render(){
  const app=document.getElementById("app");
  const topbar=document.getElementById("topbar");
  if(!me){
    topbar.style.display="none";
    app.innerHTML='<div class="panel" style="max-width:360px;margin:60px auto;">'+
      '<h2>ورود مدیر</h2>'+
      '<input id="email" placeholder="ایمیل مدیر">'+
      '<input id="password" type="password" placeholder="رمز عبور">'+
      (err?'<div class="err">'+err+'</div>':'')+
      '<button onclick="doLogin()">ورود</button>'+
    '</div>';
    return;
  }
  topbar.style.display="block";
  const myPerms = me.role==="admin" ? null : (me.permissions || ROLE_DEFAULT_PERMISSIONS_JS[me.role] || []);
  const canSee = function(perm){ return me.role==="admin" || (perm && myPerms.includes(perm)); };
  const tabDefs=[
    {key:"dashboard",label:"📊 داشبورد",perm:null,adminOnly:true},
    {key:"users",label:"👤 کاربران",perm:"users"},
    {key:"coaches",label:"🧑‍🏫 مربیان",perm:"coaches"},
    {key:"billing",label:"💳 پرداخت و اشتراک",perm:"payments"},
    {key:"tickets",label:"🎫 تیکت‌ها",perm:"tickets"},
    {key:"ai",label:"🧠 هوش مصنوعی",perm:"ai"},
    {key:"content",label:"📢 محتوا و اعلان‌ها",perm:"content"},
    {key:"team",label:"🔐 دسترسی‌ها",perm:null,adminOnly:true},
  ];
  const visibleTabs=tabDefs.filter(function(t){ return t.adminOnly ? me.role==="admin" : canSee(t.perm); });
  window._firstAdminTab = (visibleTabs[0]||{key:"dashboard"}).key;
  app.innerHTML='<div style="max-width:960px;margin:0 auto;">'+
    '<div style="display:flex;justify-content:flex-end;align-items:center;"><button class="outline" onclick="logout()">خروج</button></div>'+
    '<div style="display:flex;gap:6px;overflow-x:auto;margin:10px 0 16px;padding-bottom:4px;">'+
      visibleTabs.map(function(t){ return '<button class="tabbtn" data-tab-btn="'+t.key+'">'+t.label+'</button>'; }).join("")+
    '</div>'+
    '<div class="tabpage" data-tab="dashboard">'+
    '<div class="panel" style="border-color:rgba(216,174,82,.4);background:linear-gradient(135deg,rgba(216,174,82,.06),transparent);">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;">'+
        '<h3 style="margin:0;">⚡ داشبورد لحظه‌ای <span id="liveDot" style="display:inline-block;width:7px;height:7px;border-radius:50%;background:#3DDC74;margin-right:4px;"></span></h3>'+
        '<span style="font-size:10px;color:#9A9484;">هر ۱۰ ثانیه به‌روزرسانی می‌شه</span>'+
      '</div>'+
      '<div id="liveDashboard" style="margin-top:10px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>📊 نمای کلی</h3><div class="statgrid" id="stats" style="grid-template-columns:repeat(3,1fr);">...</div></div>'+
    '<div class="panel"><h3>📈 روند ثبت‌نام (۷ روز اخیر)</h3><div id="signupTrendChart" style="display:flex;align-items:flex-end;gap:6px;height:90px;">...</div></div>'+
    '<div class="panel"><h3>💾 پشتیبان‌گیری و بازیابی</h3>'+
      '<div style="font-size:11px;color:#9A9484;margin-bottom:8px;">یه فایل JSON از کل داده‌های سیستم دانلود کن، یا از یه فایل قبلی بازیابی کن.</div>'+
      '<button class="small" onclick="downloadBackup()">⬇️ دانلود بکاپ کامل</button>'+
      '<hr class="section-divider">'+
      '<input type="file" id="restoreFile" accept="application/json">'+
      '<button class="small danger" onclick="restoreBackup()">⚠️ بازیابی از فایل (جایگزین همه داده‌ها)</button>'+
      '<div id="backupMsg" style="font-size:11px;margin-top:4px;"></div>'+
    '</div>'+
    '<div class="panel"><h3>🕵️ لاگ فعالیت مدیران (Audit Log)</h3>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">'+
        '<select id="auditFilterType" onchange="loadAuditLog(1)" style="width:auto;">'+
          '<option value="">همه رویدادها</option>'+
          '<option value="admin_user_edited">ویرایش کاربر</option>'+
          '<option value="admin_user_blocked">مسدودسازی کاربر</option>'+
          '<option value="admin_user_unblocked">رفع مسدودی کاربر</option>'+
          '<option value="admin_user_deleted">حذف کاربر</option>'+
          '<option value="ticket_admin_reply">پاسخ به تیکت</option>'+
          '<option value="ticket_status_changed">تغییر وضعیت تیکت</option>'+
          '<option value="ticket_assigned">انتقال تیکت</option>'+
          '<option value="login_blocked">تلاش ورود مسدود</option>'+
        '</select>'+
        '<input id="auditSearch" placeholder="جستجو در شناسه/متادیتا..." oninput="loadAuditLog(1)" style="flex:1;min-width:160px;">'+
      '</div>'+
      '<div id="auditLogTable">در حال بارگذاری...</div>'+
      '<div style="display:flex;gap:8px;justify-content:center;margin-top:8px;">'+
        '<button class="small outline" onclick="auditLogPage(-1)">قبلی</button>'+
        '<span id="auditPageLabel" style="font-size:11px;color:#9A9484;align-self:center;"></span>'+
        '<button class="small outline" onclick="auditLogPage(1)">بعدی</button>'+
      '</div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="users" style="display:none;">'+
    '<div class="panel"><h3>👤 کاربران</h3><input id="search" placeholder="جستجو (نام/نام کاربری/ایمیل/موبایل)" oninput="loadUsers()"><div id="usersTable">...</div></div>'+
    '<div id="userDetailBox"></div>'+
    '</div>'+
    '<div class="tabpage" data-tab="billing" style="display:none;">'+
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
    '<div class="panel"><h3>💰 پرداخت‌ها و تراکنش‌ها</h3>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">'+
        '<select id="paymentsFilter" onchange="loadPayments()" style="width:auto;">'+
          '<option value="pending">در انتظار تایید</option>'+
          '<option value="success">موفق</option>'+
          '<option value="rejected">رد شده</option>'+
          '<option value="refunded">بازپرداخت‌شده</option>'+
          '<option value="all">همه</option>'+
        '</select>'+
        '<button class="small outline" onclick="exportPaymentsCsv()">⬇️ خروجی CSV</button>'+
      '</div>'+
      '<div id="paymentsTable">...</div>'+
      '<hr class="section-divider">'+
      '<h3 style="font-size:13px;">➕ ثبت پرداخت دستی (نقدی/حضوری)</h3>'+
      '<input id="manualPayUserId" placeholder="شناسه (ID) کاربر — از تب کاربران کپی کن">'+
      '<div style="display:flex;gap:6px;">'+
        '<input id="manualPayToman" type="number" placeholder="مبلغ تومان" style="flex:1;">'+
        '<input id="manualPayUsdt" type="number" placeholder="مبلغ USDT" style="flex:1;">'+
      '</div>'+
      '<input id="manualPayNote" placeholder="توضیح (مثلاً: پرداخت حضوری بابت اشتراک ۳ ماهه)">'+
      '<button class="small" onclick="submitManualPayment()">ثبت تراکنش</button>'+
      '<div id="manualPayMsg" style="font-size:11px;margin-top:4px;"></div>'+
    '</div>'+
    '<div class="panel"><h3>🤝 معرفی دوستان و پورسانت (Affiliate)</h3>'+
      '<div style="display:flex;gap:6px;margin-bottom:8px;">'+
        '<div style="flex:1;"><label class="flabel" style="font-size:11px;">پاداش دعوت (روز VIP)</label><input id="refSignupDays" type="number"></div>'+
        '<div style="flex:1;"><label class="flabel" style="font-size:11px;">درصد پورسانت خرید</label><input id="refCommissionPct" type="number"></div>'+
      '</div>'+
      '<button class="small" onclick="saveReferralSettings()">ذخیره تنظیمات</button>'+
      '<div id="refSettingsMsg" style="font-size:11px;margin-top:4px;"></div>'+
      '<hr class="section-divider">'+
      '<select id="refFilter" onchange="loadReferrals()" style="width:auto;">'+
        '<option value="pending">در انتظار پرداخت</option>'+
        '<option value="paid">پرداخت‌شده</option>'+
        '<option value="cancelled">لغوشده</option>'+
        '<option value="all">همه</option>'+
      '</select>'+
      '<div id="referralsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>🛍️ فروشگاه تجهیزات فیزیکی</h3>'+
      '<div style="font-weight:700;font-size:12.5px;margin-bottom:6px;">➕ محصول جدید</div>'+
      '<input id="eqTitle" placeholder="عنوان محصول">'+
      '<select id="eqCategory"><option value="supplement">مکمل</option><option value="dumbbell">دمبل و وزنه</option><option value="band">کش ورزشی</option><option value="apparel">پوشاک ورزشی</option><option value="gym_equipment">تجهیزات باشگاهی</option><option value="accessory">لوازم جانبی</option></select>'+
      '<textarea id="eqDesc" rows="2" placeholder="توضیحات (اختیاری)"></textarea>'+
      '<div style="display:flex;gap:6px;">'+
        '<input id="eqPrice" type="number" placeholder="قیمت (تومان)" style="flex:1;">'+
        '<input id="eqDiscount" type="number" placeholder="درصد تخفیف" style="flex:1;">'+
        '<input id="eqStock" type="number" placeholder="موجودی" style="flex:1;">'+
      '</div>'+
      '<button onclick="createEquipProduct()">➕ افزودن محصول</button>'+
      '<div id="eqMsg" style="font-size:11px;margin-top:4px;"></div>'+
      '<hr class="section-divider">'+
      '<div id="eqProductsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
      '<hr class="section-divider">'+
      '<div style="font-weight:700;font-size:12.5px;margin:10px 0 6px;">📦 سفارش‌ها</div>'+
      '<select id="eqOrderFilter" onchange="loadEquipOrders()" style="width:auto;">'+
        '<option value="">همه</option><option value="paid">پرداخت‌شده</option><option value="processing">در حال آماده‌سازی</option><option value="shipped">ارسال‌شده</option><option value="delivered">تحویل‌شده</option><option value="cancelled">لغوشده</option>'+
      '</select>'+
      '<div id="eqOrdersList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="ai" style="display:none;">'+
    '<div class="panel"><h3>🧠 تنظیمات مربی هوشمند</h3>'+
      '<div id="aiStatsBox" style="font-size:12px;color:#9A9484;margin-bottom:10px;">...</div>'+
      '<label style="font-size:12px;display:flex;align-items:center;gap:6px;"><input type="checkbox" id="aiEnabled"> مربی هوشمند فعال باشه</label>'+
      '<input id="aiFreeLimit" type="number" placeholder="تعداد پیام رایگان روزانه (مثلاً 5)">'+
      '<input id="aiModel" placeholder="مدل (مثلاً gemini-2.5-flash)">'+
      '<button onclick="saveAiSettings()">ذخیره تنظیمات</button>'+
      '<div id="aiSettingsErr" class="err"></div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="users" style="display:none;">'+
    '<div class="panel"><h3>🧪 اکانت‌های تست</h3>'+
      '<div style="font-size:12px;color:#9A9484;margin-bottom:8px;">با یه کلیک، ۲ اکانت کاربر عادی و یه اکانت مربیِ تاییدشده می‌سازه (یا رمزشون رو ریست می‌کنه اگه از قبل هست)</div>'+
      '<button onclick="seedTestAccounts()">🧪 ساخت اکانت‌های تست</button>'+
      '<div id="seedResult" style="margin-top:8px;font-size:12px;"></div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="coaches" style="display:none;">'+
    '<div class="panel"><h3>🧑‍🏫 مدیریت مربیان</h3>'+
      '<div id="coachStats" style="font-size:12px;color:#9A9484;margin-bottom:10px;">در حال بارگذاری...</div>'+
      '<div style="margin-bottom:10px;"><label style="font-size:12px;">درصد کمیسیون اپ از فروش/مشاوره‌ی مربیان (٪)</label>'+
      '<div style="display:flex;gap:6px;"><input id="commissionRate" type="number" step="1" style="flex:1;" placeholder="مثلاً 10"><button onclick="saveCommission()">ذخیره</button></div>'+
      '<div id="commissionMsg" style="font-size:11px;margin-top:4px;"></div></div>'+
      '<button onclick="loadPendingCoaches()">📋 درخواست‌های در انتظار</button>'+
      '<div id="pendingCoaches" style="margin-top:8px;"></div>'+
      '<h3 style="margin-top:16px;">👥 همه‌ی مربیان</h3>'+
      '<div id="allCoaches" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>💳 پلن‌های اشتراک مربیان</h3>'+
      '<div id="coachPlansEditor" style="margin-top:8px;">در حال بارگذاری...</div>'+
      '<button onclick="saveCoachPlans()" style="margin-top:8px;">💾 ذخیره‌ی همه‌ی پلن‌ها</button>'+
      '<div id="coachPlansMsg" style="font-size:11px;margin-top:4px;"></div>'+
    '</div>'+
    '<div class="panel"><h3>📤 درخواست‌های برداشت وجه مربیان</h3>'+
      '<div style="font-size:11px;color:#9A9484;margin-bottom:8px;">مربی‌ها از اینجا درخواست برداشت با اطلاعات بانکی کامل می‌فرستن. با دقت بررسی کن و بعد از واریز واقعی، تایید بزن.</div>'+
      '<select id="wdFilter" onchange="loadWithdrawalRequests()" style="width:auto;">'+
        '<option value="pending">در انتظار بررسی</option>'+
        '<option value="paid">پرداخت‌شده</option>'+
        '<option value="rejected">رد شده</option>'+
        '<option value="info_incorrect">اطلاعات نادرست</option>'+
        '<option value="all">همه</option>'+
      '</select>'+
      '<div id="withdrawalRequestsList" style="margin-top:10px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>💰 کیف پول مربیان</h3>'+
      '<div id="coachWalletsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
      '<div id="coachWalletDetail" style="margin-top:14px;"></div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="tickets" style="display:none;">'+
    '<div class="panel"><h3>🎫 تیکت‌های پشتیبانی</h3>'+
      '<div class="statgrid" id="ticketStatsBox" style="grid-template-columns:repeat(3,1fr);margin-bottom:12px;">در حال بارگذاری...</div>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;">'+
        '<select id="tkFilterStatus" onchange="loadTickets()" style="width:auto;">'+
          '<option value="">همه وضعیت‌ها</option>'+
          '<option value="new">جدید</option>'+
          '<option value="in_review">در حال بررسی</option>'+
          '<option value="answered">پاسخ داده‌شده</option>'+
          '<option value="waiting_user">منتظر کاربر</option>'+
          '<option value="closed">بسته‌شده</option>'+
        '</select>'+
        '<select id="tkFilterCategory" onchange="loadTickets()" style="width:auto;">'+
          '<option value="">همه دسته‌ها</option>'+
          '<option value="مشکلات پرداخت">مشکلات پرداخت</option>'+
          '<option value="اشتراک VIP">اشتراک VIP</option>'+
          '<option value="مشکلات فنی">مشکلات فنی</option>'+
          '<option value="گزارش باگ">گزارش باگ</option>'+
          '<option value="پیشنهادات">پیشنهادات</option>'+
          '<option value="گزارش تخلف">گزارش تخلف</option>'+
          '<option value="حساب کاربری">حساب کاربری</option>'+
          '<option value="مربیان">مربیان</option>'+
          '<option value="هوش مصنوعی">هوش مصنوعی</option>'+
          '<option value="سایر موارد">سایر موارد</option>'+
        '</select>'+
        '<select id="tkFilterPriority" onchange="loadTickets()" style="width:auto;">'+
          '<option value="">همه اولویت‌ها</option>'+
          '<option value="urgent">فوری</option>'+
          '<option value="important">مهم</option>'+
          '<option value="normal">عادی</option>'+
        '</select>'+
        '<label style="font-size:11px;display:flex;align-items:center;gap:4px;"><input type="checkbox" id="tkFilterArchived" onchange="loadTickets()"> آرشیو</label>'+
        '<input id="tkSearch" placeholder="جستجو در موضوع یا نام کاربر..." oninput="renderTicketsList()" style="flex:1;min-width:160px;">'+
      '</div>'+
      '<div id="ticketsList" style="display:flex;flex-direction:column;gap:6px;">در حال بارگذاری...</div>'+
      '<div id="ticketDetail" style="margin-top:14px;"></div>'+
      '<hr class="section-divider">'+
      '<h3 style="font-size:13px;">💬 پاسخ‌های آماده</h3>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;">'+
        '<input id="qrTitle" placeholder="عنوان کوتاه" style="flex:1;min-width:100px;">'+
        '<input id="qrText" placeholder="متن پاسخ آماده" style="flex:2;min-width:160px;">'+
        '<button class="small" onclick="createQuickReply()">افزودن</button>'+
      '</div>'+
      '<div id="quickRepliesList" style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px;"></div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="coaches" style="display:none;">'+
    '<div class="panel"><h3>🚩 گزارش‌های تخلف</h3><div id="coachReports" style="margin-top:8px;">در حال بارگذاری...</div></div>'+
    '<div class="panel"><h3>📋 نظارت بر برنامه‌های مربیان</h3>'+
      '<input id="progSearch" placeholder="جستجو بر اساس عنوان یا نام مربی" oninput="renderCoachProgramsTable()">'+
      '<div id="coachProgramsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '</div>'+
    '<div class="tabpage" data-tab="ai" style="display:none;">'+
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
    '</div>'+
    (canSee("content")?(
    '<div class="tabpage" data-tab="content" style="display:none;">'+
    '<div class="panel"><h3>📢 ارسال اعلان</h3>'+
      '<input id="notifTitle" placeholder="عنوان اعلان">'+
      '<textarea id="notifMessage" rows="3" placeholder="متن اعلان..."></textarea>'+
      '<div style="display:flex;gap:6px;flex-wrap:wrap;">'+
        '<select id="notifScope" onchange="toggleNotifTarget(this)" style="width:auto;">'+
          '<option value="all">همه کاربران</option>'+
          '<option value="vip">فقط کاربران VIP</option>'+
          '<option value="coaches">فقط مربیان</option>'+
          '<option value="user">یک کاربر خاص</option>'+
        '</select>'+
        '<input id="notifSchedule" type="datetime-local" style="flex:1;min-width:160px;">'+
      '</div>'+
      '<div id="notifTargetWrap" style="display:none;"><input id="notifTargetUserId" placeholder="شناسه (ID) کاربر مقصد"></div>'+
      '<button onclick="sendNotification()">🚀 ارسال</button>'+
      '<div id="notifMsg" style="font-size:11px;margin-top:4px;"></div>'+
      '<hr class="section-divider">'+
      '<h3 style="font-size:13px;">تاریخچهٔ اعلان‌های ارسال‌شده</h3>'+
      '<div id="notifHistory">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>📰 محتوا (مقاله/خبر/ویدئو/چالش)</h3>'+
      '<input id="contentTitle" placeholder="عنوان">'+
      '<select id="contentType" style="width:auto;"><option value="article">مقاله</option><option value="news">خبر</option><option value="video">ویدئو</option><option value="challenge">چالش</option></select>'+
      '<input id="contentCover" placeholder="آدرس تصویر کاور (اختیاری)">'+
      '<textarea id="contentBody" rows="4" placeholder="متن محتوا..."></textarea>'+
      '<label style="font-size:11px;display:flex;align-items:center;gap:4px;"><input type="checkbox" id="contentPublished" checked> منتشر بشه</label>'+
      '<button onclick="createContent()">➕ افزودن</button>'+
      '<div id="contentMsg" style="font-size:11px;margin-top:4px;"></div>'+
      '<div id="contentList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>🖼️ بنرهای تبلیغاتی</h3>'+
      '<input id="adImageUrl" placeholder="آدرس تصویر بنر">'+
      '<input id="adLinkUrl" placeholder="لینک مقصد (اختیاری)">'+
      '<input id="adPosition" type="number" placeholder="ترتیب نمایش (کوچیک‌تر = بالاتر)" value="0">'+
      '<button onclick="createAd()">➕ افزودن بنر</button>'+
      '<div id="adMsg" style="font-size:11px;margin-top:4px;"></div>'+
      '<div id="adsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '<div class="panel"><h3>🚨 گزارش‌های تخلف (کاربر، محتوا، نظر)</h3>'+
      '<select id="reportsFilter" onchange="loadReports()" style="width:auto;">'+
        '<option value="pending">در انتظار بررسی</option>'+
        '<option value="reviewing">در حال بررسی</option>'+
        '<option value="action_taken">اقدام شده</option>'+
        '<option value="dismissed">رد شده</option>'+
        '<option value="">همه</option>'+
      '</select>'+
      '<div id="reportsList" style="margin-top:8px;">در حال بارگذاری...</div>'+
    '</div>'+
    '</div>'):"")+
    (me.role==="admin"?(
    '<div class="tabpage" data-tab="team" style="display:none;">'+
    '<div class="panel"><h3>🔐 دسترسی‌ها و اعضای تیم</h3>'+
      '<div style="font-size:11px;color:#9A9484;margin-bottom:10px;">نقش‌ها: مدیر کامل (دسترسی همه‌جا) · ناظر (پیش‌فرض: مربیان، محتوا، تیکت‌ها) · پشتیبان (پیش‌فرض: تیکت‌ها، کاربران)</div>'+
      '<div id="teamList">در حال بارگذاری...</div>'+
      '<hr class="section-divider">'+
      '<h3 style="font-size:13px;">➕ افزودن عضو جدید تیم</h3>'+
      '<div style="font-size:11px;color:#9A9484;margin-bottom:6px;">کاربر باید از قبل با ایمیل/شماره‌ش عضو برنامه شده باشه؛ شناسه‌ش رو از تب کاربران کپی کن.</div>'+
      '<input id="teamAddUserId" placeholder="شناسه (ID) کاربر">'+
      '<select id="teamAddRole"><option value="support">پشتیبان</option><option value="moderator">ناظر</option><option value="admin">مدیر کامل</option></select>'+
      '<button class="small" onclick="addTeamMember()">افزودن به تیم</button>'+
      '<div id="teamAddMsg" style="font-size:11px;margin-top:4px;"></div>'+
    '</div>'+
    '</div>'):"")+
  '</div>';
  showAdminTab(window._firstAdminTab||"dashboard");
  loadLiveDashboard();
  if(!window._liveDashInterval) window._liveDashInterval=setInterval(loadLiveDashboard,10000);
  if(me.role==="admin"){ loadStats(); loadAuditLog(1); loadTeam(); }
  if(canSee("users")) loadUsers();
  if(canSee("payments")){ loadCodes(); loadPlans(); loadDiscounts(); loadPayments(); loadReferralSettings(); loadReferrals(); loadEquipProducts(); loadEquipOrders(); }
  if(canSee("ai")){ loadAiSettings(); }
  if(canSee("coaches")){ loadCommission(); loadAllCoaches(); loadCoachReports(); loadCoachPlansEditor(); loadCoachPrograms(); loadCoachWallets(); }
  if(canSee("tickets")){ loadTickets(); loadQuickReplies(); }
  if(canSee("content")){ loadNotificationsAdmin(); loadContentList(); loadAdsList(); loadReports(); }
}
const ROLE_DEFAULT_PERMISSIONS_JS={ moderator:["coaches","content","tickets"], support:["tickets","users"] };
async function loadReferralSettings(){
  try{
    const s=await api("/api/admin/referrals/settings");
    document.getElementById("refSignupDays").value=s.signupRewardDays;
    document.getElementById("refCommissionPct").value=s.commissionPercent;
  }catch(e){}
}
async function saveReferralSettings(){
  const msg=document.getElementById("refSettingsMsg");
  try{
    await api("/api/admin/referrals/settings",{method:"PUT",body:JSON.stringify({
      signupRewardDays:document.getElementById("refSignupDays").value,
      commissionPercent:document.getElementById("refCommissionPct").value
    })});
    msg.textContent="ذخیره شد ✅"; msg.style.color="#8FD19E";
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
async function loadReferrals(){
  try{
    const status=document.getElementById("refFilter").value;
    const list=await api("/api/admin/referrals"+(status!=="all"?("?status="+status):""));
    renderReferralsList(list);
  }catch(e){document.getElementById("referralsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
const REF_STATUS_BADGE={pending:["badge warn","در انتظار"],paid:["badge on","پرداخت‌شده"],cancelled:["badge off","لغوشده"]};
const REF_SOURCE_LABEL={signup:"پاداش ثبت‌نام دوست",purchase:"پورسانت خرید"};
function renderReferralsList(list){
  if(!list.length){document.getElementById("referralsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>موردی نیست</div>";return;}
  let html="<table><tr><th>معرف</th><th>معرفی‌شده</th><th>نوع</th><th>مبلغ</th><th>وضعیت</th><th>عملیات</th></tr>";
  list.forEach(function(c){
    const sb=REF_STATUS_BADGE[c.status]||["badge","-"];
    html+="<tr><td>"+esc(c.referrerName)+"</td><td>"+esc(c.referredName)+"</td><td style='font-size:11px;'>"+REF_SOURCE_LABEL[c.sourceType]+"</td>"+
      "<td>"+(c.amountToman?c.amountToman.toLocaleString("fa-IR")+" ت":"-")+"</td>"+
      "<td><span class='"+sb[0]+"'>"+sb[1]+"</span></td>"+
      "<td>"+(c.status==="pending"?("<button class='small' data-ref-pay='"+c.id+"'>پرداخت شد</button><button class='small danger' data-ref-cancel='"+c.id+"'>لغو</button>"):"")+"</td></tr>";
  });
  html+="</table>";
  document.getElementById("referralsList").innerHTML=html;
}
document.addEventListener("click",function(e){
  const rp=e.target.closest("[data-ref-pay]");
  if(rp){ api("/api/admin/referrals/"+rp.getAttribute("data-ref-pay")+"/pay",{method:"PUT"}).then(loadReferrals).catch(function(err){alert(err.message);}); return; }
  const rc=e.target.closest("[data-ref-cancel]");
  if(rc){ const reason=prompt("دلیل لغو (اختیاری):",""); if(reason===null)return; api("/api/admin/referrals/"+rc.getAttribute("data-ref-cancel")+"/cancel",{method:"PUT",body:JSON.stringify({reason:reason})}).then(loadReferrals).catch(function(err){alert(err.message);}); return; }
  const eqDel=e.target.closest("[data-eq-del]");
  if(eqDel){ if(confirm("این محصول حذف بشه؟")) api("/api/admin/equipment/products/"+eqDel.getAttribute("data-eq-del"),{method:"DELETE"}).then(loadEquipProducts).catch(function(err){alert(err.message);}); return; }
  const eqTog=e.target.closest("[data-eq-toggle]");
  if(eqTog){ const pub=eqTog.getAttribute("data-eq-toggle-val")==="1"; api("/api/admin/equipment/products/"+eqTog.getAttribute("data-eq-toggle"),{method:"PUT",body:JSON.stringify({published:!pub})}).then(loadEquipProducts).catch(function(err){alert(err.message);}); return; }
  const eqShip=e.target.closest("[data-eq-ship]");
  if(eqShip){
    const track=prompt("کد رهگیری مرسوله (اختیاری):","");
    api("/api/admin/equipment/orders/"+eqShip.getAttribute("data-eq-ship")+"/status",{method:"PUT",body:JSON.stringify({status:"shipped",trackingCode:track||null})}).then(loadEquipOrders).catch(function(err){alert(err.message);});
    return;
  }
  const eqDeliv=e.target.closest("[data-eq-deliver]");
  if(eqDeliv){ api("/api/admin/equipment/orders/"+eqDeliv.getAttribute("data-eq-deliver")+"/status",{method:"PUT",body:JSON.stringify({status:"delivered"})}).then(loadEquipOrders).catch(function(err){alert(err.message);}); return; }
  const eqCancel=e.target.closest("[data-eq-cancel]");
  if(eqCancel){ if(confirm("این سفارش لغو بشه؟ موجودی برمی‌گرده.")) api("/api/admin/equipment/orders/"+eqCancel.getAttribute("data-eq-cancel")+"/status",{method:"PUT",body:JSON.stringify({status:"cancelled"})}).then(loadEquipOrders).catch(function(err){alert(err.message);}); return; }
});
async function createEquipProduct(){
  const msg=document.getElementById("eqMsg");
  const title=document.getElementById("eqTitle").value.trim();
  if(!title){ msg.textContent="عنوان رو بنویس"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/equipment/products",{method:"POST",body:JSON.stringify({
      title:title, category:document.getElementById("eqCategory").value, description:document.getElementById("eqDesc").value,
      priceToman:document.getElementById("eqPrice").value, discountPercent:document.getElementById("eqDiscount").value, stock:document.getElementById("eqStock").value
    })});
    document.getElementById("eqTitle").value=""; document.getElementById("eqDesc").value=""; document.getElementById("eqPrice").value=""; document.getElementById("eqDiscount").value=""; document.getElementById("eqStock").value="";
    msg.textContent="افزوده شد ✅"; msg.style.color="#8FD19E";
    loadEquipProducts();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
async function loadEquipProducts(){
  try{
    const list=await api("/api/admin/equipment/products");
    const EQ_CAT={supplement:"مکمل",dumbbell:"دمبل و وزنه",band:"کش ورزشی",apparel:"پوشاک ورزشی",gym_equipment:"تجهیزات باشگاهی",accessory:"لوازم جانبی"};
    if(!list.length){document.getElementById("eqProductsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:8px;'>محصولی نیست</div>";return;}
    let html="<table><tr><th>عنوان</th><th>دسته</th><th>قیمت</th><th>موجودی</th><th>وضعیت</th><th></th></tr>";
    list.forEach(function(p){
      html+="<tr><td>"+esc(p.title)+"</td><td style='font-size:11px;'>"+(EQ_CAT[p.category]||p.category)+"</td>"+
        "<td>"+p.priceToman.toLocaleString()+(p.discountPercent?" (-"+p.discountPercent+"%)":"")+"</td>"+
        "<td style='color:"+(p.stock>0?"#3DDC74":"#FF5252")+";'>"+p.stock+"</td>"+
        "<td><span class='badge "+(p.published?"on":"off")+"'>"+(p.published?"منتشر":"مخفی")+"</span></td>"+
        "<td><button class='small' data-eq-toggle='"+p.id+"' data-eq-toggle-val='"+(p.published?1:0)+"'>"+(p.published?"مخفی کن":"منتشر کن")+"</button> <button class='small danger' data-eq-del='"+p.id+"'>حذف</button></td></tr>";
    });
    html+="</table>";
    document.getElementById("eqProductsList").innerHTML=html;
  }catch(e){document.getElementById("eqProductsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function loadEquipOrders(){
  try{
    const status=document.getElementById("eqOrderFilter").value;
    const list=await api("/api/admin/equipment/orders"+(status?("?status="+status):""));
    const ST={pending_payment:["badge warn","در انتظار پرداخت"],paid:["badge warn","پرداخت‌شده"],processing:["badge warn","در حال آماده‌سازی"],shipped:["badge on","ارسال‌شده"],delivered:["badge on","تحویل‌شده"],cancelled:["badge off","لغوشده"]};
    if(!list.length){document.getElementById("eqOrdersList").innerHTML="<div style='text-align:center;color:#9A9484;padding:8px;'>سفارشی نیست</div>";return;}
    let html="";
    list.forEach(function(o){
      const sb=ST[o.status]||["badge","-"];
      html+="<div style='border:1px solid #333;border-radius:8px;padding:10px;margin-bottom:8px;'>"+
        "<div style='display:flex;justify-content:space-between;'><b style='font-size:12px;'>"+esc(o.userName)+" — "+o.totalToman.toLocaleString()+" ت</b><span class='"+sb[0]+"'>"+sb[1]+"</span></div>"+
        "<div style='font-size:10.5px;color:#9A9484;margin-top:4px;'>"+esc(o.shipping.fullName)+" · "+esc(o.shipping.phone)+" · "+esc(o.shipping.city)+" · "+esc(o.shipping.address)+" · کدپستی "+esc(o.shipping.postalCode)+"</div>"+
        (o.trackingCode?"<div style='font-size:11px;margin-top:4px;'>کد رهگیری: "+esc(o.trackingCode)+"</div>":"")+
        (o.status==="paid"?"<button class='small' data-eq-ship='"+o.id+"' style='margin-top:6px;'>📦 ارسال شد</button>":"")+
        (o.status==="shipped"?"<button class='small' data-eq-deliver='"+o.id+"' style='margin-top:6px;'>✅ تحویل داده شد</button>":"")+
        (["paid","processing"].includes(o.status)?"<button class='small danger' data-eq-cancel='"+o.id+"' style='margin-top:6px;'>❌ لغو سفارش</button>":"")+
      "</div>";
    });
    document.getElementById("eqOrdersList").innerHTML=html;
  }catch(e){document.getElementById("eqOrdersList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function toggleNotifTarget(sel){
  document.getElementById("notifTargetWrap").style.display = sel.value==="user" ? "block" : "none";
}
async function sendNotification(){
  const title=document.getElementById("notifTitle").value.trim();
  const message=document.getElementById("notifMessage").value.trim();
  const scope=document.getElementById("notifScope").value;
  const targetUserId=document.getElementById("notifTargetUserId").value.trim();
  const scheduleVal=document.getElementById("notifSchedule").value;
  const msg=document.getElementById("notifMsg");
  if(!title||!message){ msg.textContent="عنوان و متن الزامیه"; msg.style.color="#FF5252"; return; }
  if(scope==="user"&&!targetUserId){ msg.textContent="شناسه کاربر مقصد رو وارد کن"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/notifications",{method:"POST",body:JSON.stringify({
      title:title,message:message,scope:scope,targetUserId:targetUserId||undefined,
      scheduledAt:scheduleVal?new Date(scheduleVal).toISOString():undefined
    })});
    msg.textContent="ارسال شد ✅"; msg.style.color="#8FD19E";
    document.getElementById("notifTitle").value="";document.getElementById("notifMessage").value="";document.getElementById("notifTargetUserId").value="";document.getElementById("notifSchedule").value="";
    loadNotificationsAdmin();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
const NOTIF_SCOPE_LABEL={all:"همه کاربران",vip:"فقط VIP",coaches:"فقط مربیان",user:"یک کاربر خاص"};
async function loadNotificationsAdmin(){
  try{
    const list=await api("/api/admin/notifications");
    let html="";
    if(!list.length) html="<div style='font-size:11px;color:#9A9484;'>هنوز اعلانی ارسال نشده</div>";
    list.forEach(function(n){
      const pending=n.scheduledAt&&new Date(n.scheduledAt).getTime()>Date.now();
      html+="<div style='border:1px solid var(--border,#333);border-radius:8px;padding:8px;margin-bottom:6px;'>"+
        "<div style='display:flex;justify-content:space-between;'><b style='font-size:12px;'>"+esc(n.title)+"</b>"+
        "<button class='small danger' data-notif-del='"+n.id+"' style='padding:2px 8px;'>✕</button></div>"+
        "<div style='font-size:11px;color:#9A9484;'>"+esc(n.message)+"</div>"+
        "<div style='font-size:10px;color:#9A9484;margin-top:4px;'>مخاطب: "+(NOTIF_SCOPE_LABEL[n.scope]||n.scope)+
        (pending?" · ⏳ زمان‌بندی‌شده برای "+new Date(n.scheduledAt).toLocaleString("fa-IR"):" · ✅ ارسال‌شده")+"</div>"+
      "</div>";
    });
    document.getElementById("notifHistory").innerHTML=html;
  }catch(e){}
}
async function deleteNotification(id){
  if(!confirm("حذف بشه؟"))return;
  try{ await api("/api/admin/notifications/"+id,{method:"DELETE"}); loadNotificationsAdmin(); }catch(e){alert(e.message);}
}
const CONTENT_TYPE_LABEL={article:"مقاله",news:"خبر",video:"ویدئو",challenge:"چالش"};
async function createContent(){
  const title=document.getElementById("contentTitle").value.trim();
  const type=document.getElementById("contentType").value;
  const coverImageUrl=document.getElementById("contentCover").value.trim();
  const body=document.getElementById("contentBody").value.trim();
  const published=document.getElementById("contentPublished").checked;
  const msg=document.getElementById("contentMsg");
  if(!title){ msg.textContent="عنوان الزامیه"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/content",{method:"POST",body:JSON.stringify({title:title,type:type,coverImageUrl:coverImageUrl||undefined,body:body,published:published})});
    msg.textContent="اضافه شد ✅"; msg.style.color="#8FD19E";
    document.getElementById("contentTitle").value="";document.getElementById("contentCover").value="";document.getElementById("contentBody").value="";
    loadContentList();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
async function loadContentList(){
  try{
    const list=await api("/api/admin/content");
    let html="";
    if(!list.length) html="<div style='font-size:11px;color:#9A9484;'>محتوایی ثبت نشده</div>";
    list.forEach(function(c){
      html+="<div style='display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border,#333);border-radius:8px;padding:6px 10px;margin-bottom:6px;'>"+
        "<div><b style='font-size:12px;'>"+esc(c.title)+"</b> <span style='font-size:10px;color:#9A9484;'>("+CONTENT_TYPE_LABEL[c.type]+")</span>"+
        (c.published?" <span class='badge on'>منتشر</span>":" <span class='badge off'>پیش‌نویس</span>")+"</div>"+
        "<button class='small danger' data-content-del='"+c.id+"' style='padding:2px 8px;'>✕</button>"+
      "</div>";
    });
    document.getElementById("contentList").innerHTML=html;
  }catch(e){}
}
async function deleteContent(id){
  if(!confirm("حذف بشه؟"))return;
  try{ await api("/api/admin/content/"+id,{method:"DELETE"}); loadContentList(); }catch(e){alert(e.message);}
}
async function createAd(){
  const imageUrl=document.getElementById("adImageUrl").value.trim();
  const linkUrl=document.getElementById("adLinkUrl").value.trim();
  const position=document.getElementById("adPosition").value;
  const msg=document.getElementById("adMsg");
  if(!imageUrl){ msg.textContent="آدرس تصویر الزامیه"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/ads",{method:"POST",body:JSON.stringify({imageUrl:imageUrl,linkUrl:linkUrl||undefined,position:position})});
    msg.textContent="اضافه شد ✅"; msg.style.color="#8FD19E";
    document.getElementById("adImageUrl").value="";document.getElementById("adLinkUrl").value="";
    loadAdsList();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
async function loadAdsList(){
  try{
    const list=await api("/api/admin/ads");
    let html="";
    if(!list.length) html="<div style='font-size:11px;color:#9A9484;'>بنری ثبت نشده</div>";
    list.forEach(function(a){
      html+="<div style='display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border,#333);border-radius:8px;padding:6px 10px;margin-bottom:6px;'>"+
        "<div><img src='"+esc(a.imageUrl)+"' style='width:40px;height:40px;object-fit:cover;border-radius:6px;vertical-align:middle;margin-left:6px;'>"+
        "<span style='font-size:11px;color:#9A9484;'>بازدید: "+(a.impressions||0)+" · کلیک: "+(a.clicks||0)+"</span>"+
        (a.active?" <span class='badge on'>فعال</span>":" <span class='badge off'>غیرفعال</span>")+"</div>"+
        "<div><button class='small' data-ad-toggle='"+a.id+"' style='padding:2px 8px;'>"+(a.active?"غیرفعال کن":"فعال کن")+"</button>"+
        "<button class='small danger' data-ad-del='"+a.id+"' style='padding:2px 8px;'>✕</button></div>"+
      "</div>";
    });
    document.getElementById("adsList").innerHTML=html;
  }catch(e){}
}
async function toggleAd(id,active){
  try{ await api("/api/admin/ads/"+id,{method:"PUT",body:JSON.stringify({active:active})}); loadAdsList(); }catch(e){alert(e.message);}
}
async function deleteAd(id){
  if(!confirm("حذف بشه؟"))return;
  try{ await api("/api/admin/ads/"+id,{method:"DELETE"}); loadAdsList(); }catch(e){alert(e.message);}
}
const REPORT_TYPE_LABEL={user:"👤 کاربر",content:"📰 محتوا",review:"💬 نظر"};
const REPORT_STATUS_BADGE={pending:["badge warn","در انتظار"],reviewing:["badge warn","در حال بررسی"],action_taken:["badge on","اقدام شده"],dismissed:["badge off","رد شده"]};
async function loadReports(){
  try{
    const status=document.getElementById("reportsFilter").value;
    const list=await api("/api/admin/reports"+(status?("?status="+status):""));
    renderReportsList(list);
  }catch(e){document.getElementById("reportsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function renderReportsList(list){
  if(!list.length){document.getElementById("reportsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>گزارشی نیست</div>";return;}
  let html="";
  list.forEach(function(r){
    const sb=REPORT_STATUS_BADGE[r.status]||["badge","-"];
    html+="<div style='border:1px solid var(--border,#333);border-radius:8px;padding:10px;margin-bottom:8px;'>"+
      "<div style='display:flex;justify-content:space-between;'><b style='font-size:12px;'>"+(REPORT_TYPE_LABEL[r.targetType]||r.targetType)+" — "+esc(r.targetLabel)+"</b><span class='"+sb[0]+"'>"+sb[1]+"</span></div>"+
      "<div style='font-size:11px;color:#9A9484;margin-top:4px;'>گزارش‌دهنده: "+esc(r.reporterName)+"</div>"+
      "<div style='font-size:11.5px;margin-top:6px;'>"+esc(r.reason)+"</div>"+
      (r.adminNote?"<div style='font-size:10.5px;color:#9A9484;margin-top:4px;'>یادداشت: "+esc(r.adminNote)+"</div>":"")+
      (r.status==="pending"||r.status==="reviewing"?(
        "<div style='display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;'>"+
          "<button class='small danger' data-report-action='"+r.id+"'>⚠️ اقدام (مسدود/حذف)</button>"+
          "<button class='small outline' data-report-dismiss='"+r.id+"'>رد گزارش</button>"+
        "</div>"
      ):"")+
    "</div>";
  });
  document.getElementById("reportsList").innerHTML=html;
}
async function takeReportAction(id){
  if(!confirm("این کار هدف گزارش رو مسدود/حذف می‌کنه. مطمئنی؟"))return;
  try{ await api("/api/admin/reports/"+id+"/take-action",{method:"PUT"}); loadReports(); }catch(e){alert(e.message);}
}
async function dismissReport(id){
  try{ await api("/api/admin/reports/"+id,{method:"PUT",body:JSON.stringify({status:"dismissed"})}); loadReports(); }catch(e){alert(e.message);}
}
document.addEventListener("click",function(e){
  const nd=e.target.closest("[data-notif-del]"); if(nd){ deleteNotification(nd.getAttribute("data-notif-del")); return; }
  const cd=e.target.closest("[data-content-del]"); if(cd){ deleteContent(cd.getAttribute("data-content-del")); return; }
  const ad=e.target.closest("[data-ad-del]"); if(ad){ deleteAd(ad.getAttribute("data-ad-del")); return; }
  const at=e.target.closest("[data-ad-toggle]");
  if(at){ const id=at.getAttribute("data-ad-toggle"); const isActive=at.textContent.indexOf("غیرفعال کن")>-1; toggleAd(id,!isActive); return; }
  const ra=e.target.closest("[data-report-action]"); if(ra){ takeReportAction(ra.getAttribute("data-report-action")); return; }
  const rd=e.target.closest("[data-report-dismiss]"); if(rd){ dismissReport(rd.getAttribute("data-report-dismiss")); return; }
});
async function loadTeam(){
  try{
    const team=await api("/api/admin/team");
    const ROLE_LABEL={admin:"مدیر کامل",moderator:"ناظر",support:"پشتیبان"};
    let html="<table><tr><th>نام</th><th>ایمیل</th><th>نقش</th><th>دسترسی‌ها</th><th>عملیات</th></tr>";
    team.forEach(function(u){
      const perms=u.permissions||ROLE_DEFAULT_PERMISSIONS_JS[u.role]||(u.role==="admin"?["همه"]:[]);
      html+="<tr><td>"+esc(u.name)+"</td><td style='font-size:11px;'>"+esc(u.email||u.phone||"")+"</td>"+
        "<td>"+(ROLE_LABEL[u.role]||u.role)+"</td>"+
        "<td style='font-size:10px;'>"+perms.join("، ")+"</td>"+
        "<td><button class='small' data-team-edit='"+u.id+"'>ویرایش</button></td></tr>";
    });
    html+="</table>";
    document.getElementById("teamList").innerHTML=html;
    window._teamCache=team;
  }catch(e){ document.getElementById("teamList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>"; }
}
async function addTeamMember(){
  const userId=document.getElementById("teamAddUserId").value.trim();
  const role=document.getElementById("teamAddRole").value;
  const msg=document.getElementById("teamAddMsg");
  if(!userId){ msg.textContent="شناسه کاربر رو وارد کن"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/team/"+userId+"/role",{method:"PUT",body:JSON.stringify({role:role})});
    msg.textContent="اضافه شد ✅"; msg.style.color="#8FD19E";
    document.getElementById("teamAddUserId").value="";
    loadTeam();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
function editTeamMember(userId){
  const u=(window._teamCache||[]).find(function(x){return x.id===userId;});
  if(!u) return;
  const permStr=prompt("دسترسی‌ها رو با کاما جدا کن (users, coaches, payments, tickets, ai, content) — یا برای مدیر کامل خالی بذار:", (u.permissions||[]).join(","));
  if(permStr===null) return;
  const perms=permStr.split(",").map(function(s){return s.trim();}).filter(Boolean);
  api("/api/admin/team/"+userId+"/role",{method:"PUT",body:JSON.stringify({role:u.role,permissions:perms})})
    .then(function(){ loadTeam(); }).catch(function(e){ alert(e.message); });
}
document.addEventListener("click",function(e){
  const te=e.target.closest("[data-team-edit]"); if(te){ editTeamMember(te.getAttribute("data-team-edit")); return; }
});
function showAdminTab(tab){
  window._adminActiveTab=tab;
  document.querySelectorAll(".tabpage").forEach(function(el){ el.style.display = (el.getAttribute("data-tab")===tab) ? "" : "none"; });
  document.querySelectorAll("[data-tab-btn]").forEach(function(btn){
    if(btn.getAttribute("data-tab-btn")===tab){ btn.style.background="var(--brass)"; btn.style.color="#1a1408"; btn.style.borderColor="var(--brass)"; }
    else { btn.style.background=""; btn.style.color=""; btn.style.borderColor=""; }
  });
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
const PAYMENT_TYPE_LABEL={coach_subscription:"اشتراک مربی",coach_program:"خرید برنامه",coach_booking:"رزرو مشاوره",manual:"ثبت دستی"};
const PAYMENT_STATUS_BADGE={pending:["badge warn","در انتظار"],success:["badge on","موفق"],rejected:["badge off","رد شده"],refunded:["badge off","بازپرداخت"],failed:["badge off","ناموفق"]};
async function loadPayments(){
  try{
    const filter=document.getElementById("paymentsFilter").value;
    const all= filter==="pending" ? await api("/api/admin/payments/pending") : await api("/api/admin/payments");
    const payments = filter==="all"||filter==="pending" ? all : all.filter(function(p){return p.status===filter;});
    window._paymentsCache=payments;
    let html='<table><tr><th>کاربر</th><th>نوع</th><th>مبلغ</th><th>کد تراکنش</th><th>وضعیت</th><th>عملیات</th></tr>';
    if(payments.length===0) html+='<tr><td colspan="6" style="text-align:center;color:#9A9484;">موردی نیست</td></tr>';
    payments.forEach(function(p){
      const type=(p.meta&&p.meta.type&&PAYMENT_TYPE_LABEL[p.meta.type])||(p.provider==="usdt_wallet"||p.provider==="zarinpal"?"اشتراک VIP":p.provider);
      const sb=PAYMENT_STATUS_BADGE[p.status]||["badge","-"];
      html+='<tr><td class="mono" style="font-size:10px;">'+p.userId.slice(0,8)+'</td><td style="font-size:11px;">'+type+'</td>'+
        '<td>'+(p.amountUsdt?p.amountUsdt+" USDT":(p.amountToman?p.amountToman.toLocaleString("fa-IR")+" ت":"-"))+'</td>'+
        '<td style="font-size:10px;">'+esc(p.providerRef||"-")+'</td>'+
        '<td><span class="'+sb[0]+'">'+sb[1]+'</span></td>'+
        '<td>'+
          (p.status==="pending"?'<button data-pay-approve="'+p.id+'">تایید</button><button class="danger" data-pay-reject="'+p.id+'">رد</button>':'')+
          (p.status==="success"?'<button class="small danger" data-pay-refund="'+p.id+'">بازپرداخت</button>':'')+
        '</td></tr>';
    });
    html+='</table>';
    document.getElementById("paymentsTable").innerHTML=html;
  }catch(e){}
}
async function approvePayment(id){
  if(!confirm("تایید بشه؟ (VIP یا اشتراک/برنامه/رزرو مربوطه فعال می‌شه)")) return;
  try{ await api("/api/admin/payments/"+id+"/approve",{method:"PUT"}); loadPayments(); loadStats(); }
  catch(e){ alert(e.message); }
}
async function rejectPayment(id){
  try{ await api("/api/admin/payments/"+id+"/reject",{method:"PUT"}); loadPayments(); loadStats(); }
  catch(e){ alert(e.message); }
}
async function refundPayment(id){
  const reason=prompt("دلیل بازپرداخت (اختیاری):","");
  if(reason===null) return;
  try{ await api("/api/admin/payments/"+id+"/refund",{method:"PUT",body:JSON.stringify({reason:reason})}); loadPayments(); loadStats(); }
  catch(e){ alert(e.message); }
}
async function submitManualPayment(){
  const userId=document.getElementById("manualPayUserId").value.trim();
  const toman=document.getElementById("manualPayToman").value;
  const usdt=document.getElementById("manualPayUsdt").value;
  const note=document.getElementById("manualPayNote").value.trim();
  const msg=document.getElementById("manualPayMsg");
  if(!userId||(!toman&&!usdt)){ msg.textContent="شناسه کاربر و حداقل یکی از مبلغ‌ها الزامیه"; msg.style.color="#FF5252"; return; }
  try{
    await api("/api/admin/payments/manual",{method:"POST",body:JSON.stringify({userId:userId,amountToman:toman||undefined,amountUsdt:usdt||undefined,note:note})});
    msg.textContent="ثبت شد ✅"; msg.style.color="#8FD19E";
    document.getElementById("manualPayUserId").value="";document.getElementById("manualPayToman").value="";document.getElementById("manualPayUsdt").value="";document.getElementById("manualPayNote").value="";
    loadPayments(); loadStats();
  }catch(e){ msg.textContent=e.message; msg.style.color="#FF5252"; }
}
function exportPaymentsCsv(){
  const rows=window._paymentsCache||[];
  if(!rows.length){ alert("چیزی برای خروجی نیست"); return; }
  let csv="userId,type,amountToman,amountUsdt,providerRef,status,createdAt\\n";
  rows.forEach(function(p){
    const type=(p.meta&&p.meta.type)||p.provider;
    csv+=[p.userId,type,p.amountToman||"",p.amountUsdt||"",p.providerRef||"",p.status,p.createdAt].map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(",")+"\\n";
  });
  const blob=new Blob([csv],{type:"text/csv;charset=utf-8;"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url; a.download="payments_"+new Date().toISOString().slice(0,10)+".csv";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
document.addEventListener("click",function(e){
  const ap=e.target.closest("[data-pay-approve]"); if(ap){ approvePayment(ap.getAttribute("data-pay-approve")); return; }
  const rj=e.target.closest("[data-pay-reject]"); if(rj){ rejectPayment(rj.getAttribute("data-pay-reject")); return; }
  const rf=e.target.closest("[data-pay-refund]"); if(rf){ refundPayment(rf.getAttribute("data-pay-refund")); return; }
});
async function doLogin(){
  err="";
  try{
    const email=document.getElementById("email").value.trim();
    const password=document.getElementById("password").value;
    const res=await api("/api/auth/login",{method:"POST",body:JSON.stringify({email,password})});
    if(!["admin","moderator","support"].includes(res.user.role)){ err="این حساب دسترسی مدیریت نداره"; render(); return; }
    T.access=res.accessToken;
    me=res.user;
    render();
  }catch(e){ err=e.message; render(); }
}
function logout(){ me=null; T.access=null; render(); }
async function loadLiveDashboard(){
  const el=document.getElementById("liveDashboard");
  if(!el)return; // ادمین از پنل خارج شده
  try{
    const d=await api("/api/admin/live-dashboard");
    const dot=document.getElementById("liveDot");
    if(dot) dot.style.background="#3DDC74";
    const healthLabel={connected:["متصل","#3DDC74"],configured_not_connected:["پیکربندی‌شده ولی وصل نیست","#F2CE7A"],local_file_only:["فقط فایل محلی","#9A9484"],
      configured:["فعال","#3DDC74"],not_configured:["پیکربندی نشده","#9A9484"],mirrored_to_mongodb:["خودکار روی MongoDB","#3DDC74"],local_only_no_auto_backup:["بدون بکاپ خودکار","#FF9800"]};
    function hb(key){ const v=d.health[key]; const m=healthLabel[v]||[v,"#9A9484"]; return "<span style='color:"+m[1]+";font-weight:700;'>●</span> "+m[0]; }
    el.innerHTML=
      "<div class='statgrid' style='grid-template-columns:repeat(3,1fr);margin-bottom:10px;'>"+
        "<div class='statcard'><div class='statnum' style='color:#3DDC74;'>"+d.onlineUsers+"</div><div style='font-size:10.5px;color:#9A9484;'>آنلاین (۵ دقیقه)</div></div>"+
        "<div class='statcard'><div class='statnum'>"+d.revenue.today.toLocaleString()+"</div><div style='font-size:10.5px;color:#9A9484;'>درآمد امروز (ت)</div></div>"+
        "<div class='statcard'><div class='statnum'>"+d.revenue.month.toLocaleString()+"</div><div style='font-size:10.5px;color:#9A9484;'>درآمد این ماه (ت)</div></div>"+
        "<div class='statcard'><div class='statnum'>"+d.revenue.todaySalesCount+"</div><div style='font-size:10.5px;color:#9A9484;'>فروش امروز</div></div>"+
        "<div class='statcard'><div class='statnum'>"+d.coach.totalEarnings.toLocaleString()+"</div><div style='font-size:10.5px;color:#9A9484;'>درآمد مربیان (ت)</div></div>"+
        "<div class='statcard'><div class='statnum'>"+d.coach.platformCommission.toLocaleString()+"</div><div style='font-size:10.5px;color:#9A9484;'>کمیسیون پلتفرم (ت)</div></div>"+
      "</div>"+
      "<div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11.5px;'>"+
        "<div>"+
          "<div style='color:#D8AE52;font-weight:700;margin-bottom:4px;'>سیستم و سرور</div>"+
          "<div>آپتایم: "+Math.floor(d.system.uptimeSeconds/3600)+"س "+Math.floor((d.system.uptimeSeconds%3600)/60)+"د</div>"+
          "<div>حافظه: "+d.system.memoryUsedMB+" / "+d.system.memoryTotalMB+" MB</div>"+
          "<div>Node: "+d.system.nodeVersion+"</div>"+
          "<div>مصرف AI امروز: "+d.api.aiCallsToday+" درخواست</div>"+
        "</div>"+
        "<div>"+
          "<div style='color:#D8AE52;font-weight:700;margin-bottom:4px;'>وضعیت سلامت</div>"+
          "<div>پایگاه‌داده: "+hb("database")+"</div>"+
          "<div>ایمیل: "+hb("email")+"</div>"+
          "<div>درگاه پرداخت: "+hb("paymentGateway")+"</div>"+
          "<div>کیف USDT: "+hb("usdtWallet")+"</div>"+
          "<div>بکاپ: "+hb("backup")+"</div>"+
        "</div>"+
      "</div>"+
      "<div style='margin-top:10px;font-size:10.5px;color:#9A9484;'>مجموع: "+d.totals.users+" کاربر · "+d.totals.coaches+" مربی · "+d.totals.products+" محصول · "+d.totals.tickets+" تیکت · "+d.ads.totalBanners+" بنر ("+d.ads.impressionsTotal+" بازدید)</div>";
  }catch(e){
    const dot=document.getElementById("liveDot");
    if(dot) dot.style.background="#FF5252";
  }
}
async function loadStats(){
  try{
    const s=await api("/api/admin/stats");
    document.getElementById("stats").innerHTML=
      '<div class="statcard"><div class="statnum">'+s.totalUsers+'</div>کل کاربران</div>'+
      '<div class="statcard"><div class="statnum">'+s.vipUsers+'</div>کاربر VIP</div>'+
      '<div class="statcard"><div class="statnum">'+s.signupsToday+'</div>ثبت‌نام امروز</div>'+
      '<div class="statcard"><div class="statnum">'+(s.revenueToman?s.revenueToman.toLocaleString("fa-IR")+" ت":"-")+(s.revenueUsdt?" / "+s.revenueUsdt+"$":"")+'</div>درآمد تاییدشده</div>'+
      '<div class="statcard"><div class="statnum">'+s.pendingPayments+'</div>پرداخت در انتظار</div>'+
      '<div class="statcard"><div class="statnum">'+s.totalCoaches+'</div>مربی تاییدشده</div>'+
      '<div class="statcard"><div class="statnum">'+s.pendingCoaches+'</div>درخواست مربیگری در انتظار</div>'+
      '<div class="statcard"><div class="statnum">'+s.openTickets+'</div>تیکت باز</div>'+
      '<div class="statcard"><div class="statnum">'+s.totalVipCodes+'</div>کد VIP ساخته‌شده</div>';
    const maxSignup=Math.max.apply(null,s.signupTrend.map(function(d){return d.signups;}).concat([1]));
    document.getElementById("signupTrendChart").innerHTML=s.signupTrend.map(function(d){
      const h=Math.round((d.signups/maxSignup)*70)+8;
      const day=new Date(d.date).toLocaleDateString("fa-IR",{weekday:"short"});
      return "<div style='flex:1;text-align:center;'>"+
        "<div style='background:var(--brass,#D8AE52);border-radius:4px 4px 0 0;height:"+h+"px;margin:0 auto;width:70%;'></div>"+
        "<div style='font-size:9px;color:#9A9484;margin-top:3px;'>"+day+"</div>"+
        "<div style='font-size:9px;'>"+d.signups+"</div>"+
      "</div>";
    }).join("");
    loadAiChart();
  }catch(e){}
}
window._auditPage=1;
async function loadAuditLog(page){
  if(page) window._auditPage=page;
  try{
    const type=document.getElementById("auditFilterType").value;
    const q=document.getElementById("auditSearch").value;
    const params=new URLSearchParams({page:window._auditPage,limit:30});
    if(type)params.set("type",type);
    if(q)params.set("search",q);
    const r=await api("/api/admin/audit-log?"+params.toString());
    window._auditTotalPages=Math.max(1,Math.ceil(r.total/r.limit));
    let html="<table><tr><th>زمان</th><th>رویداد</th><th>کاربر مرتبط</th><th>جزئیات</th></tr>";
    if(!r.items.length) html+="<tr><td colspan='4' style='text-align:center;color:#9A9484;'>موردی یافت نشد</td></tr>";
    r.items.forEach(function(e){
      html+="<tr><td style='font-size:10px;white-space:nowrap;'>"+new Date(e.createdAt).toLocaleString("fa-IR")+"</td>"+
        "<td style='font-size:11px;'>"+esc(e.type)+"</td>"+
        "<td style='font-size:11px;'>"+(e.userName?esc(e.userName):(e.userId?esc(e.userId).slice(0,8):"-"))+"</td>"+
        "<td style='font-size:10px;color:#9A9484;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;'>"+esc(JSON.stringify(e.meta||{}))+"</td></tr>";
    });
    html+="</table>";
    document.getElementById("auditLogTable").innerHTML=html;
    document.getElementById("auditPageLabel").textContent="صفحه "+window._auditPage+" از "+window._auditTotalPages;
  }catch(e){ document.getElementById("auditLogTable").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>"; }
}
function auditLogPage(delta){
  const next=window._auditPage+delta;
  if(next<1||next>(window._auditTotalPages||1))return;
  loadAuditLog(next);
}
async function loadUsers(){
  try{
    const q=document.getElementById("search").value;
    const users=await api("/api/admin/users?search="+encodeURIComponent(q));
    let html='<table><tr><th>نام</th><th>نام کاربری</th><th>ایمیل/موبایل</th><th>نقش</th><th>وضعیت</th><th>عملیات</th></tr>';
    users.forEach(function(u){
      const vipOn=u.vip&&u.vip.active;
      html+='<tr><td>'+esc(u.name)+'</td><td class="mono">'+(u.username?"@"+esc(u.username):"<span style='color:#9A9484;'>—</span>")+'</td><td>'+esc(u.email||u.phone||"")+'</td><td>'+u.role+'</td>'+
        '<td>'+
          '<span class="badge '+(vipOn?"on":"off")+'">'+(vipOn?"VIP فعال":"بدون VIP")+'</span>'+
          (u.blocked?' <span class="badge off" style="background:rgba(255,82,82,.15);color:#FF5252;">مسدود</span>':'')+
        '</td>'+
        '<td><button class="small" data-user-view="'+u.id+'">مشاهده</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("usersTable").innerHTML=html;
  }catch(e){}
}
async function giftVip(userId){
  const days=prompt("چند روز VIP هدیه بدم؟","30");
  if(!days) return;
  try{ await api("/api/admin/users/"+userId+"/vip",{method:"PUT",body:JSON.stringify({active:true,days:Number(days)})}); loadUsers(); if(window._currentUserDetail&&window._currentUserDetail.user.id===userId) openUserDetail(userId); }
  catch(e){ alert(e.message); }
}
async function revokeVip(userId){
  if(!confirm("مطمئنی VIP این کاربر لغو بشه؟")) return;
  try{ await api("/api/admin/users/"+userId+"/vip",{method:"PUT",body:JSON.stringify({active:false})}); loadUsers(); if(window._currentUserDetail&&window._currentUserDetail.user.id===userId) openUserDetail(userId); }
  catch(e){ alert(e.message); }
}
async function openUserDetail(userId){
  const box=document.getElementById("userDetailBox");
  box.innerHTML="<div class='panel'>در حال بارگذاری...</div>";
  try{
    const data=await api("/api/admin/users/"+userId);
    window._currentUserDetail=data;
    renderUserDetail();
    box.scrollIntoView({behavior:"smooth",block:"start"});
  }catch(e){ box.innerHTML="<div class='panel' style='color:#FF5252;'>"+esc(e.message)+"</div>"; }
}
function renderUserDetail(){
  const d=window._currentUserDetail; if(!d) return;
  const u=d.user;
  const vipOn=u.vip&&u.vip.active;
  let html="<div class='panel'>"+
    "<div style='display:flex;justify-content:space-between;align-items:center;'>"+
      "<h3 style='margin:0;'>👤 "+esc(u.name)+(u.username?" <span style='color:#9A9484;font-size:12px;'>@"+esc(u.username)+"</span>":"")+(u.blocked?" <span style='color:#FF5252;font-size:11px;'>(مسدود)</span>":"")+"</h3>"+
      "<button class='small outline' data-user-close-detail='1'>بستن ✕</button>"+
    "</div>"+
    "<div style='font-size:11px;color:#9A9484;margin:6px 0 12px;'>عضویت: "+new Date(u.createdAt).toLocaleDateString("fa-IR")+" · نقش: "+u.role+"</div>"+
    "<label class='flabel' style='font-size:11px;'>نام</label><input id='ud_name' value='"+esc(u.name||"")+"'>"+
    "<label class='flabel' style='font-size:11px;'>نام کاربری</label><input id='ud_username' value='"+esc(u.username||"")+"' dir='ltr' style='text-align:left;'>"+
    "<label class='flabel' style='font-size:11px;'>ایمیل</label><input id='ud_email' value='"+esc(u.email||"")+"'>"+
    "<label class='flabel' style='font-size:11px;'>موبایل</label><input id='ud_phone' value='"+esc(u.phone||"")+"'>"+
    "<div style='display:flex;gap:6px;'>"+
      "<div style='flex:1;'><label class='flabel' style='font-size:11px;'>قد (cm)</label><input id='ud_height' type='number' value='"+esc((u.profile&&u.profile.height)||"")+"'></div>"+
      "<div style='flex:1;'><label class='flabel' style='font-size:11px;'>وزن (kg)</label><input id='ud_weight' type='number' value='"+esc((u.profile&&u.profile.weight)||"")+"'></div>"+
    "</div>"+
    "<button data-user-save='"+u.id+"' style='margin-top:6px;'>💾 ذخیره تغییرات</button>"+
    "<hr class='section-divider'>"+
    "<div style='display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;'>"+
      "<button class='small' data-user-gift='"+u.id+"'>🎁 هدیه VIP</button>"+
      (vipOn?"<button class='small danger' data-user-revoke='"+u.id+"'>لغو VIP</button>":"")+
      "<button class='small outline' data-user-toggle-block='"+u.id+"'>"+(u.blocked?"✅ رفع مسدودی":"🚫 مسدودسازی")+"</button>"+
      "<button class='small danger' data-user-delete='"+u.id+"'>🗑️ حذف حساب</button>"+
    "</div>"+
    "<div style='font-size:11px;color:#9A9484;'>"+
      "💳 پرداخت‌ها: "+d.payments.length+" مورد"+(d.payments[0]?(" · آخرین: "+esc(d.payments[0].status||"-")+" ("+new Date(d.payments[0].createdAt).toLocaleDateString("fa-IR")+")"):"")+"<br>"+
      "📊 ثبت وضعیت بدنی: "+d.stats.length+" مورد"+"<br>"+
      "🏆 رکوردهای شخصی: "+d.records.length+" مورد"+"<br>"+
      "🧠 مصرف AI (۱۴ روز اخیر): "+d.aiUsage.reduce(function(s,a){return s+(a.count||0);},0)+" پیام"+
      (d.coachProfile?("<br>🧑‍🏫 پروفایل مربی‌گری: وضعیت "+esc(d.coachProfile.status||"-")):"")+
    "</div>"+
  "</div>";
  document.getElementById("userDetailBox").innerHTML=html;
}
async function saveUserEdit(userId){
  const patch={
    name:document.getElementById("ud_name").value.trim(),
    username:document.getElementById("ud_username").value.trim(),
    email:document.getElementById("ud_email").value.trim(),
    phone:document.getElementById("ud_phone").value.trim(),
    height:document.getElementById("ud_height").value?Number(document.getElementById("ud_height").value):undefined,
    weight:document.getElementById("ud_weight").value?Number(document.getElementById("ud_weight").value):undefined,
  };
  try{ await api("/api/admin/users/"+userId,{method:"PUT",body:JSON.stringify(patch)}); alert("ذخیره شد ✅"); loadUsers(); openUserDetail(userId); }
  catch(e){ alert(e.message); }
}
async function toggleUserBlock(userId){
  const d=window._currentUserDetail;
  const nowBlocked=!(d&&d.user.blocked);
  if(!confirm(nowBlocked?"این کاربر مسدود بشه؟":"مسدودیت این کاربر برداشته بشه؟")) return;
  try{ await api("/api/admin/users/"+userId+"/block",{method:"PUT",body:JSON.stringify({blocked:nowBlocked})}); loadUsers(); openUserDetail(userId); }
  catch(e){ alert(e.message); }
}
async function deleteUserAccount(userId){
  if(!confirm("⚠️ حذف حساب غیرقابل‌بازگشته. مطمئنی؟")) return;
  if(!confirm("برای تایید نهایی دوباره تایید کن.")) return;
  try{ await api("/api/admin/users/"+userId,{method:"DELETE"}); document.getElementById("userDetailBox").innerHTML=""; window._currentUserDetail=null; loadUsers(); }
  catch(e){ alert(e.message); }
}
document.addEventListener("click",function(e){
  const tabBtn=e.target.closest("[data-tab-btn]"); if(tabBtn){ showAdminTab(tabBtn.getAttribute("data-tab-btn")); return; }
  const v=e.target.closest("[data-user-view]"); if(v){ openUserDetail(v.getAttribute("data-user-view")); return; }
  const g=e.target.closest("[data-user-gift]"); if(g){ giftVip(g.getAttribute("data-user-gift")); return; }
  const rv=e.target.closest("[data-user-revoke]"); if(rv){ revokeVip(rv.getAttribute("data-user-revoke")); return; }
  const s=e.target.closest("[data-user-save]"); if(s){ saveUserEdit(s.getAttribute("data-user-save")); return; }
  const tb=e.target.closest("[data-user-toggle-block]"); if(tb){ toggleUserBlock(tb.getAttribute("data-user-toggle-block")); return; }
  const del=e.target.closest("[data-user-delete]"); if(del){ deleteUserAccount(del.getAttribute("data-user-delete")); return; }
  const cl=e.target.closest("[data-user-close-detail]"); if(cl){ document.getElementById("userDetailBox").innerHTML=""; window._currentUserDetail=null; return; }
});
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
      " · اشتراک فعال: "+s.activeSubscriptions+" · مسدود: "+s.banned;
  }catch(e){}
}
async function loadCommission(){
  try{
    const s=await api("/api/admin/coach-settings");
    document.getElementById("commissionRate").value=Math.round(s.commissionRate*100);
  }catch(e){}
}
async function saveCommission(){
  document.getElementById("commissionMsg").textContent="";
  try{
    const pct=Number(document.getElementById("commissionRate").value)||0;
    await api("/api/admin/coach-settings",{method:"PUT",body:JSON.stringify({commissionRate:pct/100})});
    document.getElementById("commissionMsg").textContent="ذخیره شد ✅";
    document.getElementById("commissionMsg").style.color="#3DDC74";
  }catch(e){ document.getElementById("commissionMsg").textContent=e.message; document.getElementById("commissionMsg").style.color="#FF5252"; }
}
async function seedTestAccounts(){
  document.getElementById("seedResult").innerHTML="در حال ساخت...";
  try{
    const list=await api("/api/admin/seed-test-accounts",{method:"POST"});
    let html="<table><tr><th>ایمیل</th><th>رمز عبور</th><th>نقش</th></tr>";
    list.forEach(function(a){ html+="<tr><td>"+esc(a.email)+"</td><td>"+esc(a.password)+"</td><td>"+esc(a.role)+"</td></tr>"; });
    html+="</table>";
    document.getElementById("seedResult").innerHTML=html;
  }catch(e){document.getElementById("seedResult").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function loadCoachWallets(){
  try{
    window._allCoachWallets=await api("/api/admin/coach-wallets");
    renderCoachWalletsTable();
    loadWithdrawalRequests();
  }catch(e){document.getElementById("coachWalletsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function renderCoachWalletsTable(){
  const list=window._allCoachWallets||[];
  if(!list.length){document.getElementById("coachWalletsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>مربی‌ای پیدا نشد</div>";return;}
  let totalBalance=0,totalEarn=0,totalComm=0;
  list.forEach(function(w){totalBalance+=w.balance;totalEarn+=w.totalEarnings;totalComm+=w.totalCommission;});
  let html="<div class='statgrid' style='margin-bottom:10px;'>"+
    "<div class='statcard'><div class='statnum'>"+totalBalance.toLocaleString()+"</div><div style='font-size:11px;color:#9A9484;'>مجموع موجودی مربیان (ت)</div></div>"+
    "<div class='statcard'><div class='statnum'>"+totalComm.toLocaleString()+"</div><div style='font-size:11px;color:#9A9484;'>کل کمیسیون اپ (ت)</div></div>"+
  "</div>";
  html+="<table><tr><th>مربی</th><th>موجودی</th><th>درآمد کل</th><th>کمیسیون پرداختی</th><th></th></tr>";
  list.forEach(function(w){
    html+="<tr><td>"+esc(w.coachName)+(w.pendingWithdrawals?" <span class='badge warn'>"+w.pendingWithdrawals+" درخواست برداشت</span>":"")+"</td>"+
      "<td style='color:#3DDC74;font-weight:700;'>"+w.balance.toLocaleString()+" ت</td>"+
      "<td>"+w.totalEarnings.toLocaleString()+" ت</td>"+
      "<td>"+w.totalCommission.toLocaleString()+" ت</td>"+
      "<td><button class='small' data-wallet-open='"+w.coachId+"'>مشاهده</button></td></tr>";
  });
  html+="</table>";
  document.getElementById("coachWalletsList").innerHTML=html;
}
async function openCoachWallet(coachId){
  document.getElementById("coachWalletDetail").innerHTML="در حال بارگذاری...";
  try{
    const data=await api("/api/admin/coach-wallets/"+coachId);
    window._currentWallet=data;
    renderCoachWalletDetail();
  }catch(e){document.getElementById("coachWalletDetail").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
const WD_STATUS_BADGE={pending:["badge warn","در انتظار بررسی"],paid:["badge on","پرداخت‌شده"],rejected:["badge off","رد شده"],info_incorrect:["badge off","اطلاعات نادرست"]};
function renderCoachWalletDetail(){
  const d=window._currentWallet;
  if(!d)return;
  const w=d.wallet,c=d.coach;
  let html="<div style='border:1.5px solid rgba(216,174,82,.3);border-radius:10px;padding:14px;'>"+
    "<h3>💰 کیف پول "+esc(c.name)+"</h3>"+
    "<div class='statgrid' style='margin-bottom:10px;'>"+
      "<div class='statcard'><div class='statnum'>"+w.balance.toLocaleString()+"</div><div style='font-size:11px;color:#9A9484;'>موجودی فعلی</div></div>"+
      "<div class='statcard'><div class='statnum'>"+w.totalEarnings.toLocaleString()+"</div><div style='font-size:11px;color:#9A9484;'>درآمد کل</div></div>"+
    "</div>";
  const wds=d.withdrawals||[];
  if(wds.length){
    html+="<h3 style='font-size:13px;'>درخواست‌های برداشت این مربی</h3>";
    wds.forEach(function(wr){
      const sb=WD_STATUS_BADGE[wr.status]||["badge","-"];
      html+="<div style='border:1px solid var(--border,#333);border-radius:8px;padding:8px;margin-bottom:6px;'>"+
        "<div style='display:flex;justify-content:space-between;'><b style='font-size:12px;'>"+Number(wr.amount).toLocaleString()+" تومان</b><span class='"+sb[0]+"'>"+sb[1]+"</span></div>"+
        "<div style='font-size:10px;color:#9A9484;'>"+new Date(wr.createdAt).toLocaleDateString("fa-IR")+"</div>"+
      "</div>";
    });
  }
  html+="<h3 style='font-size:13px;margin-top:14px;'>تاریخچه‌ی تراکنش‌ها</h3>"+
    "<table><tr><th>تاریخ</th><th>نوع</th><th>مبلغ</th><th>توضیح</th></tr>";
  const txs=(w.transactions||[]).slice().reverse();
  const typeLabel={earning:"درآمد",commission:"کمیسیون",withdrawal:"برداشت",withdrawal_refund:"بازگشت برداشت",adjustment_credit:"تعدیل (+)",adjustment_debit:"تعدیل (-)"};
  txs.forEach(function(t){
    const pos=t.type==="earning"||t.type==="adjustment_credit"||t.type==="withdrawal_refund";
    html+="<tr><td style='font-size:10px;'>"+new Date(t.date).toLocaleDateString("fa-IR")+"</td>"+
      "<td>"+(typeLabel[t.type]||t.type)+"</td>"+
      "<td style='color:"+(pos?"#3DDC74":"#FF5252")+";'>"+(pos?"+":"-")+t.amount.toLocaleString()+"</td>"+
      "<td style='font-size:10px;'>"+esc(t.desc||"")+"</td></tr>";
  });
  html+="</table>"+
    "<h3 style='font-size:13px;margin-top:14px;'>تعدیل دستی</h3>"+
    "<div style='display:flex;gap:4px;'>"+
      "<select id='adjDirection' style='flex:1;'><option value='credit'>افزودن (+)</option><option value='debit'>کسر (-)</option></select>"+
      "<input id='adjAmount' type='number' placeholder='مبلغ' style='flex:1;'>"+
    "</div>"+
    "<input id='adjReason' placeholder='دلیل (الزامی)'>"+
    "<button data-wallet-adjust='"+c.id+"'>ثبت تعدیل</button>"+
  "</div>";
  document.getElementById("coachWalletDetail").innerHTML=html;
}
async function submitWalletAdjust(coachId){
  const direction=document.getElementById("adjDirection").value;
  const amount=Number(document.getElementById("adjAmount").value);
  const reason=document.getElementById("adjReason").value.trim();
  if(!amount||amount<=0){alert("مبلغ رو درست وارد کن");return;}
  if(!reason){alert("دلیل تعدیل رو بنویس");return;}
  try{
    await api("/api/admin/coach-wallets/"+coachId+"/adjust",{method:"POST",body:JSON.stringify({amount,direction,reason})});
    alert("ثبت شد ✅");
    openCoachWallet(coachId);
    loadCoachWallets();
  }catch(e){alert(e.message);}
}

/* ===== درخواست‌های برداشت وجه — پنل مرکزی (مهم‌ترین بخش مالی) ===== */
const WD_METHOD_LABEL={sheba:"شبا (انتقال بانکی)",card:"کارت به کارت"};
async function loadWithdrawalRequests(){
  try{
    const filter=(document.getElementById("wdFilter")||{}).value||"pending";
    const params=filter==="all"?"":("?status="+filter);
    window._withdrawals=await api("/api/admin/coach-wallets/withdrawals/list"+params);
    renderWithdrawalRequests();
  }catch(e){document.getElementById("withdrawalRequestsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function renderWithdrawalRequests(){
  const list=window._withdrawals||[];
  if(!list.length){document.getElementById("withdrawalRequestsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>درخواستی نیست</div>";return;}
  let html="";
  list.forEach(function(wr){
    const sb=WD_STATUS_BADGE[wr.status]||["badge","-"];
    const b=wr.bankInfo||{};
    html+="<div style='border:1.5px solid rgba(216,174,82,.3);border-radius:10px;padding:12px;margin-bottom:10px;'>"+
      "<div style='display:flex;justify-content:space-between;align-items:center;'>"+
        "<b style='font-size:13px;'>"+esc(wr.coachName)+(wr.coachUsername?" <span style='color:#9A9484;font-size:11px;'>(@"+esc(wr.coachUsername)+")</span>":"")+"</b>"+
        "<span class='"+sb[0]+"'>"+sb[1]+"</span>"+
      "</div>"+
      "<div style='font-size:18px;font-weight:800;color:#D8AE52;margin:6px 0;'>"+Number(wr.amount).toLocaleString("fa-IR")+" تومان</div>"+
      "<div style='font-size:11px;line-height:2;background:rgba(255,255,255,.03);border-radius:8px;padding:8px;'>"+
        "روش: <b>"+(WD_METHOD_LABEL[wr.method]||wr.method)+"</b><br>"+
        "صاحب حساب: <b>"+esc(b.accountHolderName||"-")+"</b><br>"+
        "بانک: <b>"+esc(b.bankName||"-")+"</b><br>"+
        (wr.method==="sheba"?("شماره شبا: <b class='mono' style='direction:ltr;display:inline-block;'>"+esc(b.sheba||"-")+"</b>"):("شماره کارت: <b class='mono' style='direction:ltr;display:inline-block;'>"+esc(b.cardNumber||"-")+"</b>"))+
      "</div>"+
      "<div style='font-size:10px;color:#9A9484;margin-top:4px;'>ثبت درخواست: "+new Date(wr.createdAt).toLocaleString("fa-IR")+"</div>"+
      (wr.adminNote?("<div style='font-size:11px;color:#9A9484;margin-top:4px;'>یادداشت ادمین: "+esc(wr.adminNote)+"</div>"):"")+
      (wr.rejectReason?("<div style='font-size:11px;color:#FF5252;margin-top:4px;'>دلیل رد: "+esc(wr.rejectReason)+"</div>"):"")+
      (wr.status==="pending"?(
        "<div style='display:flex;gap:6px;flex-wrap:wrap;margin-top:10px;'>"+
          "<button class='small' data-wd-approve='"+wr.id+"' data-method='"+wr.method+"'>✅ تایید و ثبت واریز</button>"+
          "<button class='small outline' data-wd-incorrect='"+wr.id+"'>⚠️ اطلاعات نادرسته</button>"+
          "<button class='small danger' data-wd-reject='"+wr.id+"'>❌ رد کن</button>"+
        "</div>"
      ):"")+
    "</div>";
  });
  document.getElementById("withdrawalRequestsList").innerHTML=html;
}
async function approveWithdrawal(id,method){
  const note=prompt("یادداشت (اختیاری) — مثلاً شماره پیگیری تراکنش بانکی:","");
  if(note===null)return;
  try{
    await api("/api/admin/coach-wallets/withdrawals/"+id+"/approve",{method:"PUT",body:JSON.stringify({method:method,note:note})});
    alert("ثبت شد ✅ — به مربی اطلاع داده شد");
    loadWithdrawalRequests(); loadCoachWallets();
  }catch(e){alert(e.message);}
}
async function rejectWithdrawal(id){
  const reason=prompt("دلیل رد درخواست رو بنویس:","");
  if(!reason)return;
  try{
    await api("/api/admin/coach-wallets/withdrawals/"+id+"/reject",{method:"PUT",body:JSON.stringify({reason:reason})});
    alert("رد شد و مبلغ به کیف‌پول مربی برگشت");
    loadWithdrawalRequests(); loadCoachWallets();
  }catch(e){alert(e.message);}
}
async function markWithdrawalInfoIncorrect(id){
  const note=prompt("چی اشتباهه؟ (اختیاری، برای مربی نمایش داده می‌شه):","");
  if(note===null)return;
  try{
    await api("/api/admin/coach-wallets/withdrawals/"+id+"/info-incorrect",{method:"PUT",body:JSON.stringify({note:note})});
    alert("ثبت شد — مربی مطلع شد و می‌تونه دوباره با اطلاعات درست درخواست بده");
    loadWithdrawalRequests(); loadCoachWallets();
  }catch(e){alert(e.message);}
}
document.addEventListener("click",function(e){
  const wo=e.target.closest("[data-wallet-open]"); if(wo){ openCoachWallet(wo.getAttribute("data-wallet-open")); return; }
  const wa=e.target.closest("[data-wallet-adjust]"); if(wa){ submitWalletAdjust(wa.getAttribute("data-wallet-adjust")); return; }
  const wda=e.target.closest("[data-wd-approve]"); if(wda){ approveWithdrawal(wda.getAttribute("data-wd-approve"),wda.getAttribute("data-method")); return; }
  const wdr=e.target.closest("[data-wd-reject]"); if(wdr){ rejectWithdrawal(wdr.getAttribute("data-wd-reject")); return; }
  const wdi=e.target.closest("[data-wd-incorrect]"); if(wdi){ markWithdrawalInfoIncorrect(wdi.getAttribute("data-wd-incorrect")); return; }
});
const TICKET_STATUS_LABELS={"new":"جدید",in_review:"در حال بررسی",answered:"پاسخ داده‌شده",waiting_user:"منتظر کاربر",closed:"بسته‌شده"};
const TICKET_STATUS_BADGE={"new":"badge warn",in_review:"badge warn",answered:"badge on",waiting_user:"badge warn",closed:"badge off"};
const TICKET_PRIORITY_LABELS={urgent:"🔴 فوری",important:"🟡 مهم",normal:"عادی"};
async function loadTickets(){
  try{
    const params=new URLSearchParams();
    const st=document.getElementById("tkFilterStatus").value;
    const cat=document.getElementById("tkFilterCategory").value;
    const pr=document.getElementById("tkFilterPriority").value;
    const arch=document.getElementById("tkFilterArchived").checked;
    if(st)params.set("status",st);
    if(cat)params.set("category",cat);
    if(pr)params.set("priority",pr);
    params.set("archived",arch?"true":"false");
    window._allTickets=await api("/api/admin/tickets?"+params.toString());
    renderTicketsList();
    loadTicketStats();
  }catch(e){document.getElementById("ticketsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function loadTicketStats(){
  try{
    const s=await api("/api/admin/tickets/stats");
    let h="";
    h+="<div class='statcard'><div class='statnum'>"+s.total+"</div><div style='font-size:11px;'>کل تیکت‌ها</div></div>";
    h+="<div class='statcard'><div class='statnum' style='"+(s.unread>0?"color:#FF5252;":"")+"'>"+s.unread+"</div><div style='font-size:11px;'>خوانده‌نشده</div></div>";
    h+="<div class='statcard'><div class='statnum'>"+((s.byStatus["new"]||0)+(s.byStatus.in_review||0))+"</div><div style='font-size:11px;'>منتظر رسیدگی</div></div>";
    h+="<div class='statcard'><div class='statnum'>"+(s.avgFirstResponseMinutes!=null?s.avgFirstResponseMinutes+"د":"-")+"</div><div style='font-size:11px;'>میانگین زمان پاسخ</div></div>";
    document.getElementById("ticketStatsBox").innerHTML=h;
  }catch(e){}
}
function formatTicketDate(iso){
  if(!iso)return "-";
  const d=new Date(iso);
  return d.toLocaleDateString("fa-IR")+" - "+d.toLocaleTimeString("fa-IR",{hour:"2-digit",minute:"2-digit"});
}
function renderTicketsList(){
  const q=(document.getElementById("tkSearch").value||"").trim().toLowerCase();
  let list=window._allTickets||[];
  if(q) list=list.filter(function(t){return (t.subject||"").toLowerCase().indexOf(q)>-1 || (t.userName||"").toLowerCase().indexOf(q)>-1;});
  if(!list.length){document.getElementById("ticketsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>تیکتی پیدا نشد</div>";return;}
  // خوانده‌نشده‌ها اول نمایش داده بشن
  list=list.slice().sort(function(a,b){ return (b.unread?1:0)-(a.unread?1:0); });
  let html="";
  list.forEach(function(t){
    const badge=TICKET_STATUS_BADGE[t.status]||"badge";
    const label=TICKET_STATUS_LABELS[t.status]||t.status;
    const pr=TICKET_PRIORITY_LABELS[t.priority]||t.priority||"";
    html+="<div class='report-card' data-tk-open='"+t.id+"' style='cursor:pointer;"+(t.unread?"border-color:var(--brass,#D8AE52);background:rgba(216,174,82,.06);":"")+"'>"+
      "<div style='display:flex;justify-content:space-between;align-items:center;gap:8px;'>"+
        "<b style='font-size:12.5px;'>"+(t.unread?"🔵 ":"")+"#"+(t.ticketNumber||"-")+" — "+esc(t.subject)+"</b>"+
        "<span class='"+badge+"'>"+label+"</span>"+
      "</div>"+
      "<div style='font-size:11px;color:#9A9484;margin-top:4px;'>"+esc(t.userName||"-")+" · "+esc(t.category||"-")+" · "+pr+(t.archived?" · 📦 آرشیو":"")+"</div>"+
      "<div style='font-size:10px;color:#9A9484;margin-top:3px;'>🕒 آخرین پیام: "+formatTicketDate(t.lastMessageAt)+" · ثبت: "+formatTicketDate(t.createdAt)+"</div>"+
    "</div>";
  });
  document.getElementById("ticketsList").innerHTML=html;
}
async function openTicket(id){
  document.getElementById("ticketDetail").innerHTML="در حال بارگذاری...";
  try{
    const data=await api("/api/admin/tickets/"+id);
    window._currentTicket=data.ticket; window._currentMessages=data.messages;
    renderTicketDetail();
    loadTickets(); // برای پاک شدن نشان خوانده‌نشده از لیست
  }catch(e){document.getElementById("ticketDetail").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function renderTicketAttachment(a){
  if(!a||!a.url)return "";
  if(a.type==="video")return "<video class='thumb' style='object-fit:cover;display:block;margin-bottom:4px;' src='"+a.url+"' controls></video>";
  if(a.type==="pdf")return "<div style='margin-bottom:4px;'><a href='"+a.url+"' target='_blank' style='font-size:11px;color:#D8AE52;'>📄 دانلود فایل PDF</a></div>";
  return "<a href='"+a.url+"' target='_blank'><img class='thumb' src='"+a.url+"' style='margin-bottom:4px;display:block;'></a>";
}
function renderTicketDetail(){
  const t=window._currentTicket, msgs=window._currentMessages||[];
  if(!t)return;
  let html="<div style='border:1.5px solid rgba(216,174,82,.3);border-radius:10px;padding:14px;'>"+
    "<h3>#"+(t.ticketNumber||"-")+" — "+esc(t.subject)+"</h3>"+
    "<div style='font-size:11px;color:#9A9484;margin-bottom:4px;'>کاربر: "+esc(t.userName||"-")+" ("+esc(t.userEmail||"-")+") · تلفن: "+esc(t.userPhone||"-")+" · دسته: "+esc(t.category||"-")+" · اولویت: "+(TICKET_PRIORITY_LABELS[t.priority]||t.priority||"-")+"</div>"+
    "<div style='font-size:10px;color:#9A9484;margin-bottom:8px;'>🕒 ثبت تیکت: "+formatTicketDate(t.createdAt)+" · آخرین پیام: "+formatTicketDate(t.lastMessageAt)+"</div>"+
    (t.rating?"<div style='font-size:11px;color:#F2CE7A;margin-bottom:8px;'>⭐ امتیاز کاربر: "+t.rating+"/5"+(t.ratingText?" — "+esc(t.ratingText):"")+"</div>":"")+
    "<div style='max-height:320px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;margin-bottom:10px;padding:6px;background:rgba(0,0,0,.2);border-radius:8px;'>";
  msgs.forEach(function(m){
    const mine=m.senderRole==="admin";
    const atts=(m.attachments&&m.attachments.length)?m.attachments:(m.attachmentUrl?[{url:m.attachmentUrl,type:"image"}]:[]);
    html+="<div style='align-self:"+(mine?"flex-end":"flex-start")+";max-width:78%;background:"+(mine?"rgba(216,174,82,.15)":"rgba(255,255,255,.04)")+";border-radius:10px;padding:8px 10px;'>"+
      "<div style='font-size:9px;color:#9A9484;margin-bottom:3px;'>"+(mine?"👨‍💼 پشتیبانی":"👤 کاربر")+" · "+formatTicketDate(m.createdAt)+"</div>"+
      atts.map(renderTicketAttachment).join("")+
      (m.text?"<div style='font-size:12px;white-space:pre-wrap;'>"+esc(m.text)+"</div>":"")+
    "</div>";
  });
  html+="</div>"+
    "<textarea id='ticketReplyText' placeholder='پاسخت رو بنویس یا از پاسخ آماده انتخاب کن...' style='min-height:60px;'></textarea>"+
    "<input type='file' id='ticketReplyFile' accept='image/png,image/jpeg,image/webp,video/mp4,video/webm,video/quicktime,application/pdf'>"+
    "<div style='margin-top:6px;display:flex;gap:6px;align-items:center;flex-wrap:wrap;'>"+
    "<select id='ticketReplyStatus' style='width:auto;'>"+
      "<option value='answered'"+(t.status==="answered"?" selected":"")+">پاسخ داده‌شده</option>"+
      "<option value='in_review'"+(t.status==="in_review"?" selected":"")+">در حال بررسی</option>"+
      "<option value='waiting_user'"+(t.status==="waiting_user"?" selected":"")+">منتظر کاربر</option>"+
      "<option value='new'"+(t.status==="new"?" selected":"")+">جدید بمونه</option>"+
      "<option value='closed'"+(t.status==="closed"?" selected":"")+">بسته بشه</option>"+
    "</select>"+
    "<button data-tk-reply-send='"+t.id+"'>ارسال پاسخ</button>"+
    "<button class='outline small' data-tk-archive='"+t.id+"'>"+(t.archived?"خروج از آرشیو":"📦 آرشیو")+"</button>"+
    "</div>"+
  "</div>";
  document.getElementById("ticketDetail").innerHTML=html;
}
async function sendTicketReply(id){
  const text=document.getElementById("ticketReplyText").value.trim();
  const fileInput=document.getElementById("ticketReplyFile");
  const status=document.getElementById("ticketReplyStatus").value;
  const hasFile=fileInput.files&&fileInput.files[0];
  if(!text&&!hasFile){alert("پیام یا فایل رو وارد کن");return;}
  const fd=new FormData();
  fd.append("message",text); fd.append("status",status);
  if(hasFile) fd.append("file0",fileInput.files[0]);
  try{
    await apiUpload("/api/admin/tickets/"+id+"/reply",fd);
    await openTicket(id);
    loadTickets();
  }catch(e){alert(e.message||"خطا در ارسال پاسخ");}
}
async function toggleTicketArchive(id){
  const t=window._currentTicket;
  try{
    await api("/api/admin/tickets/"+id+"/archive",{method:"PUT",body:JSON.stringify({archived:!(t&&t.archived)})});
    await openTicket(id);
    loadTickets();
  }catch(e){alert(e.message);}
}
async function loadQuickReplies(){
  try{ window._quickReplies=await api("/api/admin/tickets/quick-replies"); renderQuickRepliesList(); }catch(e){}
}
function renderQuickRepliesList(){
  const list=window._quickReplies||[];
  const box=document.getElementById("quickRepliesList");
  if(!box)return;
  if(!list.length){box.innerHTML="<div style='font-size:11px;color:#9A9484;'>هنوز پاسخ آماده‌ای ثبت نشده</div>";return;}
  let html="";
  list.forEach(function(q){
    html+="<div style='display:flex;align-items:center;gap:4px;background:rgba(255,255,255,.04);border-radius:8px;padding:4px 8px;'>"+
      "<button class='small' data-qr-use='"+q.id+"' title='"+esc(q.text)+"'>"+esc(q.title)+"</button>"+
      "<button class='small danger' data-qr-del='"+q.id+"' style='padding:4px 7px;'>✕</button>"+
    "</div>";
  });
  box.innerHTML=html;
}
async function createQuickReply(){
  const title=document.getElementById("qrTitle").value.trim();
  const text=document.getElementById("qrText").value.trim();
  if(!title||!text){alert("عنوان و متن پاسخ آماده رو پر کن");return;}
  try{
    await api("/api/admin/tickets/quick-replies",{method:"POST",body:JSON.stringify({title:title,text:text})});
    document.getElementById("qrTitle").value=""; document.getElementById("qrText").value="";
    loadQuickReplies();
  }catch(e){alert(e.message);}
}
async function deleteQuickReply(id){
  if(!confirm("این پاسخ آماده حذف بشه؟"))return;
  try{ await api("/api/admin/tickets/quick-replies/"+id,{method:"DELETE"}); loadQuickReplies(); }catch(e){alert(e.message);}
}
function useQuickReply(id){
  const q=(window._quickReplies||[]).find(function(x){return x.id===id;});
  if(q){ const ta=document.getElementById("ticketReplyText"); if(ta) ta.value=q.text; }
}
// دلگیت کلیک برای دکمه‌های تیکت (چون آی‌دی‌ها داینامیک هستن و innerHTML مدام جایگزین می‌شه)
document.addEventListener("click",function(e){
  const openBtn=e.target.closest("[data-tk-open]");
  if(openBtn){ openTicket(openBtn.getAttribute("data-tk-open")); return; }
  const replyBtn=e.target.closest("[data-tk-reply-send]");
  if(replyBtn){ sendTicketReply(replyBtn.getAttribute("data-tk-reply-send")); return; }
  const archBtn=e.target.closest("[data-tk-archive]");
  if(archBtn){ toggleTicketArchive(archBtn.getAttribute("data-tk-archive")); return; }
  const qrUse=e.target.closest("[data-qr-use]");
  if(qrUse){ useQuickReply(qrUse.getAttribute("data-qr-use")); return; }
  const qrDel=e.target.closest("[data-qr-del]");
  if(qrDel){ deleteQuickReply(qrDel.getAttribute("data-qr-del")); return; }
});
async function loadCoachPlansEditor(){
  try{
    const plans=await api("/api/admin/coach-plans");
    let html="";
    plans.forEach(function(p,i){
      html+="<div style='border:1px solid rgba(255,255,255,.1);border-radius:6px;padding:8px;margin-bottom:8px;'>"+
        "<div style='font-size:11px;color:#9A9484;margin-bottom:4px;'>پلن: "+esc(p.id)+"</div>"+
        "<input id='plan_name_"+i+"' value='"+esc(p.name)+"' placeholder='نام پلن' style='width:100%;margin-bottom:4px;'>"+
        "<div style='display:flex;gap:4px;'>"+
        "<input id='plan_price_"+i+"' type='number' value='"+p.priceToman+"' placeholder='قیمت تومان' style='flex:1;'>"+
        "<input id='plan_priceusdt_"+i+"' type='number' value='"+p.priceUsdt+"' placeholder='قیمت USDT' style='flex:1;'>"+
        "<input id='plan_days_"+i+"' type='number' value='"+p.durationDays+"' placeholder='مدت (روز)' style='flex:1;'>"+
        "</div>"+
        "<textarea id='plan_features_"+i+"' placeholder='ویژگی‌ها (با ویرگول جدا کن)' style='width:100%;margin-top:4px;'>"+esc((p.features||[]).join(", "))+"</textarea>"+
        "<input id='plan_id_"+i+"' type='hidden' value='"+esc(p.id)+"'>"+
      "</div>";
    });
    document.getElementById("coachPlansEditor").innerHTML=html;
    window._coachPlansCount=plans.length;
  }catch(e){document.getElementById("coachPlansEditor").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function saveCoachPlans(){
  document.getElementById("coachPlansMsg").textContent="";
  try{
    const n=window._coachPlansCount||0;
    const plans=[];
    for(let i=0;i<n;i++){
      plans.push({
        id:document.getElementById("plan_id_"+i).value,
        name:document.getElementById("plan_name_"+i).value,
        priceToman:Number(document.getElementById("plan_price_"+i).value)||0,
        priceUsdt:Number(document.getElementById("plan_priceusdt_"+i).value)||0,
        durationDays:Number(document.getElementById("plan_days_"+i).value)||30,
        features:document.getElementById("plan_features_"+i).value.split(",").map(s=>s.trim()).filter(Boolean),
      });
    }
    await api("/api/admin/coach-plans",{method:"PUT",body:JSON.stringify({plans})});
    document.getElementById("coachPlansMsg").textContent="ذخیره شد ✅";
    document.getElementById("coachPlansMsg").style.color="#3DDC74";
  }catch(e){ document.getElementById("coachPlansMsg").textContent=e.message; document.getElementById("coachPlansMsg").style.color="#FF5252"; }
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
        "<div style='font-size:11px;color:#D8AE52;margin-top:4px;'>🏋️ باشگاه: "+esc(c.gymName||"-")+"</div>"+
        (c.socialInstagram?"<div style='font-size:11px;color:#9A9484;'>📷 "+esc(c.socialInstagram)+"</div>":"")+
        "<div style='margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;'>"+
          (c.certificateUrls||[]).map(function(u){return "<a href='"+u+"' target='_blank'><img src='"+u+"' style='width:70px;height:70px;object-fit:cover;border-radius:6px;border:1px solid rgba(255,255,255,.15);'></a>";}).join("")+
        "</div>"+
        "<div style='margin-top:6px;'>"+
        "<button onclick=approveCoach(\\""+c.id+"\\")>✅ تایید</button>"+
        "<button class='danger' onclick=rejectCoach(\\""+c.id+"\\")>❌ رد</button>"+
        "</div>"+
        "<div style='margin-top:6px;'><input id='pendmsg_"+c.id+"' placeholder='مثلاً: لطفاً مدرک واضح‌تری ارسال کن' style='width:70%;display:inline-block;font-size:11px;'>"+
        "<button onclick=sendCoachNotice(\\""+c.id+"\\",true) style='font-size:11px;'>ارسال پیام</button></div>"+
        "</div>";
    });
    document.getElementById("pendingCoaches").innerHTML=html;
  }catch(e){document.getElementById("pendingCoaches").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function approveCoach(id){
  if(!confirm("تایید بشه؟"))return;
  try{await api("/api/admin/coaches/"+id+"/approve",{method:"PUT"});alert("تایید شد ✅");loadPendingCoaches();loadCoachStats();loadAllCoaches();}catch(e){alert(e.message);}
}
async function rejectCoach(id){
  if(!confirm("رد بشه؟"))return;
  try{await api("/api/admin/coaches/"+id+"/reject",{method:"PUT"});alert("رد شد");loadPendingCoaches();loadCoachStats();loadAllCoaches();}catch(e){alert(e.message);}
}
async function loadAllCoaches(){
  try{
    const list=await api("/api/admin/coaches/all");
    const tiers=[["","خودکار"],["bronze","🥉 برنز"],["silver","🥈 نقره"],["gold","🥇 طلا"],["platinum","💎 پلاتین"],["elite","👑 الیت"]];
    let html='<table><tr><th>نام</th><th>وضعیت</th><th>شاگرد</th><th>فروش</th><th>درآمد کل</th><th>سطح</th><th>عملیات</th><th>اعلان</th></tr>';
    list.forEach(function(c){
      const statusBadge=c.status==="approved"?'<span class="badge on">تاییدشده</span>':c.status==="banned"?'<span class="badge off">مسدود</span>':c.status==="pending"?'<span class="badge warn">در انتظار</span>':'<span class="badge off">'+esc(c.status)+'</span>';
      const curTier=(c.ranking&&c.ranking.rankOverride)||"";
      let tierOptions="";
      tiers.forEach(function(t){ tierOptions+="<option value='"+t[0]+"' "+(t[0]===curTier?"selected":"")+">"+t[1]+"</option>"; });
      html+='<tr><td>'+esc(c.name||"-")+(c.username?"<div style='font-size:10px;color:#9A9484;'>@"+esc(c.username)+"</div>":"")+'</td><td>'+statusBadge+'</td>'+
        '<td>'+(c.students||0)+'</td><td>'+(c.totalSales||0)+'</td>'+
        '<td>'+((c.wallet&&c.wallet.totalEarnings)||0).toLocaleString()+' ت</td>'+
        '<td style="font-size:10px;">'+esc((c.ranking&&c.ranking.rank)||"-")+
          '<div style="margin-top:4px;"><select class="tier-select" id="tier_'+c.id+'" style="font-size:10px;padding:3px;">'+tierOptions+'</select>'+
          '<button class="small" onclick="setCoachTier(\\''+c.id+'\\')">ثبت</button></div></td>'+
        '<td>'+(c.status==="banned"?
          '<button onclick="unbanCoach(\\''+c.id+'\\')">رفع مسدودی</button>':
          (c.status==="approved"?'<button class="danger" onclick="banCoach(\\''+c.id+'\\')">مسدود کن</button>':''))+'</td>'+
        '<td><input id="notice_'+c.id+'" placeholder="متن اعلان" style="width:110px;display:inline-block;font-size:11px;">'+
          '<button onclick="sendCoachNotice(\\''+c.id+'\\')" style="font-size:11px;">ارسال</button></td></tr>';
    });
    html+='</table>';
    document.getElementById("allCoaches").innerHTML=html;
  }catch(e){document.getElementById("allCoaches").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function setCoachTier(id){
  const tier=document.getElementById("tier_"+id).value;
  try{await api("/api/admin/coaches/"+id+"/rank",{method:"PUT",body:JSON.stringify({tier:tier||null})});alert("سطح مربی بروزرسانی شد ✅");loadAllCoaches();}catch(e){alert(e.message);}
}
async function banCoach(id){
  if(!confirm("این مربی مسدود بشه؟ دیگه توی مارکت‌پلیس دیده نمی‌شه."))return;
  try{await api("/api/admin/coaches/"+id+"/ban",{method:"PUT"});loadAllCoaches();loadCoachStats();}catch(e){alert(e.message);}
}
async function unbanCoach(id){
  try{await api("/api/admin/coaches/"+id+"/unban",{method:"PUT"});loadAllCoaches();loadCoachStats();}catch(e){alert(e.message);}
}
async function sendCoachNotice(id,isPending){
  const el=document.getElementById((isPending?"pendmsg_":"notice_")+id);
  const text=el.value.trim();
  if(!text)return;
  try{await api("/api/admin/coaches/"+id+"/notice",{method:"POST",body:JSON.stringify({text})});alert("پیام ارسال شد ✅");el.value="";}catch(e){alert(e.message);}
}
async function loadCoachReports(){
  try{
    const list=await api("/api/admin/coach-reports");
    let html="";
    if(!list.length) html="<div style='text-align:center;color:#9A9484;padding:12px;'>گزارش تخلفی ثبت نشده ✅</div>";
    const statusLabel={open:["badge warn","تازه"],reviewing:["badge warn","در حال بررسی"],approved:["badge on","تاییدشده - آماده‌ی تماس"],rejected:["badge off","رد شده"],resolved:["badge on","بسته‌شده"]};
    list.forEach(function(r){
      const sl=statusLabel[r.status]||["badge","-"];
      html+="<div class='report-card'>"+
        "<div><b>"+esc(r.coachName)+"</b> — گزارش از "+esc(r.userName)+" <span class='"+sl[0]+"' style='margin-right:6px;'>"+sl[1]+"</span></div>"+
        "<div style='font-size:11px;color:#9A9484;margin-top:6px;'>"+esc(r.reason)+"</div>"+
        (r.phone?"<div style='font-size:11.5px;color:#F2CE7A;margin-top:6px;'>📞 شماره تماس: <b>"+esc(r.phone)+"</b> <a href='tel:"+esc(r.phone)+"' style='color:#3DDC74;'>(تماس)</a></div>":"")+
        (r.evidenceUrls&&r.evidenceUrls.length?"<div class='evidence-row'>"+r.evidenceUrls.map(function(u){return "<a href='"+u+"' target='_blank'><img class='thumb' src='"+u+"'></a>";}).join("")+"</div>":"")+
        (r.adminReply?"<div style='font-size:11px;color:#9A9484;margin-top:6px;background:rgba(255,255,255,.03);padding:6px;border-radius:6px;'>یادداشت قبلی: "+esc(r.adminReply)+"</div>":"")+
        "<textarea id='reply_"+r.id+"' placeholder='یادداشت داخلی (اختیاری)' style='margin-top:8px;font-size:11px;min-height:40px;'></textarea>"+
        "<div style='margin-top:4px;'>"+
        "<button class='small' onclick=setReportStatus(\\""+r.id+"\\",\\"reviewing\\")>🔍 در حال بررسی</button>"+
        "<button class='small' onclick=setReportStatus(\\""+r.id+"\\",\\"approved\\")>✅ تایید (آماده‌ی تماس)</button>"+
        "<button class='small danger' onclick=setReportStatus(\\""+r.id+"\\",\\"rejected\\")>❌ رد</button>"+
        "<button class='small outline' onclick=setReportStatus(\\""+r.id+"\\",\\"resolved\\")>📁 بستن پرونده</button>"+
        "</div>"+
      "</div>";
    });
    document.getElementById("coachReports").innerHTML=html;
  }catch(e){document.getElementById("coachReports").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
async function setReportStatus(id,status){
  const replyEl=document.getElementById("reply_"+id);
  const adminReply=replyEl?replyEl.value.trim():"";
  try{
    await api("/api/admin/coach-reports/"+id,{method:"PUT",body:JSON.stringify({status,adminReply})});
    loadCoachReports();
  }catch(e){alert(e.message);}
}
async function loadCoachPrograms(){
  try{
    window._allCoachPrograms=await api("/api/admin/coach-programs");
    renderCoachProgramsTable();
  }catch(e){document.getElementById("coachProgramsList").innerHTML="<div style='color:#FF5252;'>"+esc(e.message)+"</div>";}
}
function renderCoachProgramsTable(){
  const q=(document.getElementById("progSearch").value||"").trim().toLowerCase();
  let list=window._allCoachPrograms||[];
  if(q) list=list.filter(function(p){return (p.title||"").toLowerCase().includes(q)||(p.coachName||"").toLowerCase().includes(q);});
  if(!list.length){document.getElementById("coachProgramsList").innerHTML="<div style='text-align:center;color:#9A9484;padding:12px;'>برنامه‌ای پیدا نشد</div>";return;}
  let html="";
  list.forEach(function(p){
    const cat=(p.content&&p.content.category)||"other";
    const icon=cat==="workout"?"🏋️":cat==="nutrition"?"🥗":"📄";
    html+="<div class='report-card'>"+
      "<div class='row' style='display:flex;justify-content:space-between;align-items:flex-start;'>"+
      "<div>"+icon+" <b>"+esc(p.title)+"</b><div style='font-size:11px;color:#9A9484;margin-top:2px;'>مربی: "+esc(p.coachName)+" · فروش: "+(p.salesCount||0)+"</div></div>"+
      "<div style='font-weight:800;color:#F2CE7A;'>"+(p.priceToman||0).toLocaleString()+" ت</div>"+
      "</div>"+
      (p.description?"<div style='font-size:11px;color:#9A9484;margin-top:6px;'>"+esc(p.description).substring(0,150)+"</div>":"")+
      "<button class='small' onclick=viewProgramDetail('"+p.id+"')>👁️ مشاهده‌ی کامل</button>"+
      "<button class='small danger' onclick=deleteCoachProgram('"+p.id+"','"+esc(p.title).replace(/'/g,"")+"')>🗑️ حذف و اخطار به مربی</button>"+
    "</div>";
  });
  document.getElementById("coachProgramsList").innerHTML=html;
}
function viewProgramDetail(id){
  const p=(window._allCoachPrograms||[]).find(x=>x.id===id);
  if(!p)return;
  alert(JSON.stringify(p.content||{},null,2).substring(0,1500));
}
async function deleteCoachProgram(id,title){
  const warning=prompt("متن اخطاری که برای مربی ارسال بشه:","برنامه‌ی «"+title+"» به دلیل مغایرت با قوانین حذف شد.");
  if(warning===null)return;
  try{
    await api("/api/admin/coach-programs/"+id,{method:"DELETE",body:JSON.stringify({warning})});
    alert("حذف شد و اخطار ارسال شد ✅");
    loadCoachPrograms();
  }catch(e){alert(e.message);}
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
      const required = ["specialty", "city", "bio", "gymName"];
      for (const f of required) {
        if (!body[f] || !String(body[f]).trim()) throw httpError(400, "فیلد " + f + " الزامی است");
      }
      const CERT_ALLOWED = ["image/png", "image/jpeg", "image/webp"];
      const MAX_CERT_BYTES = 5 * 1024 * 1024;
      const certificateUrls = [];
      const files = req.files || {};
      for (let i = 0; i < 6; i++) {
        const file = files["certificate" + i];
        if (!file) continue;
        if (!CERT_ALLOWED.includes(file.mimeType)) throw httpError(400, "فرمت مدرک باید png، jpg یا webp باشد");
        if (file.size > MAX_CERT_BYTES) throw httpError(400, "حجم هر مدرک نباید بیشتر از ۵ مگابایت باشد");
        const ext = file.mimeType.split("/")[1] || "jpg";
        const filename = `cert_${crypto.randomBytes(8).toString("hex")}.${ext}`;
        fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
        certificateUrls.push(`/uploads/${filename}`);
      }
      if (!certificateUrls.length) throw httpError(400, "حداقل یک تصویر از مدارک یا گواهینامه‌هات رو بارگذاری کن");

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
        gymName: String(body.gymName).slice(0, 200),
        socialInstagram: body.socialInstagram ? String(body.socialInstagram).slice(0, 200) : "",
        certificateUrls,
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
coachRoutes.post("/rate", CoachController.rateCoach);

// === Admin Coach Routes ===
const AdminCoachController = {
  listPending: (req, res, next) => {
    try { requireAdminUser(req.userId, "coaches"); res.json(CoachRepo.findPending()); } catch (e) { next(e); }
  },
  listAll: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const all = CoachRepo.all();
      const enriched = all.map((c) => {
        const wallet = CoachWalletRepo.getOrCreate(c.id);
        const ranking = computeCoachRanking(c.id);
        const students = CoachStudentRepo.findByCoach(c.id).filter((s) => s.status === "active").length;
        const programs = CoachProgramRepo.findByCoach(c.id);
        const totalSales = programs.reduce((s, p) => s + (p.salesCount || 0), 0);
        const u = UserRepo.findById(c.userId);
        return Object.assign({}, c, {
          wallet: { balance: wallet.balance, totalEarnings: wallet.totalEarnings, totalCommission: wallet.totalCommission },
          ranking, students, totalSales, username: u ? u.username : null,
        });
      });
      res.json(enriched);
    } catch (e) { next(e); }
  },
  approve: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const coach = CoachRepo.update(req.params.id, { status: "approved", verified: true });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      SecurityLog.log({ userId: req.userId, type: "coach_approved", meta: { coachId: req.params.id } });
      res.json(coach);
    } catch (e) { next(e); }
  },
  reject: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const coach = CoachRepo.update(req.params.id, { status: "rejected" });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      SecurityLog.log({ userId: req.userId, type: "coach_rejected", meta: { coachId: req.params.id } });
      res.json(coach);
    } catch (e) { next(e); }
  },
  setVerified: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const coach = CoachRepo.update(req.params.id, { verified: !!req.body.verified });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      res.json(coach);
    } catch (e) { next(e); }
  },
  setSubscription: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const { subscription } = req.body;
      const coach = CoachRepo.update(req.params.id, { subscription });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      res.json(coach);
    } catch (e) { next(e); }
  },
  stats: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const all = CoachRepo.all();
      res.json({
        totalCoaches: all.length,
        approved: all.filter((c) => c.status === "approved").length,
        pending: all.filter((c) => c.status === "pending").length,
        verified: all.filter((c) => c.verified).length,
        activeSubscriptions: all.filter((c) => c.subscription !== "none").length,
        banned: all.filter((c) => c.status === "banned").length,
      });
    } catch (e) { next(e); }
  },
  ban: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const coach = CoachRepo.update(req.params.id, { status: "banned" });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      SecurityLog.log({ userId: req.userId, type: "coach_banned", meta: { coachId: req.params.id } });
      res.json(coach);
    } catch (e) { next(e); }
  },
  unban: (req, res, next) => {
    try {
      requireAdminUser(req.userId, "coaches");
      const coach = CoachRepo.update(req.params.id, { status: "approved" });
      if (!coach) throw httpError(404, "مربی پیدا نشد");
      res.json(coach);
    } catch (e) { next(e); }
  },
};

// === تنظیم درصد کمیسیون توسط ادمین ===
adminRoutes.get("/coach-settings", (req, res, next) => {
  try { requireAdminUser(req.userId, "coaches"); res.json({ commissionRate: getCoachCommissionRate() }); } catch (e) { next(e); }
});
adminRoutes.put("/coach-settings", (req, res, next) => {
  try { requireAdminUser(req.userId, "coaches"); res.json({ commissionRate: setCoachCommissionRate(req.body.commissionRate) }); } catch (e) { next(e); }
});
adminRoutes.put("/coaches/:id/ban", AdminCoachController.ban);
adminRoutes.put("/coaches/:id/unban", AdminCoachController.unban);
adminRoutes.put("/coaches/:id/rank", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const { tier } = req.body;
    const allowed = [null, "", "bronze", "silver", "gold", "platinum", "elite"];
    if (!allowed.includes(tier)) throw httpError(400, "سطح نامعتبر است");
    const coach = CoachRepo.update(req.params.id, { rankOverride: tier || null });
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    res.json(Object.assign({}, coach, { ranking: computeCoachRanking(coach.id) }));
  } catch (e) { next(e); }
});

// === گزارش تخلف مربیان ===
const _coachReports = collection("coach_reports");
/* ================= گزارش تخلف عمومی (کاربر / محتوا / نظر) ================= */
const _reports = collection("reports");
const REPORT_TARGET_TYPES = ["user", "content", "review"];
usersRoutes.post("/reports", (req, res, next) => {
  try {
    const { targetType, targetId, reason } = req.body;
    if (!REPORT_TARGET_TYPES.includes(targetType)) throw httpError(400, "نوع گزارش نامعتبر است");
    if (!isNonEmptyString(targetId)) throw httpError(400, "شناسه هدف گزارش الزامی است");
    if (!isNonEmptyString(reason)) throw httpError(400, "دلیل گزارش رو بنویس");
    const row = _reports.insert({ reporterId: req.userId, targetType, targetId, reason: String(reason).slice(0, 1000), status: "pending", adminNote: null });
    res.status(201).json(row);
  } catch (e) { next(e); }
});
adminRoutes.get("/reports", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const { status, targetType } = req.query || {};
    let list = _reports.all();
    if (status) list = list.filter((r) => r.status === status);
    if (targetType) list = list.filter((r) => r.targetType === targetType);
    const enriched = list.map((r) => {
      const reporter = UserRepo.findById(r.reporterId);
      let targetLabel = r.targetId;
      if (r.targetType === "user") { const u = UserRepo.findById(r.targetId); targetLabel = u ? (u.name + (u.username ? " (@" + u.username + ")" : "")) : "کاربر حذف‌شده"; }
      else if (r.targetType === "content") { const c = ContentRepo.findById(r.targetId); targetLabel = c ? c.title : "محتوای حذف‌شده"; }
      else if (r.targetType === "review") { const rv = _productReviews.findById(r.targetId); targetLabel = rv ? ("نظر: " + rv.comment.slice(0, 60)) : "نظر حذف‌شده"; }
      return Object.assign({}, r, { reporterName: reporter ? reporter.name : "-", targetLabel });
    });
    res.json(enriched.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.put("/reports/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const { status, adminNote } = req.body;
    const patch = {};
    if (status !== undefined) {
      if (!["pending", "reviewing", "action_taken", "dismissed"].includes(status)) throw httpError(400, "وضعیت نامعتبر است");
      patch.status = status;
    }
    if (adminNote !== undefined) patch.adminNote = String(adminNote).slice(0, 1000);
    const row = _reports.update(req.params.id, patch);
    if (!row) throw httpError(404, "پیدا نشد");
    res.json(row);
  } catch (e) { next(e); }
});
adminRoutes.put("/reports/:id/take-action", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const r = _reports.findById(req.params.id);
    if (!r) throw httpError(404, "پیدا نشد");
    if (r.targetType === "user") UserRepo.update(r.targetId, { blocked: true });
    else if (r.targetType === "content") ContentRepo.update(r.targetId, { published: false });
    else if (r.targetType === "review") _productReviews.remove(r.targetId);
    const updated = _reports.update(r.id, { status: "action_taken" });
    SecurityLog.log({ userId: req.userId, type: "report_action_taken", meta: { reportId: r.id, targetType: r.targetType, targetId: r.targetId } });
    res.json(updated);
  } catch (e) { next(e); }
});

/* ================= فروشگاه تجهیزات فیزیکی (مکمل، دمبل، لباس، تجهیزات باشگاهی) ================= */
const _equipProducts = collection("equipment_products");
const _equipOrders = collection("equipment_orders");
const EQUIP_CATEGORIES = { supplement: "مکمل", dumbbell: "دمبل و وزنه", band: "کش ورزشی", apparel: "پوشاک ورزشی", gym_equipment: "تجهیزات باشگاهی", accessory: "لوازم جانبی" };
const EquipProductRepo = {
  create: (data) => _equipProducts.insert(data),
  findById: (id) => _equipProducts.findById(id),
  update: (id, patch) => _equipProducts.update(id, patch),
  delete: (id) => _equipProducts.remove(id),
  all: () => _equipProducts.all(),
  findPublished: () => _equipProducts.findMany((p) => p.published),
};
const EquipOrderRepo = {
  create: (data) => _equipOrders.insert(data),
  findById: (id) => _equipOrders.findById(id),
  update: (id, patch) => _equipOrders.update(id, patch),
  findByUser: (userId) => _equipOrders.findMany((o) => o.userId === userId),
  all: () => _equipOrders.all(),
};
function equipFinalPrice(p) { return p.discountPercent ? Math.round(p.priceToman * (1 - p.discountPercent / 100)) : p.priceToman; }

// --- مرور فروشگاه (کاربر) ---
usersRoutes.get("/equipment", (req, res) => {
  const list = EquipProductRepo.findPublished().map((p) => Object.assign({}, p, { finalPriceToman: equipFinalPrice(p), inStock: p.stock > 0 }));
  res.json(list);
});
usersRoutes.post("/equipment/order", (req, res, next) => {
  try {
    const { items, shipping } = req.body;
    if (!Array.isArray(items) || !items.length) throw httpError(400, "سبد خرید خالیه");
    if (!shipping || !isNonEmptyString(shipping.fullName) || !isNonEmptyString(shipping.phone) || !isNonEmptyString(shipping.address) || !isNonEmptyString(shipping.city) || !isNonEmptyString(shipping.postalCode)) {
      throw httpError(400, "اطلاعات ارسال (نام، موبایل، آدرس، شهر، کد پستی) رو کامل پر کن");
    }
    const orderItems = [];
    let total = 0;
    for (const it of items) {
      const p = EquipProductRepo.findById(it.productId);
      if (!p || !p.published) throw httpError(404, "یکی از محصولات دیگه موجود نیست");
      const qty = Math.max(1, Math.min(20, Number(it.qty) || 1));
      if (p.stock < qty) throw httpError(400, "موجودی «" + p.title + "» کافی نیست (باقیمانده: " + p.stock + ")");
      const price = equipFinalPrice(p);
      orderItems.push({ productId: p.id, title: p.title, price, qty, subtotal: price * qty });
      total += price * qty;
    }
    // رزرو موجودی
    orderItems.forEach((it) => { const p = EquipProductRepo.findById(it.productId); EquipProductRepo.update(p.id, { stock: p.stock - it.qty }); });
    const order = EquipOrderRepo.create({
      userId: req.userId, items: orderItems, totalToman: total,
      shipping: { fullName: shipping.fullName.trim(), phone: shipping.phone.trim(), province: (shipping.province || "").trim(), city: shipping.city.trim(), address: shipping.address.trim(), postalCode: shipping.postalCode.trim() },
      status: "pending_payment", trackingCode: null, paymentId: null,
    });
    SecurityLog.log({ userId: req.userId, type: "equipment_order_created", meta: { orderId: order.id, total } });
    res.status(201).json(order);
  } catch (e) { next(e); }
});
usersRoutes.get("/equipment/my-orders", (req, res, next) => {
  try { res.json(EquipOrderRepo.findByUser(req.userId).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))); } catch (e) { next(e); }
});
usersRoutes.post("/equipment/orders/:id/submit-payment", (req, res, next) => {
  try {
    const order = EquipOrderRepo.findById(req.params.id);
    if (!order || order.userId !== req.userId) throw httpError(404, "سفارش پیدا نشد");
    if (order.status !== "pending_payment") throw httpError(400, "این سفارش قبلاً پرداخت شده یا لغو شده");
    const { txHash, method } = req.body;
    if (!isNonEmptyString(txHash)) throw httpError(400, "کد پیگیری تراکنش رو وارد کن");
    const payment = _payments.insert({
      userId: req.userId, planId: null, provider: method === "usdt" ? "usdt_wallet" : "manual_admin",
      providerRef: txHash, amountToman: order.totalToman, amountUsdt: null, status: "pending",
      meta: { type: "equipment_order", orderId: order.id },
    });
    EquipOrderRepo.update(order.id, { paymentId: payment.id });
    res.json({ ok: true, paymentId: payment.id });
  } catch (e) { next(e); }
});

// --- مدیریت ادمین ---
adminRoutes.get("/equipment/products", (req, res, next) => {
  try { requireAdminUser(req.userId, "payments"); res.json(EquipProductRepo.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))); } catch (e) { next(e); }
});
adminRoutes.post("/equipment/products", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const { title, description, category, priceToman, discountPercent, stock, sku } = req.body;
    if (!isNonEmptyString(title)) throw httpError(400, "عنوان الزامیه");
    if (!EQUIP_CATEGORIES[category]) throw httpError(400, "دسته‌بندی نامعتبره");
    const files = req.files || {};
    let coverImageUrl = null, images = [];
    if (files.cover) coverImageUrl = saveTicketFile(files.cover).url;
    Object.keys(files).forEach((k) => { if (/^gallery\d*$/.test(k)) images.push(saveTicketFile(files[k]).url); });
    const product = EquipProductRepo.create({
      title: String(title).slice(0, 200), description: String(description || "").slice(0, 2000), category,
      priceToman: Number(priceToman) || 0, discountPercent: Math.max(0, Math.min(90, Number(discountPercent) || 0)),
      stock: Math.max(0, Number(stock) || 0), sku: (sku || "").trim() || null,
      coverImageUrl, images: images.slice(0, 6), published: true,
    });
    res.status(201).json(product);
  } catch (e) { next(e); }
});
adminRoutes.put("/equipment/products/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const p = EquipProductRepo.findById(req.params.id);
    if (!p) throw httpError(404, "محصول پیدا نشد");
    const patch = {};
    ["title", "description", "priceToman", "discountPercent", "stock", "published", "sku"].forEach((k) => { if (req.body[k] !== undefined) patch[k] = req.body[k]; });
    if (req.body.category !== undefined) { if (!EQUIP_CATEGORIES[req.body.category]) throw httpError(400, "دسته‌بندی نامعتبره"); patch.category = req.body.category; }
    const files = req.files || {};
    if (files.cover) patch.coverImageUrl = saveTicketFile(files.cover).url;
    res.json(EquipProductRepo.update(p.id, patch));
  } catch (e) { next(e); }
});
adminRoutes.delete("/equipment/products/:id", (req, res, next) => {
  try { requireAdminUser(req.userId, "payments"); EquipProductRepo.delete(req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});
adminRoutes.get("/equipment/orders", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const { status } = req.query || {};
    let list = EquipOrderRepo.all();
    if (status) list = list.filter((o) => o.status === status);
    const enriched = list.map((o) => { const u = UserRepo.findById(o.userId); return Object.assign({}, o, { userName: u ? u.name : "-", userPhone: u ? u.phone : null }); });
    res.json(enriched.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.put("/equipment/orders/:id/status", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "payments");
    const order = EquipOrderRepo.findById(req.params.id);
    if (!order) throw httpError(404, "سفارش پیدا نشد");
    const { status, trackingCode } = req.body;
    if (!["paid", "processing", "shipped", "delivered", "cancelled"].includes(status)) throw httpError(400, "وضعیت نامعتبره");
    const patch = { status };
    if (trackingCode !== undefined) patch.trackingCode = trackingCode;
    if (status === "cancelled" && order.status !== "cancelled") {
      order.items.forEach((it) => { const p = EquipProductRepo.findById(it.productId); if (p) EquipProductRepo.update(p.id, { stock: p.stock + it.qty }); });
    }
    const updated = EquipOrderRepo.update(order.id, patch);
    const statusLabel = { paid: "پرداخت تایید شد", processing: "در حال آماده‌سازی", shipped: "ارسال شد", delivered: "تحویل داده شد", cancelled: "لغو شد" }[status];
    notifyCoachUser(order.userId, "📦 وضعیت سفارشت تغییر کرد", "سفارش شما: " + statusLabel + (trackingCode ? (" — کد رهگیری: " + trackingCode) : ""));
    SecurityLog.log({ userId: req.userId, type: "equipment_order_status_changed", meta: { orderId: order.id, status } });
    res.json(updated);
  } catch (e) { next(e); }
});
const CoachReportRepo = {
  create: (data) => _coachReports.insert(data),
  all: () => _coachReports.all(),
  findById: (id) => _coachReports.findById(id),
  update: (id, patch) => _coachReports.update(id, patch),
};
coachRoutes.post("/report", (req, res, next) => {
  try {
    const { coachId, reason, phone } = req.body;
    const coach = CoachRepo.findById(coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    if (!isNonEmptyString(reason)) throw httpError(400, "دلیل گزارش رو بنویس");
    if (!isNonEmptyString(phone)) throw httpError(400, "شماره تماس برای هماهنگی رو وارد کن");

    const EV_ALLOWED = ["image/png", "image/jpeg", "image/webp"];
    const MAX_EV_BYTES = 5 * 1024 * 1024;
    const evidenceUrls = [];
    const files = req.files || {};
    for (let i = 0; i < 4; i++) {
      const file = files["evidence" + i];
      if (!file) continue;
      if (!EV_ALLOWED.includes(file.mimeType)) throw httpError(400, "فرمت مدرک باید png، jpg یا webp باشد");
      if (file.size > MAX_EV_BYTES) throw httpError(400, "حجم هر مدرک نباید بیشتر از ۵ مگابایت باشد");
      const ext = file.mimeType.split("/")[1] || "jpg";
      const filename = `report_${crypto.randomBytes(8).toString("hex")}.${ext}`;
      fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
      evidenceUrls.push(`/uploads/${filename}`);
    }
    if (!evidenceUrls.length) throw httpError(400, "حداقل یک تصویر مدرک بارگذاری کن");

    const row = CoachReportRepo.create({
      coachId, userId: req.userId, reason: String(reason).slice(0, 1000),
      phone: String(phone).slice(0, 20), evidenceUrls, status: "open", adminReply: "",
    });
    res.status(201).json(row);
  } catch (e) { next(e); }
});
coachRoutes.get("/my-reports", (req, res, next) => {
  try {
    const list = _coachReports.findMany((r) => r.userId === req.userId).map((r) => {
      const c = CoachRepo.findById(r.coachId);
      return Object.assign({}, r, { coachName: c ? c.name : "-" });
    });
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.get("/coach-reports", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const list = CoachReportRepo.all().map((r) => {
      const c = CoachRepo.findById(r.coachId);
      const u = UserRepo.findById(r.userId);
      return Object.assign({}, r, { coachName: c ? c.name : "-", userName: u ? u.name : "-" });
    });
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-reports/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const { status, adminReply } = req.body;
    const patch = {};
    if (status !== undefined) {
      if (!["open", "reviewing", "approved", "rejected", "resolved"].includes(status)) throw httpError(400, "وضعیت نامعتبر است");
      patch.status = status;
    }
    if (adminReply !== undefined) patch.adminReply = String(adminReply).slice(0, 1000);
    const row = CoachReportRepo.update(req.params.id, patch);
    if (!row) throw httpError(404, "پیدا نشد");
    res.json(row);
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-reports/:id/resolve", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const row = CoachReportRepo.update(req.params.id, { status: "resolved" });
    if (!row) throw httpError(404, "پیدا نشد");
    res.json(row);
  } catch (e) { next(e); }
});

// === اعلان اختصاصی برای مربی ===
const _coachNotices = collection("coach_notices");
const CoachNoticeRepo = {
  create: (data) => _coachNotices.insert(data),
  findByCoach: (coachId) => _coachNotices.findMany((n) => n.coachId === coachId),
};
adminRoutes.post("/coaches/:id/notice", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const coach = CoachRepo.findById(req.params.id);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    if (!isNonEmptyString(req.body.text)) throw httpError(400, "متن اعلان رو بنویس");
    const notice = CoachNoticeRepo.create({ coachId: coach.id, text: String(req.body.text).slice(0, 500) });
    res.status(201).json(notice);
  } catch (e) { next(e); }
});

// === ساخت اکانت‌های تست برای QA (فقط ادمین) ===
adminRoutes.post("/seed-test-accounts", (req, res, next) => {
  try {
    requireAdminUser(req.userId);
    const password = "Test@1234";
    const accounts = [
      { email: "student1@test.com", name: "شاگرد تست ۱", makeCoach: false },
      { email: "student2@test.com", name: "شاگرد تست ۲", makeCoach: false },
      { email: "coach1@test.com", name: "مربی تست", makeCoach: true },
    ];
    const results = [];
    accounts.forEach((acc) => {
      let user = UserRepo.findByEmail(acc.email);
      if (!user) {
        user = UserRepo.create({
          name: acc.name, email: acc.email, phone: null,
          passwordHash: hashPassword(password), role: "user", emailVerified: true, phoneVerified: false, avatarUrl: null,
          profile: { age: null, height: null, weight: null, gender: null, trainingGoal: null, trainingLevel: null, trainingHistory: null },
          vip: { active: false, plan: null, expiresAt: null },
        });
      } else {
        user = UserRepo.update(user.id, { passwordHash: hashPassword(password), emailVerified: true });
      }
      if (acc.makeCoach && !CoachRepo.findByUserId(user.id)) {
        CoachRepo.create({
          userId: user.id, name: acc.name, specialty: "بدنسازی و پرورش اندام", city: "تهران", country: "ایران",
          bio: "این یک اکانت تستی برای بررسی امکانات مربیگریه.", experience: 5, languages: ["فارسی"],
          pricePerSession: 200000, onlineSessions: true, avatarUrl: null,
          gymName: "باشگاه تست آیرون", socialInstagram: "", certificateUrls: [],
          status: "approved", verified: true, subscription: "professional", studentIds: [], totalSales: 0,
        });
      }
      results.push({ email: acc.email, password, role: acc.makeCoach ? "coach" : "user" });
    });
    res.json(results);
  } catch (e) { next(e); }
});
// === مرحله ۵: تولید برنامه با هوش مصنوعی برای مربی ===
coachRoutes.post("/ai/generate-program", async (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    if (coach.status !== "approved") throw httpError(400, "فقط مربیان تاییدشده به این قابلیت دسترسی دارن");
    const settings = getAiSettings();
    if (!settings.enabled) throw httpError(503, "هوش مصنوعی فعلاً توسط مدیر غیرفعال شده");
    if (!env.GEMINI_API_KEY) throw httpError(503, "هنوز کلید هوش مصنوعی تنظیم نشده");
    const { category, prompt } = req.body;
    if (!["workout", "nutrition"].includes(category)) throw httpError(400, "نوع نامعتبر است");
    if (!isNonEmptyString(prompt)) throw httpError(400, "توضیح بده چه برنامه‌ای می‌خوای بسازی");

    const schema = category === "workout"
      ? `{"days":[{"title":"عنوان روز به فارسی","exercises":[{"name":"نام حرکت","sets":"تعداد ست مثلا 4","reps":"تعداد تکرار یا زمان مثلا 12 یا 30 ثانیه","rest":"ثانیه استراحت مثلا 60","note":"نکته‌ی تکنیکی کوتاه (اختیاری)"}]}]}`
      : `{"meals":[{"title":"عنوان وعده به فارسی مثلا صبحانه","items":[{"name":"نام ماده‌ی غذایی","amount":"مقدار مثلا 150 گرم","note":"توضیح کوتاه (اختیاری)"}]}]}`;
    const systemPrompt = "تو یک دستیار متخصص طراحی برنامه‌ی " + (category === "workout" ? "تمرینی بدنسازی" : "تغذیه‌ی ورزشی") +
      " برای اپلیکیشن فارسی «پروتکل آیرون» هستی. بر اساس درخواست مربی، یک برنامه‌ی کامل، دقیق و عملی طراحی کن. " +
      "خروجی رو فقط و فقط به‌صورت یک JSON معتبر با این ساختار دقیق برگردون، بدون هیچ متن اضافه، بدون Markdown، بدون ```:\n" + schema +
      "\nهمه‌ی متن‌ها باید فارسی باشن. حداقل ۲ و حداکثر ۷ آیتم در هر بخش.";

    const result = await callGemini(env.GEMINI_API_KEY, settings.model, systemPrompt, [], prompt.slice(0, 500));
    let cleaned = result.text.trim().replace(/^```json\s*/i, "").replace(/^```\s*/, "").replace(/```\s*$/, "");
    let parsed;
    try { parsed = JSON.parse(cleaned); } catch (e) { throw httpError(502, "هوش مصنوعی خروجی قابل‌فهمی نداد؛ دوباره امتحان کن"); }
    if (category === "workout" && !Array.isArray(parsed.days)) throw httpError(502, "ساختار خروجی نامعتبر بود");
    if (category === "nutrition" && !Array.isArray(parsed.meals)) throw httpError(502, "ساختار خروجی نامعتبر بود");
    res.json(parsed);
  } catch (e) { next(e); }
});

coachRoutes.get("/notices", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(CoachNoticeRepo.findByCoach(coach.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});

// افزودن مدرک بیشتر به درخواست در انتظار بررسی (مثلاً بعد از درخواست ادمین برای مدارک بیشتر)
coachRoutes.post("/certificates", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    if (coach.status !== "pending" && coach.status !== "rejected") throw httpError(400, "فقط برای درخواست‌های در انتظار یا ردشده می‌تونی مدرک اضافه کنی");
    const CERT_ALLOWED = ["image/png", "image/jpeg", "image/webp"];
    const MAX_CERT_BYTES = 5 * 1024 * 1024;
    const existing = coach.certificateUrls || [];
    const newUrls = [];
    const files = req.files || {};
    for (let i = 0; i < 6; i++) {
      const file = files["certificate" + i];
      if (!file) continue;
      if (existing.length + newUrls.length >= 10) break;
      if (!CERT_ALLOWED.includes(file.mimeType)) throw httpError(400, "فرمت مدرک باید png، jpg یا webp باشد");
      if (file.size > MAX_CERT_BYTES) throw httpError(400, "حجم هر مدرک نباید بیشتر از ۵ مگابایت باشد");
      const ext = file.mimeType.split("/")[1] || "jpg";
      const filename = `cert_${crypto.randomBytes(8).toString("hex")}.${ext}`;
      fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
      newUrls.push(`/uploads/${filename}`);
    }
    if (!newUrls.length) throw httpError(400, "هیچ تصویری دریافت نشد");
    const updated = CoachRepo.update(coach.id, { certificateUrls: existing.concat(newUrls), status: "pending" });
    res.json(updated);
  } catch (e) { next(e); }
});

adminRoutes.get("/coaches/pending", AdminCoachController.listPending);
adminRoutes.get("/coaches/all", AdminCoachController.listAll);
adminRoutes.put("/coaches/:id/approve", AdminCoachController.approve);
adminRoutes.put("/coaches/:id/reject", AdminCoachController.reject);
adminRoutes.put("/coaches/:id/verify", AdminCoachController.setVerified);
adminRoutes.put("/coaches/:id/subscription", AdminCoachController.setSubscription);
adminRoutes.get("/coaches/stats", AdminCoachController.stats);


const app = new Router();
app.get("/health", (req, res) => res.json({ ok: true, env: env.NODE_ENV, time: new Date().toISOString(), storage: _mongoReady ? "mongodb" : "local-file (ephemeral on Render!)" }));
app.get("/admin", (req, res) => { res.setHeader("Content-Type", "text/html; charset=utf-8"); res.end(ADMIN_PAGE_HTML); });
app.mount("/api/auth", authRoutes);
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
const DEFAULT_COACH_PLANS = [
  { id: "starter", name: "Starter Coach", durationDays: 30, priceToman: 150000, priceUsdt: 5, maxStudents: 20, features: ["ثبت پروفایل", "حداکثر ۲۰ شاگرد", "ساخت برنامه", "چت با شاگردان"] },
  { id: "professional", name: "Professional Coach", durationDays: 90, priceToman: 350000, priceUsdt: 12, maxStudents: null, features: ["شاگرد نامحدود", "فروش برنامه", "فروش رژیم", "دریافت رزرو", "گزارشات کامل", "آنالیز درآمد", "اولویت نمایش"] },
  { id: "elite", name: "Elite Coach", durationDays: 365, priceToman: 1200000, priceUsdt: 40, maxStudents: null, features: ["تمام امکانات Professional", "تیک آبی تایید شده", "تبلیغ رایگان", "نشان مربی برتر", "پشتیبانی اختصاصی", "ابزارهای AI"] },
];
function getCoachPlans() {
  const rec = _aiSettings.findOne((s) => s.key === "coach_plans");
  return rec && Array.isArray(rec.value) && rec.value.length ? rec.value : DEFAULT_COACH_PLANS;
}
function setCoachPlans(plans) {
  if (!Array.isArray(plans) || !plans.length) throw httpError(400, "لیست پلن‌ها نامعتبر است");
  const clean = plans.map((p) => ({
    id: String(p.id || "").trim() || crypto.randomBytes(4).toString("hex"),
    name: String(p.name || "").slice(0, 100),
    durationDays: Number(p.durationDays) || 30,
    priceToman: Number(p.priceToman) || 0,
    priceUsdt: Number(p.priceUsdt) || 0,
    maxStudents: p.maxStudents === null || p.maxStudents === "" || p.maxStudents === undefined ? null : Number(p.maxStudents),
    features: Array.isArray(p.features) ? p.features.map((f) => String(f).slice(0, 100)) : String(p.features || "").split(",").map((f) => f.trim()).filter(Boolean),
  }));
  const rec = _aiSettings.findOne((s) => s.key === "coach_plans");
  if (rec) _aiSettings.update(rec.id, { value: clean });
  else _aiSettings.insert({ key: "coach_plans", value: clean });
  return clean;
}
adminRoutes.get("/coach-plans", (req, res, next) => { try { requireAdminUser(req.userId, "coaches"); res.json(getCoachPlans()); } catch (e) { next(e); } });
adminRoutes.put("/coach-plans", (req, res, next) => { try { requireAdminUser(req.userId, "coaches"); res.json(setCoachPlans(req.body.plans)); } catch (e) { next(e); } });

coachRoutes.get("/plans", (req, res) => res.json(getCoachPlans()));

coachRoutes.post("/subscribe", async (req, res, next) => {
  try {
    const { planId, txHash, discountCode } = req.body;
    const plan = getCoachPlans().find((p) => p.id === planId);
    if (!plan) throw httpError(400, "پلن نامعتبر است");
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "ابتدا باید مربی شوید");
    if (!isNonEmptyString(txHash)) throw httpError(400, "شناسه‌ی تراکنش (Tx Hash) رو وارد کن");

    let amountToman = plan.priceToman;
    let discRec = null;
    if (discountCode) {
      const r = DiscountService.validateAndCompute(discountCode, plan.priceToman);
      discRec = r.discountCode; amountToman = r.finalAmount;
    }

    // ثبت پرداخت (در انتظار تایید)
    const payment = PaymentRepo.create({
      userId: req.userId,
      amountToman, amountUsdt: plan.priceUsdt,
      provider: "coach_subscription",
      status: "pending",
      providerRef: txHash.trim(),
      discountCode: discountCode || null,
      meta: { type: "coach_subscription", planId, coachId: coach.id },
    });
    if (discRec) DiscountService.markUsed(discRec);

    res.status(201).json({ paymentId: payment.id, plan, amountToman, walletAddress: env.USDT_WALLET_ADDRESS || "", network: env.USDT_WALLET_NETWORK || "TRC20" });
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
    else if (type === "withdrawal_refund") { w.balance += Number(amount); }
    _coachWallet.update(w.id, { balance: w.balance, totalEarnings: w.totalEarnings, totalCommission: w.totalCommission, transactions: w.transactions });
    return w;
  },
};

/* ================= درخواست‌های برداشت وجه مربیان (مهم‌ترین بخش مالی) ================= */
const MIN_WITHDRAWAL_TOMAN = 500000;
const _coachWithdrawals = collection("coach_withdrawals");
const WithdrawalRepo = {
  create: (data) => _coachWithdrawals.insert(data),
  findById: (id) => _coachWithdrawals.findById(id),
  findByCoach: (coachId) => _coachWithdrawals.findMany((w) => w.coachId === coachId),
  hasPending: (coachId) => !!_coachWithdrawals.findOne((w) => w.coachId === coachId && w.status === "pending"),
  all: () => _coachWithdrawals.all(),
  update: (id, patch) => _coachWithdrawals.update(id, patch),
};
function notifyCoachUser(coachUserId, title, message) {
  NotificationRepo.create({ title, message, scope: "user", targetUserId: coachUserId, scheduledAt: null, readBy: [], createdBy: "system" });
}

// === نظارت کامل ادمین بر کیف‌پول مربیان ===
adminRoutes.get("/coach-wallets", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const coaches = CoachRepo.all();
    const list = coaches.map((c) => {
      const w = CoachWalletRepo.getOrCreate(c.id);
      const txs = w.transactions || [];
      const pendingWithdrawals = WithdrawalRepo.findByCoach(c.id).filter((x) => x.status === "pending").length;
      return {
        coachId: c.id, coachName: c.name, coachStatus: c.status,
        balance: w.balance, totalEarnings: w.totalEarnings, totalCommission: w.totalCommission,
        txCount: txs.length, lastTxDate: txs.length ? txs[txs.length - 1].date : null,
        pendingWithdrawals,
      };
    });
    res.json(list.sort((a, b) => b.balance - a.balance));
  } catch (e) { next(e); }
});
adminRoutes.get("/coach-wallets/:coachId", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const coach = CoachRepo.findById(req.params.coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    const w = CoachWalletRepo.getOrCreate(coach.id);
    const withdrawals = WithdrawalRepo.findByCoach(coach.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).map(decryptedWithdrawal);
    res.json({ coach: { id: coach.id, name: coach.name, status: coach.status }, wallet: w, withdrawals });
  } catch (e) { next(e); }
});
adminRoutes.post("/coach-wallets/:coachId/adjust", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const coach = CoachRepo.findById(req.params.coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    const { amount, direction, reason } = req.body;
    const amt = Number(amount);
    if (!amt || amt <= 0) throw httpError(400, "مبلغ نامعتبر است");
    if (!["credit", "debit"].includes(direction)) throw httpError(400, "نوع تراکنش نامعتبر است");
    if (!isNonEmptyString(reason)) throw httpError(400, "دلیل تعدیل رو بنویس");
    const w = CoachWalletRepo.getOrCreate(coach.id);
    if (direction === "debit" && w.balance < amt) throw httpError(400, "موجودی کافی نیست");
    const tx = { id: crypto.randomUUID(), type: direction === "credit" ? "adjustment_credit" : "adjustment_debit", amount: amt, desc: "تعدیل دستی ادمین: " + String(reason).slice(0, 200), date: new Date().toISOString() };
    w.transactions = (w.transactions || []).concat([tx]).slice(-100);
    w.balance += direction === "credit" ? amt : -amt;
    if (direction === "credit") w.totalEarnings += amt;
    _coachWallet.update(w.id, { balance: w.balance, totalEarnings: w.totalEarnings, transactions: w.transactions });
    SecurityLog.log({ userId: req.userId, type: "coach_wallet_adjusted", meta: { coachId: coach.id, amount: amt, direction, reason } });
    res.json(w);
  } catch (e) { next(e); }
});

// === درخواست‌های برداشت: لیست همه، تایید (واریز شد)، رد، اعلام اطلاعات نادرست ===
adminRoutes.get("/coach-wallets/withdrawals/list", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const { status } = req.query || {};
    let list = WithdrawalRepo.all();
    if (status) list = list.filter((w) => w.status === status);
    list = list.map((w) => {
      const coach = CoachRepo.findById(w.coachId);
      const u = coach ? UserRepo.findById(coach.userId) : null;
      return Object.assign({}, decryptedWithdrawal(w), { coachName: coach ? coach.name : "-", coachUsername: u ? u.username : null });
    });
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-wallets/withdrawals/:id/approve", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const wr = WithdrawalRepo.findById(req.params.id);
    if (!wr) throw httpError(404, "درخواست پیدا نشد");
    if (wr.status !== "pending") throw httpError(400, "این درخواست قبلاً بررسی شده");
    const { method, note } = req.body;
    const payMethod = method === "card" ? "کارت به کارت" : "شبا (انتقال بانکی)";
    const updated = WithdrawalRepo.update(wr.id, { status: "paid", paidMethod: method || "sheba", adminNote: note || null, processedAt: new Date().toISOString(), processedBy: req.userId });
    CoachWalletRepo.addTransaction(wr.coachId, "withdrawal", 0, "برداشت تایید و واریز شد (" + payMethod + ") — مبلغ قبلاً کسر شده بود");
    const coach = CoachRepo.findById(wr.coachId);
    if (coach) notifyCoachUser(coach.userId, "واریز برداشت شما انجام شد ✅", "مبلغ " + Number(wr.amount).toLocaleString("fa-IR") + " تومان از طریق " + payMethod + " به حسابت واریز شد." + (note ? (" توضیح: " + note) : ""));
    SecurityLog.log({ userId: req.userId, type: "coach_withdrawal_approved", meta: { withdrawalId: wr.id, coachId: wr.coachId, amount: wr.amount, method } });
    res.json(updated);
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-wallets/withdrawals/:id/reject", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const wr = WithdrawalRepo.findById(req.params.id);
    if (!wr) throw httpError(404, "درخواست پیدا نشد");
    if (wr.status !== "pending") throw httpError(400, "این درخواست قبلاً بررسی شده");
    const { reason } = req.body;
    if (!isNonEmptyString(reason)) throw httpError(400, "دلیل رد رو بنویس");
    const updated = WithdrawalRepo.update(wr.id, { status: "rejected", rejectReason: reason, processedAt: new Date().toISOString(), processedBy: req.userId });
    CoachWalletRepo.addTransaction(wr.coachId, "withdrawal_refund", wr.amount, "بازگشت مبلغ درخواست برداشت ردشده");
    const coach = CoachRepo.findById(wr.coachId);
    if (coach) notifyCoachUser(coach.userId, "درخواست برداشت شما رد شد ❌", "دلیل: " + reason + " — مبلغ به موجودی کیف‌پولت برگشت.");
    SecurityLog.log({ userId: req.userId, type: "coach_withdrawal_rejected", meta: { withdrawalId: wr.id, coachId: wr.coachId, reason } });
    res.json(updated);
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-wallets/withdrawals/:id/info-incorrect", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const wr = WithdrawalRepo.findById(req.params.id);
    if (!wr) throw httpError(404, "درخواست پیدا نشد");
    if (wr.status !== "pending") throw httpError(400, "این درخواست قبلاً بررسی شده");
    const { note } = req.body;
    const updated = WithdrawalRepo.update(wr.id, { status: "info_incorrect", adminNote: note || null, processedAt: new Date().toISOString(), processedBy: req.userId });
    CoachWalletRepo.addTransaction(wr.coachId, "withdrawal_refund", wr.amount, "بازگشت مبلغ — اطلاعات بانکی نادرست بود");
    const coach = CoachRepo.findById(wr.coachId);
    if (coach) notifyCoachUser(coach.userId, "اطلاعات بانکی نادرست بود ⚠️", "مشخصات بانکی‌ای که فرستادی درست نبود" + (note ? (": " + note) : "") + ". لطفاً دوباره با اطلاعات درست درخواست بده. مبلغ به موجودی کیف‌پولت برگشت.");
    SecurityLog.log({ userId: req.userId, type: "coach_withdrawal_info_incorrect", meta: { withdrawalId: wr.id, coachId: wr.coachId, note } });
    res.json(updated);
  } catch (e) { next(e); }
});

coachRoutes.get("/wallet", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(CoachWalletRepo.getOrCreate(coach.id));
  } catch (e) { next(e); }
});

coachRoutes.get("/wallet/withdrawals", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(WithdrawalRepo.findByCoach(coach.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).map(decryptedWithdrawal));
  } catch (e) { next(e); }
});

coachRoutes.post("/wallet/withdraw", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    if (WithdrawalRepo.hasPending(coach.id)) throw httpError(400, "یه درخواست برداشت دیگه در حال بررسیه؛ تا نتیجه‌ش مشخص بشه نمی‌تونی درخواست جدید بدی");
    const { amount, method, cardNumber, sheba, bankName, accountHolderName } = req.body;
    const amt = Number(amount);
    if (!amt || amt <= 0) throw httpError(400, "مبلغ نامعتبر است");
    if (amt < MIN_WITHDRAWAL_TOMAN) throw httpError(400, "حداقل مبلغ برداشت " + MIN_WITHDRAWAL_TOMAN.toLocaleString("fa-IR") + " تومانه");
    if (!["sheba", "card"].includes(method)) throw httpError(400, "روش برداشت رو مشخص کن (شبا یا کارت به کارت)");
    if (!isNonEmptyString(bankName)) throw httpError(400, "نام بانک الزامیه");
    if (!isNonEmptyString(accountHolderName)) throw httpError(400, "نام صاحب حساب الزامیه");
    if (method === "sheba" && !/^IR[0-9]{24}$/i.test(String(sheba || "").replace(/\s/g, ""))) throw httpError(400, "شماره شبا نامعتبره (باید با IR شروع بشه و ۲۴ رقم بعدش باشه)");
    if (method === "card" && !/^[0-9]{16}$/.test(String(cardNumber || "").replace(/[\s-]/g, ""))) throw httpError(400, "شماره کارت باید ۱۶ رقم باشه");
    const w = CoachWalletRepo.getOrCreate(coach.id);
    if (w.balance < amt) throw httpError(400, "موجودی کافی نیست (موجودی فعلی: " + w.balance.toLocaleString("fa-IR") + " تومان)");
    CoachWalletRepo.addTransaction(coach.id, "withdrawal", amt, "درخواست برداشت — در انتظار بررسی ادمین");
    const cleanCard = method === "card" ? String(cardNumber).replace(/[\s-]/g, "") : null;
    const cleanSheba = method === "sheba" ? String(sheba).replace(/\s/g, "").toUpperCase() : null;
    const wr = WithdrawalRepo.create({
      coachId: coach.id, amount: amt, method,
      bankInfo: {
        cardNumber: encryptSensitive(cleanCard),
        sheba: encryptSensitive(cleanSheba),
        bankName: bankName.trim(), accountHolderName: accountHolderName.trim(),
      },
      status: "pending", adminNote: null, rejectReason: null, paidMethod: null, processedAt: null, processedBy: null,
    });
    SecurityLog.log({ userId: req.userId, type: "coach_withdrawal_requested", meta: { withdrawalId: wr.id, coachId: coach.id, amount: amt, method } });
    res.status(201).json({ ok: true, withdrawal: Object.assign({}, wr, { bankInfo: { cardNumber: cleanCard, sheba: cleanSheba, bankName: wr.bankInfo.bankName, accountHolderName: wr.bankInfo.accountHolderName } }), balance: w.balance });
  } catch (e) { next(e); }
});

// === مرحله ۴: فروش برنامه توسط مربی ===
const _coachPrograms = collection("coach_programs");
const CoachProgramRepo = {
  create: (data) => _coachPrograms.insert(data),
  findByCoach: (coachId) => _coachPrograms.findMany((p) => p.coachId === coachId),
  findApproved: () => _coachPrograms.findMany((p) => p.status === "approved" && p.published !== false),
  findById: (id) => _coachPrograms.findById(id),
  update: (id, patch) => _coachPrograms.update(id, patch),
  all: () => _coachPrograms.all(),
  delete: (id) => _coachPrograms.remove(id),
};
const PRODUCT_TYPES = {
  workout_program: "برنامه تمرینی", nutrition_plan: "برنامه غذایی", course: "دوره آموزشی",
  pdf: "فایل PDF", video: "ویدئو", ebook: "کتاب الکترونیکی", package: "پکیج آموزشی",
  // مقادیر قدیمی — برای سازگاری با فرم برنامه‌ساز فعلی که هنوز این‌ها رو می‌فرسته
  "تمرینی": "برنامه تمرینی", "غذایی": "برنامه غذایی", "عمومی": "پکیج آموزشی",
};
const _productReviews = collection("product_reviews");
const ProductReviewRepo = {
  create: (data) => _productReviews.insert(data),
  findByProduct: (productId) => _productReviews.findMany((r) => r.productId === productId),
  findByUserAndProduct: (userId, productId) => _productReviews.findOne((r) => r.userId === userId && r.productId === productId),
};
const _productPurchases = collection("product_purchases");
const ProductPurchaseRepo = {
  create: (data) => _productPurchases.insert(data),
  hasPurchased: (userId, productId) => !!_productPurchases.findOne((p) => p.userId === userId && p.productId === productId),
  findByUser: (userId) => _productPurchases.findMany((p) => p.userId === userId),
};
function productWithStats(p) {
  const reviews = ProductReviewRepo.findByProduct(p.id);
  const avgRating = reviews.length ? +(reviews.reduce((s, r) => s + r.rating, 0) / reviews.length).toFixed(1) : 0;
  const finalPriceToman = p.discountPercent ? Math.round((p.priceToman || 0) * (1 - p.discountPercent / 100)) : (p.priceToman || 0);
  return Object.assign({}, p, { avgRating, reviewCount: reviews.length, finalPriceToman });
}

// === نظارت ادمین بر برنامه‌های منتشرشده‌ی مربیان ===
adminRoutes.get("/coach-programs", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const list = CoachProgramRepo.all().map((p) => {
      const c = CoachRepo.findById(p.coachId);
      return Object.assign({}, productWithStats(p), { coachName: c ? c.name : "-" });
    });
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.put("/coach-programs/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "محصول پیدا نشد");
    const patch = {};
    ["title", "description", "priceToman", "priceUsdt", "discountPercent", "published", "featured"].forEach((k) => { if (req.body[k] !== undefined) patch[k] = req.body[k]; });
    res.json(CoachProgramRepo.update(prog.id, patch));
  } catch (e) { next(e); }
});
adminRoutes.delete("/coach-programs/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "coaches");
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "برنامه پیدا نشد");
    CoachProgramRepo.delete(prog.id);
    const warnText = req.body && req.body.warning ? String(req.body.warning).slice(0, 500) : ("برنامه‌ی «" + prog.title + "» به دلیل مغایرت با قوانین حذف شد.");
    CoachNoticeRepo.create({ coachId: prog.coachId, text: "⚠️ اخطار: " + warnText });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

coachRoutes.post("/program", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const { title, description, type, priceToman, priceUsdt, content, discountPercent } = req.body;
    if (!title || !type) throw httpError(400, "عنوان و نوع الزامی است");
    if (!PRODUCT_TYPES[type]) throw httpError(400, "نوع محصول نامعتبر است");
    const files = req.files || {};
    let coverImageUrl = null, images = [], fileUrl = null;
    if (files.cover) coverImageUrl = saveTicketFile(files.cover).url;
    Object.keys(files).forEach((k) => { if (/^gallery\d*$/.test(k)) images.push(saveTicketFile(files[k]).url); });
    if (files.deliverable) fileUrl = saveTicketFile(files.deliverable).url;
    const disc = Math.max(0, Math.min(90, Number(discountPercent) || 0));
    const prog = CoachProgramRepo.create({
      coachId: coach.id, title: String(title).slice(0, 200),
      description: String(description || "").slice(0, 2000),
      type: String(type), priceToman: Number(priceToman) || 0,
      priceUsdt: Number(priceUsdt) || 0, content: content || null,
      coverImageUrl, images: images.slice(0, 6), fileUrl, discountPercent: disc,
      downloadCount: 0, published: true, publishedAt: new Date().toISOString(),
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

coachRoutes.put("/program/:id", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog || prog.coachId !== coach.id) throw httpError(404, "برنامه پیدا نشد");
    const { title, description, type, priceToman, priceUsdt, content, discountPercent, published } = req.body;
    const patch = {};
    if (title !== undefined) { if (!title) throw httpError(400, "عنوان الزامی است"); patch.title = String(title).slice(0, 200); }
    if (description !== undefined) patch.description = String(description || "").slice(0, 2000);
    if (type !== undefined) { if (!PRODUCT_TYPES[type]) throw httpError(400, "نوع محصول نامعتبر است"); patch.type = String(type); }
    if (priceToman !== undefined) patch.priceToman = Number(priceToman) || 0;
    if (priceUsdt !== undefined) patch.priceUsdt = Number(priceUsdt) || 0;
    if (content !== undefined) patch.content = content;
    if (discountPercent !== undefined) patch.discountPercent = Math.max(0, Math.min(90, Number(discountPercent) || 0));
    if (published !== undefined) patch.published = !!published;
    const files = req.files || {};
    if (files.cover) patch.coverImageUrl = saveTicketFile(files.cover).url;
    if (files.deliverable) patch.fileUrl = saveTicketFile(files.deliverable).url;
    res.json(CoachProgramRepo.update(prog.id, patch));
  } catch (e) { next(e); }
});
coachRoutes.put("/program/:id/publish", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog || prog.coachId !== coach.id) throw httpError(404, "برنامه پیدا نشد");
    res.json(CoachProgramRepo.update(prog.id, { published: !!req.body.published }));
  } catch (e) { next(e); }
});

coachRoutes.delete("/program/:id", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog || prog.coachId !== coach.id) throw httpError(404, "برنامه پیدا نشد");
    CoachProgramRepo.delete(prog.id);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

coachRoutes.get("/programs/market", (req, res) => {
  const list = CoachProgramRepo.findApproved();
  const enriched = list.map((p) => {
    const coach = CoachRepo.findById(p.coachId);
    const ranking = coach ? computeCoachRanking(coach.id) : null;
    return Object.assign({}, productWithStats(p), {
      coachName: coach ? coach.name : "مربی",
      coachVerified: coach ? !!coach.verified : false,
      coachRank: ranking ? ranking.rank : null,
      coachAvgRating: ranking ? ranking.avgRating : 0,
    });
  });
  res.json(enriched);
});
coachRoutes.get("/programs/:id/reviews", (req, res, next) => {
  try {
    const reviews = ProductReviewRepo.findByProduct(req.params.id).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const enriched = reviews.map((r) => { const u = UserRepo.findById(r.userId); return Object.assign({}, r, { userName: u ? u.name : "کاربر" }); });
    res.json(enriched);
  } catch (e) { next(e); }
});
coachRoutes.post("/programs/:id/review", (req, res, next) => {
  try {
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "محصول پیدا نشد");
    if (!ProductPurchaseRepo.hasPurchased(req.userId, prog.id)) throw httpError(403, "فقط خریداران این محصول می‌تونن نظر بدن");
    if (ProductReviewRepo.findByUserAndProduct(req.userId, prog.id)) throw httpError(400, "قبلاً برای این محصول نظر ثبت کردی");
    const rating = Number(req.body.rating);
    if (!(rating >= 1 && rating <= 5)) throw httpError(400, "امتیاز باید بین ۱ تا ۵ باشه");
    const review = ProductReviewRepo.create({ productId: prog.id, userId: req.userId, rating, comment: (req.body.comment || "").toString().slice(0, 500) });
    res.status(201).json(review);
  } catch (e) { next(e); }
});
coachRoutes.get("/programs/:id/download", (req, res, next) => {
  try {
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "محصول پیدا نشد");
    const coach = CoachRepo.findById(prog.coachId);
    const isOwner = coach && coach.userId === req.userId;
    if (!isOwner && !ProductPurchaseRepo.hasPurchased(req.userId, prog.id)) throw httpError(403, "این محصول رو نخریدی");
    if (!prog.fileUrl) throw httpError(404, "فایلی برای این محصول ثبت نشده");
    CoachProgramRepo.update(prog.id, { downloadCount: (prog.downloadCount || 0) + 1 });
    res.json({ url: prog.fileUrl });
  } catch (e) { next(e); }
});
coachRoutes.get("/my-purchases", (req, res, next) => {
  try {
    const purchases = ProductPurchaseRepo.findByUser(req.userId);
    const enriched = purchases.map((pu) => {
      const prog = CoachProgramRepo.findById(pu.productId);
      const coach = prog ? CoachRepo.findById(prog.coachId) : null;
      const alreadyReviewed = !!ProductReviewRepo.findByUserAndProduct(req.userId, pu.productId);
      return Object.assign({}, pu, { product: prog || null, coachName: coach ? coach.name : "-", alreadyReviewed });
    }).filter((p) => p.product);
    res.json(enriched.sort((a, b) => new Date(b.purchasedAt) - new Date(a.purchasedAt)));
  } catch (e) { next(e); }
});

coachRoutes.post("/programs/:id/buy", async (req, res, next) => {
  try {
    const prog = CoachProgramRepo.findById(req.params.id);
    if (!prog) throw httpError(404, "برنامه پیدا نشد");
    const coach = CoachRepo.findById(prog.coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    const { txHash } = req.body;
    if (!isNonEmptyString(txHash)) throw httpError(400, "شناسه‌ی تراکنش (Tx Hash) رو وارد کن");

    // ثبت پرداخت
    const payment = PaymentRepo.create({
      userId: req.userId, amountToman: prog.priceToman, amountUsdt: prog.priceUsdt,
      provider: "coach_program", status: "pending", providerRef: txHash.trim(),
      meta: { type: "coach_program", programId: prog.id, coachId: coach.id },
    });

    res.status(201).json({ paymentId: payment.id, program: prog, walletAddress: env.USDT_WALLET_ADDRESS || "", network: env.USDT_WALLET_NETWORK || "TRC20" });
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

    const now = new Date();
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfWeek = new Date(startOfDay.getTime() - 6 * 86400000);
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const earnings = (wallet.transactions || []).filter((t) => t.type === "earning");
    const sumSince = (from) => earnings.filter((t) => new Date(t.date) >= from).reduce((s, t) => s + t.amount, 0);

    const salesChart = [];
    for (let i = 6; i >= 0; i--) {
      const dayStart = new Date(startOfDay.getTime() - i * 86400000);
      const dayEnd = new Date(dayStart.getTime() + 86400000);
      const amount = earnings.filter((t) => { const d = new Date(t.date); return d >= dayStart && d < dayEnd; }).reduce((s, t) => s + t.amount, 0);
      salesChart.push({ date: dayStart.toISOString().slice(0, 10), amount });
    }
    const studentRows = CoachStudentRepo.findByCoach(coach.id);
    const studentGrowth = [];
    for (let i = 6; i >= 0; i--) {
      const dayStart = new Date(startOfDay.getTime() - i * 86400000);
      const dayEnd = new Date(dayStart.getTime() + 86400000);
      const count = studentRows.filter((s) => { const d = new Date(s.createdAt); return d >= dayStart && d < dayEnd && s.status === "active"; }).length;
      studentGrowth.push({ date: dayStart.toISOString().slice(0, 10), count });
    }

    res.json({
      ranking,
      wallet: { balance: wallet.balance, totalEarnings: wallet.totalEarnings, totalCommission: wallet.totalCommission },
      income: { today: sumSince(startOfDay), week: sumSince(startOfWeek), month: sumSince(startOfMonth), total: wallet.totalEarnings },
      programs: { total: programs.length, totalSales },
      students: studentRows.filter((s) => s.status === "active").length,
      subscription: coach.subscription || "none",
      salesChart, studentGrowth,
    });
  } catch (e) { next(e); }
});

// === مرحله ۴: مدیریت شاگردان و چت ===
const _coachStudents = collection("coach_students");
const CoachStudentRepo = {
  create: (data) => _coachStudents.insert(data),
  findById: (id) => _coachStudents.findById(id),
  findByCoach: (coachId) => _coachStudents.findMany((s) => s.coachId === coachId),
  findByCoachAndUser: (coachId, userId) => _coachStudents.findOne((s) => s.coachId === coachId && s.userId === userId),
  findByUser: (userId) => _coachStudents.findMany((s) => s.userId === userId),
  update: (id, patch) => _coachStudents.update(id, patch),
};
const _coachMessages = collection("coach_messages");
const CoachMessageRepo = {
  create: (data) => _coachMessages.insert(data),
  findThread: (coachId, userId) => _coachMessages.findMany((m) => m.coachId === coachId && m.studentUserId === userId).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)),
};
function publicStudentRow(row) {
  const u = UserRepo.findById(row.userId);
  return Object.assign({}, row, { userName: u ? u.name : "کاربر", userUsername: u ? u.username : null, userAvatar: u ? u.avatarUrl : null });
}
function publicCoachOfRow(row) {
  const c = CoachRepo.findById(row.coachId);
  const u = c ? UserRepo.findById(c.userId) : null;
  return Object.assign({}, row, {
    coachName: c ? c.name : "مربی",
    coachAvatar: u ? u.avatarUrl : null,
    coachSpecialty: c ? c.specialty : "",
  });
}

// درخواست شاگردی برای یک مربی
coachRoutes.post("/students/request", (req, res, next) => {
  try {
    const { coachId } = req.body;
    const coach = CoachRepo.findById(coachId);
    if (!coach || coach.status !== "approved") throw httpError(404, "مربی پیدا نشد");
    const existing = CoachStudentRepo.findByCoachAndUser(coachId, req.userId);
    if (existing && existing.status !== "removed") throw httpError(400, "قبلاً درخواست دادی یا شاگرد این مربی هستی");
    const row = CoachStudentRepo.create({ coachId, userId: req.userId, status: "pending" });
    res.status(201).json(row);
  } catch (e) { next(e); }
});

// لیست شاگردان یک مربی (برای خودِ مربی)
coachRoutes.get("/students", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    res.json(CoachStudentRepo.findByCoach(coach.id).map(publicStudentRow));
  } catch (e) { next(e); }
});

// تایید یا رد یا حذف شاگرد توسط مربی
coachRoutes.post("/students/:id/status", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const row = CoachStudentRepo.findById(req.params.id);
    if (!row || row.coachId !== coach.id) throw httpError(404, "پیدا نشد");
    const { status } = req.body;
    if (!["active", "rejected", "removed"].includes(status)) throw httpError(400, "وضعیت نامعتبر است");
    const updated = CoachStudentRepo.update(row.id, { status });
    res.json(publicStudentRow(updated));
  } catch (e) { next(e); }
});

// لیست مربی‌هایی که کاربر عادی به عنوان شاگرد به اون‌ها وصله
coachRoutes.get("/my-coaches", (req, res, next) => {
  try {
    res.json(CoachStudentRepo.findByUser(req.userId).map(publicCoachOfRow));
  } catch (e) { next(e); }
});

// دریافت پیام‌های یک گفتگو (هم مربی هم شاگرد می‌تونن بخونن)
coachRoutes.get("/chat", (req, res, next) => {
  try {
    const { coachId, studentUserId } = req.query;
    if (!coachId || !studentUserId) throw httpError(400, "پارامتر ناقص است");
    const coach = CoachRepo.findById(coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    const isCoachSide = coach.userId === req.userId;
    const isStudentSide = studentUserId === req.userId;
    if (!isCoachSide && !isStudentSide) throw httpError(403, "دسترسی نداری");
    res.json(CoachMessageRepo.findThread(coachId, studentUserId));
  } catch (e) { next(e); }
});

// ارسال پیام (متن یا فایل/عکس/ویدیو)
coachRoutes.post("/chat/send", (req, res, next) => {
  try {
    const { coachId, studentUserId, text } = req.body;
    if (!coachId || !studentUserId) throw httpError(400, "پارامتر ناقص است");
    const coach = CoachRepo.findById(coachId);
    if (!coach) throw httpError(404, "مربی پیدا نشد");
    const isCoachSide = coach.userId === req.userId;
    const isStudentSide = studentUserId === req.userId;
    if (!isCoachSide && !isStudentSide) throw httpError(403, "دسترسی نداری");
    const rel = CoachStudentRepo.findByCoachAndUser(coachId, studentUserId);
    if (!rel || rel.status !== "active") throw httpError(400, "این گفتگو فعال نیست");

    let attachmentUrl = null, attachmentType = null;
    const file = req.files && (req.files.attachment || req.files.file);
    if (file) {
      const ALLOWED = ["image/png", "image/jpeg", "image/webp", "video/mp4", "video/quicktime", "application/pdf"];
      if (!ALLOWED.includes(file.mimeType)) throw httpError(400, "فرمت فایل مجاز نیست");
      if (file.size > 25 * 1024 * 1024) throw httpError(400, "حجم فایل نباید بیشتر از ۲۵ مگابایت باشد");
      const ext = (file.filename && file.filename.includes(".")) ? file.filename.split(".").pop() : (file.mimeType.split("/")[1] || "bin");
      const filename = `chat_${crypto.randomBytes(8).toString("hex")}.${ext}`;
      fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
      attachmentUrl = `/uploads/${filename}`;
      attachmentType = file.mimeType.startsWith("image/") ? "image" : file.mimeType.startsWith("video/") ? "video" : "file";
    }
    if (!isNonEmptyString(text) && !attachmentUrl) throw httpError(400, "پیام خالیه");

    const msg = CoachMessageRepo.create({
      coachId, studentUserId,
      senderRole: isCoachSide ? "coach" : "student",
      text: text ? String(text).slice(0, 2000) : "",
      attachmentUrl, attachmentType, read: false,
    });
    res.status(201).json(msg);
  } catch (e) { next(e); }
});

// === مرحله ۵: رزرو مشاوره ===
const _coachBookings = collection("coach_bookings");
const CoachBookingRepo = {
  create: (data) => _coachBookings.insert(data),
  findById: (id) => _coachBookings.findById(id),
  findByCoach: (coachId) => _coachBookings.findMany((b) => b.coachId === coachId),
  findByUser: (userId) => _coachBookings.findMany((b) => b.userId === userId),
  update: (id, patch) => _coachBookings.update(id, patch),
};
const BOOKING_TYPES = { online: "آنلاین", inperson: "حضوری", phone: "تلفنی", video: "تصویری" };

// درخواست رزرو مشاوره + ثبت پرداخت (در انتظار تایید ادمین)
coachRoutes.post("/bookings", async (req, res, next) => {
  try {
    const { coachId, type, requestedTime, note, txHash } = req.body;
    const coach = CoachRepo.findById(coachId);
    if (!coach || coach.status !== "approved") throw httpError(404, "مربی پیدا نشد");
    if (!BOOKING_TYPES[type]) throw httpError(400, "نوع مشاوره نامعتبر است");
    if (!isNonEmptyString(requestedTime) || isNaN(Date.parse(requestedTime))) throw httpError(400, "زمان معتبر انتخاب کن");
    if (new Date(requestedTime).getTime() < Date.now()) throw httpError(400, "زمان انتخابی باید در آینده باشد");
    if (!isNonEmptyString(txHash)) throw httpError(400, "شناسه‌ی تراکنش (Tx Hash) رو وارد کن");
    const amountToman = coach.pricePerSession || 0;

    const payment = PaymentRepo.create({
      userId: req.userId, amountToman, amountUsdt: null,
      provider: "coach_booking", status: "pending", providerRef: txHash.trim(),
      meta: { type: "coach_booking", coachId, bookingType: type, requestedTime, note: note ? String(note).slice(0, 500) : "" },
    });
    res.status(201).json({ paymentId: payment.id, walletAddress: env.USDT_WALLET_ADDRESS || "", network: env.USDT_WALLET_NETWORK || "TRC20" });
  } catch (e) { next(e); }
});

// لیست مشاوره‌های یک مربی (برای خودِ مربی)
coachRoutes.get("/bookings", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const list = CoachBookingRepo.findByCoach(coach.id).map((b) => {
      const u = UserRepo.findById(b.userId);
      return Object.assign({}, b, { userName: u ? u.name : "کاربر" });
    });
    res.json(list.sort((a, b) => new Date(a.requestedTime) - new Date(b.requestedTime)));
  } catch (e) { next(e); }
});

// لیست مشاوره‌های کاربر عادی
coachRoutes.get("/bookings/mine", (req, res, next) => {
  try {
    const list = CoachBookingRepo.findByUser(req.userId).map((b) => {
      const c = CoachRepo.findById(b.coachId);
      return Object.assign({}, b, { coachName: c ? c.name : "مربی" });
    });
    res.json(list.sort((a, b) => new Date(a.requestedTime) - new Date(b.requestedTime)));
  } catch (e) { next(e); }
});

// تغییر وضعیت رزرو توسط مربی (تکمیل‌شده / لغو)
coachRoutes.post("/bookings/:id/status", (req, res, next) => {
  try {
    const coach = CoachRepo.findByUserId(req.userId);
    if (!coach) throw httpError(400, "شما مربی نیستید");
    const row = CoachBookingRepo.findById(req.params.id);
    if (!row || row.coachId !== coach.id) throw httpError(404, "پیدا نشد");
    const { status } = req.body;
    if (!["completed", "cancelled"].includes(status)) throw httpError(400, "وضعیت نامعتبر است");
    res.json(CoachBookingRepo.update(row.id, { status }));
  } catch (e) { next(e); }
});

// نکته‌ی مهم: این مسیر باید آخرین مسیر GET ثبت‌شده روی coachRoutes باشه
// چون ":id" با هر مسیر تک‌بخشی مطابقت پیدا می‌کنه و اگه زودتر ثبت بشه، مسیرهای دیگه رو می‌پوشونه
coachRoutes.get("/:id", CoachController.getCoach);

// ================= سیستم تیکت پشتیبانی (نسخه‌ی حرفه‌ای) =================
const _tickets = collection("tickets");
const _ticketMessages = collection("ticket_messages");
const _ticketQuickReplies = collection("ticket_quick_replies");

const TICKET_CATEGORIES = ["مشکلات پرداخت", "اشتراک VIP", "مشکلات فنی", "گزارش باگ", "پیشنهادات", "گزارش تخلف", "حساب کاربری", "مربیان", "هوش مصنوعی", "سایر موارد"];
const TICKET_PRIORITIES = ["normal", "important", "urgent"]; // عادی، مهم، فوری
const TICKET_STATUSES = ["new", "in_review", "answered", "waiting_user", "closed"]; // جدید، در حال بررسی، پاسخ داده شده، در انتظار پاسخ کاربر، بسته شده

function nextTicketNumber() {
  const all = _tickets.all();
  const max = all.reduce((m, t) => Math.max(m, Number(t.ticketNumber) || 0), 10000);
  return max + 1;
}
const TicketRepo = {
  create: (data) => _tickets.insert(data),
  findById: (id) => _tickets.findById(id),
  findByUser: (userId) => _tickets.findMany((t) => t.userId === userId),
  all: () => _tickets.all(),
  update: (id, patch) => _tickets.update(id, patch),
};
const TicketMessageRepo = {
  create: (data) => _ticketMessages.insert(data),
  findByTicket: (ticketId) => _ticketMessages.findMany((m) => m.ticketId === ticketId).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)),
};
const QuickReplyRepo = {
  all: () => _ticketQuickReplies.all().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt)),
  create: (data) => _ticketQuickReplies.insert(data),
  remove: (id) => _ticketQuickReplies.remove(id),
};

// انواع فایل مجاز برای پیوست تیکت (عکس، ویدئو، PDF)
const TICKET_FILE_RULES = {
  image: { mimes: ["image/png", "image/jpeg", "image/webp"], maxSize: 5 * 1024 * 1024, exts: { "image/png": "png", "image/jpeg": "jpg", "image/webp": "webp" } },
  video: { mimes: ["video/mp4", "video/webm", "video/quicktime"], maxSize: 30 * 1024 * 1024, exts: { "video/mp4": "mp4", "video/webm": "webm", "video/quicktime": "mov" } },
  pdf: { mimes: ["application/pdf"], maxSize: 10 * 1024 * 1024, exts: { "application/pdf": "pdf" } },
};
function classifyTicketFile(mime) {
  for (const kind of Object.keys(TICKET_FILE_RULES)) {
    if (TICKET_FILE_RULES[kind].mimes.includes(mime)) return kind;
  }
  return null;
}
function saveTicketFile(file) {
  const kind = classifyTicketFile(file.mimeType);
  if (!kind) throw httpError(400, "فرمت فایل مجاز نیست (فقط عکس، ویدئو یا PDF)");
  const rule = TICKET_FILE_RULES[kind];
  if (file.size > rule.maxSize) throw httpError(400, `حجم فایل نباید بیشتر از ${Math.round(rule.maxSize / (1024 * 1024))} مگابایت باشد`);
  const ext = rule.exts[file.mimeType] || "bin";
  const filename = `ticket_${crypto.randomBytes(8).toString("hex")}.${ext}`;
  fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
  return { url: `/uploads/${filename}`, type: kind, name: file.filename || filename };
}
// چند فایل هم‌زمان: کلیدهای file0, file1, ... یا image0 (سازگاری قدیمی)
function collectTicketAttachments(files) {
  const out = [];
  Object.keys(files || {}).forEach((key) => {
    if (/^(file|image)\d*$/.test(key)) out.push(saveTicketFile(files[key]));
  });
  return out.slice(0, 5); // حداکثر ۵ فایل هر پیام
}

const ticketRoutes = new Router();
ticketRoutes.use(requireAuth);

// ساخت تیکت جدید
ticketRoutes.post("/", (req, res, next) => {
  try {
    const { subject, category, message, priority, coachId } = req.body;
    if (!isNonEmptyString(subject)) throw httpError(400, "موضوع تیکت رو بنویس");
    if (!isNonEmptyString(message)) throw httpError(400, "متن پیام رو بنویس");
    const cat = TICKET_CATEGORIES.includes(category) ? category : "سایر موارد";
    const pr = TICKET_PRIORITIES.includes(priority) ? priority : "normal";
    const attachments = collectTicketAttachments(req.files);

    const ticket = TicketRepo.create({
      ticketNumber: nextTicketNumber(),
      userId: req.userId, subject: String(subject).slice(0, 150), category: cat, priority: pr,
      status: "new", assignedTo: null, archived: false,
      firstResponseAt: null, closedAt: null, rating: null, ratingText: null,
      lastMessageAt: new Date().toISOString(), lastAdminReadAt: null,
    });
    TicketMessageRepo.create({
      ticketId: ticket.id, senderRole: "user", text: String(message).slice(0, 3000),
      attachments, attachmentUrl: attachments[0] ? attachments[0].url : null, // attachmentUrl برای سازگاری با فرانت قدیمی
    });
    SecurityLog.log({ userId: req.userId, type: "ticket_created", meta: { ticketId: ticket.id, category: cat, priority: pr } });
    res.status(201).json(ticket);
  } catch (e) { next(e); }
});

// لیست تیکت‌های کاربر
ticketRoutes.get("/", (req, res, next) => {
  try {
    const list = TicketRepo.findByUser(req.userId).sort((a, b) => new Date(b.lastMessageAt || b.createdAt) - new Date(a.lastMessageAt || a.createdAt));
    res.json(list);
  } catch (e) { next(e); }
});

// جزییات یک تیکت (فقط صاحبش)
ticketRoutes.get("/:id", (req, res, next) => {
  try {
    const ticket = TicketRepo.findById(req.params.id);
    if (!ticket || ticket.userId !== req.userId) throw httpError(404, "تیکت پیدا نشد");
    res.json({ ticket, messages: TicketMessageRepo.findByTicket(ticket.id) });
  } catch (e) { next(e); }
});

// پاسخ کاربر به تیکت خودش
ticketRoutes.post("/:id/reply", (req, res, next) => {
  try {
    const ticket = TicketRepo.findById(req.params.id);
    if (!ticket || ticket.userId !== req.userId) throw httpError(404, "تیکت پیدا نشد");
    if (ticket.status === "closed") throw httpError(400, "این تیکت بسته شده؛ برای ادامه یه تیکت جدید بزن");
    const { message } = req.body;
    const attachments = collectTicketAttachments(req.files);
    if (!isNonEmptyString(message) && !attachments.length) throw httpError(400, "پیام خالیه");
    const msg = TicketMessageRepo.create({
      ticketId: ticket.id, senderRole: "user", text: message ? String(message).slice(0, 3000) : "",
      attachments, attachmentUrl: attachments[0] ? attachments[0].url : null,
    });
    // پیام جدید کاربر یعنی دوباره منتظر رسیدگی ادمینه
    TicketRepo.update(ticket.id, { status: "new", lastMessageAt: new Date().toISOString() });
    res.status(201).json(msg);
  } catch (e) { next(e); }
});

// امتیازدهی کاربر به یه تیکتِ بسته‌شده
ticketRoutes.post("/:id/rate", (req, res, next) => {
  try {
    const ticket = TicketRepo.findById(req.params.id);
    if (!ticket || ticket.userId !== req.userId) throw httpError(404, "تیکت پیدا نشد");
    if (ticket.status !== "closed") throw httpError(400, "فقط تیکت‌های بسته‌شده رو می‌شه امتیاز داد");
    const rating = Number(req.body.rating);
    if (!(rating >= 1 && rating <= 5)) throw httpError(400, "امتیاز باید بین ۱ تا ۵ باشه");
    const updated = TicketRepo.update(ticket.id, { rating, ratingText: (req.body.text || "").toString().slice(0, 500) });
    res.json(updated);
  } catch (e) { next(e); }
});

// === ادمین: مدیریت تیکت‌ها ===
adminRoutes.get("/tickets", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const { status, category, priority, archived } = req.query || {};
    let list = TicketRepo.all();
    if (status) list = list.filter((t) => t.status === status);
    if (category) list = list.filter((t) => t.category === category);
    if (priority) list = list.filter((t) => t.priority === priority);
    list = list.filter((t) => !!t.archived === (archived === "true"));
    list = list.map((t) => {
      const u = UserRepo.findById(t.userId);
      const msgs = TicketMessageRepo.findByTicket(t.id);
      const lastMsg = msgs[msgs.length - 1];
      const unread = !!lastMsg && lastMsg.senderRole === "user" && (!t.lastAdminReadAt || new Date(lastMsg.createdAt) > new Date(t.lastAdminReadAt));
      return Object.assign({}, t, { userName: u ? u.name : "-", userEmail: u ? u.email : "-", unread });
    });
    res.json(list.sort((a, b) => new Date(b.lastMessageAt || b.createdAt) - new Date(a.lastMessageAt || a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.get("/tickets/stats", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const all = TicketRepo.all();
    const withFirstResponse = all.filter((t) => t.firstResponseAt);
    const avgFirstResponseMin = withFirstResponse.length
      ? Math.round(withFirstResponse.reduce((sum, t) => sum + (new Date(t.firstResponseAt) - new Date(t.createdAt)) / 60000, 0) / withFirstResponse.length)
      : null;
    const unreadCount = all.filter((t) => {
      const msgs = TicketMessageRepo.findByTicket(t.id);
      const lastMsg = msgs[msgs.length - 1];
      return !!lastMsg && lastMsg.senderRole === "user" && (!t.lastAdminReadAt || new Date(lastMsg.createdAt) > new Date(t.lastAdminReadAt));
    }).length;
    res.json({
      total: all.length,
      unread: unreadCount,
      byStatus: TICKET_STATUSES.reduce((acc, s) => { acc[s] = all.filter((t) => t.status === s).length; return acc; }, {}),
      byPriority: TICKET_PRIORITIES.reduce((acc, p) => { acc[p] = all.filter((t) => t.priority === p).length; return acc; }, {}),
      avgFirstResponseMinutes: avgFirstResponseMin,
      avgRating: (() => {
        const rated = all.filter((t) => t.rating);
        return rated.length ? +(rated.reduce((s, t) => s + t.rating, 0) / rated.length).toFixed(2) : null;
      })(),
    });
  } catch (e) { next(e); }
});
// پاسخ‌های آماده (Quick Replies) — باید قبل از /tickets/:id ثبت بشه چون روتر بر اساس ترتیب ثبت مچ می‌کنه
adminRoutes.get("/tickets/quick-replies", (req, res, next) => {
  try { requireAdminUser(req.userId, "tickets"); res.json(QuickReplyRepo.all()); } catch (e) { next(e); }
});
adminRoutes.post("/tickets/quick-replies", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const { title, text } = req.body;
    if (!isNonEmptyString(title) || !isNonEmptyString(text)) throw httpError(400, "عنوان و متن الزامی است");
    res.status(201).json(QuickReplyRepo.create({ title: String(title).slice(0, 80), text: String(text).slice(0, 3000) }));
  } catch (e) { next(e); }
});
adminRoutes.delete("/tickets/quick-replies/:id", (req, res, next) => {
  try { requireAdminUser(req.userId, "tickets"); QuickReplyRepo.remove(req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});
adminRoutes.get("/tickets/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    let ticket = TicketRepo.findById(req.params.id);
    if (!ticket) throw httpError(404, "تیکت پیدا نشد");
    ticket = TicketRepo.update(ticket.id, { lastAdminReadAt: new Date().toISOString() });
    const u = UserRepo.findById(ticket.userId);
    res.json({ ticket: Object.assign({}, ticket, { userName: u ? u.name : "-", userEmail: u ? u.email : "-", userPhone: u ? u.phone : "-" }), messages: TicketMessageRepo.findByTicket(ticket.id) });
  } catch (e) { next(e); }
});
adminRoutes.post("/tickets/:id/reply", (req, res, next) => {
  try {
    const admin = requireAdminUser(req.userId, "tickets");
    const ticket = TicketRepo.findById(req.params.id);
    if (!ticket) throw httpError(404, "تیکت پیدا نشد");
    const { message, status } = req.body;
    const attachments = collectTicketAttachments(req.files);
    if (!isNonEmptyString(message) && !attachments.length) throw httpError(400, "پیام خالیه");
    const msg = TicketMessageRepo.create({
      ticketId: ticket.id, senderRole: "admin", senderName: admin.name || "پشتیبانی",
      text: message ? String(message).slice(0, 3000) : "", attachments, attachmentUrl: attachments[0] ? attachments[0].url : null,
    });
    const patch = { lastMessageAt: new Date().toISOString() };
    if (!ticket.firstResponseAt) patch.firstResponseAt = new Date().toISOString();
    if (status && TICKET_STATUSES.includes(status)) patch.status = status;
    else patch.status = "answered";
    if (patch.status === "closed" && !ticket.closedAt) patch.closedAt = new Date().toISOString();
    TicketRepo.update(ticket.id, patch);
    SecurityLog.log({ userId: req.userId, type: "ticket_admin_reply", meta: { ticketId: ticket.id, status: patch.status } });
    res.status(201).json(msg);
  } catch (e) { next(e); }
});
adminRoutes.put("/tickets/:id/status", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const { status } = req.body;
    if (!TICKET_STATUSES.includes(status)) throw httpError(400, "وضعیت نامعتبر است");
    const patch = { status };
    const existing = TicketRepo.findById(req.params.id);
    if (status === "closed" && existing && !existing.closedAt) patch.closedAt = new Date().toISOString();
    if (status !== "closed") patch.closedAt = null; // بازگشایی مجدد
    const ticket = TicketRepo.update(req.params.id, patch);
    if (!ticket) throw httpError(404, "تیکت پیدا نشد");
    SecurityLog.log({ userId: req.userId, type: "ticket_status_changed", meta: { ticketId: ticket.id, status } });
    res.json(ticket);
  } catch (e) { next(e); }
});
adminRoutes.put("/tickets/:id/assign", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const { adminId } = req.body;
    if (adminId) {
      const target = UserRepo.findById(adminId);
      if (!target || target.role !== "admin") throw httpError(400, "ادمین مقصد نامعتبر است");
    }
    const ticket = TicketRepo.update(req.params.id, { assignedTo: adminId || null });
    if (!ticket) throw httpError(404, "تیکت پیدا نشد");
    SecurityLog.log({ userId: req.userId, type: "ticket_assigned", meta: { ticketId: ticket.id, assignedTo: adminId || null } });
    res.json(ticket);
  } catch (e) { next(e); }
});
adminRoutes.put("/tickets/:id/archive", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "tickets");
    const ticket = TicketRepo.update(req.params.id, { archived: !!req.body.archived });
    if (!ticket) throw httpError(404, "تیکت پیدا نشد");
    res.json(ticket);
  } catch (e) { next(e); }
});
// پاسخ‌های آماده (Quick Replies)

/* ================= اعلان‌ها (Notifications) ================= */
const _notifications = collection("notifications");
const NotificationRepo = {
  create: (data) => _notifications.insert(data),
  all: () => _notifications.all(),
  findById: (id) => _notifications.findById(id),
  update: (id, patch) => _notifications.update(id, patch),
  remove: (id) => _notifications.remove(id),
};
function notificationMatchesUser(n, user) {
  if (n.scheduledAt && new Date(n.scheduledAt).getTime() > Date.now()) return false; // هنوز زمانش نرسیده
  if (n.scope === "all") return true;
  if (n.scope === "vip") return !!(user.vip && user.vip.active);
  if (n.scope === "coaches") return !!_coaches.findOne((c) => c.userId === user.id && c.status === "approved");
  if (n.scope === "user") return n.targetUserId === user.id;
  return false;
}
usersRoutes.get("/notifications", (req, res, next) => {
  try {
    const user = UserRepo.findById(req.userId);
    const list = NotificationRepo.all().filter((n) => notificationMatchesUser(n, user))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50)
      .map((n) => Object.assign({}, n, { read: (n.readBy || []).includes(req.userId) }));
    res.json(list);
  } catch (e) { next(e); }
});
usersRoutes.put("/notifications/:id/read", (req, res, next) => {
  try {
    const n = NotificationRepo.findById(req.params.id);
    if (!n) throw httpError(404, "اعلان یافت نشد");
    const readBy = n.readBy || [];
    if (!readBy.includes(req.userId)) readBy.push(req.userId);
    res.json(NotificationRepo.update(n.id, { readBy }));
  } catch (e) { next(e); }
});
adminRoutes.get("/notifications", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); res.json(NotificationRepo.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))); } catch (e) { next(e); }
});
adminRoutes.post("/notifications", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const { title, message, scope, targetUserId, scheduledAt } = req.body;
    if (!isNonEmptyString(title)) throw httpError(400, "عنوان الزامی است");
    if (!isNonEmptyString(message)) throw httpError(400, "متن اعلان الزامی است");
    if (!["all", "vip", "coaches", "user"].includes(scope)) throw httpError(400, "مخاطب نامعتبر است");
    if (scope === "user" && !targetUserId) throw httpError(400, "برای اعلان تکی، شناسه کاربر لازمه");
    const n = NotificationRepo.create({
      title: String(title).slice(0, 100), message: String(message).slice(0, 1000),
      scope, targetUserId: scope === "user" ? targetUserId : null,
      scheduledAt: scheduledAt || null, readBy: [], createdBy: req.userId,
    });
    SecurityLog.log({ userId: req.userId, type: "notification_sent", meta: { notificationId: n.id, scope } });
    res.status(201).json(n);
  } catch (e) { next(e); }
});
adminRoutes.delete("/notifications/:id", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); NotificationRepo.remove(req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});

/* ================= مدیریت محتوا (مقاله/خبر/ویدئو/چالش) ================= */
const _contentPosts = collection("content_posts");
const ContentRepo = {
  create: (data) => _contentPosts.insert(data),
  all: () => _contentPosts.all(),
  findById: (id) => _contentPosts.findById(id),
  update: (id, patch) => _contentPosts.update(id, patch),
  remove: (id) => _contentPosts.remove(id),
};
usersRoutes.get("/content", (req, res, next) => {
  try {
    const { type } = req.query || {};
    let list = ContentRepo.all().filter((c) => c.published);
    if (type) list = list.filter((c) => c.type === type);
    res.json(list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
  } catch (e) { next(e); }
});
adminRoutes.get("/content", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); res.json(ContentRepo.all().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))); } catch (e) { next(e); }
});
adminRoutes.post("/content", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const { title, body, type, coverImageUrl, published } = req.body;
    if (!isNonEmptyString(title)) throw httpError(400, "عنوان الزامی است");
    if (!["article", "news", "video", "challenge"].includes(type)) throw httpError(400, "نوع محتوا نامعتبر است");
    const row = ContentRepo.create({
      title: String(title).slice(0, 150), body: String(body || "").slice(0, 20000),
      type, coverImageUrl: coverImageUrl || null, published: !!published, createdBy: req.userId,
    });
    res.status(201).json(row);
  } catch (e) { next(e); }
});
adminRoutes.put("/content/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const allowed = {};
    ["title", "body", "type", "coverImageUrl", "published"].forEach((k) => { if (req.body[k] !== undefined) allowed[k] = req.body[k]; });
    const row = ContentRepo.update(req.params.id, allowed);
    if (!row) throw httpError(404, "پیدا نشد");
    res.json(row);
  } catch (e) { next(e); }
});
adminRoutes.delete("/content/:id", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); ContentRepo.remove(req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});

/* ================= بنرهای تبلیغاتی ================= */
const _adBanners = collection("ad_banners");
const AdRepo = {
  create: (data) => _adBanners.insert(data),
  all: () => _adBanners.all(),
  findById: (id) => _adBanners.findById(id),
  update: (id, patch) => _adBanners.update(id, patch),
  remove: (id) => _adBanners.remove(id),
};
usersRoutes.get("/ads", (req, res, next) => {
  try {
    const list = AdRepo.all().filter((a) => a.active).sort((a, b) => (a.position || 0) - (b.position || 0));
    res.json(list);
  } catch (e) { next(e); }
});
usersRoutes.post("/ads/:id/impression", (req, res, next) => {
  try {
    const a = AdRepo.findById(req.params.id);
    if (a) AdRepo.update(a.id, { impressions: (a.impressions || 0) + 1 });
    res.json({ ok: true });
  } catch (e) { next(e); }
});
usersRoutes.post("/ads/:id/click", (req, res, next) => {
  try {
    const a = AdRepo.findById(req.params.id);
    if (a) AdRepo.update(a.id, { clicks: (a.clicks || 0) + 1 });
    res.json({ ok: true });
  } catch (e) { next(e); }
});
adminRoutes.get("/ads", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); res.json(AdRepo.all().sort((a, b) => (a.position || 0) - (b.position || 0))); } catch (e) { next(e); }
});
adminRoutes.post("/ads", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const { imageUrl, linkUrl, position } = req.body;
    if (!isNonEmptyString(imageUrl)) throw httpError(400, "آدرس تصویر بنر الزامی است");
    const row = AdRepo.create({ imageUrl, linkUrl: linkUrl || null, position: Number(position) || 0, active: true, impressions: 0, clicks: 0 });
    res.status(201).json(row);
  } catch (e) { next(e); }
});
adminRoutes.put("/ads/:id", (req, res, next) => {
  try {
    requireAdminUser(req.userId, "content");
    const allowed = {};
    ["imageUrl", "linkUrl", "position", "active"].forEach((k) => { if (req.body[k] !== undefined) allowed[k] = req.body[k]; });
    const row = AdRepo.update(req.params.id, allowed);
    if (!row) throw httpError(404, "پیدا نشد");
    res.json(row);
  } catch (e) { next(e); }
});
adminRoutes.delete("/ads/:id", (req, res, next) => {
  try { requireAdminUser(req.userId, "content"); AdRepo.remove(req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});

app.mount("/api/coach", coachRoutes);
app.mount("/api/users", usersRoutes);
app.mount("/api/admin", adminRoutes);
app.mount("/api/tickets", ticketRoutes);
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
