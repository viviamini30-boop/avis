const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");
const express = require("express");
const helmet = require("helmet");
const multer = require("multer");
const { WebSocket, WebSocketServer } = require("ws");
const { rateLimit } = require("express-rate-limit");

const ROOT = __dirname;
const STORAGE_DIR = process.env.PRIVATE_UPLOAD_DIR || path.join(ROOT, "private-uploads");
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const FILE_FIELDS = ["driversLicenseFront", "driversLicenseBack"];
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SESSION_COOKIE = "aivestora_session";
const SESSION_TTL_SECONDS = 12 * 60 * 60;
const MARKET_CACHE_MS = 5 * 60 * 1000;
const MARKET_SYMBOLS = {
  SPX: "S&P 500",
  NDX: "Nasdaq 100",
  DJI: "Dow Jones"
};
const scrypt = promisify(crypto.scrypt);
const marketDataCache = new Map();

function requiredSecret(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must be set in .env.`);
  return value;
}

let adminPassword = requiredSecret("ADMIN_PASSWORD");
if (Buffer.byteLength(adminPassword, "utf8") < 24) {
  throw new Error("ADMIN_PASSWORD must be at least 24 bytes. Run node setup.js to create secure configuration.");
}

const encryptionKey = Buffer.from(requiredSecret("DATA_ENCRYPTION_KEY"), "base64");
if (encryptionKey.length !== 32) {
  throw new Error("DATA_ENCRYPTION_KEY must be a base64-encoded 32-byte key. Run node setup.js to create secure configuration.");
}

const sessionSecret = Buffer.from(requiredSecret("SESSION_SECRET"), "base64");
if (sessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must be a base64-encoded secret of at least 32 bytes. Run node setup.js to create secure configuration.");
}

const app = express();
const marketWebSocketServer = new WebSocketServer({ noServer: true });
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const trustProxySetting = process.env.TRUST_PROXY;
const trustProxyHops = trustProxySetting && /^\d+$/.test(trustProxySetting)
  ? Number(trustProxySetting)
  : null;
const trustProxy = trustProxyHops ?? trustProxySetting ?? "loopback";

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error("PORT must be a valid TCP port.");
}

const isLocalHost = ["127.0.0.1", "::1", "localhost"].includes(host);
const isApprovedPublicBind = host === "0.0.0.0" &&
  process.env.NODE_ENV === "production" &&
  process.env.ALLOW_PUBLIC_BIND === "true" &&
  Number.isSafeInteger(trustProxyHops) &&
  trustProxyHops > 0;

if (!isLocalHost && !isApprovedPublicBind) {
  throw new Error("Public binding requires production mode, ALLOW_PUBLIC_BIND=true, and a positive numeric TRUST_PROXY hop count.");
}

app.set("trust proxy", trustProxy);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  },
  referrerPolicy: { policy: "no-referrer" }
}));

function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(plainText), cipher.final()]);
  return Buffer.concat([Buffer.from([1]), iv, cipher.getAuthTag(), encrypted]);
}

function decrypt(cipherText) {
  if (cipherText.length < 29 || cipherText[0] !== 1) {
    throw new Error("Encrypted submission data is invalid or uses an unsupported version.");
  }
  const iv = cipherText.subarray(1, 13);
  const authTag = cipherText.subarray(13, 29);
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(cipherText.subarray(29)), decipher.final()]);
}

function validateAdminPassword(password) {
  if (typeof password !== "string" || !/^[\x20-\x7e]{12,128}$/.test(password)) {
    throw new RequestError(400, "Choose an administrator password of 12–128 printable ASCII characters.");
  }
}

async function loadAdminPassword() {
  try {
    const encryptedPassword = await fs.readFile(path.join(STORAGE_DIR, "admin-password.enc"));
    const storedPassword = decrypt(encryptedPassword).toString("utf8");
    validateAdminPassword(storedPassword);
    adminPassword = storedPassword;
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw new Error("The stored administrator password could not be loaded.", { cause: error });
  }
}

async function saveAdminPassword(password) {
  const destination = path.join(STORAGE_DIR, "admin-password.enc");
  const temporary = path.join(STORAGE_DIR, `admin-password-${crypto.randomUUID()}.tmp`);
  try {
    await writeNewFile(temporary, encrypt(Buffer.from(password, "utf8")));
    await fs.rename(temporary, destination);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    crypto.timingSafeEqual(leftBuffer, leftBuffer);
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

class RequestError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function normalizeEmail(value) {
  if (typeof value !== "string") throw new RequestError(400, "Enter a valid email address.");
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new RequestError(400, "Enter a valid email address.");
  }
  return email;
}

function validatePassword(password) {
  if (typeof password !== "string" || Array.from(password).length < 12 || Array.from(password).length > 128) {
    throw new RequestError(400, "Password must be between 12 and 128 characters.");
  }
}

async function hashPassword(password, salt = crypto.randomBytes(16)) {
  const derivedKey = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return { salt: salt.toString("base64"), passwordHash: derivedKey.toString("base64") };
}

async function verifyPassword(password, user) {
  const salt = Buffer.from(user.passwordSalt, "base64");
  const expected = Buffer.from(user.passwordHash, "base64");
  if (salt.length !== 16 || expected.length !== 64) return false;
  const actual = await scrypt(password, salt, expected.length, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return crypto.timingSafeEqual(actual, expected);
}

async function readUsers() {
  try {
    const encrypted = await fs.readFile(path.join(STORAGE_DIR, "users.enc"));
    const users = JSON.parse(decrypt(encrypted).toString("utf8"));
    if (!Array.isArray(users)) throw new Error("Encrypted user account store has an invalid format.");
    return users;
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function writeUsers(users) {
  const destination = path.join(STORAGE_DIR, "users.enc");
  const temporary = path.join(STORAGE_DIR, `users-${crypto.randomUUID()}.tmp`);
  try {
    await writeNewFile(temporary, encrypt(Buffer.from(JSON.stringify(users), "utf8")));
    await fs.rename(temporary, destination);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}

let accountQueue = Promise.resolve();
async function withAccountLock(operation) {
  const previous = accountQueue;
  let release;
  accountQueue = new Promise((resolve) => { release = resolve; });
  await previous;
  try {
    return await operation();
  } finally {
    release();
  }
}

function createSessionToken(userId) {
  const payload = Buffer.from(JSON.stringify({
    userId,
    expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000
  })).toString("base64url");
  const signature = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function getSessionUserId(req) {
  const cookie = (req.headers.cookie || "").split(";").map((item) => item.trim())
    .find((item) => item.startsWith(`${SESSION_COOKIE}=`));
  if (!cookie) return null;
  const token = cookie.slice(SESSION_COOKIE.length + 1);
  const [payload, signature, extra] = token.split(".");
  if (!payload || !signature || extra !== undefined) return null;
  const expected = crypto.createHmac("sha256", sessionSecret).update(payload).digest("base64url");
  if (!safeEqual(signature, expected)) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!UUID_PATTERN.test(session.userId) || !Number.isFinite(session.expiresAt) || session.expiresAt <= Date.now()) return null;
    return session.userId;
  } catch (error) {
    return null;
  }
}

function setSessionCookie(res, userId) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.set("Set-Cookie", `${SESSION_COOKIE}=${createSessionToken(userId)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}${secure}`);
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.set("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
}

async function requireUser(req, res, next) {
  res.set("Cache-Control", "no-store");
  try {
    const userId = getSessionUserId(req);
    if (!userId) {
      if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Sign in required." });
      return res.redirect(302, "/signin.html");
    }
    const users = await readUsers();
    const user = users.find((item) => item.id === userId);
    if (!user) {
      clearSessionCookie(res);
      if (req.path.startsWith("/api/")) return res.status(401).json({ error: "Sign in required." });
      return res.redirect(302, "/signin.html");
    }
    const balanceCents = user.balanceCents ?? 0;
    if (!Number.isSafeInteger(balanceCents) || balanceCents < 0) {
      throw new Error("Account balance is invalid.");
    }
    req.user = {
      id: user.id,
      email: user.email,
      name: typeof user.fullName === "string" && user.fullName.trim() && !user.fullName.includes("@")
        ? user.fullName.trim()
        : null,
      balanceCents
    };
    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(req, res, next) {
  res.set("Cache-Control", "no-store");
  const header = req.get("authorization") || "";
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(header);
  if (!match) return res.status(401).json({ error: "Admin password required." });

  let credentials;
  try {
    credentials = Buffer.from(match[1], "base64").toString("utf8");
  } catch (error) {
    return res.status(401).json({ error: "Invalid admin credentials." });
  }
  const separator = credentials.indexOf(":");
  if (separator < 0 || credentials.slice(0, separator) !== "admin" ||
      !safeEqual(credentials.slice(separator + 1), adminPassword)) {
    return res.status(401).json({ error: "Invalid admin credentials." });
  }
  next();
}

function requireSecureTransport(req, res, next) {
  if (process.env.NODE_ENV === "production" && !req.secure) {
    return res.status(400).json({ error: "HTTPS is required for sensitive submissions." });
  }
  next();
}

function requireIdentitySubmissionsEnabled(req, res, next) {
  if (process.env.NODE_ENV === "production" && process.env.ENABLE_IDENTITY_SUBMISSIONS !== "true") {
    return res.status(503).json({ error: "Identity submissions are disabled pending production security review." });
  }
  next();
}

function detectFileType(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return { mimeType: "image/jpeg", extension: ".jpg" };
  }
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    return { mimeType: "image/png", extension: ".png" };
  }
  if (buffer.length >= 12 && buffer.toString("ascii", 0, 4) === "RIFF" &&
      buffer.toString("ascii", 8, 12) === "WEBP") {
    return { mimeType: "image/webp", extension: ".webp" };
  }
  if (buffer.length >= 5 && buffer.toString("ascii", 0, 5) === "%PDF-") {
    return { mimeType: "application/pdf", extension: ".pdf" };
  }
  return null;
}

function cleanText(value, label, maximum) {
  if (typeof value !== "string") throw new RequestError(400, `${label} is required.`);
  const cleaned = value.trim();
  if (!cleaned || cleaned.length > maximum) throw new RequestError(400, `${label} is required and must be at most ${maximum} characters.`);
  return cleaned;
}

function getDetails(body) {
  const fullName = cleanText(body.fullName, "Full name", 120);
  const email = normalizeEmail(body.email);
  const phone = cleanText(body.phone, "Phone number", 40);
  const country = cleanText(body.country, "Country or region", 100);
  const ssnInput = cleanText(body.ssn, "Social Security number", 11);
  const ssn = ssnInput.replaceAll("-", "");
  if (!/^[+()\d .-]{7,40}$/.test(phone)) throw new RequestError(400, "Enter a valid phone number.");
  if (!/^\d{9}$/.test(ssn)) throw new RequestError(400, "Enter a valid 9-digit Social Security number.");
  if (body.contactConsent !== "on") throw new RequestError(400, "Consent is required to submit this form.");
  return { fullName, email, phone, country, ssn, contactConsent: true };
}

function getRegistrationPassword(body) {
  validatePassword(body.accountPassword);
  if (body.accountPassword !== body.confirmPassword) {
    throw new RequestError(400, "The passwords do not match.");
  }
  return body.accountPassword;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 2, fields: 8, fieldSize: 2048, parts: 10 }
}).fields(FILE_FIELDS.map((name) => ({ name, maxCount: 1 })));

function getUploadedFiles(req) {
  const files = {};
  for (const fieldName of FILE_FIELDS) {
    const file = req.files && req.files[fieldName] && req.files[fieldName][0];
    if (!file) throw new RequestError(400, `Both sides of the driver's license are required (${fieldName}).`);
    const type = detectFileType(file.buffer);
    if (!type) throw new RequestError(400, "Files must be valid JPEG, PNG, WebP, or PDF documents.");
    files[fieldName] = { file, type };
  }
  return files;
}

async function writeNewFile(filePath, data) {
  await fs.writeFile(filePath, data, { flag: "wx", mode: 0o600 });
}

async function readRecord(id) {
  const encrypted = await fs.readFile(path.join(STORAGE_DIR, `${id}.record.enc`));
  return JSON.parse(decrypt(encrypted).toString("utf8"));
}

async function findSubmissionName(email) {
  const entries = await fs.readdir(STORAGE_DIR);
  for (const entry of entries) {
    if (!entry.endsWith(".record.enc")) continue;
    const id = entry.slice(0, -".record.enc".length);
    if (!UUID_PATTERN.test(id)) continue;
    const record = await readRecord(id);
    const fullName = record.details && record.details.fullName;
    if (record.details &&
        record.details.email === email &&
        Date.parse(record.expiresAt) > Date.now() &&
        typeof fullName === "string" &&
        fullName.trim() &&
        !fullName.includes("@")) {
      return fullName.trim();
    }
  }
  return null;
}

async function removeSubmission(id, record) {
  await Promise.all([
    fs.rm(path.join(STORAGE_DIR, `${id}.record.enc`), { force: true }),
    fs.rm(path.join(STORAGE_DIR, `${id}.front.enc`), { force: true }),
    fs.rm(path.join(STORAGE_DIR, `${id}.back.enc`), { force: true })
  ]);
  return record;
}

let cleanupInProgress = false;
async function purgeExpiredSubmissions() {
  if (cleanupInProgress) return;
  cleanupInProgress = true;
  try {
    await fs.mkdir(STORAGE_DIR, { recursive: true, mode: 0o700 });
    const entries = await fs.readdir(STORAGE_DIR);
    for (const entry of entries) {
      if (entry.endsWith(".front.enc") || entry.endsWith(".back.enc")) {
        const suffix = entry.endsWith(".front.enc") ? ".front.enc" : ".back.enc";
        const id = entry.slice(0, -suffix.length);
        if (!UUID_PATTERN.test(id)) continue;
        try {
          await fs.access(path.join(STORAGE_DIR, `${id}.record.enc`));
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
          const filePath = path.join(STORAGE_DIR, entry);
          const fileInfo = await fs.stat(filePath);
          if (Date.now() - fileInfo.mtimeMs >= RETENTION_MS) await fs.rm(filePath, { force: true });
        }
        continue;
      }
      if (!entry.endsWith(".record.enc")) continue;
      const id = entry.slice(0, -".record.enc".length);
      if (!UUID_PATTERN.test(id)) continue;
      try {
        const record = await readRecord(id);
        if (!Number.isFinite(Date.parse(record.expiresAt))) {
          throw new Error("Submission expiry is missing or invalid.");
        }
        if (Date.parse(record.expiresAt) <= Date.now()) await removeSubmission(id, record);
      } catch (error) {
        const recordPath = path.join(STORAGE_DIR, entry);
        const recordInfo = await fs.stat(recordPath);
        if (Date.now() - recordInfo.mtimeMs >= RETENTION_MS) {
          await removeSubmission(id, {});
        } else {
          console.error(`Unable to inspect submission ${id} for retention cleanup.`, error);
        }
      }
    }
  } catch (error) {
    console.error("Submission retention cleanup failed.", error);
  } finally {
    cleanupInProgress = false;
  }
}

app.get("/", (req, res) => res.redirect("/index.html"));
for (const page of ["index.html", "register.html", "signin.html", "admin.html"]) {
  app.get(`/${page}`, (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(path.join(ROOT, page));
  });
}

app.get("/dashboard.html", requireSecureTransport, requireUser, (req, res) => {
  res.sendFile(path.join(ROOT, "dashboard.html"));
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.post("/api/auth/login", requireSecureTransport, loginLimiter, express.json({ limit: "4kb" }), async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body && req.body.email);
    const password = req.body && req.body.password;
    if (typeof password !== "string" || Array.from(password).length > 128) {
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    const users = await readUsers();
    const user = users.find((item) => item.email === email);
    if (!user || !(await verifyPassword(password, user))) {
      if (!user) await hashPassword(password || "invalid-password");
      return res.status(401).json({ error: "Email or password is incorrect." });
    }
    const registeredName = await findSubmissionName(user.email);
    if (registeredName && user.fullName !== registeredName) {
      await withAccountLock(async () => {
        const currentUsers = await readUsers();
        const currentUser = currentUsers.find((item) => item.id === user.id);
        if (currentUser && currentUser.fullName !== registeredName) {
          currentUser.fullName = registeredName;
          await writeUsers(currentUsers);
        }
      });
    }
    setSessionCookie(res, user.id);
    res.set("Cache-Control", "no-store");
    res.json({ message: "Signed in." });
  } catch (error) {
    if (error instanceof RequestError) return res.status(error.status).json({ error: error.message });
    next(error);
  }
});

app.post("/api/auth/logout", (req, res) => {
  clearSessionCookie(res);
  res.set("Cache-Control", "no-store");
  res.status(204).end();
});

app.get("/api/auth/session", requireSecureTransport, requireUser, async (req, res, next) => {
  try {
    const name = req.user.name || await findSubmissionName(req.user.email);
    res.json({
      email: req.user.email,
      name: name || "Account",
      balanceCents: req.user.balanceCents
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/market/:symbol", requireSecureTransport, requireUser, rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false
}), async (req, res, next) => {
  try {
    const symbol = req.params.symbol.toUpperCase();
    if (!Object.hasOwn(MARKET_SYMBOLS, symbol)) {
      return res.status(400).json({ error: "Choose a supported market index." });
    }
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) {
      return res.status(503).json({ error: "Live market data is unavailable." });
    }
    const cached = marketDataCache.get(symbol);
    if (cached && Date.now() - cached.fetchedAt < MARKET_CACHE_MS) {
      res.set("Cache-Control", "no-store");
      return res.json(cached.data);
    }

    const timeSeriesUrl = new URL("https://api.twelvedata.com/time_series");
    timeSeriesUrl.search = new URLSearchParams({
      symbol,
      interval: "1day",
      outputsize: "30",
      apikey: apiKey
    }).toString();
    const quoteUrl = new URL("https://api.twelvedata.com/quote");
    quoteUrl.search = new URLSearchParams({ symbol, apikey: apiKey }).toString();
    let responses;
    try {
      responses = await Promise.all([
        fetch(timeSeriesUrl, { signal: AbortSignal.timeout(10000) }),
        fetch(quoteUrl, { signal: AbortSignal.timeout(10000) })
      ]);
    } catch (error) {
      if (error.name === "TimeoutError" || error.name === "AbortError") {
        return res.status(504).json({ error: "The market-data provider timed out. Try again shortly." });
      }
      console.error("Market-data provider request failed.", error.cause?.code || error.name);
      return res.status(502).json({ error: "The market-data provider could not be reached. Try again later." });
    }
    if (responses.some((response) => !response.ok)) {
      return res.status(502).json({ error: "The market-data provider could not be reached. Try again later." });
    }
    let providerResults;
    try {
      providerResults = await Promise.all(responses.map((response) => response.json()));
    } catch (error) {
      console.error("Market-data provider returned an invalid response.", error.name);
      return res.status(502).json({ error: "The market-data provider returned an invalid response." });
    }
    const [providerHistory, providerQuote] = providerResults;
    if (providerHistory.status === "error" || providerQuote.status === "error" ||
        !Array.isArray(providerHistory.values)) {
      const errorMessage = [providerHistory.message, providerQuote.message]
        .filter((message) => typeof message === "string")
        .join(" ");
      const quotaError = /limit|quota|credits/i.test(errorMessage);
      return res.status(quotaError ? 503 : 502).json({
        error: quotaError
          ? "The market-data provider limit was reached. Please wait before refreshing."
          : "Live market data is temporarily unavailable for this index."
      });
    }

    const values = providerHistory.values
      .map((item) => ({ date: item.datetime, close: Number(item.close) }))
      .filter((item) => typeof item.date === "string" && Number.isFinite(item.close) && item.close > 0)
      .sort((a, b) => a.date.localeCompare(b.date));
    const quotePrice = Number(providerQuote.close);
    const previousClose = Number(providerQuote.previous_close);
    const dailyChangePercent = Number(providerQuote.percent_change);
    if (values.length < 2 || !Number.isFinite(quotePrice) || quotePrice <= 0 ||
        !Number.isFinite(previousClose) || previousClose <= 0 ||
        !Number.isFinite(dailyChangePercent)) {
      return res.status(502).json({ error: "The market-data provider returned incomplete quote or chart data." });
    }

    const history = values.map((item, index) => ({
      date: item.date,
      close: index === values.length - 1 ? quotePrice : item.close,
      changePercent: index === values.length - 1
        ? dailyChangePercent
        : index === 0
          ? 0
          : ((item.close - values[index - 1].close) / values[index - 1].close) * 100
    }));
    const recentValues = values.slice(-20);
    const movingAverage20 = recentValues.length === 20
      ? recentValues.reduce((sum, item) => sum + item.close, 0) / recentValues.length
      : null;
    const twentyDayChangePercent = values.length >= 21
      ? ((quotePrice - values[values.length - 21].close) / values[values.length - 21].close) * 100
      : null;
    let signal = { label: "Insufficient history", direction: "neutral" };
    if (movingAverage20 !== null && twentyDayChangePercent !== null) {
      const alignedTrend = quotePrice > movingAverage20 && twentyDayChangePercent >= 0.5;
      const decliningTrend = quotePrice < movingAverage20 && twentyDayChangePercent <= -0.5;
      signal = alignedTrend
        ? { label: "Positive momentum", direction: "positive" }
        : decliningTrend
          ? { label: "Negative momentum", direction: "negative" }
          : { label: "Mixed / flat", direction: "neutral" };
    }
    const data = {
      symbol,
      name: MARKET_SYMBOLS[symbol],
      fetchedAt: new Date().toISOString(),
      currentPrice: quotePrice,
      previousClose,
      dailyChangePercent,
      twentyDayChangePercent,
      signal,
      history
    };
    marketDataCache.set(symbol, { fetchedAt: Date.now(), data });
    res.set("Cache-Control", "no-store");
    res.json(data);
  } catch (error) {
    next(error);
  }
});

app.post("/api/submissions", requireSecureTransport, requireIdentitySubmissionsEnabled, rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-8",
  legacyHeaders: false
}), (req, res, next) => {
  upload(req, res, (error) => {
    if (!error) return next();
    if (error instanceof multer.MulterError) {
      const tooLarge = error.code === "LIMIT_FILE_SIZE";
      return res.status(tooLarge ? 413 : 400).json({
        error: tooLarge ? "Each file must be 8 MB or smaller." : "Invalid upload. Attach one file for each side of the license."
      });
    }
    next(error);
  });
}, async (req, res, next) => {
  try {
    const details = getDetails(req.body);
    const password = getRegistrationPassword(req.body);
    const files = getUploadedFiles(req);
    const createdAccount = await withAccountLock(async () => {
      const users = await readUsers();
      if (users.some((user) => user.email === details.email)) {
        throw new RequestError(409, "An account with this email already exists. Sign in instead.");
      }
      const credentials = await hashPassword(password);
      const userId = crypto.randomUUID();
      const id = crypto.randomUUID();
      const receivedAt = new Date();
      const createdPaths = [];
      const record = {
        id,
        receivedAt: receivedAt.toISOString(),
        expiresAt: new Date(receivedAt.getTime() + RETENTION_MS).toISOString(),
        details,
        files: {}
      };

      await fs.mkdir(STORAGE_DIR, { recursive: true, mode: 0o700 });
      try {
        for (const [fieldName, { file, type }] of Object.entries(files)) {
          const side = fieldName === "driversLicenseFront" ? "front" : "back";
          const storagePath = path.join(STORAGE_DIR, `${id}.${side}.enc`);
          const originalName = path.basename(file.originalname).replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 180) || `license-${side}${type.extension}`;
          await writeNewFile(storagePath, encrypt(file.buffer));
          createdPaths.push(storagePath);
          record.files[side] = { originalName, mimeType: type.mimeType, size: file.size };
        }
        const recordPath = path.join(STORAGE_DIR, `${id}.record.enc`);
        await writeNewFile(recordPath, encrypt(Buffer.from(JSON.stringify(record), "utf8")));
        createdPaths.push(recordPath);
        users.push({
          id: userId,
          email: details.email,
          fullName: details.fullName,
          balanceCents: 0,
          passwordSalt: credentials.salt,
          passwordHash: credentials.passwordHash,
          createdAt: receivedAt.toISOString()
        });
        await writeUsers(users);
      } catch (error) {
        await Promise.all(createdPaths.map((filePath) => fs.rm(filePath, { force: true })));
        throw error;
      }
      return { id, userId };
    });
    setSessionCookie(res, createdAccount.userId);
    res.set("Cache-Control", "no-store");
    res.status(201).json({
      message: "Your account and submission were created securely.",
      id: createdAccount.id
    });
  } catch (error) {
    if (error instanceof RequestError) return res.status(error.status).json({ error: error.message });
    next(error);
  }
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.post("/api/admin/password", requireSecureTransport, adminLimiter, requireAdmin, express.json({ limit: "2kb" }), async (req, res, next) => {
  try {
    const { newPassword, confirmPassword } = req.body || {};
    validateAdminPassword(newPassword);
    if (newPassword !== confirmPassword) {
      throw new RequestError(400, "The new administrator passwords do not match.");
    }
    if (safeEqual(newPassword, adminPassword)) {
      throw new RequestError(400, "Choose a different administrator password.");
    }
    await saveAdminPassword(newPassword);
    adminPassword = newPassword;
    res.set("Cache-Control", "no-store");
    res.json({ message: "Administrator password changed." });
  } catch (error) {
    if (error instanceof RequestError) return res.status(error.status).json({ error: error.message });
    next(error);
  }
});

app.get("/api/admin/submissions", requireSecureTransport, adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    await fs.mkdir(STORAGE_DIR, { recursive: true, mode: 0o700 });
    const entries = await fs.readdir(STORAGE_DIR);
    const records = [];
    for (const entry of entries) {
      if (!entry.endsWith(".record.enc")) continue;
      const id = entry.slice(0, -".record.enc".length);
      if (!UUID_PATTERN.test(id)) continue;
      const record = await readRecord(id);
      if (Date.parse(record.expiresAt) > Date.now()) records.push(record);
    }
    records.sort((a, b) => b.receivedAt.localeCompare(a.receivedAt));
    res.json(records);
  } catch (error) {
    next(error);
  }
});

app.get("/api/admin/accounts", requireSecureTransport, adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const users = await readUsers();
    res.set("Cache-Control", "no-store");
    res.json(users
      .map(({ id, email, fullName, balanceCents, createdAt }) => ({
        id,
        email,
        fullName: fullName || email,
        balanceCents: balanceCents ?? 0,
        createdAt
      }))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  } catch (error) {
    next(error);
  }
});

app.post("/api/admin/accounts/:id/balance", requireSecureTransport, adminLimiter, requireAdmin, express.json({ limit: "1kb" }), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { action, amount } = req.body || {};
    if (!UUID_PATTERN.test(id)) return res.status(400).json({ error: "Invalid account." });
    if (!["add", "subtract"].includes(action) ||
        typeof amount !== "string" ||
        !/^\d{1,14}(?:\.\d{1,2})?$/.test(amount)) {
      return res.status(400).json({ error: "Choose add or subtract and enter a valid amount with up to two decimal places." });
    }
    const [whole, fraction = ""] = amount.split(".");
    const amountCents = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
    if (!Number.isSafeInteger(amountCents) || amountCents <= 0) {
      return res.status(400).json({ error: "Enter an amount greater than $0.00 within the supported range." });
    }

    let balanceCents;
    await withAccountLock(async () => {
      const users = await readUsers();
      const user = users.find((item) => item.id === id);
      if (!user) throw Object.assign(new Error("Account not found."), { code: "ENOENT" });
      const currentBalance = user.balanceCents ?? 0;
      if (!Number.isSafeInteger(currentBalance) || currentBalance < 0) {
        throw new Error("Account balance is invalid.");
      }
      balanceCents = action === "add"
        ? currentBalance + amountCents
        : currentBalance - amountCents;
      if (balanceCents < 0) {
        throw new RequestError(400, "The subtraction would take this account below $0.00.");
      }
      if (!Number.isSafeInteger(balanceCents)) {
        throw new RequestError(400, "The updated balance exceeds the supported range.");
      }
      user.balanceCents = balanceCents;
      await writeUsers(users);
    });

    res.set("Cache-Control", "no-store");
    res.json({ id, balanceCents });
  } catch (error) {
    if (error instanceof RequestError) return res.status(error.status).json({ error: error.message });
    if (error.code === "ENOENT") return res.status(404).json({ error: "Account not found." });
    next(error);
  }
});

app.delete("/api/admin/accounts/:id", requireSecureTransport, adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!UUID_PATTERN.test(id)) return res.status(400).json({ error: "Invalid account." });
    await withAccountLock(async () => {
      const users = await readUsers();
      const remainingUsers = users.filter((user) => user.id !== id);
      if (remainingUsers.length === users.length) throw Object.assign(new Error("Account not found."), { code: "ENOENT" });
      await writeUsers(remainingUsers);
    });
    res.status(204).end();
  } catch (error) {
    if (error.code === "ENOENT") return res.status(404).json({ error: "Account not found." });
    next(error);
  }
});

app.get("/api/admin/submissions/:id/:side", requireSecureTransport, adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const { id, side } = req.params;
    if (!UUID_PATTERN.test(id) || !["front", "back"].includes(side)) {
      return res.status(400).json({ error: "Invalid submission or document." });
    }
    const record = await readRecord(id);
    if (Date.parse(record.expiresAt) <= Date.now()) {
      await removeSubmission(id, record);
      return res.status(404).json({ error: "This submission has expired." });
    }
    const encryptedFile = await fs.readFile(path.join(STORAGE_DIR, `${id}.${side}.enc`));
    const plainFile = decrypt(encryptedFile);
    const document = record.files[side];
    const downloadName = document.originalName.replace(/[^\x20-\x7e]|["\\\r\n]/g, "_");
    res.set({
      "Cache-Control": "no-store",
      "Content-Type": document.mimeType,
      "Content-Length": String(plainFile.length),
      "Content-Disposition": `attachment; filename="${downloadName}"`
    });
    res.send(plainFile);
  } catch (error) {
    if (error.code === "ENOENT") return res.status(404).json({ error: "Document not found." });
    next(error);
  }
});

app.delete("/api/admin/submissions/:id", requireSecureTransport, adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!UUID_PATTERN.test(id)) return res.status(400).json({ error: "Invalid submission." });
    const record = await readRecord(id);
    await removeSubmission(id, record);
    res.status(204).end();
  } catch (error) {
    if (error.code === "ENOENT") return res.status(404).json({ error: "Submission not found." });
    next(error);
  }
});

app.use((error, req, res, next) => {
  console.error("Request failed.", error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "The request could not be completed. Please try again later." });
});

function rejectWebSocketUpgrade(socket, statusCode, statusText) {
  socket.write(`HTTP/1.1 ${statusCode} ${statusText}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

async function handleMarketWebSocketUpgrade(req, socket, head) {
  try {
    const requestUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
    if (requestUrl.pathname !== "/api/market-stream") {
      return rejectWebSocketUpgrade(socket, 404, "Not Found");
    }
    const origin = req.headers.origin;
    const expectedOrigin = `${req.secure ? "https" : "http"}://${req.headers.host}`;
    if (origin && origin !== expectedOrigin) {
      return rejectWebSocketUpgrade(socket, 403, "Forbidden");
    }
    if (process.env.NODE_ENV === "production" && !req.secure) {
      return rejectWebSocketUpgrade(socket, 400, "HTTPS Required");
    }
    const userId = getSessionUserId(req);
    const symbol = (requestUrl.searchParams.get("symbol") || "").toUpperCase();
    if (!userId) return rejectWebSocketUpgrade(socket, 401, "Unauthorized");
    if (!Object.hasOwn(MARKET_SYMBOLS, symbol)) return rejectWebSocketUpgrade(socket, 400, "Invalid Market");
    const apiKey = process.env.TWELVE_DATA_API_KEY;
    if (!apiKey) return rejectWebSocketUpgrade(socket, 503, "Market Data Unavailable");
    const users = await readUsers();
    if (!users.some((user) => user.id === userId)) {
      return rejectWebSocketUpgrade(socket, 401, "Unauthorized");
    }

    marketWebSocketServer.handleUpgrade(req, socket, head, (browserSocket) => {
      marketWebSocketServer.emit("connection", browserSocket, req, symbol, apiKey);
    });
  } catch (error) {
    console.error("Market quote stream authorization failed.", error.name);
    if (!socket.destroyed) rejectWebSocketUpgrade(socket, 500, "Internal Server Error");
  }
}

marketWebSocketServer.on("connection", (browserSocket, req, symbol, apiKey) => {
  const upstreamUrl = new URL("wss://ws.twelvedata.com/v1/quotes/price");
  upstreamUrl.searchParams.set("apikey", apiKey);
  const providerSocket = new WebSocket(upstreamUrl);
  let subscribed = false;
  const upstreamTimeout = setTimeout(() => {
    if (providerSocket.readyState === WebSocket.CONNECTING) providerSocket.terminate();
  }, 10000);

  browserSocket.send(JSON.stringify({ type: "status", status: "connecting" }));
  providerSocket.on("open", () => {
    clearTimeout(upstreamTimeout);
    providerSocket.send(JSON.stringify({
      action: "subscribe",
      params: { symbols: symbol }
    }));
    subscribed = true;
    if (browserSocket.readyState === WebSocket.OPEN) {
      browserSocket.send(JSON.stringify({ type: "status", status: "connected", symbol }));
    }
  });
  providerSocket.on("message", (message) => {
    try {
      const update = JSON.parse(message.toString());
      if (update.status === "error" || update.event === "error") {
        if (browserSocket.readyState === WebSocket.OPEN) {
          browserSocket.send(JSON.stringify({
            type: "error",
            message: "The market-data provider could not stream quotes for this index."
          }));
        }
        return;
      }
      if (update.event !== "price" || update.symbol !== symbol) return;
      const price = Number(update.price);
      if (!Number.isFinite(price) || price <= 0) return;
      if (browserSocket.readyState === WebSocket.OPEN) {
        browserSocket.send(JSON.stringify({
          type: "quote",
          symbol,
          price,
          timestamp: Number.isFinite(Number(update.timestamp)) ? Number(update.timestamp) : null
        }));
      }
    } catch (error) {
      console.error("Market quote stream returned an invalid message.", error.name);
    }
  });
  providerSocket.on("error", () => {
    clearTimeout(upstreamTimeout);
    if (browserSocket.readyState === WebSocket.OPEN) {
      browserSocket.send(JSON.stringify({ type: "error", message: "Live quote stream disconnected." }));
    }
    browserSocket.close(1011, "Live quote stream unavailable");
  });
  providerSocket.on("close", () => {
    clearTimeout(upstreamTimeout);
    if (browserSocket.readyState === WebSocket.OPEN) {
      if (!subscribed) browserSocket.send(JSON.stringify({ type: "error", message: "Live quote stream disconnected." }));
      browserSocket.close(1011, "Live quote stream disconnected");
    }
  });
  browserSocket.on("close", () => {
    clearTimeout(upstreamTimeout);
    if (providerSocket.readyState === WebSocket.OPEN || providerSocket.readyState === WebSocket.CONNECTING) {
      providerSocket.close();
    }
  });
});

async function start() {
  await fs.mkdir(STORAGE_DIR, { recursive: true, mode: 0o700 });
  await loadAdminPassword();
  await purgeExpiredSubmissions();
  setInterval(purgeExpiredSubmissions, 60 * 60 * 1000).unref();
  const server = http.createServer(app);
  server.on("upgrade", handleMarketWebSocketUpgrade);
  server.listen(port, host, () => {
    console.log(`Aivestora is available at http://${host}:${port}`);
    console.log("Private uploads are encrypted and retained for up to 30 days.");
  });
}

start().catch((error) => {
  console.error("The upload service could not start.", error);
  process.exitCode = 1;
});
