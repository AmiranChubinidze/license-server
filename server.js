const path = require("path");
const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const { db, run, get, all, DB_PATH } = require("./db");
const dbExistsOnStartup = fs.existsSync(DB_PATH);
console.log(`[DB] Path: ${DB_PATH} | exists: ${dbExistsOnStartup}`);

require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();
const allowedOrigins = [
  "https://amnairi.xyz",
  "https://www.amnairi.xyz",
  "https://amnairi.onrender.com",
  "https://license-server-z3vf.onrender.com",
  "http://localhost:3000",
  "chrome-extension://hmkndkpjehkgomaedmaghccedjfgkkeb",
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-admin-key"],
  })
);
console.log("[CORS] Allowed origins:", allowedOrigins);
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const ADMIN_KEY = process.env.ADMIN_KEY || "change_this_admin_key";
const SOAP_DATE_KEYS = ["create_date", "last_update_date"];
let soapDateKey = SOAP_DATE_KEYS[0];

const REQUIRED_USER_COLUMNS = [
  {
    name: "su",
    ddl: "ALTER TABLE users ADD COLUMN su TEXT NOT NULL UNIQUE",
    description: "TEXT NOT NULL UNIQUE",
  },
  {
    name: "sp",
    ddl: "ALTER TABLE users ADD COLUMN sp TEXT NOT NULL DEFAULT ''",
    description: "TEXT NOT NULL DEFAULT ''",
  },
  {
    name: "company_name",
    ddl: "ALTER TABLE users ADD COLUMN company_name TEXT NOT NULL DEFAULT ''",
    description: "TEXT NOT NULL DEFAULT ''",
  },
  {
    name: "active",
    ddl: "ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
    description: "INTEGER NOT NULL DEFAULT 1",
  },
  {
    name: "updated_at",
    ddl: "ALTER TABLE users ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP",
    description: "DATETIME DEFAULT CURRENT_TIMESTAMP",
  },
];

async function logUsersTableSchema(tag) {
  try {
    const info = await all("PRAGMA table_info(users)");
    if (Array.isArray(info)) {
      console.log(`[DB] Users schema snapshot${tag ? ` (${tag})` : ""}:`);
      console.table(info);
    } else {
      console.log("[DB] PRAGMA table_info(users) returned no rows");
    }
    return Array.isArray(info) ? info : [];
  } catch (err) {
    console.error("[DB] Failed to inspect users table:", err?.message || err);
    return [];
  }
}

async function migrateUsersTableColumns() {
  const info = await logUsersTableSchema("before migration");
  const columnsPresent = new Set(info.map((col) => col.name));
  const missingColumns = REQUIRED_USER_COLUMNS.filter(
    (col) => !columnsPresent.has(col.name)
  );

  if (!missingColumns.length) {
    console.log("[DB] Users table already has all required columns");
    await logUsersTableSchema("verified");
    return;
  }

  for (const col of missingColumns) {
    try {
      await run(col.ddl);
      console.log(
        `[DB MIGRATION] Added missing column: ${col.name} (${col.description})`
      );
    } catch (err) {
      console.error(
        `[DB MIGRATION] Failed to add column ${col.name}:`,
        err?.message || err
      );
      throw err;
    }
  }

  await logUsersTableSchema("after migration");
}

async function autodetectSoapDateKey() {
  try {
    const user = await get(
      "SELECT su, sp FROM users WHERE TRIM(IFNULL(sp, '')) <> '' LIMIT 1"
    );
    if (!user) {
      console.warn("[SOAP] Skipping date parameter autodetect; no users with stored SP");
      return;
    }
    const probeRange = buildProbeRange();
    for (const key of SOAP_DATE_KEYS) {
      try {
        const xml = await requestWaybillXml(user, probeRange, key);
        const statusCode = extractSoapStatus(xml);
        if (statusCode === -100) {
          console.warn(`[SOAP] Probe with ${key}_s/e returned STATUS -100`);
          continue;
        }
        soapDateKey = key;
        console.log(`[SOAP] Using ${soapDateKey}_s/e for all calls`);
        return;
      } catch (err) {
        console.error(`[SOAP] Probe using ${key}_s/e failed:`, err?.message || err);
      }
    }
    soapDateKey = SOAP_DATE_KEYS[0];
    console.warn("[SOAP] Autodetect failed; defaulting to create_date");
  } catch (err) {
    console.error("[SOAP] Autodetect skipped due to error:", err?.message || err);
  }
}

async function initDb() {
  if (!db) {
    console.error("Database not initialized; skipping migrations.");
    return;
  }
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      su TEXT NOT NULL UNIQUE,
      sp TEXT NOT NULL,
      company_name TEXT NOT NULL,
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await run(`CREATE INDEX IF NOT EXISTS users_su_idx ON users (su)`);
  await migrateUsersTableColumns();
  await autodetectSoapDateKey();
}



function requireAdmin(req, res, next) {
  const key = req.headers["x-admin-key"] || req.body?.adminKey;
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ success: false, message: "Unauthorized" });
  }
  return next();
}

function serializeUser(record) {
  if (!record) return null;
  return {
    name: record.company_name,
    su: record.su,
  };
}

function extractToken(req) {
  const header = (req.headers?.authorization || req.headers?.Authorization || "").trim();
  if (header.startsWith("Bearer ")) {
    return header.slice(7).trim();
  }
  if (req.query?.token) return req.query.token;
  if (req.body?.token) return req.body.token;
  if (req.body?.refreshToken) return req.body.refreshToken;
  return null;
}

async function findActiveUser(su) {
  if (!su) return null;
  return await get(
    "SELECT su, sp, company_name, active FROM users WHERE su = ?",
    [su]
  );
}

function issueToken(user, options = {}) {
  const payload = {
    su: user.su,
    name: user.company_name,
    type: options.type ?? "access",
  };

  if (options.extraClaims && typeof options.extraClaims === "object") {
    Object.assign(payload, options.extraClaims);
  }

  const expiresIn =
    options.expiresIn ?? (payload.type === "refresh" ? "30d" : "24h");
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

const issueAccessToken = (user, { sp } = {}) =>
  issueToken(user, {
    type: "access",
    expiresIn: "24h",
    extraClaims: sp ? { sp } : undefined,
  });
const issueRefreshToken = (user) => issueToken(user, { type: "refresh", expiresIn: "30d" });

function decodeToken(token, options = {}) {
  return jwt.verify(token, JWT_SECRET, options);
}

function normalizeAmount(raw) {
  if (typeof raw !== "string") return 0;
  const cleaned = raw.replace(/\s+/g, "").replace(/,/g, ".").replace(/[^\d.-]/g, "");
  const value = Number.parseFloat(cleaned);
  return Number.isFinite(value) ? value : 0;
}

function buildDateRange(monthKey) {
  const now = new Date();
  let year = now.getFullYear();
  let month = now.getMonth();

  if (typeof monthKey === "string" && /^\d{4}-\d{2}$/.test(monthKey)) {
    const [y, m] = monthKey.split("-").map(Number);
    year = y;
    month = m - 1;
  }

  const start = new Date(Date.UTC(year, month, 1));
  const end = new Date(Date.UTC(year, month + 1, 0));

  const toIso = (date) =>
    `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(
      date.getUTCDate()
    ).padStart(2, "0")}`;

  return {
    start: toIso(start),
    end: toIso(end),
  };
}

function formatIsoDateUTC(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(
    date.getUTCDate()
  ).padStart(2, "0")}`;
}

function buildProbeRange() {
  const now = new Date();
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  start.setUTCDate(start.getUTCDate() - 1);
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  end.setUTCDate(end.getUTCDate() + 1);
  return {
    start: formatIsoDateUTC(start),
    end: formatIsoDateUTC(end),
  };
}

function sanitizeSoapDateKey(key) {
  return SOAP_DATE_KEYS.includes(key) ? key : SOAP_DATE_KEYS[0];
}

async function fetchWaybillTotal({ su, sp }, monthKey) {
  const { start, end } = buildDateRange(monthKey);
  try {
    const xml = await requestWaybillXml({ su, sp }, { start, end });
    const amountMatches = [
      ...xml.matchAll(/<([A-Za-z0-9_:]*?(?:FULL_AMOUNT|AMOUNT))>([\d\s.,-]+)<\/\1>/gi),
    ];
    console.log(`[SOAP] Found ${amountMatches.length} amounts`);
    const statusCode = extractSoapStatus(xml);
    if (typeof statusCode === "number") {
      handleSoapStatus(statusCode, su);
    }

    if (!amountMatches.length) {
      console.log("[SOAP] Total parsed: 0.00");
      return { total: 0, message: "No waybills found" };
    }

    const combined = amountMatches
      .map((match) => normalizeAmount(match[2] || "0"))
      .reduce((sum, amount) => sum + amount, 0);

    const total = Number(combined.toFixed(2));
    console.log(`[SOAP] Total parsed: ${total.toFixed(2)}`);
    return { total, message: "OK" };
  } catch (err) {
    console.error("[SOAP] Request failed:", err?.message || err);
    if (err?.isSoapError) {
      throw err;
    }
    const error = new Error(err?.message || "SOAP request failed");
    error.isSoapError = true;
    throw error;
  }
}

async function requestWaybillXml(credentials, range, overrideKey) {
  const key = sanitizeSoapDateKey(overrideKey || soapDateKey);
  const startTag = `${key}_s`;
  const endTag = `${key}_e`;
  const xmlBody = `
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <get_waybills_v1 xmlns="http://tempuri.org/">
      <su>${credentials.su}</su>
      <sp>${credentials.sp}</sp>
      <${startTag}>${range.start}</${startTag}>
      <${endTag}>${range.end}</${endTag}>
    </get_waybills_v1>
  </soap:Body>
</soap:Envelope>`.trim();

  console.log(
    `[SOAP] Request started for ${credentials.su} (${range.start}..${range.end}) using ${key}_s/e`
  );
  const response = await axios.post(
    "https://services.rs.ge/WayBillService/WayBillService.asmx?op=get_waybills_v1",
    xmlBody,
    {
      headers: {
        "Content-Type": "text/xml; charset=UTF-8",
        SOAPAction: "http://tempuri.org/get_waybills_v1",
        "Accept-Charset": "UTF-8",
      },
      timeout: 120000,
      responseType: "arraybuffer",
    }
  );

  if (!response?.data) {
    throw new Error("Empty response from RS SOAP service");
  }

  const xml = Buffer.from(response.data).toString("utf8");
  console.log(`[SOAP] Response length: ${xml.length}`);
  return xml;
}

function extractSoapStatus(xml) {
  const match = xml.match(/<STATUS>(-?\d+)<\/STATUS>/i);
  if (!match) return null;
  const value = Number.parseInt(match[1], 10);
  return Number.isNaN(value) ? null : value;
}

function handleSoapStatus(statusCode, su) {
  if (statusCode === -1072) {
    const error = new Error("User lacks RS.ge permissions");
    error.isSoapError = true;
    error.soapStatus = -1072;
    error.httpStatus = 403;
    error.su = su;
    throw error;
  }
  if (statusCode === -100) {
    const error = new Error("RS.ge rejected date parameters");
    error.isSoapError = true;
    error.soapStatus = -100;
    error.su = su;
    throw error;
  }
}

function ensureDatabase(res) {
  if (!db) {
    res.status(500).json({ success: false, error: "Database not initialized" });
    return false;
  }
  return true;
}

function selectEffectiveSp(userSp, providedSp, su) {
  const stored = (userSp || "").trim();
  if (stored) return stored;
  if (typeof providedSp === "string" && providedSp.trim()) return providedSp.trim();
  console.warn(`[AUTH] Missing SP for ${su}`);
  return null;
}

app.post("/auth", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const su = (req.body?.su || "").trim();
  const sp = typeof req.body?.sp === "string" ? req.body.sp : "";

  if (!su || !sp) {
    return res.status(400).json({ valid: false, message: "Missing credentials" });
  }

  try {
    const user = await findActiveUser(su);

    if (!user || !user.active) {
      return res
        .status(401)
        .json({ valid: false, message: "???????? ???????????? ?? ??????" });
    }

    const token = issueAccessToken(user, { sp });
    return res.json({
      valid: true,
      token,
      label: user.company_name,
      expiresInHours: 24,
    });
  } catch (err) {
    console.error("Auth error:", err);
    return res.status(500).json({ valid: false, message: "Server error" });
  }
});
app.get("/ping", (_req, res) => res.json({ ok: true }))
console.log("Loaded routes: /login, /verify, /refresh, /waybill/total");
app.post("/login", async (req, res) => {
  if (!ensureDatabase(res)) return;

  const body = req.body || {};

  const su = (body.su || "").trim();
  const sp = typeof body.sp === "string" ? body.sp : "";
  console.log("[/login] Login attempt for SU:", su);

  if (!fs.existsSync(DB_PATH)) {
    console.error(`[/login] Database file missing: ${DB_PATH}`);
    return res.status(500).json({ success: false, error: "Database file missing" });
  }

  if (!su) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }

  try {
    const user = await findActiveUser(su);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "???????? ???????????? ?? ??????" });
    }

    if (!user.active) {
      return res.status(403).json({ success: false, message: "User is inactive" });
    }

    const effectiveSp = selectEffectiveSp(user.sp, sp, su);
    if (!effectiveSp) {
      return res.status(400).json({ success: false, message: "Missing credentials" });
    }

    const token = issueAccessToken(user, { sp: effectiveSp });
    const refreshToken = issueRefreshToken(user);
    return res.json({
      success: true,
      token,
      refreshToken,
      user: serializeUser(user),
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/loginHybrid", async (req, res) => {
  if (!ensureDatabase(res)) return;

  const su = (req.body?.su || "").trim();
  const sp = typeof req.body?.sp === "string" ? req.body.sp : "";
  console.log("[/loginHybrid] Login attempt for SU:", su);

  if (!su || !sp) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }

  try {
    const user = await findActiveUser(su);

    if (!user || !user.active) {
      return res
        .status(401)
        .json({ success: false, message: "User not found or inactive" });
    }

    const token = issueAccessToken(user, { sp });
    const refreshToken = issueRefreshToken(user);
    return res.json({
      success: true,
      token,
      refreshToken,
      user: serializeUser(user),
    });
  } catch (err) {
    console.error("[/loginHybrid] Login error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/debug/users", async (_req, res) => {
  if (!ensureDatabase(res)) return;

  if (!fs.existsSync(DB_PATH)) {
    console.error(`[/debug/users] Database file missing: ${DB_PATH}`);
    return res.status(500).json({ success: false, error: "Database file missing" });
  }

  try {
    const records = await all("SELECT su, active FROM users ORDER BY su ASC");
    return res.json({ users: records.map((record) => ({ su: record.su, active: record.active })) });
  } catch (err) {
    console.error("[/debug/users] Failed to list users:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get("/verify", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const token = extractToken(req);
  if (!token) {
    return res.status(400).json({ valid: false, message: "Missing token" });
  }

  try {
    const decoded = decodeToken(token);
    const user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ valid: false, message: "User revoked or not found" });
    }

    return res.json({ valid: true, user: serializeUser(user) });
  } catch (err) {
    return res.status(401).json({ valid: false, message: "Invalid or expired token" });
  }
});

app.post("/refresh", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const incoming = extractToken(req);
  if (!incoming) {
    return res.status(400).json({ success: false, message: "Missing token" });
  }

  try {
    const decoded = decodeToken(incoming);
    if (decoded.type && decoded.type !== "refresh") {
      return res.status(400).json({ success: false, message: "Refresh token required" });
    }
    const user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ success: false, message: "User revoked or not found" });
    }

    return res
      .status(401)
      .json({ success: false, message: "Re-authentication required" });
  } catch (err) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
});

app.post("/auth/refresh", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const token = req.body?.token;
  if (!token) {
    return res.status(400).json({ message: "Missing token" });
  }

  try {
    const decoded = decodeToken(token, { ignoreExpiration: false });
    const user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ message: "User revoked or not found" });
    }

    return res.status(401).json({ message: "Re-authentication required" });
  } catch (err) {
    console.warn("Token refresh failed:", err?.message || err);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
});

app.post("/validateToken", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const token = req.body?.token;
  if (!token) {
    return res.json({ valid: false, message: "Missing token" });
  }

  try {
    const decoded = decodeToken(token);
    const user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.json({ valid: false, message: "Token revoked" });
    }

    return res.json({
      valid: true,
      label: user.company_name,
      su: decoded.su,
    });
  } catch (err) {
    return res.json({ valid: false, message: "Token invalid" });
  }
});

app.post("/waybill/total", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const token = extractToken(req);
  const month = req.body?.month;
  if (!token) {
    return res.status(400).json({ message: "Missing token" });
  }

  let user;
  try {
    const decoded = decodeToken(token);
    user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ message: "User revoked or not found" });
    }

    const effectiveSp = selectEffectiveSp(user.sp, decoded.sp, decoded.su);
    if (!effectiveSp) {
      return res.status(401).json({ message: "Session expired; please login again" });
    }

    const result = await fetchWaybillTotal({ su: user.su, sp: effectiveSp }, month);
    if (result && typeof result === "object" && result !== null) {
      const totalValue = Number.isFinite(result.total) ? Number(result.total) : 0;
      return res.json({
        total: totalValue.toFixed(2),
        message: result.message || "OK",
      });
    }

    const total = Number.isFinite(result) ? Number(result) : 0;
    return res.json({ total: total.toFixed(2), message: "OK" });
  } catch (err) {
    if (err?.soapStatus === -1072) {
      console.warn(
        `[SOAP] SU ${user?.su || "unknown"} returned STATUS -1072 (no permission)`
      );
      return res
        .status(403)
        .json({ success: false, code: -1072, message: "User lacks RS.ge permissions" });
    }
    console.error("Waybill total failed:", err?.message || err);
    if (err?.isSoapError) {
      return res.status(502).json({
        message: "RS.ge SOAP error",
        details: err.message || "SOAP request failed",
      });
    }

    const isJwtError =
      err?.name === "JsonWebTokenError" ||
      err?.name === "TokenExpiredError" ||
      err?.name === "NotBeforeError";
    if (isJwtError) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    return res
      .status(500)
      .json({ message: err?.message || "Failed to calculate total" });
  }
});

app.get("/admin/users", requireAdmin, async (req, res) => {
  if (!ensureDatabase(res)) return;
  try {
    const users = await all(
      "SELECT id, su, company_name, active, created_at, updated_at FROM users ORDER BY company_name ASC"
    );
    return res.json({ success: true, users });
  } catch (err) {
    console.error("List users failed:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.post("/admin/addUser", requireAdmin, async (req, res) => {
  if (!ensureDatabase(res)) return;
  const su = (req.body?.su || "").trim();
  const companyName = (req.body?.company_name || "").trim();

  if (!su || !companyName) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  try {
    const placeholderSp = "";
    await run(
      `INSERT INTO users (su, sp, company_name, active)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(su) DO UPDATE SET
         sp = excluded.sp,
         company_name = excluded.company_name,
         active = 1,
         updated_at = CURRENT_TIMESTAMP`,
      [su, placeholderSp, companyName]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("Add user failed:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.post("/admin/revokeUser", requireAdmin, async (req, res) => {
  if (!ensureDatabase(res)) return;
  const su = (req.body?.su || "").trim();
  if (!su) {
    return res.status(400).json({ success: false, message: "Missing SU" });
  }

  try {
    const result = await run(
      `UPDATE users
       SET active = 0,
           updated_at = CURRENT_TIMESTAMP
       WHERE su = ?`,
      [su]
    );

    if (!result.changes) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.json({ success: true });
  } catch (err) {
    console.error("Revoke user failed:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

app.use(express.static(__dirname));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "admin.html")));

app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  const status = err?.status || err?.statusCode || 500;
  res.status(status).json({
    success: false,
    error: err?.message || "Internal server error",
  });
});

const PORT = process.env.PORT || 3000;

initDb()
  .then(() => {
    if (String(process.env.STUB_SOAP || "").toLowerCase() === "true") {
      const a = Number(process.env.STUB_SOAP_AMOUNT || 12345.67);
      console.log(`[STUB] SOAP disabled; returning total = ${a.toFixed(2)}`);
    }
    const server = app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on ${PORT}`);
    });
    server.keepAliveTimeout = 120000;
    server.headersTimeout = 125000;
  })
  .catch((err) => {
    console.error("DB initialization failed:", err);
  });
