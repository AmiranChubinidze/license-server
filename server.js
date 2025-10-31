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
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const ADMIN_KEY = process.env.ADMIN_KEY || "change_this_admin_key";

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
  const expiresIn =
    options.expiresIn ?? (payload.type === "refresh" ? "30d" : "24h");
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

const issueAccessToken = (user) => issueToken(user, { type: "access", expiresIn: "24h" });
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
  const isCurrentMonth = year === now.getFullYear() && month === now.getMonth();
  const endDay = isCurrentMonth
    ? now.getUTCDate()
    : new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  const end = new Date(Date.UTC(year, month, endDay));

  const toIso = (date) =>
    `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(
      date.getUTCDate()
    ).padStart(2, "0")}`;

  return {
    start: toIso(start),
    end: toIso(end),
  };
}

async function fetchWaybillTotal({ su, sp }, monthKey) {
  const stub = String(process.env.STUB_SOAP || "").toLowerCase() === "true";
  if (stub) {
    const amount = Number(process.env.STUB_SOAP_AMOUNT || 12345.67);
    if (!Number.isFinite(amount)) return 12345.67;
    return Number(amount.toFixed(2));
  }

  const { start, end } = buildDateRange(monthKey);
  const soapEnvelope = `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <get_waybills_v1 xmlns="http://tempuri.org/">
      <su>${su}</su>
      <sp>${sp}</sp>
      <last_update_date_s>${start}</last_update_date_s>
      <last_update_date_e>${end}</last_update_date_e>
    </get_waybills_v1>
  </soap:Body>
</soap:Envelope>`;

  try {
    const response = await axios.post(
      "https://services.rs.ge/WayBillService/WayBillService.asmx?op=get_waybills_v1",
      soapEnvelope,
      {
        headers: {
          "Content-Type": "text/xml; charset=utf-8",
          SOAPAction: "http://tempuri.org/get_waybills_v1",
        },
        timeout: 120000,
      }
    );

    if (!response?.data || typeof response.data !== "string") {
      throw new Error("Empty response from RS SOAP service");
    }

    const matches = [...response.data.matchAll(/<(FULL_AMOUNT|AMOUNT)>([^<]+)<\/\1>/gi)];
    const total = matches.reduce((sum, match) => sum + normalizeAmount(match[2]), 0);
    return Number(total.toFixed(2));
  } catch (error) {
    const message = error?.response?.status
      ? `SOAP request failed (${error.response.status})`
      : error.message || "SOAP request failed";
    throw new Error(message);
  }
}

function ensureDatabase(res) {
  if (!db) {
    res.status(500).json({ success: false, error: "Database not initialized" });
    return false;
  }
  return true;
}

app.post("/auth", async (req, res) => {
  if (!ensureDatabase(res)) return;
  const su = (req.body?.su || "").trim();
  const sp = (req.body?.sp || "").trim();

  if (!su || !sp) {
    return res.status(400).json({ valid: false, message: "Missing credentials" });
  }

  try {
    const user = await findActiveUser(su);

    if (!user || !user.active || user.sp !== sp) {
      return res
        .status(401)
        .json({ valid: false, message: "???????? ???????????? ?? ??????" });
    }

    const token = issueToken(user);
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
  console.log("[/login] body:", body);

  const su = (body.su || "").trim();
  const sp = (body.sp || "").trim();
  console.log("[/login] trimmed su:", su);

  if (!fs.existsSync(DB_PATH)) {
    console.error(`[/login] Database file missing: ${DB_PATH}`);
    return res.status(500).json({ success: false, error: "Database file missing" });
  }

  if (!su || !sp) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }

  try {
    const user = await findActiveUser(su);
    console.log("[/login] user lookup:", user);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "???????? ???????????? ?? ??????" });
    }

    if (user.sp !== sp) {
      return res
        .status(401)
        .json({ success: false, message: "???????? ???????????? ?? ??????" });
    }

    if (!user.active) {
      return res.status(403).json({ success: false, message: "User is inactive" });
    }

    const token = issueAccessToken(user);
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

    const newToken = issueAccessToken(user);
    const newRefreshToken = issueRefreshToken(user);
    return res.json({
      success: true,
      token: newToken,
      refreshToken: newRefreshToken,
      user: serializeUser(user),
    });
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

    const newToken = issueToken(user);
    return res.json({ newToken });
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

  try {
    const decoded = decodeToken(token);
    const user = await findActiveUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ message: "User revoked or not found" });
    }

    const total = await fetchWaybillTotal(user, month);
    return res.json({ total });
  } catch (err) {
    console.error("Waybill total failed:", err?.message || err);
    return res.status(500).json({ message: err?.message || "Failed to calculate total" });
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
  const sp = (req.body?.sp || "").trim();
  const companyName = (req.body?.company_name || "").trim();

  if (!su || !sp || !companyName) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  try {
    await run(
      `INSERT INTO users (su, sp, company_name, active)
       VALUES (?, ?, ?, 1)
       ON CONFLICT(su) DO UPDATE SET
         sp = excluded.sp,
         company_name = excluded.company_name,
         active = 1,
         updated_at = CURRENT_TIMESTAMP`,
      [su, sp, companyName]
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
