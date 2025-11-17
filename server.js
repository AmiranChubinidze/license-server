const path = require("path");
const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const xml2js = require("xml2js");
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
  "chrome-extension://modggbahbkbgcmpnhjbfjfpncolajcde",
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
const SOAP_DATE_KEY_OVERRIDE = process.env.SOAP_DATE_KEY
  ? sanitizeSoapDateKey(process.env.SOAP_DATE_KEY)
  : null;
let soapDateKey = SOAP_DATE_KEY_OVERRIDE || SOAP_DATE_KEYS[0];
const WAYBILL_ALLOWED_STATUSES = new Set(["1", "3", "4"]);
const WAYBILL_EXCLUDED_TYPE = "6";
const WAYBILL_AMOUNT_FIELDS = ["FULL_AMOUNT", "AMOUNT", "TOTAL_AMOUNT", "SUM_AMOUNT"];
const WAYBILL_ID_KEYS = ["WAYBILL_ID", "WB_ID", "ID", "DOC_ID", "WAYBILLID"];
const WAYBILL_PARENT_KEYS = ["PAR_ID", "PARENT_ID", "CORRECTED_ID", "CORR_ID"];
const WAYBILL_SELLER_KEYS = ["SELER_UN_ID", "SELLER_UN_ID", "SELLER_ID"];
const WAYBILL_BUYER_TIN_KEYS = ["BUYER_TIN", "BUYERID", "BUYER_ID"];
const WAYBILL_TRANSPORTER_TIN_KEYS = ["TRANSPORTER_TIN", "TRANSPORTERID", "TRANSPORTER_ID"];
const WAYBILL_CANDIDATE_FIELDS = new Set([
  "FULL_AMOUNT",
  "AMOUNT",
  "TOTAL_AMOUNT",
  "SUM_AMOUNT",
  "STATUS",
  "TYPE",
  "PAR_ID",
  "PARENT_ID",
  "WAYBILL_ID",
  "WB_ID",
  "ID",
  "DOC_ID",
  "SELER_UN_ID",
  "SELLER_UN_ID",
  "BUYER_TIN",
]);
const { stripPrefix } = xml2js.processors;
const SOAP_DATASET_PARSER = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs: false,
  tagNameProcessors: [stripPrefix],
  attrNameProcessors: [stripPrefix],
  trim: true,
});
const WAYBILL_FILTER_CONFIG = createWaybillFilterConfig(process.env);

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
  if (SOAP_DATE_KEY_OVERRIDE) {
    console.log(
      `[SOAP] Using ${soapDateKey}_s/e from SOAP_DATE_KEY environment override`
    );
    return;
  }
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
  if (typeof raw === "number") {
    return Number.isFinite(raw) ? raw : 0;
  }
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

function chunkDateRange(range, windowDays = 3) {
  const startDate = new Date(`${range.start}T00:00:00Z`);
  const endDate = new Date(`${range.end}T00:00:00Z`);
  const chunks = [];
  if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
    return chunks;
  }
  let cursor = new Date(startDate);
  while (cursor <= endDate) {
    const chunkStart = new Date(cursor);
    const chunkEnd = new Date(cursor);
    chunkEnd.setUTCDate(chunkEnd.getUTCDate() + windowDays - 1);
    if (chunkEnd > endDate) {
      chunkEnd.setTime(endDate.getTime());
    }
    chunks.push({
      start: formatIsoDateUTC(chunkStart),
      end: formatIsoDateUTC(chunkEnd),
    });
    cursor.setUTCDate(cursor.getUTCDate() + windowDays);
  }
  return chunks;
}

function sanitizeSoapDateKey(key) {
  return SOAP_DATE_KEYS.includes(key) ? key : SOAP_DATE_KEYS[0];
}

async function fetchWaybillTotal(credentials, monthKey) {
  const range = buildDateRange(monthKey);
  try {
    const xml = await requestWaybillXml(credentials, range);
    const summary = await summarizeWaybillTotalsFromXml(xml, credentials.su);
    logWaybillSummary(summary);
    return summary;
  } catch (err) {
    if (err?.soapStatus === -1072) {
      try {
        return await fetchWaybillTotalInChunks(credentials, range);
      } catch (chunkErr) {
        if (!chunkErr.isSoapError) {
          chunkErr.isSoapError = true;
        }
        throw chunkErr;
      }
    }
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
    const error = new Error("RS.ge returned STATUS -1072");
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

async function summarizeWaybillTotalsFromXml(xml, su) {
  const statusCode = extractSoapStatus(xml);
  if (typeof statusCode === "number") {
    handleSoapStatus(statusCode, su);
  }

  const { records } = await parseWaybillRecords(xml);
  const processed = records.length;

  if (!processed) {
    return {
      total: 0,
      included: 0,
      excluded: 0,
      processed: 0,
      message: "No waybills found",
    };
  }

  const filtered = filterWaybillRecords(records, WAYBILL_FILTER_CONFIG);
  const summary = {
    total: Number(filtered.total.toFixed(2)),
    included: filtered.included,
    excluded: filtered.excluded,
    processed,
    message: "OK",
  };

  if (filtered.logs?.length) {
    summary.logs = filtered.logs;
  }

  return summary;
}

function logWaybillSummary(summary) {
  const processed = Number.isFinite(summary?.processed) ? summary.processed : 0;
  const included = Number.isFinite(summary?.included) ? summary.included : 0;
  const excluded = Number.isFinite(summary?.excluded) ? summary.excluded : 0;
  const total = Number.isFinite(summary?.total) ? Number(summary.total).toFixed(2) : "0.00";
  console.log(
    `[WAYBILL_SUMMARY] Total count: ${processed} | Included: ${included} | Excluded: ${excluded} | Total: ${total}`
  );
}

function extractWaybillDatasetXml(xml) {
  if (typeof xml !== "string") {
    return "";
  }
  const match = xml.match(/<get_waybills_v1Result[^>]*>([\s\S]*?)<\/get_waybills_v1Result>/i);
  if (!match) {
    return "";
  }
  let payload = match[1]?.trim() || "";
  if (!payload) {
    return "";
  }
  if (payload.startsWith("<![CDATA[")) {
    payload = payload.replace(/^<!\[CDATA\[/i, "").replace(/\]\]>$/i, "");
  }
  return decodeHtmlEntities(payload);
}

async function parseWaybillRecords(xml) {
  try {
    const datasetXml = extractWaybillDatasetXml(xml);
    if (!datasetXml) {
      return { records: [] };
    }
    const dataset = await SOAP_DATASET_PARSER.parseStringPromise(datasetXml);
    const records = collectWaybillRows(dataset);
    return { records };
  } catch (err) {
    console.error("[SOAP] Failed to parse waybill dataset:", err?.message || err);
    return { records: [] };
  }
}

function decodeHtmlEntities(payload) {
  if (typeof payload !== "string") return "";
  return payload
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function collectWaybillRows(tree) {
  const rows = [];
  const seen = new Set();

  function walk(node) {
    if (!node || typeof node !== "object") {
      return;
    }
    if (seen.has(node)) {
      return;
    }
    seen.add(node);

    if (Array.isArray(node)) {
      node.forEach((child) => walk(child));
      return;
    }

    if (looksLikeWaybillRecord(node)) {
      rows.push(normalizeWaybillRecord(node));
      return;
    }

    for (const value of Object.values(node)) {
      walk(value);
    }
  }

  walk(tree);
  return rows;
}

function looksLikeWaybillRecord(node) {
  if (!node || typeof node !== "object") {
    return false;
  }
  const keys = Object.keys(node).map((key) => key.toUpperCase());
  const markerHits = keys.filter((key) => WAYBILL_CANDIDATE_FIELDS.has(key));
  const hasAmount = keys.some((key) => WAYBILL_AMOUNT_FIELDS.includes(key));
  return markerHits.length >= 2 && hasAmount;
}

function normalizeWaybillRecord(node) {
  const normalized = {};
  for (const [key, value] of Object.entries(node)) {
    const upperKey = key.toUpperCase();
    normalized[upperKey] = extractScalarValue(value);
  }
  return normalized;
}

function extractScalarValue(value) {
  if (Array.isArray(value)) {
    if (value.length === 1) {
      return extractScalarValue(value[0]);
    }
    return value.map((entry) => extractScalarValue(entry));
  }
  if (value && typeof value === "object") {
    if (Object.prototype.hasOwnProperty.call(value, "_")) {
      return extractScalarValue(value._);
    }
    return value;
  }
  if (typeof value === "string") {
    return value.trim();
  }
  return value ?? "";
}

function filterWaybillRecords(records, config) {
  const logBuffer = config.debugLogs ? [] : null;
  const included = [];
  let excludedCount = 0;

  const { correctedParentIds, childByParentId } = buildCorrectionIndex(records);

  for (const record of records) {
    const reason = determineExclusionReason(record, config, {
      correctedParentIds,
      childByParentId,
    });
    if (reason) {
      excludedCount += 1;
      emitFilterLog(logBuffer, reason);
      continue;
    }
    included.push(record);
  }

  const total = included.reduce((acc, record) => acc + extractAmountFromRecord(record), 0);

  return {
    total,
    included: included.length,
    excluded: excludedCount,
    logs: logBuffer || undefined,
  };
}

function extractAmountFromRecord(record) {
  for (const key of WAYBILL_AMOUNT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      continue;
    }
    const rawValue = Array.isArray(record[key]) ? record[key][0] : record[key];
    const amount = normalizeAmount(rawValue);
    if (Number.isFinite(amount)) {
      return amount;
    }
  }
  return 0;
}

function buildCorrectionIndex(records) {
  const correctedParentIds = new Set();
  const childByParentId = new Map();
  for (const record of records) {
    const parentId = resolveParentId(record);
    const childId = resolveWaybillId(record);
    if (parentId) {
      correctedParentIds.add(parentId);
      if (childId) {
        childByParentId.set(parentId, childId);
      }
    }
  }
  return { correctedParentIds, childByParentId };
}

function resolveWaybillId(record) {
  const raw = getFirstValue(record, WAYBILL_ID_KEYS);
  if (raw === undefined || raw === null || raw === "") return "";
  return String(raw).trim();
}

function resolveParentId(record) {
  const raw = getFirstValue(record, WAYBILL_PARENT_KEYS);
  if (raw === undefined || raw === null || raw === "") return "";
  return String(raw).trim();
}

function getFirstValue(record, keys) {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(record, key)) {
      const value = record[key];
      if (Array.isArray(value)) {
        return value[0];
      }
      return value;
    }
  }
  return "";
}

function determineExclusionReason(record, config, correctionContext) {
  const id = resolveWaybillId(record) || "unknown";
  const status = String(record.STATUS ?? "").trim();
  const normalizedStatus = status ? String(Number(status) || status).trim() : "";
  if (normalizedStatus && !WAYBILL_ALLOWED_STATUSES.has(normalizedStatus)) {
    return `Skipped STATUS=${normalizedStatus} waybill ID=${id}`;
  }

  const typeValue = String(record.TYPE ?? "").trim();
  const normalizedType = typeValue ? String(Number(typeValue) || typeValue).trim() : "";
  if (normalizedType === WAYBILL_EXCLUDED_TYPE) {
    return `Excluded TYPE=${WAYBILL_EXCLUDED_TYPE} sub-waybill ID=${id}`;
  }

  if (id && correctionContext.correctedParentIds.has(id)) {
    const child = correctionContext.childByParentId.get(id);
    if (child) {
      return `Excluded corrected parent ID=${id} replaced_by=${child}`;
    }
    return `Excluded corrected parent ID=${id}`;
  }

  const sellerUnId = String(getFirstValue(record, WAYBILL_SELLER_KEYS) || "").trim();
  const buyerTin = normalizeTin(getFirstValue(record, WAYBILL_BUYER_TIN_KEYS));
  const transporterTin = normalizeTin(getFirstValue(record, WAYBILL_TRANSPORTER_TIN_KEYS));

  const hasPartyContext = Boolean(config.mySellerUnId || config.myTin);
  const isSeller = Boolean(config.mySellerUnId && sellerUnId && config.mySellerUnId === sellerUnId);
  const isBuyer = Boolean(config.myTin && buyerTin && config.myTin === buyerTin);
  const transporterMatches =
    Boolean(config.myTin) && Boolean(transporterTin) && config.myTin === transporterTin;

  if (hasPartyContext && !isSeller && !isBuyer) {
    if (transporterMatches) {
      return `Excluded transporter-only waybill ID=${id}`;
    }
    if (transporterTin && config.myTin && transporterTin !== config.myTin) {
      return `Excluded transporter mismatch waybill ID=${id}`;
    }
    return `Excluded non-matching party waybill ID=${id}`;
  }

  return null;
}

function emitFilterLog(buffer, message) {
  if (!buffer) {
    return;
  }
  const entry = `[WAYBILL_FILTER] ${message}`;
  buffer.push(entry);
  console.log(entry);
}

function createWaybillFilterConfig(env = {}) {
  const myTin = normalizeTin(env.MY_TIN || "");
  const mySellerUnId = (env.MY_SELLER_UN_ID || "").trim();
  const debugLogs = parseBoolean(env.DEBUG_FILTER_LOGS);

  if (!myTin) {
    console.warn("[WAYBILL_FILTER] MY_TIN not configured; buyer filtering limited");
  }
  if (!mySellerUnId) {
    console.warn("[WAYBILL_FILTER] MY_SELLER_UN_ID not configured; seller filtering limited");
  }
  if (debugLogs) {
    console.log("[WAYBILL_FILTER] Debug logging enabled");
  }

  return { myTin, mySellerUnId, debugLogs };
}

function parseBoolean(value) {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") {
    return value !== 0;
  }
  if (typeof value === "string") {
    return ["1", "true", "yes", "on"].includes(value.trim().toLowerCase());
  }
  return false;
}

function normalizeTin(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value).replace(/\s+/g, "");
}

async function fetchWaybillTotalInChunks(credentials, range, windowDays = 3) {
  const segments = chunkDateRange(range, windowDays);
  if (!segments.length) {
    const emptySummary = {
      total: 0,
      included: 0,
      excluded: 0,
      processed: 0,
      message: "No waybills found",
    };
    logWaybillSummary(emptySummary);
    return emptySummary;
  }
  console.warn(
    `[SOAP] Range too wide for ${credentials.su}; retrying in ${segments.length} chunk(s) of ${windowDays} day(s)`
  );
  const debugLogs = WAYBILL_FILTER_CONFIG.debugLogs ? [] : null;
  let combinedTotal = 0;
  let combinedIncluded = 0;
  let combinedExcluded = 0;
  let combinedProcessed = 0;

  for (const segment of segments) {
    try {
      const xml = await requestWaybillXml(credentials, segment);
      const summary = await summarizeWaybillTotalsFromXml(xml, credentials.su);
      combinedTotal += Number(summary.total) || 0;
      combinedIncluded += Number(summary.included) || 0;
      combinedExcluded += Number(summary.excluded) || 0;
      combinedProcessed += Number(summary.processed) || 0;
      if (debugLogs && Array.isArray(summary.logs) && summary.logs.length) {
        debugLogs.push(...summary.logs);
      }
      if (debugLogs) {
        debugLogs.push(
          `[WAYBILL_FILTER] Segment ${segment.start}..${segment.end} total=${Number(
            summary.total
          ).toFixed(2)}`
        );
      }
    } catch (err) {
      if (err?.soapStatus === -1072 && windowDays > 1) {
        const nextWindow = Math.max(1, Math.floor(windowDays / 2));
        console.warn(
          `[SOAP] Segment ${segment.start}..${segment.end} still too wide; retrying with ${nextWindow}-day window`
        );
        const nested = await fetchWaybillTotalInChunks(
          credentials,
          segment,
          nextWindow
        );
        combinedTotal += Number(nested.total) || 0;
        combinedIncluded += Number(nested.included) || 0;
        combinedExcluded += Number(nested.excluded) || 0;
        combinedProcessed += Number(nested.processed) || 0;
        if (debugLogs && Array.isArray(nested.logs) && nested.logs.length) {
          debugLogs.push(...nested.logs);
        }
        continue;
      }
      throw err;
    }
  }

  const finalSummary = {
    total: Number(combinedTotal.toFixed(2)),
    included: combinedIncluded,
    excluded: combinedExcluded,
    processed: combinedProcessed,
    message: "OK",
  };
  if (debugLogs?.length) {
    finalSummary.logs = debugLogs;
  }
  logWaybillSummary(finalSummary);
  return finalSummary;
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
    if (result && typeof result === "object") {
      const totalValue = Number.isFinite(result.total) ? Number(result.total) : 0;
      const payload = {
        total: Number(totalValue.toFixed(2)),
        included: Number.isFinite(result.included) ? result.included : 0,
        excluded: Number.isFinite(result.excluded) ? result.excluded : 0,
        message: result.message || "OK",
      };
      if (Array.isArray(result.logs) && result.logs.length) {
        payload.logs = result.logs;
      }
      return res.json(payload);
    }

    const fallbackTotal = Number.isFinite(result) ? Number(result) : 0;
    return res.json({
      total: Number(fallbackTotal.toFixed(2)),
      included: 0,
      excluded: 0,
      message: "OK",
    });
  } catch (err) {
    if (err?.soapStatus === -1072) {
      console.warn(
        `[SOAP] SU ${user?.su || "unknown"} returned STATUS -1072 (RS permissions or limits)`
      );
      return res.status(403).json({
        success: false,
        code: -1072,
        message: "RS.ge rejected this request (STATUS -1072). Please verify SU permissions or try again later.",
      });
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

