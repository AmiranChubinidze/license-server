const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env") });
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const xml2js = require("xml2js");
const { supabase } = require("./supabaseClient");

const app = express();
const allowedOrigins = [
  "https://amnairi.xyz",
  "https://www.amnairi.xyz",
  "https://amnairi.onrender.com",
  "https://license-server-z3vf.onrender.com",
  "http://localhost:3000",
  "chrome-extension://hbbbkkjdjngfagckieciipdnbinbepon",
  "chrome-extension://nknjpddihjgbpmanhocgeclijichkocm",
];
const isExtensionOrigin = (origin) =>
  typeof origin === "string" && origin.startsWith("chrome-extension://");
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin) || isExtensionOrigin(origin)) {
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
if (!supabase) {
  console.error("[SUPABASE] Missing SUPABASE_URL or SUPABASE_SERVICE_KEY");
}
const SERVICE_USERS_TABLE = "service_users";
const LOGIN_REQUESTS_TABLE = "login_requests";
const SOAP_DATE_KEYS = ["last_update_date", "create_date"];
const SOAP_DATE_KEY_OVERRIDE_RAW = process.env.SOAP_DATE_KEY;
const SOAP_DATE_KEY_OVERRIDE = resolveSoapDateKeyOverride(SOAP_DATE_KEY_OVERRIDE_RAW);
let soapDateKey = SOAP_DATE_KEY_OVERRIDE || null;
const soapDisabledBySu = new Map();
const ENABLE_SOAP_EXPERIMENTAL =
  String(process.env.ENABLE_SOAP_EXPERIMENTAL || "").toLowerCase() !== "false";
const WAYBILL_ALLOWED_STATUSES = new Set(["1", "2", "8", "-2"]);
const WAYBILL_AMOUNT_FIELDS = ["FULL_AMOUNT"];
const WAYBILL_EXPECTED_TYPE = "2";
const WAYBILL_ID_KEYS = ["WAYBILL_ID", "WB_ID", "ID", "DOC_ID", "WAYBILLID"];
const WAYBILL_PARENT_KEYS = ["PAR_ID", "PARENT_ID", "CORRECTED_ID", "CORR_ID"];
const WAYBILL_IS_CORRECTED_KEYS = [
  "IS_CORRECTED",
  "ISCORRECTED",
  "IS_CORRECTION",
  "IS_CORR",
  "CORRECTED",
];
const WAYBILL_SELLER_KEYS = ["SELER_UN_ID", "SELLER_UN_ID", "SELLER_ID"];
const WAYBILL_SELLER_TIN_KEYS = ["SELLER_TIN"];
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
const WAYBILL_DATE_SOURCE = "BEGIN_DATE";
const { stripPrefix } = xml2js.processors;
const SOAP_DATASET_PARSER = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs: false,
  tagNameProcessors: [stripPrefix],
  attrNameProcessors: [stripPrefix],
  trim: true,
});
const BASE_WAYBILL_FILTER_CONFIG = createWaybillFilterConfig({
  debugLogs: process.env.DEBUG_FILTER_LOGS,
  myTin: "",
});

function parseTinFromSu(su) {
  if (typeof su !== "string") return null;
  const trimmed = su.trim();
  if (!trimmed || !trimmed.includes(":")) return null;
  const parts = trimmed.split(":");
  const candidate = parts[parts.length - 1].replace(/\D+/g, "").trim();
  if (!candidate) return null;
  return candidate;
}

async function fetchSupabaseUserBySu(su) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(SERVICE_USERS_TABLE)
    .select("*")
    .eq("su", su)
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase query failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function upsertSupabaseUser(payload) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(SERVICE_USERS_TABLE)
    .upsert(payload, { onConflict: "su" })
    .select()
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase upsert failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function updateSupabaseUser(fields, su) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(SERVICE_USERS_TABLE)
    .update(fields)
    .eq("su", su)
    .select()
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase update failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function createLoginRequest(payload) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(LOGIN_REQUESTS_TABLE)
    .insert(payload)
    .select()
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase insert failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function fetchLoginRequestById(id) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(LOGIN_REQUESTS_TABLE)
    .select("*")
    .eq("id", id)
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase query failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function deleteServiceUser(su) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(SERVICE_USERS_TABLE)
    .delete()
    .eq("su", su)
    .select("su");
  if (error) {
    throw new Error(error.message || "Supabase delete failed");
  }
  return Array.isArray(data) ? data : [];
}

async function listPendingLoginRequests() {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(LOGIN_REQUESTS_TABLE)
    .select("id, su, tin, plain_sp, created_at, ip, user_agent")
    .eq("status", "pending")
    .order("created_at", { ascending: true });
  if (error) {
    throw new Error(error.message || "Supabase query failed");
  }
  return Array.isArray(data) ? data : [];
}

async function updateLoginRequest(id, fields) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(LOGIN_REQUESTS_TABLE)
    .update(fields)
    .eq("id", id)
    .select()
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase update failed");
  }
  return Array.isArray(data) && data.length ? data[0] : null;
}

async function hasPendingRequest(su) {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(LOGIN_REQUESTS_TABLE)
    .select("id")
    .eq("su", su)
    .eq("status", LOGIN_STATUSES.PENDING)
    .limit(1);
  if (error) {
    throw new Error(error.message || "Supabase query failed");
  }
  return Array.isArray(data) && data.length > 0;
}

async function ensurePendingRequest({ su, tin, plain_sp, ip, userAgent, nowIso }) {
  const alreadyPending = await hasPendingRequest(su);
  if (alreadyPending) return null;
  return await createLoginRequest({
    su,
    tin,
    plain_sp,
    status: LOGIN_STATUSES.PENDING,
    created_at: nowIso,
    ip,
    user_agent: userAgent,
  });
}

async function listSupabaseUsers() {
  if (!supabase) throw new Error("Supabase not configured");
  const { data, error } = await supabase
    .from(SERVICE_USERS_TABLE)
    .select("su, tin, status, blocked_until, updated_at")
    .order("su", { ascending: true });
  if (error) {
    throw new Error(error.message || "Supabase query failed");
  }
  return Array.isArray(data) ? data : [];
}

async function autodetectSoapDateKey() {
  if (SOAP_DATE_KEY_OVERRIDE) {
    soapDateKey = SOAP_DATE_KEY_OVERRIDE;
    console.log(`[SOAP] Using ${soapDateKey}_s/e from SOAP_DATE_KEY environment override`);
    return;
  }
  if (!supabase) {
    console.warn("[SOAP] Skipping date parameter autodetect; Supabase not configured");
    return;
  }
  try {
    const { data, error } = await supabase
      .from(SERVICE_USERS_TABLE)
      .select("su, plain_sp")
      .not("plain_sp", "is", null)
      .neq("plain_sp", "")
      .eq("status", "approved")
      .limit(1);
    if (error) {
      console.warn("[SOAP] Skipping date autodetect; Supabase error:", error.message);
      return;
    }
    const user = Array.isArray(data) && data.length ? data[0] : null;
    if (!user) {
      console.warn("[SOAP] Skipping date parameter autodetect; no users with stored SP");
      return;
    }
    const probeRange = buildProbeRange();
    for (const key of SOAP_DATE_KEYS) {
      try {
        const xml = await requestWaybillXml({ su: user.su, sp: user.plain_sp }, probeRange, key);
        const statusCode = extractSoapStatus(xml);
        if (statusCode === -100 || statusCode === -1072) {
          console.warn(`[SOAP] Probe with ${key}_s/e returned STATUS ${statusCode}`);
          continue;
        }
        soapDateKey = key;
        console.log(`[SOAP] Autodetected date key ${soapDateKey}_s/e for SU ${user.su}`);
        return;
      } catch (err) {
        console.error(`[SOAP] Probe using ${key}_s/e failed:`, err?.message || err);
      }
    }
    soapDateKey = SOAP_DATE_KEYS[0];
    console.warn(`[SOAP] Autodetect failed; defaulting to ${soapDateKey}_s/e`);
  } catch (err) {
    console.error("[SOAP] Autodetect skipped due to error:", err?.message || err);
  }
}

function ensureSupabase(res) {
  if (supabase) return true;
  res
    .status(500)
    .json({ success: false, message: "Supabase not configured. Check SUPABASE_URL and SUPABASE_SERVICE_KEY." });
  return false;
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
    tin: record.tin || "",
    status: record.status || "",
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

function isBlocked(user) {
  if (!user?.blocked_until) return false;
  const until = new Date(user.blocked_until);
  return Number.isFinite(until.getTime()) && until.getTime() > Date.now();
}

async function findApprovedUser(su) {
  if (!su) return null;
  const user = await fetchSupabaseUserBySu(su);
  if (!user) return null;
  if (user.status !== "approved") return null;
  if (isBlocked(user)) return null;
  user.active = user.active !== false;
  if (!user.tin) {
    const parsedTin = parseTinFromSu(su);
    if (parsedTin) {
      try {
        await updateSupabaseUser({ tin: parsedTin, updated_at: new Date().toISOString() }, su);
        user.tin = parsedTin;
      } catch (err) {
        console.warn("[SUPABASE] Failed to backfill TIN for", su, err?.message || err);
      }
    }
  }
  user.tin = user.tin || "";
  user.company_name = user.company_name || "";
  return user;
}

function issueToken(user, options = {}) {
  const payload = {
    su: user.su,
    name: user.company_name,
    tin: user.tin,
    type: options.type ?? "access",
  };

  if (options.extraClaims && typeof options.extraClaims === "object") {
    Object.assign(payload, options.extraClaims);
  }

  const expiresIn =
    options.expiresIn ?? (payload.type === "refresh" ? "30d" : "24h");
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

const issueAccessToken = (user) =>
  issueToken(user, {
    type: "access",
    expiresIn: "24h",
  });
const issueRefreshToken = (user) =>
  issueToken(user, {
    type: "refresh",
    expiresIn: "30d",
  });

function decodeToken(token, options = {}) {
  return jwt.verify(token, JWT_SECRET, options);
}

function normalizeAmount(raw) {
  if (typeof raw === "number") {
    return Number.isFinite(raw) ? raw : null;
  }
  if (typeof raw !== "string") return null;
  const cleaned = raw.replace(/\s+/g, "").replace(/,/g, ".").replace(/[^\d.-]/g, "");
  const value = Number.parseFloat(cleaned);
  return Number.isFinite(value) ? value : null;
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

function countDaysInclusive(range) {
  if (!range?.start || !range?.end) {
    return Infinity;
  }
  const startDate = new Date(`${range.start}T00:00:00Z`);
  const endDate = new Date(`${range.end}T00:00:00Z`);
  if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime())) {
    return Infinity;
  }
  const diffMs = endDate.getTime() - startDate.getTime();
  return Math.floor(diffMs / (24 * 60 * 60 * 1000)) + 1;
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

function resolveSoapDateKeyOverride(raw) {
  if (!raw) {
    return null;
  }
  const candidate = String(raw).trim().toLowerCase();
  if (!SOAP_DATE_KEYS.includes(candidate)) {
    console.warn(`[SOAP] Ignoring invalid SOAP_DATE_KEY override: ${raw}`);
    return null;
  }
  return candidate;
}

function getAlternateSoapDateKey(key) {
  return SOAP_DATE_KEYS.find((entry) => entry !== key) || null;
}

function sanitizeSoapDateKey(key) {
  return SOAP_DATE_KEYS.includes(key) ? key : SOAP_DATE_KEYS[0];
}

function shouldUseFallbackKey(err) {
  return err?.soapStatus === -1072;
}

function shouldRetryWithSmallerWindow(err, windowDays) {
  if (windowDays <= 1) {
    return false;
  }
  if (err?.isTimeout || err?.isNetworkError) {
    return true;
  }
  if (err?.httpStatus && err.httpStatus >= 500) {
    return true;
  }
  if (err?.isHtmlResponse) {
    return true;
  }
  if (err?.soapStatus === -1072 && shouldUseFallbackKey(err)) {
    return false;
  }
  return false;
}

const MAX_SOAP_WINDOW_DAYS = 3;

async function fetchWaybillTotal(credentials, monthKey, options = {}) {
  const captureLists = Boolean(options.captureLists);
  const baseFilterConfig = options.filterConfig || BASE_WAYBILL_FILTER_CONFIG;
  const filterConfig =
    captureLists && !baseFilterConfig.captureLists
      ? { ...baseFilterConfig, captureLists: true }
      : baseFilterConfig;
  const range = buildDateRange(monthKey);
  const rangeDays = countDaysInclusive(range);
  if (rangeDays > MAX_SOAP_WINDOW_DAYS) {
    console.warn(
      `[SOAP] Range ${range.start}..${range.end} exceeds ${MAX_SOAP_WINDOW_DAYS} days; chunking immediately`
    );
    return await fetchWaybillTotalInChunks(credentials, range, {
      windowDays: MAX_SOAP_WINDOW_DAYS,
      targetRange: range,
      filterConfig,
      captureLists,
    });
  }
  try {
    const xml = await requestWaybillXml(credentials, range);
    const summary = await summarizeWaybillTotalsFromXml(
      xml,
      credentials.su,
      range,
      filterConfig
    );
    logWaybillSummary(summary);
    return summary;
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
  assertSoapEnabled(credentials?.su);
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

function handleSoapStatus(statusCode, su, options = {}) {
  const allow1072Fallback = Boolean(options.allow1072Fallback);
  if (statusCode === -1072) {
    if (allow1072Fallback) {
      return;
    }
    disableSoapForSu(su, "-1072");
    throw new SoapDisabledError(su, "-1072");
  }
  if (statusCode === -100) {
    const error = new Error("RS.ge rejected date parameters");
    error.isSoapError = true;
    error.soapStatus = -100;
    error.su = su;
    throw error;
  }
}

class SOAPDateKeyError extends Error {
  constructor(message) {
    super(message);
    this.name = "SOAPDateKeyError";
    this.isSoapError = true;
  }
}

class SoapDisabledError extends Error {
  constructor(su, reason) {
    super(`SOAP disabled for SU ${su}: ${reason}`);
    this.name = "SoapDisabledError";
    this.su = su;
    this.reason = reason;
    this.isSoapError = true;
  }
}

function isSoapDisabled(su) {
  if (!su) return false;
  const entry = soapDisabledBySu.get(su);
  return Boolean(entry && entry.disabled);
}

function assertSoapEnabled(su) {
  if (isSoapDisabled(su)) {
    const entry = soapDisabledBySu.get(su);
    throw new SoapDisabledError(su, entry?.reason || "disabled");
  }
}

function disableSoapForSu(su, reason) {
  if (!su) return;
  if (soapDisabledBySu.has(su)) return;
  soapDisabledBySu.set(su, {
    disabled: true,
    reason,
    firstSeenAt: new Date().toISOString(),
  });
  console.warn(
    `[SOAP] Disabling SOAP for SU ${su} due to STATUS ${reason || "-1072"} (RS permissions or limits)`
  );
}

async function summarizeWaybillTotalsFromXml(
  xml,
  su,
  targetRange,
  filterConfig = BASE_WAYBILL_FILTER_CONFIG
) {
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

  const filtered = filterWaybillRecords(records, filterConfig, targetRange, {
    captureLists: Boolean(filterConfig.captureLists),
  });
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
  if (filterConfig.captureLists) {
    summary.includedRecords = filtered.includedRecords || [];
    summary.excludedRecords = filtered.excludedRecords || [];
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

function filterWaybillRecords(records, config, targetRange, options = {}) {
  const debug = Boolean(config.debugLogs);
  const logBuffer = debug ? [] : null;
  const captureLists = Boolean(options.captureLists);
  const included = [];
  const excluded = [];
  let excludedCount = 0;
  let includedCount = 0;
  let total = 0;

  for (const record of records) {
    const id = resolveWaybillId(record) || "unknown";
    const log = (tag, message) => {
      const entry = `[${tag}] id=${id} ${message}`;
      if (logBuffer) {
        logBuffer.push(entry);
      }
      if (debug && !logBuffer) {
        console.debug(entry);
      }
    };

    const decision = determineExclusionReason(record, config, { targetRange, log });

    const debugEntry = buildDebugEntry(record, decision);

    if (decision.exclude) {
      excludedCount += 1;
      if (captureLists) {
        excluded.push(debugEntry);
      }
      continue;
    }

    includedCount += 1;
    total += decision.amount;
    log("AMOUNT_ADDED", `amount=${decision.amount.toFixed(2)}`);
    if (captureLists) {
      included.push(debugEntry);
    }
  }

  if (logBuffer) {
    logBuffer.push(
      `[FINAL_SUM] total=${total.toFixed(2)} included=${includedCount} excluded=${excludedCount}`
    );
  }

  return {
    total,
    included: includedCount,
    excluded: excludedCount,
    logs: logBuffer || undefined,
    includedRecords: captureLists ? included : undefined,
    excludedRecords: captureLists ? excluded : undefined,
  };
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

function determineExclusionReason(record, config, correctionContext = {}) {
  const id = resolveWaybillId(record) || "unknown";
  const log = correctionContext.log;
  const effectiveDate = getEffectiveDate(record, { id, log });
  const baseDecision = {
    exclude: false,
    reason: null,
    id,
    effectiveDate,
  };

  if (!effectiveDate) {
    if (log) {
      log("DATE_FILTER_OUT", 'reason="missing or invalid date"');
    }
    return {
      ...baseDecision,
      exclude: true,
      reason: "missing or invalid date",
    };
  }

  if (correctionContext?.targetRange) {
    const { start, end } = correctionContext.targetRange;
    if (effectiveDate < start || effectiveDate > end) {
      if (log) {
        log(
          "DATE_FILTER_OUT",
          `effective=${effectiveDate} reason="outside target range ${start}..${end}"`
        );
      }
      return {
        ...baseDecision,
        exclude: true,
        reason: `effective date ${effectiveDate} outside ${start}..${end}`,
      };
    }
  }

  const amount = normalizeFullAmount(record);

  return {
    ...baseDecision,
    amount: Number.isFinite(amount) ? amount : 0,
  };
}

// Transportation totals are calculated strictly by BEGIN_DATE. Invalid or missing dates exclude the waybill.
function getEffectiveDate(waybill, options = {}) {
  const id = options?.id || resolveWaybillId(waybill) || "unknown";
  const log = options?.log;
  const beginRaw = getFirstValue(waybill, [WAYBILL_DATE_SOURCE]);
  const normalized = normalizeWaybillDate(beginRaw);

  if (log) {
    log("DATE_PICK", `source=${WAYBILL_DATE_SOURCE} value=${normalized || beginRaw || "missing"}`);
  }

  return normalized;
}

function normalizeFullAmount(record) {
  const raw = getFirstValue(record, WAYBILL_AMOUNT_FIELDS);
  if (raw === undefined || raw === null || raw === "") {
    return null;
  }
  const amount = normalizeAmount(raw);
  if (!Number.isFinite(amount)) {
    return null;
  }
  if (amount < 0) {
    return null;
  }
  return amount;
}

function normalizeStatus(raw) {
  const value = raw === undefined || raw === null ? "" : String(raw).trim();
  if (!value) {
    return "";
  }
  const num = Number(value);
  if (Number.isFinite(num)) {
    return String(num);
  }
  return value;
}

function normalizeType(raw) {
  const value = raw === undefined || raw === null ? "" : String(raw).trim();
  if (!value) {
    return "";
  }
  const num = Number(value);
  if (Number.isFinite(num)) {
    return String(num);
  }
  return value;
}

function normalizeIsCorrected(raw) {
  const value = raw === undefined || raw === null ? "" : String(raw).trim().toLowerCase();
  if (!value) {
    return false;
  }
  if (["1", "true", "yes"].includes(value)) {
    return true;
  }
  const num = Number(value);
  return Number.isFinite(num) && num === 1;
}

function resolveRole(myTin, sellerTin, buyerTin, transporterTin) {
  if (myTin && sellerTin && myTin === sellerTin) {
    return "seller";
  }
  if (myTin && buyerTin && myTin === buyerTin) {
    return "buyer";
  }
  if (myTin && transporterTin && myTin === transporterTin) {
    return "transporter";
  }
  return "unknown";
}

function buildDebugEntry(record, decision) {
  const amount = Number.isFinite(decision.amount) ? Number(decision.amount.toFixed(2)) : null;
  return {
    ID: decision.id || resolveWaybillId(record) || "",
    EFFECTIVE_DATE: decision.effectiveDate || null,
    FULL_AMOUNT: amount,
    EXCLUDED_REASON: decision.reason || null,
    DATE_SOURCE: WAYBILL_DATE_SOURCE,
    RAW_DATES: {
      BEGIN_DATE:
        decision.rawDates?.begin ??
        getFirstValue(record, [WAYBILL_DATE_SOURCE]) ??
        "",
      ACTIVATE_DATE: decision.rawDates?.activate ?? getFirstValue(record, ["ACTIVATE_DATE"]) ?? "",
      CREATE_DATE: decision.rawDates?.create ?? getFirstValue(record, ["CREATE_DATE"]) ?? "",
    },
  };
}

function isValidDateParts(year, month, day) {
  if (
    !Number.isInteger(year) ||
    !Number.isInteger(month) ||
    !Number.isInteger(day) ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31
  ) {
    return false;
  }
  const candidate = new Date(Date.UTC(year, month - 1, day));
  return (
    !Number.isNaN(candidate.getTime()) &&
    candidate.getUTCFullYear() === year &&
    candidate.getUTCMonth() === month - 1 &&
    candidate.getUTCDate() === day
  );
}

function normalizeWaybillDate(raw) {
  if (raw === null || raw === undefined) {
    return null;
  }
  const value = String(raw).trim();
  if (!value) {
    return null;
  }
  const match = value.match(/(\d{4})[-/.](\d{2})[-/.](\d{2})/);
  if (match) {
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    if (isValidDateParts(year, month, day)) {
      return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(
        day
      ).padStart(2, "0")}`;
    }
    return null;
  }
  const parsed = new Date(value.replace(" ", "T"));
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  const iso = formatIsoDateUTC(parsed);
  const [year, month, day] = iso.split("-").map(Number);
  return isValidDateParts(year, month, day) ? iso : null;
}

function emitAnomalyLog(id, reason, buffer) {
  const entry = `[WAYBILL_ANOMALY] ID=${id} reason=${reason}`;
  console.warn(entry);
  if (buffer) {
    buffer.push(entry);
  }
}

function emitDebugLog(entry, buffer, debug) {
  if (buffer) {
    buffer.push(entry);
  }
  if (debug) {
    console.debug(entry);
  }
}

function buildMonthKeyFromQuery(year, month) {
  const y = Number(year);
  const m = Number(month);
  if (!Number.isInteger(y) || !Number.isInteger(m)) {
    return undefined;
  }
  if (m < 1 || m > 12) {
    return undefined;
  }
  return `${String(y).padStart(4, "0")}-${String(m).padStart(2, "0")}`;
}

function emitFilterLog(buffer, message) {
  if (!buffer) {
    return;
  }
  const entry = `[WAYBILL_FILTER] ${message}`;
  buffer.push(entry);
  console.log(entry);
}

function createWaybillFilterConfig(options = {}) {
  const myTin = normalizeTin(options.myTin || "");
  const debugLogs = parseBoolean(
    options.DEBUG_FILTER_LOGS !== undefined ? options.DEBUG_FILTER_LOGS : options.debugLogs
  );
  if (debugLogs) {
    console.log("[WAYBILL_FILTER] Debug logging enabled");
  }
  return { myTin, debugLogs };
}

function buildWaybillFilterConfig(overrides = {}) {
  if (!overrides || typeof overrides !== "object" || !Object.keys(overrides).length) {
    return BASE_WAYBILL_FILTER_CONFIG;
  }
  return { ...BASE_WAYBILL_FILTER_CONFIG, ...overrides };
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

async function fetchWaybillTotalInChunks(credentials, range, options = {}) {
  const windowDays = options.windowDays ?? 3;
  const targetRange = options.targetRange || range;
  const baseFilterConfig = options.filterConfig || BASE_WAYBILL_FILTER_CONFIG;
  const captureLists = Boolean(options.captureLists);
  const filterConfig =
    captureLists && !baseFilterConfig.captureLists
      ? { ...baseFilterConfig, captureLists: true }
      : baseFilterConfig;
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
  const debugLogs = filterConfig.debugLogs ? [] : null;
  let combinedTotal = 0;
  let combinedIncluded = 0;
  let combinedExcluded = 0;
  let combinedProcessed = 0;
  const combinedIncludedRecords = captureLists ? [] : null;
  const combinedExcludedRecords = captureLists ? [] : null;

  for (const segment of segments) {
    try {
      const xml = await requestWaybillXml(credentials, segment);
      const summary = await summarizeWaybillTotalsFromXml(
        xml,
        credentials.su,
        targetRange,
        filterConfig
      );
      if (captureLists && summary.includedRecords?.length) {
        combinedIncludedRecords.push(...summary.includedRecords);
      }
      if (captureLists && summary.excludedRecords?.length) {
        combinedExcludedRecords.push(...summary.excludedRecords);
      }
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
      if (shouldRetryWithSmallerWindow(err, windowDays)) {
        const nextWindow = Math.max(1, Math.floor(windowDays / 2));
        console.warn(
          `[SOAP] Segment ${segment.start}..${segment.end} still too wide; retrying with ${nextWindow}-day window`
        );
        const nested = await fetchWaybillTotalInChunks(credentials, segment, {
          windowDays: nextWindow,
          targetRange,
          filterConfig,
          captureLists,
        });
        if (captureLists && nested.includedRecords?.length) {
          combinedIncludedRecords.push(...nested.includedRecords);
        }
        if (captureLists && nested.excludedRecords?.length) {
          combinedExcludedRecords.push(...nested.excludedRecords);
        }
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
  if (captureLists) {
    finalSummary.includedRecords = combinedIncludedRecords || [];
    finalSummary.excludedRecords = combinedExcludedRecords || [];
  }
  logWaybillSummary(finalSummary);
  return finalSummary;
}

async function buildRefreshedSession(incomingToken) {
  const decoded = decodeToken(incomingToken);
  if (decoded.type && decoded.type !== "refresh") {
    const error = new Error("Refresh token required");
    error.status = 400;
    throw error;
  }

  const user = await findApprovedUser(decoded.su);
  if (!user || !user.active) {
    const error = new Error("User revoked or not found");
    error.status = 401;
    throw error;
  }

  const token = issueAccessToken(user);
  const refreshToken = issueRefreshToken(user);
  return { token, refreshToken, user: serializeUser(user) };
}

const LOGIN_STATUSES = {
  APPROVED: "approved",
  PENDING: "pending",
  DENIED: "denied",
};

function buildPendingResponse(res) {
  return res.status(403).json({
    success: false,
    status: "pending_approval",
    message: "Your account is pending admin approval.",
  });
}

function buildBlockedResponse(res) {
  return res.status(403).json({
    success: false,
    status: "blocked",
    message: "Access temporarily denied. Please try again later.",
  });
}

async function handleAuthLogin(req, res) {
  if (!ensureSupabase(res)) return;

  const su = (req.body?.su || "").trim();
  const sp = typeof req.body?.sp === "string" ? req.body.sp.trim() : "";
  const ip =
    (req.headers["x-forwarded-for"] || "")
      .toString()
      .split(",")
      .map((p) => p.trim())
      .find(Boolean) || req.ip || "";
  const userAgent = req.headers["user-agent"] || "";

  if (!su || !sp) {
    return res
      .status(400)
      .json({ success: false, status: "invalid_input", message: "Missing credentials" });
  }

  const tin = parseTinFromSu(su);
  if (!tin) {
    return res.status(400).json({
      success: false,
      status: "invalid_su",
      message: "Invalid SU format. Cannot parse TIN.",
    });
  }

  const nowIso = new Date().toISOString();

  let user = null;
  try {
    user = await fetchSupabaseUserBySu(su);
  } catch (err) {
    console.error("[/auth/login] Supabase query failed:", err?.message || err);
    return res.status(500).json({
      success: false,
      status: "db_error",
      message: "Database error.",
    });
  }

  try {
    if (!user) {
      await ensurePendingRequest({ su, tin, plain_sp: sp, ip, userAgent, nowIso });
      await upsertSupabaseUser({
        su,
        tin,
        plain_sp: sp,
        status: LOGIN_STATUSES.PENDING,
        blocked_until: null,
        updated_at: nowIso,
      });
      return buildPendingResponse(res);
    }

    // Always persist the freshest SP and TIN.
    await updateSupabaseUser(
      { plain_sp: sp, tin, updated_at: nowIso },
      su
    );
    user.plain_sp = sp;
    user.tin = tin;

    if (isBlocked(user)) {
      return buildBlockedResponse(res);
    }

    if (user.status === LOGIN_STATUSES.DENIED) {
      if (isBlocked(user)) {
        return buildBlockedResponse(res);
      }
      await ensurePendingRequest({ su, tin, plain_sp: sp, ip, userAgent, nowIso });
      await updateSupabaseUser(
        { status: LOGIN_STATUSES.PENDING, blocked_until: null, updated_at: nowIso },
        su
      );
      return buildPendingResponse(res);
    }

    if (user.status === LOGIN_STATUSES.PENDING) {
      return buildPendingResponse(res);
    }

    if (user.status !== LOGIN_STATUSES.APPROVED) {
      return res.status(403).json({
        success: false,
        status: "blocked",
        message: "Access temporarily denied. Please try again later.",
      });
    }

    // Approved flow
    await updateSupabaseUser(
      {
        tin,
        plain_sp: sp,
        status: LOGIN_STATUSES.APPROVED,
        blocked_until: null,
        last_login_at: nowIso,
        updated_at: nowIso,
      },
      su
    );
    const approvedUser = await fetchSupabaseUserBySu(su);
    const token = issueAccessToken(approvedUser);
    const refreshToken = issueRefreshToken(approvedUser);

    return res.json({
      success: true,
      status: "approved",
      token,
      refreshToken,
      user: serializeUser(approvedUser),
    });
  } catch (err) {
    console.error("[/auth/login] Failed:", err?.message || err);
    return res.status(500).json({
      success: false,
      status: "server_error",
      message: "Unexpected error.",
    });
  }
}
app.get("/ping", (_req, res) => res.json({ ok: true }));
console.log("Loaded routes: /login, /verify, /refresh");
app.post("/login", handleAuthLogin);
app.post("/loginHybrid", handleAuthLogin);
app.post("/auth", handleAuthLogin);
app.post("/auth/login", handleAuthLogin);

app.get("/debug/users", async (_req, res) => {
  if (!ensureSupabase(res)) return;

  try {
    const records = await listSupabaseUsers();
    return res.json({
      users: records.map((record) => ({
        su: record.su,
        status: record.status,
        tin: record.tin,
        blocked_until: record.blocked_until || null,
      })),
    });
  } catch (err) {
    console.error("[/debug/users] Failed to list users:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get("/debug/waybills", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const token = extractToken(req);
  if (!token) {
    return res.status(400).json({ success: false, message: "Missing token" });
  }

  const monthKey = buildMonthKeyFromQuery(req.query?.year, req.query?.month);
  const debugMode = parseBoolean(req.query?.debug);
  let filterConfig = debugMode
    ? buildWaybillFilterConfig({ debugLogs: true })
    : BASE_WAYBILL_FILTER_CONFIG;

  let user;
  try {
    const decoded = decodeToken(token);
    user = await findApprovedUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ success: false, message: "User revoked or not found" });
    }

    const effectiveSp = (user.plain_sp || "").trim();
    if (!effectiveSp) {
      return res.status(401).json({ success: false, message: "Missing SP for user" });
    }
    const myTin = normalizeTin(user.tin);
    if (!myTin) {
      return res.status(400).json({ success: false, message: "TIN missing for user" });
    }
    filterConfig = buildWaybillFilterConfig({ ...filterConfig, myTin });

    const result = await fetchWaybillTotal(
      { su: user.su, sp: effectiveSp },
      monthKey,
      { filterConfig, captureLists: true }
    );

    return res.json({
      success: true,
      included: result.includedRecords || [],
      excluded: result.excludedRecords || [],
      logs: result.logs || [],
    });
  } catch (err) {
    if (err instanceof SoapDisabledError) {
      return res.status(503).json({
        success: false,
        code: "SOAP_DISABLED",
        message:
          "SOAP waybill service is not available for this account. Use grid totals instead.",
      });
    }
    console.error("[/debug/waybills] Failed:", err?.message || err);
    if (err?.isSoapError) {
      return res.status(502).json({
        success: false,
        message: "RS.ge SOAP error",
        details: err.message || "SOAP request failed",
      });
    }

    const isJwtError =
      err?.name === "JsonWebTokenError" ||
      err?.name === "TokenExpiredError" ||
      err?.name === "NotBeforeError";
    if (isJwtError) {
      return res.status(401).json({ success: false, message: "Invalid or expired token" });
    }

    return res
      .status(500)
      .json({ success: false, message: err?.message || "Failed to fetch waybills" });
  }
});

function registerSoapRoutes(appInstance) {
  // dev/experimental SOAP routes (legacy/debug only)
  appInstance.get("/waybill/debugList", async (req, res) => {
    if (!ensureSupabase(res)) return;
    const token = extractToken(req);
    if (!token) {
      return res.status(400).json({ success: false, message: "Missing token" });
    }

    const monthKey = buildMonthKeyFromQuery(req.query?.year, req.query?.month);
    let filterConfig = buildWaybillFilterConfig({ debugLogs: true });

    let user;
    try {
      const decoded = decodeToken(token);
      user = await findApprovedUser(decoded.su);

      if (!user || !user.active) {
        return res.status(401).json({ success: false, message: "User revoked or not found" });
      }

      const effectiveSp = (user.plain_sp || "").trim();
      if (!effectiveSp) {
        return res.status(401).json({ success: false, message: "Missing SP for user" });
      }
      const myTin = normalizeTin(user.tin);
      if (!myTin) {
        return res.status(400).json({ success: false, message: "TIN missing for user" });
      }
      filterConfig = buildWaybillFilterConfig({ ...filterConfig, myTin });

      const result = await fetchWaybillTotal(
        { su: user.su, sp: effectiveSp },
        monthKey,
        { filterConfig, captureLists: true }
      );

      return res.json({
        success: true,
        included: result.includedRecords || [],
        excluded: result.excludedRecords || [],
        logs: result.logs || [],
      });
    } catch (err) {
      if (err instanceof SoapDisabledError) {
        return res.status(503).json({
          success: false,
          code: "SOAP_DISABLED",
          message:
            "SOAP waybill service is not available for this account. Use grid totals instead.",
        });
      }
      console.error("[/waybill/debugList] Failed:", err?.message || err);
      if (err?.isSoapError) {
        return res.status(502).json({
          success: false,
          message: "RS.ge SOAP error",
          details: err.message || "SOAP request failed",
        });
      }

      const isJwtError =
        err?.name === "JsonWebTokenError" ||
        err?.name === "TokenExpiredError" ||
        err?.name === "NotBeforeError";
      if (isJwtError) {
        return res.status(401).json({ success: false, message: "Invalid or expired token" });
      }

      return res
        .status(500)
        .json({ success: false, message: err?.message || "Failed to fetch waybills" });
    }
  });

  appInstance.get("/debug/waybills", async (req, res) => {
    if (!ensureSupabase(res)) return;
    const token = extractToken(req);
    if (!token) {
      return res.status(400).json({ success: false, message: "Missing token" });
    }

    const monthKey = buildMonthKeyFromQuery(req.query?.year, req.query?.month);
    const debugMode = parseBoolean(req.query?.debug);
    let filterConfig = debugMode
      ? buildWaybillFilterConfig({ debugLogs: true })
      : BASE_WAYBILL_FILTER_CONFIG;

    let user;
    try {
      const decoded = decodeToken(token);
      user = await findApprovedUser(decoded.su);

      if (!user || !user.active) {
        return res.status(401).json({ success: false, message: "User revoked or not found" });
      }

      const effectiveSp = (user.plain_sp || "").trim();
      if (!effectiveSp) {
        return res.status(401).json({ success: false, message: "Missing SP for user" });
      }
      const myTin = normalizeTin(user.tin);
      if (!myTin) {
        return res.status(400).json({ success: false, message: "TIN missing for user" });
      }
      filterConfig = buildWaybillFilterConfig({ ...filterConfig, myTin });

      const result = await fetchWaybillTotal(
        { su: user.su, sp: effectiveSp },
        monthKey,
        { filterConfig, captureLists: true }
      );

      return res.json({
        success: true,
        included: result.includedRecords || [],
        excluded: result.excludedRecords || [],
        logs: result.logs || [],
      });
    } catch (err) {
      if (err instanceof SoapDisabledError) {
        return res.status(503).json({
          success: false,
          code: "SOAP_DISABLED",
          message:
            "SOAP waybill service is not available for this account. Use grid totals instead.",
        });
      }
      console.error("[/debug/waybills] Failed:", err?.message || err);
      if (err?.isSoapError) {
        return res.status(502).json({
          success: false,
          message: "RS.ge SOAP error",
          details: err.message || "SOAP request failed",
        });
      }

      const isJwtError =
        err?.name === "JsonWebTokenError" ||
        err?.name === "TokenExpiredError" ||
        err?.name === "NotBeforeError";
      if (isJwtError) {
        return res.status(401).json({ success: false, message: "Invalid or expired token" });
      }

      return res
        .status(500)
        .json({ success: false, message: err?.message || "Failed to fetch waybills" });
    }
  });
}

app.get("/verify", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const token = extractToken(req);
  if (!token) {
    return res.status(400).json({ valid: false, message: "Missing token" });
  }

  try {
    const decoded = decodeToken(token);
    const user = await findApprovedUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ valid: false, message: "User revoked or not found" });
    }

    return res.json({ valid: true, user: serializeUser(user) });
  } catch (err) {
    return res.status(401).json({ valid: false, message: "Invalid or expired token" });
  }
});

app.post("/refresh", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const incoming = extractToken(req);
  if (!incoming) {
    return res.status(400).json({ success: false, message: "Missing token" });
  }

  try {
    const session = await buildRefreshedSession(incoming);
    return res.json({ success: true, ...session });
  } catch (err) {
    const isJwtError =
      err?.name === "JsonWebTokenError" ||
      err?.name === "TokenExpiredError" ||
      err?.name === "NotBeforeError";
    const status = err?.status || err?.statusCode || (isJwtError ? 401 : 500);
    return res.status(status).json({
      success: false,
      message: err?.message || "Token refresh failed",
    });
  }
});

app.post("/auth/refresh", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const token = req.body?.token;
  if (!token) {
    return res.status(400).json({ success: false, message: "Missing token" });
  }

  try {
    const session = await buildRefreshedSession(token);
    return res.json({ success: true, ...session });
  } catch (err) {
    console.warn("Token refresh failed:", err?.message || err);
    const isJwtError =
      err?.name === "JsonWebTokenError" ||
      err?.name === "TokenExpiredError" ||
      err?.name === "NotBeforeError";
    const status = err?.status || err?.statusCode || (isJwtError ? 401 : 500);
    return res.status(status).json({
      success: false,
      message: err?.message || "Invalid or expired token",
    });
  }
});

app.post("/validateToken", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const token = req.body?.token;
  if (!token) {
    return res.json({ valid: false, message: "Missing token" });
  }

  try {
    const decoded = decodeToken(token);
    const user = await findApprovedUser(decoded.su);

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

// Primary production endpoint: SOAP strict total for the given month.
app.post("/waybill/total", async (req, res) => {
  if (!ensureSupabase(res)) return;
  const token = extractToken(req);
  const debugMode = parseBoolean(req.query?.debug);
  let filterConfig = debugMode
    ? buildWaybillFilterConfig({ debugLogs: true })
    : BASE_WAYBILL_FILTER_CONFIG;

  if (!token) {
    return res.status(400).json({ success: false, message: "Missing token" });
  }

  // month can be provided as "YYYY-MM" or via year/month numeric fields
  const bodyMonth = req.body?.month;
  const bodyYear = req.body?.year;
  let monthKey = typeof bodyMonth === "string" ? bodyMonth : undefined;
  if (!monthKey && Number.isInteger(Number(bodyYear)) && Number.isInteger(Number(bodyMonth))) {
    const paddedMonth = String(Number(bodyMonth)).padStart(2, "0");
    monthKey = `${bodyYear}-${paddedMonth}`;
  }
  const range = buildDateRange(monthKey);

  let user;
  try {
    const decoded = decodeToken(token);
    user = await findApprovedUser(decoded.su);

    if (!user || !user.active) {
      return res.status(401).json({ success: false, message: "User revoked or not found" });
    }

    const effectiveSp = (user.plain_sp || "").trim();
    if (!effectiveSp) {
      return res.status(401).json({ success: false, message: "Missing SP for user" });
    }
    const myTin = normalizeTin(user.tin);
    if (!myTin) {
      return res.status(400).json({ success: false, message: "TIN missing for user" });
    }
    filterConfig = buildWaybillFilterConfig({ ...filterConfig, myTin });

    const result = await fetchWaybillTotal(
      { su: user.su, sp: effectiveSp },
      monthKey,
      { filterConfig }
    );
    const totalValue =
      result && typeof result === "object" && Number.isFinite(result.total) ? result.total : 0;
    return res.json({
      success: true,
      total: Number(totalValue.toFixed(2)),
      from: range.start,
      to: range.end,
    });
  } catch (err) {
    if (err instanceof SoapDisabledError) {
      return res.status(503).json({
        success: false,
        code: "SOAP_DISABLED",
        message:
          "SOAP waybill service is not available for this account. Use RS grid or manual reconciliation.",
      });
    }
    if (err?.isSoapError) {
      return res.status(502).json({
        success: false,
        message: "RS.ge SOAP error",
        details: err.message || "SOAP request failed",
      });
    }

    const isJwtError =
      err?.name === "JsonWebTokenError" ||
      err?.name === "TokenExpiredError" ||
      err?.name === "NotBeforeError";
    if (isJwtError) {
      return res.status(401).json({ success: false, message: "Invalid or expired token" });
    }

    return res
      .status(500)
      .json({ success: false, message: err?.message || "Failed to calculate total" });
  }
});

if (ENABLE_SOAP_EXPERIMENTAL) {
  registerSoapRoutes(app);
}

app.get("/admin/users", requireAdmin, async (req, res) => {
  if (!ensureSupabase(res)) return;
  try {
    const { data, error } = await supabase
      .from(SERVICE_USERS_TABLE)
      .select("id, su, company_name, tin, status, blocked_until, created_at, updated_at")
      .neq("status", LOGIN_STATUSES.PENDING)
      .order("company_name", { ascending: true });
    if (error) {
      throw new Error(error.message || "Supabase error");
    }
    return res.json({ success: true, users: data || [] });
  } catch (err) {
    console.error("List users failed:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.get("/admin/login-requests", requireAdmin, async (_req, res) => {
  if (!ensureSupabase(res)) return;
  try {
    const requests = await listPendingLoginRequests();
    return res.json({ success: true, requests });
  } catch (err) {
    console.error("List login requests failed:", err?.message || err);
    return res.status(500).json({ success: false, status: "db_error", message: "Database error" });
  }
});

app.post("/admin/login-requests/:id/approve", requireAdmin, async (req, res) => {
  if (!ensureSupabase(res)) return;
  const id = req.params?.id;
  const adminId = (req.body?.admin_id || "").trim() || null;
  if (!id) {
    return res.status(400).json({ success: false, message: "Missing request id" });
  }
  try {
    const requestRow = await fetchLoginRequestById(id);
    if (!requestRow || requestRow.status !== LOGIN_STATUSES.PENDING) {
      return res.status(400).json({ success: false, message: "Request not pending or not found" });
    }
    const nowIso = new Date().toISOString();
    await upsertSupabaseUser({
      su: requestRow.su,
      tin: requestRow.tin,
      plain_sp: requestRow.plain_sp,
      status: LOGIN_STATUSES.APPROVED,
      blocked_until: null,
      updated_at: nowIso,
    });
    await updateLoginRequest(id, {
      status: LOGIN_STATUSES.APPROVED,
      decided_at: nowIso,
      decided_by: adminId,
      reason: null,
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Approve login request failed:", err?.message || err);
    return res.status(500).json({ success: false, status: "db_error", message: "Database error" });
  }
});

app.post("/admin/login-requests/:id/deny", requireAdmin, async (req, res) => {
  if (!ensureSupabase(res)) return;
  const id = req.params?.id;
  const adminId = (req.body?.admin_id || "").trim() || null;
  const reason = (req.body?.reason || "").trim() || null;
  if (!id) {
    return res.status(400).json({ success: false, message: "Missing request id" });
  }
  try {
    const requestRow = await fetchLoginRequestById(id);
    if (!requestRow || requestRow.status !== LOGIN_STATUSES.PENDING) {
      return res.status(400).json({ success: false, message: "Request not pending or not found" });
    }
    const now = new Date();
    await deleteServiceUser(requestRow.su);
    await updateLoginRequest(id, {
      status: LOGIN_STATUSES.DENIED,
      decided_at: now.toISOString(),
      decided_by: adminId,
      reason,
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Deny login request failed:", err?.message || err);
    return res.status(500).json({ success: false, status: "db_error", message: "Database error" });
  }
});

app.post("/admin/addUser", requireAdmin, async (req, res) => {
  if (!ensureSupabase(res)) return;
  const su = (req.body?.su || "").trim();
  const companyName = (req.body?.company_name || "").trim();

  if (!su || !companyName) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  const tin = parseTinFromSu(su);
  if (!tin) {
    return res.status(400).json({ success: false, message: "Invalid SU format (TIN missing)" });
  }

  try {
    const nowIso = new Date().toISOString();
    await upsertSupabaseUser({
      su,
      company_name: companyName,
      plain_sp: "",
      tin,
      status: LOGIN_STATUSES.APPROVED,
      blocked_until: null,
      updated_at: nowIso,
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Add user failed:", err);
    return res.status(500).json({ success: false, message: "Database error" });
  }
});

app.post("/admin/revokeUser", requireAdmin, async (req, res) => {
  if (!ensureSupabase(res)) return;
  const su = (req.body?.su || "").trim();
  if (!su) {
    return res.status(400).json({ success: false, message: "Missing SU" });
  }

  try {
    await deleteServiceUser(su);
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

async function initializeRuntime() {
  await autodetectSoapDateKey();
}

initializeRuntime()
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
    console.error("Initialization failed:", err);
  });

