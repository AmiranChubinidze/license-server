const axios = require("axios");
const { wrapper } = require("axios-cookiejar-support");
const { CookieJar } = require("tough-cookie");
const cheerio = require("cheerio");
const fs = require("fs");
const path = require("path");

const RS_BASE_URL = "https://eservices.rs.ge";
const RS_LOGIN_PATH = "/Login.aspx";
const RS_WAYBILL_PAGE = "/WB/Waybills.aspx";
const RS_AUTH_PATH = "/WebServices/hsUsers.ashx/Authenticate";
const RS_GRID_PATH = "/WebServices/hsWaybill.ashx/GrdWaybills";
const RS_TIMEOUT_MS = 30000;
const USER_AGENT = "AmnairiRS-LicenseServer/1.0";

const RS_DATA_TYPES = {
  string: 0,
  number: 1,
  date: 2,
  formatNumber: 3,
  object: 4,
};

const RS_FILTER_FUNCS = {
  Equal: 0,
  Contains: 1,
  Begin: 2,
  InList: 3,
  InListContains: 4,
  Between: 5,
  Less: 6,
  NotContains: 7,
  Greater: 8,
  LessEqualMonth: 9,
  NotEqual: 10,
  GreaterOrEqual: 13,
};

const STATUS_FILTER_VALUES = ["1", "2", "8"];
const STATUS_TEXT_FILTER_VALUES = ["აქტიური", "დასრულებული", "გადამზიდავთან გადაგზავნილი"];

const GEORGIAN_MONTHS = {
  იან: 1,
  იანვ: 1,
  თებ: 2,
  თებრ: 2,
  მარ: 3,
  მარტ: 3,
  აპრ: 4,
  აპრილ: 4,
  მაი: 5,
  მაის: 5,
  ივნ: 6,
  ივნის: 6,
  ივლ: 7,
  ივლის: 7,
  აგვ: 8,
  აგვისტ: 8,
  სექ: 9,
  სექტ: 9,
  ოქტ: 10,
  ოქტომბ: 10,
  ნოე: 11,
  ნოემბ: 11,
  დეკ: 12,
  დეკემბ: 12,
};

class RsAuthError extends Error {
  constructor(message) {
    super(message || "RS authentication failed");
    this.name = "RsAuthError";
  }
}

class RsHttpError extends Error {
  constructor(message, statusCode) {
    super(message || "RS HTTP error");
    this.name = "RsHttpError";
    this.statusCode = statusCode;
  }
}

class RsParseError extends Error {
  constructor(message) {
    super(message || "Failed to parse RS response");
    this.name = "RsParseError";
  }
}

class RsSchemaChangedError extends Error {
  constructor(message) {
    super(message || "RS response schema changed");
    this.name = "RsSchemaChangedError";
  }
}

class RsSessionError extends Error {
  constructor(message) {
    super(message || "RS session expired");
    this.name = "RsSessionError";
  }
}

class RsSessionExpiredError extends Error {
  constructor(message) {
    super(message || "RS session expired, got login page");
    this.name = "RsSessionExpiredError";
  }
}

class RsHtmlResponseError extends Error {
  /**
   * @param {string} message
   * @param {{ htmlSnippet?: string; statusCode?: number; url?: string }} [meta]
   */
  constructor(message, meta = {}) {
    super(message || "RS returned HTML instead of JSON");
    this.name = "RsHtmlResponseError";
    this.htmlSnippet = meta.htmlSnippet || "";
    this.statusCode = meta.statusCode;
    this.url = meta.url;
  }
}

/**
 * @typedef {Object} RsSession
 * @property {import("axios").AxiosInstance} client
 * @property {CookieJar} jar
 * @property {string} su
 * @property {string} tin
 */

/**
 * @typedef {Object} RsGridTotalResult
 * @property {number} total
 * @property {string} rsStartDate
 * @property {string} rsEndDate
 * @property {{ fieldIndex: number; fields: string[]; fromRs: string; rawSummary?: any }} [details]
 */

function createHttpClient(jar) {
  return wrapper(
    axios.create({
      baseURL: RS_BASE_URL,
      jar,
      withCredentials: true,
      timeout: RS_TIMEOUT_MS,
      headers: {
        "User-Agent": USER_AGENT,
      },
      validateStatus: (status) => status >= 200 && status < 600,
    })
  );
}

function buildMonthRange(year, month) {
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) {
    throw new RsParseError("Invalid year or month");
  }
  const start = new Date(Date.UTC(year, month - 1, 1));
  const end = new Date(Date.UTC(year, month, 0));
  return {
    start: formatIso(start),
    end: formatIso(end),
  };
}

function formatIso(date) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}-${String(
    date.getUTCDate()
  ).padStart(2, "0")}`;
}

function parseHiddenValue(html, fieldId) {
  if (typeof html !== "string") return "";
  const regex = new RegExp(`id=["']${fieldId}["'][^>]*value=["']([^"']+)["']`, "i");
  const match = html.match(regex);
  return match ? match[1] : "";
}

function extractHiddenInputValue(html, key) {
  if (typeof html !== "string") return "";
  const lowerKey = key.toLowerCase();
  const inputRegex = /<input[^>]*>/gi;
  let match;
  while ((match = inputRegex.exec(html))) {
    const tag = match[0];
    const idMatch = tag.match(/id=["']?([^"'>\s]+)/i);
    const nameMatch = tag.match(/name=["']?([^"'>\s]+)/i);
    const idVal = idMatch && idMatch[1] ? idMatch[1].toLowerCase() : "";
    const nameVal = nameMatch && nameMatch[1] ? nameMatch[1].toLowerCase() : "";
    if (idVal.includes(lowerKey) || nameVal.includes(lowerKey)) {
      const valueMatch = tag.match(/value=["']([^"']*)["']/i);
      if (valueMatch && valueMatch[1] !== undefined) {
        return valueMatch[1];
      }
    }
  }
  return "";
}

function extractPageSession(html) {
  const pageIdFromHidden = parseHiddenValue(html, "PageID");
  const sessionIdFromHidden = parseHiddenValue(html, "SessionID");

  const pageIdRegex = /PageID["']?\s*[:=]\s*["']([^"']+)["']/i;
  const sessionIdRegex = /SessionID["']?\s*[:=]\s*["']([^"']+)["']/i;
  const pageIdJsonRegex = /"PageID"\s*:\s*"([^"']+)"/i;
  const sessionIdJsonRegex = /"SessionID"\s*:\s*"([^"']+)"/i;
  const currentTabRegex = /currentTab["']?\s*[:=]\s*["']([^"']+)["']/i;

  let pageId = pageIdFromHidden || "";
  let sessionId = sessionIdFromHidden || "";
  let currentTab = "tab_given";

  if (!pageId) {
    const m = typeof html === "string" ? html.match(pageIdRegex) : null;
    if (m && m[1]) {
      pageId = m[1];
    }
  }

  if (!pageId && typeof html === "string") {
    const m = html.match(pageIdJsonRegex);
    if (m && m[1]) {
      pageId = m[1];
    }
  }

  if (!sessionId) {
    const m = typeof html === "string" ? html.match(sessionIdRegex) : null;
    if (m && m[1]) {
      sessionId = m[1];
    }
  }

  if (!sessionId && typeof html === "string") {
    const m = html.match(sessionIdJsonRegex);
    if (m && m[1]) {
      sessionId = m[1];
    }
  }

  if (typeof html === "string") {
    const m = html.match(currentTabRegex);
    if (m && m[1]) {
      currentTab = m[1];
    }
  }

  return { pageId, sessionId, currentTab };
}

function assertWaybillGridPage($) {
  const hasGrid =
    $('table[id*="WaybillGrid"]').length > 0 ||
    $('div[id*="WaybillGrid"]').length > 0 ||
    $('input[id*="WaybillPageSize"]').length > 0;

  const isLogin =
    $('input[name="userName"]').length > 0 ||
    $('form[id*="loginForm"]').length > 0 ||
    $('form[action*="Login"]').length > 0;

  if (isLogin) {
    throw new RsSessionExpiredError("RS session expired, got login page instead of waybills grid");
  }

  if (!hasGrid) {
    throw new RsSchemaChangedError("Waybills grid not found on page");
  }
}

async function dumpWaybillHtmlForDebug(html, context = {}) {
  try {
    const { su = "unknown", year = "na", month = "na" } = context;
    const debugDir = path.join(process.cwd(), "tmp", "rs-debug");
    await fs.promises.mkdir(debugDir, { recursive: true });
    const fileName = `rs-waybills-${su}-${year}-${month}-${Date.now()}.html`;
    const fullPath = path.join(debugDir, fileName);
    await fs.promises.writeFile(fullPath, html, "utf8");
    return fullPath;
  } catch (err) {
    console.error("[RS_GRID][Waybills][DEBUG_DUMP_FAILED]", err?.message || err);
    return null;
  }
}

async function extractWaybillsPageMetadata(html, context = {}) {
  if (typeof html !== "string" || !html.trim()) {
    const err = new RsSchemaChangedError("Waybills page HTML missing or invalid");
    err.htmlSnippet = typeof html === "string" ? html.slice(0, 200) : "";
    throw err;
  }

  const $ = cheerio.load(html);
  assertWaybillGridPage($);

  const PageID =
    $('input[id="PageID"]').attr("value") ||
    $('input[name="ctl00$PageID"]').attr("value") ||
    extractHiddenInputValue(html, "PageID");
  const SessionID =
    $('input[id="SessionID"]').attr("value") ||
    $('input[name="ctl00$SessionID"]').attr("value") ||
    extractHiddenInputValue(html, "SessionID");

  if (!PageID || !SessionID) {
    const snippet = html.slice(0, 500);
    const err = new RsSchemaChangedError("Waybills grid metadata not found; RS.ge DOM likely changed");
    err.htmlSnippet = snippet;
    err.pageID = PageID;
    err.sessionID = SessionID;
    err.debugHtmlFile = await dumpWaybillHtmlForDebug(html, context);
    throw err;
  }

  return { PageID, SessionID };
}

function setRsCookie(jar, name, value) {
  if (!value) return Promise.resolve();
  const cookieString = `${name}=${value}; Path=/;`;
  return new Promise((resolve, reject) => {
    jar.setCookie(cookieString, RS_BASE_URL, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

function normalizeRsResponse(payload) {
  if (payload && typeof payload === "object") {
    if (Object.prototype.hasOwnProperty.call(payload, "d")) {
      return payload.d;
    }
    return payload;
  }
  if (typeof payload === "string") {
    const parsed = safeJsonParse(payload);
    return parsed ? normalizeRsResponse(parsed) : null;
  }
  return payload;
}

function isHtmlPayload(body, headers) {
  const contentType = (headers?.["content-type"] || headers?.["Content-Type"] || "").toLowerCase();
  if (contentType.includes("text/html")) return true;
  if (typeof body === "string") {
    const trimmed = body.trim();
    return trimmed.startsWith("<");
  }
  return false;
}

function extractHtmlSnippet(body, limit = 300) {
  let dataType = typeof body;
  try {
    if (typeof body === "string") {
      return { snippet: body.slice(0, limit), dataType };
    }
    if (Buffer.isBuffer(body)) {
      return { snippet: body.toString("utf8").slice(0, limit), dataType: "buffer" };
    }
    if (body !== null && body !== undefined) {
      return { snippet: JSON.stringify(body).slice(0, limit), dataType };
    }
    return { snippet: "", dataType };
  } catch (err) {
    return { snippet: "[unserializable response data]", dataType };
  }
}

function safeJsonParse(raw) {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "object") return raw;
  if (typeof raw !== "string") return null;
  const trimmed = raw.trim().replace(/^\uFEFF/, "");
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch (err) {
    return null;
  }
}

function tryParseJsonOrObject(raw) {
  if (raw && typeof raw === "object") return raw;
  if (typeof raw === "string") {
    const direct = safeJsonParse(raw);
    if (direct) return direct;
    const braceIdx = raw.indexOf("{");
    if (braceIdx >= 0) {
      const substring = raw.slice(braceIdx);
      const nested = safeJsonParse(substring);
      if (nested) return nested;
    }
  }
  return null;
}

function isProbablyLoginPage(html) {
  if (typeof html !== "string") return false;
  const lower = html.toLowerCase();
  return (
    lower.includes("login") ||
    lower.includes("auth") ||
    lower.includes("ავტორიზაცია") ||
    lower.includes("username") ||
    lower.includes("password")
  );
}

function parseTinFromSu(su) {
  if (typeof su !== "string") return "";
  const parts = su.split(":");
  const last = parts[parts.length - 1] || "";
  return last.replace(/\D+/g, "").trim();
}

async function createRsSession(su, sp) {
  if (!su || !sp) {
    throw new RsAuthError("Missing RS credentials");
  }
  const jar = new CookieJar();
  const client = createHttpClient(jar);

  const loginPageResp = await client.get(RS_LOGIN_PATH, {
    headers: {
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "User-Agent": USER_AGENT,
    },
  });

  if (loginPageResp.status >= 500) {
    throw new RsHttpError("RS login page unavailable", loginPageResp.status);
  }

  const { pageId: loginPageId, sessionId: loginSessionId } = extractPageSession(
    loginPageResp.data || ""
  );
  if (!loginPageId || !loginSessionId) {
    throw new RsParseError("Failed to read PageID/SessionID from RS login page");
  }

  const loginPayload = {
    pageID: loginPageId,
    PageID: loginPageId,
    SessionID: loginSessionId,
    username: su,
    password: sp,
    screen: "1920",
    vcode: "",
    check: "0",
    latitude: null,
    longitude: null,
  };

  const authResp = await client.post(RS_AUTH_PATH, loginPayload, {
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "X-Requested-With": "XMLHttpRequest",
      Origin: RS_BASE_URL,
      Referer: `${RS_BASE_URL}${RS_LOGIN_PATH}`,
    },
    responseType: "text",
  });

  const rawAuth = authResp.data;
  const contentType =
    (authResp.headers && (authResp.headers["content-type"] || authResp.headers["Content-Type"])) ||
    "";

  if (authResp.status >= 500) {
    throw new RsHttpError("RS authentication unavailable", authResp.status);
  }

  let authBody = null;
  const parsedAuth = tryParseJsonOrObject(rawAuth);
  if (parsedAuth) {
    const normalized = normalizeRsResponse(parsedAuth);
    if (normalized && typeof normalized === "object") {
      authBody = normalized;
    }
  }

  const looksLikeHtml = isHtmlPayload(rawAuth, authResp.headers);
  if (!authBody && looksLikeHtml) {
    const { snippet, dataType } = extractHtmlSnippet(rawAuth, 500);
    const err = new RsHtmlResponseError("RS login returned HTML", {
      htmlSnippet: snippet,
      statusCode: authResp.status,
      url: authResp.config?.url,
      contentType,
      dataType,
    });
    throw err;
  }

  if (!authBody) {
    throw new RsAuthError("Empty RS authentication response");
  }
  if (authResp.status === 401 || authResp.status === 403) {
    throw new RsAuthError("RS rejected credentials");
  }
  if (authBody.CustomError) {
    throw new RsAuthError(authBody.ErrorText || "RS rejected credentials");
  }
  if (authBody.AuthenticationStep && authBody.AuthenticationStep !== 2) {
    throw new RsAuthError("RS authentication requires additional verification");
  }
  const hasUserName = Boolean(authBody.UserName);
  const hasUserToken = typeof authBody.userToken === "string" && authBody.userToken.trim().length > 0;
  const hasId = authBody.ID !== undefined || authBody.UserId !== undefined;
  if (!hasUserName || !hasUserToken || !hasId) {
    throw new RsAuthError("Unexpected RS authentication payload");
  }
  if (authBody.userToken) {
    await setRsCookie(jar, "userToken", authBody.userToken);
  }
  if (authBody.chat_token) {
    await setRsCookie(jar, "chatToken", authBody.chat_token);
  }
  await setRsCookie(jar, "isEmp", "0");

  return { client, jar, su, tin: parseTinFromSu(su) };
}

async function fetchWaybillPageMeta(session, context = {}) {
  const pageResp = await session.client.get(RS_WAYBILL_PAGE, {
    headers: {
      Referer: `${RS_BASE_URL}/`,
      "User-Agent": USER_AGENT,
      "Accept-Language": "ka,en;q=0.9",
    },
  });

  if (pageResp.status === 401 || pageResp.status === 403) {
    throw new RsSessionError("RS session unauthorized for waybill page");
  }
  if (pageResp.status >= 500) {
    throw new RsHttpError("RS waybill page unavailable", pageResp.status);
  }
  const html = pageResp.data || "";
  if (isProbablyLoginPage(html)) {
    const snippet =
      typeof html === "string" ? html.slice(0, 500) : "[non-string waybill page response]";
    const err = new RsSessionExpiredError("RS returned login shell for waybill page");
    err.htmlSnippet = snippet;
    throw err;
  }
  try {
    const meta = await extractWaybillsPageMetadata(html, context);
    const currentTab =
      (typeof html === "string" &&
        (html.match(/currentTab["']?\s*[:=]\s*["']([^"']+)["']/i)?.[1] || "tab_given")) ||
      "tab_given";
    return { pageId: meta.PageID, sessionId: meta.SessionID, currentTab };
  } catch (err) {
    const snippet =
      typeof html === "string" ? html.slice(0, 500) : "[non-string waybill page response]";
    console.error("[RS_GRID][Waybills][METADATA_PARSE_FAILED]", {
      reason: err?.message || "Failed to extract page metadata for waybills",
      snippet,
      debugHtmlFile: err?.debugHtmlFile,
    });
    throw err;
  }
}

function buildFilterExpression(range) {
  const filters = [
    {
      FieldName: "ACTIVATE_DATE",
      DataType: RS_DATA_TYPES.date,
      FilterValue: {
        StartDate: range.start,
        EndDate: range.end,
        DefaultPeriod: 31,
        DateType: 1,
      },
      Func: RS_FILTER_FUNCS.Between,
    },
    {
      FieldName: "STATUS",
      DataType: RS_DATA_TYPES.number,
      FilterValue: STATUS_FILTER_VALUES.join(","),
      Func: RS_FILTER_FUNCS.InList,
    },
    {
      FieldName: "mdWaybillStatus",
      DataType: RS_DATA_TYPES.string,
      FilterValue: STATUS_TEXT_FILTER_VALUES.join(","),
      Func: RS_FILTER_FUNCS.InList,
    },
  ];
  return filters;
}

function buildSummaryFields() {
  return [
    {
      FieldName: "FULL_AMOUNT",
      SummaryFunction: 1,
      SummaryFraction: 2,
      SummaryField: null,
      SummaryType: 0,
      FieldName2: "",
      SummaryFunction2: 0,
    },
    {
      FieldName: "TRANSPORT_COAST",
      SummaryFunction: 1,
      SummaryFraction: 2,
      SummaryField: null,
      SummaryType: 0,
      FieldName2: "",
      SummaryFunction2: 0,
    },
  ];
}

async function requestGrid(session, payload) {
  const resp = await session.client.post(RS_GRID_PATH, payload, {
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "X-Requested-With": "XMLHttpRequest",
      Referer: `${RS_BASE_URL}/WB/Waybills`,
      Origin: RS_BASE_URL,
      "Accept-Language": "ka,en;q=0.9",
    },
  });
  if (resp.status === 401 || resp.status === 403) {
    throw new RsSessionError("RS rejected grid request (session)");
  }
  if (isHtmlPayload(resp.data, resp.headers)) {
    const { snippet, dataType } = extractHtmlSnippet(resp.data, 500);
    if (isProbablyLoginPage(snippet)) {
      const err = new RsSessionError("RS returned login HTML for grid request");
      err.htmlSnippet = snippet;
      err.statusCode = resp.status;
      throw err;
    }
    const err = new RsHtmlResponseError("RS returned HTML for grid request", {
      htmlSnippet: snippet,
      statusCode: resp.status,
      url: resp.config?.url,
      contentType:
        (resp.headers && (resp.headers["content-type"] || resp.headers["Content-Type"])) || "",
      dataType,
    });
    err.response = resp;
    throw err;
  }
  if (resp.status >= 500) {
    throw new RsHttpError("RS grid endpoint unavailable", resp.status);
  }
  const parsedData = tryParseJsonOrObject(resp.data);
  if (!parsedData) {
    throw new RsParseError("Empty RS grid response");
  }
  return parsedData;
}

function parseAmount(value) {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : NaN;
  }
  if (typeof value !== "string") return NaN;
  const compact = value.replace(/\s+/g, "");
  const hasComma = compact.includes(",");
  const hasDot = compact.includes(".");
  const commaAsDecimal = hasComma && !hasDot;
  const normalized = compact.replace(/,/g, commaAsDecimal ? "." : "").replace(/[^\d.-]/g, "");
  const parsed = Number.parseFloat(normalized);
  return Number.isFinite(parsed) ? parsed : NaN;
}

function pickFullAmount(payload, fallbackRange) {
  if (!payload || typeof payload !== "object" || !payload.d) {
    const err = new RsSchemaChangedError("RS grid payload missing d");
    err.payload = payload;
    throw err;
  }
  const envelope = payload.d;
  const dataSection = envelope.Data || envelope.data || {};
  const fields = dataSection.Fields || dataSection.fields || [];
  const rows = Array.isArray(dataSection.Rows) ? dataSection.Rows : [];
  const summaryRow =
    Array.isArray(dataSection.SummaryRow) && dataSection.SummaryRow.length
      ? dataSection.SummaryRow
      : Array.isArray(envelope.SummaryRow) && envelope.SummaryRow.length
        ? envelope.SummaryRow
        : null;
  const summaryObject = envelope.Summary || dataSection.Summary;

  if (!Array.isArray(fields) || !Array.isArray(rows)) {
    const err = new RsSchemaChangedError("Fields or Rows missing in RS response");
    err.payload = payload;
    throw err;
  }

  const amountIdx = fields.findIndex(
    (field) => typeof field === "string" && field.toUpperCase() === "FULL_AMOUNT"
  );
  if (amountIdx < 0) {
    const err = new RsSchemaChangedError("FULL_AMOUNT missing in RS response");
    err.payload = payload;
    throw err;
  }

  let total = null;
  let rawSummary = summaryRow || summaryObject || null;

  if (summaryRow && summaryRow.length > amountIdx) {
    const candidate = parseAmount(summaryRow[amountIdx]);
    if (Number.isFinite(candidate)) {
      total = candidate;
    }
  }

  if (total === null && summaryObject && typeof summaryObject === "object") {
    const key = Object.keys(summaryObject).find((k) => k.toUpperCase() === "FULL_AMOUNT");
    if (key) {
      const candidate = parseAmount(summaryObject[key]);
      if (Number.isFinite(candidate)) {
        total = candidate;
      }
    }
  }

  if (total === null) {
    let sum = 0;
    for (const row of rows) {
      if (!Array.isArray(row)) continue;
      const value = parseAmount(row[amountIdx]);
      if (Number.isFinite(value)) {
        sum += value;
      }
    }
    total = sum;
  }

  if (!Number.isFinite(total)) {
    const err = new RsParseError("Unable to parse FULL_AMOUNT");
    err.payload = payload;
    throw err;
  }

  const normalizedStart = normalizeDateString(
    envelope.StartDate || envelope.startDate || getDefaultStart(envelope),
    fallbackRange.start
  );
  const normalizedEnd = normalizeDateString(
    envelope.EndDate || envelope.endDate || getDefaultEnd(envelope),
    fallbackRange.end
  );

  return {
    total: Number(total.toFixed(2)),
    rsStartDate: normalizedStart,
    rsEndDate: normalizedEnd,
    details: { fieldIndex: amountIdx, fields, fromRs: "grid", rawSummary },
  };
}

function parseGeorgianMonthToken(token) {
  if (!token) return null;
  const cleaned = token.toString().trim().toLowerCase();
  if (!cleaned) return null;
  return GEORGIAN_MONTHS[cleaned] || null;
}

function parseDayMonthYear(value) {
  const match = value.match(/(\d{1,2})[-/.]\s*([^\s/-]+)\s*[-/.]\s*(\d{2,4})/);
  if (!match) return null;
  const day = Number(match[1]);
  const monthToken = match[2];
  const yearRaw = Number(match[3]);
  const month = Number.isFinite(Number(monthToken))
    ? Number(monthToken)
    : parseGeorgianMonthToken(monthToken);
  if (!Number.isFinite(day) || !Number.isFinite(month)) return null;
  const year = yearRaw < 100 ? 2000 + yearRaw : yearRaw;
  return { day, month, year };
}

function normalizeDateString(value, fallback) {
  if (typeof value !== "string") return fallback || "";
  const trimmed = value.trim();
  const isoMatch = trimmed.match(/(\d{4})[-/.](\d{2})[-/.](\d{2})/);
  if (isoMatch) {
    return `${isoMatch[1]}-${isoMatch[2]}-${isoMatch[3]}`;
  }
  const rangeParts = trimmed.split("/").map((p) => p.trim());
  if (rangeParts.length === 2) {
    const first = normalizeDateString(rangeParts[0]);
    if (first) return first;
  }
  const dmy = parseDayMonthYear(trimmed);
  if (dmy) {
    return `${String(dmy.year).padStart(4, "0")}-${String(dmy.month).padStart(2, "0")}-${String(
      dmy.day
    ).padStart(2, "0")}`;
  }
  const parsed = new Date(trimmed.replace(" ", "T"));
  if (Number.isNaN(parsed.getTime())) {
    return fallback || "";
  }
  return formatIso(parsed);
}

function getDefaultStart(envelope) {
  if (!envelope?.DefaultValues || typeof envelope.DefaultValues !== "object") return "";
  const raw = envelope.DefaultValues.ACTIVATE_DATE;
  if (typeof raw !== "string") return "";
  const parts = raw.split("/").map((p) => p.trim());
  return parts[0] || "";
}

function getDefaultEnd(envelope) {
  if (!envelope?.DefaultValues || typeof envelope.DefaultValues !== "object") return "";
  const raw = envelope.DefaultValues.ACTIVATE_DATE;
  if (typeof raw !== "string") return "";
  const parts = raw.split("/").map((p) => p.trim());
  return parts[1] || "";
}

function shouldRetry(err) {
  if (err instanceof RsSessionError) return false;
  if (err instanceof RsHtmlResponseError) return false;
  const status = err?.statusCode || err?.response?.status;
  if (status && status >= 500) return true;
  const code = err?.code ? String(err.code) : "";
  return ["ECONNRESET", "ETIMEDOUT", "ECONNABORTED"].includes(code);
}

async function runWithRetry(fn, attempts, onRetry) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i >= attempts - 1 || !shouldRetry(err)) {
        throw err;
      }
      if (typeof onRetry === "function") {
        onRetry(err, i + 1);
      }
    }
  }
  throw lastErr;
}

/**
 * Fetch the strict grid total for a given month from RS Waybills.
 * @param {{ su: string; plain_sp: string; year: number; month: number; }} opts
 * @returns {Promise<RsGridTotalResult>}
 */
async function fetchRsGridTotalForMonth(opts) {
  const range = buildMonthRange(opts.year, opts.month);
  let lastError;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const session = await createRsSession(opts.su, opts.plain_sp);
      const pageMeta = await fetchWaybillPageMeta(session, {
        su: opts.su,
        year: opts.year,
        month: opts.month,
      });
      const payload = {
        PageID: pageMeta.pageId,
        SessionID: pageMeta.sessionId,
        currentTab: pageMeta.currentTab || "tab_given",
        currentTabNotif: "",
        startDate: range.start,
        endDate: range.end,
        StartDate: range.start,
        EndDate: range.end,
        filterExpression: buildFilterExpression(range),
        gridData: 1,
        ignorePeriod: false,
        maximumRows: 10,
        sortExpression: "",
        startRowIndex: 0,
        summaryFields: buildSummaryFields(),
      };

      const gridResponse = await runWithRetry(
        () => requestGrid(session, payload),
        2,
        (err, retryAttempt) => {
          console.warn(
            `[RS_GRID] Retry ${retryAttempt} for ${opts.su} due to ${err?.message || err}`
          );
        }
      );

      return pickFullAmount(gridResponse, range);
    } catch (err) {
      lastError = err;
      if (err instanceof RsSessionError || err instanceof RsSessionExpiredError) {
        console.warn(`[RS_GRID] Session error for ${opts.su}; re-authenticating`);
        continue;
      }
      throw err;
    }
  }

  throw lastError || new Error("Failed to fetch RS grid total");
}

// Dev helper for local verification:
// (async () => {
//   const result = await fetchRsGridTotalForMonth({
//     su: "amnairi:412761097",
//     plain_sp: "Amikoio33@",
//     year: 2025,
//     month: 11,
//   });
//   console.log("GRID RESULT", result);
// })().catch(console.error);

module.exports = {
  fetchRsGridTotalForMonth,
  createRsSession,
  RsAuthError,
  RsHttpError,
  RsParseError,
  RsSchemaChangedError,
  RsSessionError,
  RsSessionExpiredError,
  RsHtmlResponseError,
};
