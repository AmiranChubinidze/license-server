const axios = require("axios");
const { wrapper } = require("axios-cookiejar-support");
const { CookieJar } = require("tough-cookie");

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

const STATUS_FILTER_VALUES = ["1", "2", "8", "-2"];

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
 * @property {any} [rawSummary]
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

function extractPageSession(html) {
  const pageIdFromHidden = parseHiddenValue(html, "PageID");
  const sessionIdFromHidden = parseHiddenValue(html, "SessionID");

  const pageIdRegex = /PageID["']?\s*[:=]\s*["']([^"']+)["']/i;
  const sessionIdRegex = /SessionID["']?\s*[:=]\s*["']([^"']+)["']/i;
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

  if (!sessionId) {
    const m = typeof html === "string" ? html.match(sessionIdRegex) : null;
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

function normalizeRsResponse(payload) {
  if (
    payload &&
    typeof payload === "object" &&
    Object.prototype.hasOwnProperty.call(payload, "d")
  ) {
    return payload.d;
  }
  if (typeof payload === "string") {
    try {
      const parsed = JSON.parse(payload);
      return normalizeRsResponse(parsed);
    } catch (err) {
      return null;
    }
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

  let authBody = null;
  if (typeof rawAuth === "string") {
    const trimmed = rawAuth.trim();
    if (trimmed.startsWith("{")) {
      try {
        const parsed = JSON.parse(trimmed);
        const normalized = normalizeRsResponse(parsed);
        if (normalized && typeof normalized === "object") {
          authBody = normalized;
        }
      } catch {
        // fall through to HTML/error handling
      }
    }
    const looksLikeHtml =
      (trimmed.startsWith("<!DOCTYPE") ||
        trimmed.startsWith("<html") ||
        trimmed.startsWith("<")) ||
      contentType.toLowerCase().includes("text/html");
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
  } else if (isHtmlPayload(rawAuth, authResp.headers)) {
    const { snippet, dataType } = extractHtmlSnippet(rawAuth, 500);
    const err = new RsHtmlResponseError("RS login returned HTML", {
      htmlSnippet: snippet,
      statusCode: authResp.status,
      url: authResp.config?.url,
      contentType,
      dataType,
    });
    throw err;
  } else {
    const normalized = normalizeRsResponse(rawAuth);
    if (normalized && typeof normalized === "object") {
      authBody = normalized;
    }
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
  if (authBody.userToken) {
    jar.setCookieSync(`userToken=${authBody.userToken}; Domain=eservices.rs.ge; Path=/; Secure`, RS_BASE_URL);
  }
  if (authBody.chat_token) {
    jar.setCookieSync(`chatToken=${authBody.chat_token}; Domain=eservices.rs.ge; Path=/; Secure`, RS_BASE_URL);
  }

  return { client, jar, su, tin: parseTinFromSu(su) };
}

async function fetchWaybillPageMeta(session) {
  const pageResp = await session.client.get(RS_WAYBILL_PAGE, {
    headers: {
      Referer: `${RS_BASE_URL}/`,
      "User-Agent": USER_AGENT,
    },
  });

  if (pageResp.status === 401 || pageResp.status === 403) {
    throw new RsSessionError("RS session unauthorized for waybill page");
  }
  if (pageResp.status >= 500) {
    throw new RsHttpError("RS waybill page unavailable", pageResp.status);
  }
  const html = pageResp.data || "";
  const { pageId, sessionId, currentTab } = extractPageSession(html);
  if (!pageId || !sessionId) {
    const snippet =
      typeof html === "string" ? html.slice(0, 1000) : "[non-string waybill page response]";
    console.error("[RS_GRID][Waybills][METADATA_PARSE_FAILED]", {
      reason: "Failed to extract page metadata for waybills",
      snippet,
    });
    throw new RsSessionError("Failed to extract page metadata for waybills");
  }
  return { pageId, sessionId, currentTab: currentTab || "tab_given" };
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
    },
  });
  if (isHtmlPayload(resp.data, resp.headers)) {
    const { snippet, dataType } = extractHtmlSnippet(resp.data, 500);
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
  const normalized = normalizeRsResponse(resp.data);
  if (!normalized) {
    throw new RsParseError("Empty RS grid response");
  }
  return normalized;
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
  const rsStartDate = payload.StartDate || payload.startDate || fallbackRange.start;
  const rsEndDate = payload.EndDate || payload.endDate || fallbackRange.end;

  const dataSection = payload.Data || payload.data || {};
  const fields = dataSection.Fields || dataSection.fields || [];
  const summaryRow = dataSection.SummaryRow || dataSection.summaryRow || payload.SummaryRow;
  const summaryObject = payload.Summary || dataSection.Summary;

  if (!Array.isArray(fields) || !Array.isArray(summaryRow)) {
    const err = new RsSchemaChangedError("Fields or SummaryRow missing in RS response");
    err.payload = payload;
    throw err;
  }

  const amountIdx = fields.findIndex(
    (field) => typeof field === "string" && field.toUpperCase() === "FULL_AMOUNT"
  );
  if (amountIdx < 0 || amountIdx >= summaryRow.length) {
    const err = new RsSchemaChangedError("FULL_AMOUNT missing in RS response");
    err.payload = payload;
    throw err;
  }

  let candidate = summaryRow[amountIdx];
  if (candidate === null && summaryObject && typeof summaryObject === "object") {
    const key = Object.keys(summaryObject).find((k) => k.toUpperCase() === "FULL_AMOUNT");
    if (key) {
      candidate = summaryObject[key];
    }
  }
  if (candidate === null && Array.isArray(dataSection.Rows) && dataSection.Rows.length === 0) {
    candidate = 0;
  }
  if (candidate === null) {
    const err = new RsSchemaChangedError("FULL_AMOUNT missing in RS response");
    err.payload = payload;
    throw err;
  }

  const total = parseAmount(candidate);
  if (!Number.isFinite(total)) {
    const err = new RsParseError("Unable to parse FULL_AMOUNT");
    err.payload = payload;
    throw err;
  }

  const normalizedStart = normalizeDateString(rsStartDate);
  const normalizedEnd = normalizeDateString(rsEndDate);
  const rawSummary = summaryRow || summaryObject || null;
  return { total, rsStartDate: normalizedStart, rsEndDate: normalizedEnd, rawSummary };
}

function normalizeDateString(value) {
  if (typeof value !== "string") return "";
  const match = value.match(/(\d{4})[-/.](\d{2})[-/.](\d{2})/);
  if (match) {
    return `${match[1]}-${match[2]}-${match[3]}`;
  }
  const parsed = new Date(value.replace(" ", "T"));
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }
  return formatIso(parsed);
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
 * @param {{ su: string; sp: string; year: number; month: number; }} opts
 * @returns {Promise<RsGridTotalResult>}
 */
async function fetchRsGridTotalForMonth(opts) {
  const range = buildMonthRange(opts.year, opts.month);
  let lastError;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const session = await createRsSession(opts.su, opts.sp);
      const pageMeta = await fetchWaybillPageMeta(session);
      const payload = {
        PageID: pageMeta.pageId,
        SessionID: pageMeta.sessionId,
        currentTab: "tab_given",
        currentTabNotif: "",
        endDate: "",
        filterExpression: buildFilterExpression(range),
        gridData: 1,
        ignorePeriod: false,
        maximumRows: 200,
        sortExpression: "",
        startDate: "",
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
      if (err instanceof RsSessionError) {
        console.warn(`[RS_GRID] Session error for ${opts.su}; re-authenticating`);
        continue;
      }
      throw err;
    }
  }

  throw lastError || new Error("Failed to fetch RS grid total");
}

module.exports = {
  fetchRsGridTotalForMonth,
  createRsSession,
  RsAuthError,
  RsHttpError,
  RsParseError,
  RsSchemaChangedError,
  RsSessionError,
  RsHtmlResponseError,
};
