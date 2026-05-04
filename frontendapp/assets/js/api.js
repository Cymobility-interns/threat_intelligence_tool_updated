// assets/js/api.js
// API layer: dynamic base URL, timeout/abort, in-memory cache, central error type.

// Dynamically match API_BASE to the frontend hostname to keep session cookies working
export const API_BASE = `http://${window.location.hostname || "127.0.0.1"}:8000`;

const DEFAULT_TIMEOUT_MS = 15000;

// Custom error so callers can distinguish HTTP vs network/timeout
export class ApiError extends Error {
  constructor(message, { status = 0, detail = null, cause = null } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.cause = cause;
  }
}

/**
 * fetchJSON(url, opts) — core wrapper around fetch.
 *  - Adds AbortController timeout
 *  - Always sends credentials (session cookies)
 *  - Parses JSON safely (returns {} on empty body)
 *  - Throws ApiError on non-2xx or network/timeout failures
 */
export async function fetchJSON(url, { method = "GET", body, headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, signal } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  // chain external signal if provided
  if (signal) signal.addEventListener("abort", () => controller.abort(), { once: true });

  const init = {
    method,
    credentials: "include",
    signal: controller.signal,
    headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
  };
  if (body !== undefined) init.body = typeof body === "string" ? body : JSON.stringify(body);

  let response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError") {
      throw new ApiError("Request timed out. Please try again.", { cause: err });
    }
    throw new ApiError("Cannot connect to server. Please check your network.", { cause: err });
  }
  clearTimeout(timer);

  let payload = {};
  try { payload = await response.json(); } catch { payload = {}; }

  if (!response.ok) {
    const detail = payload?.detail || `HTTP ${response.status}`;
    throw new ApiError(detail, { status: response.status, detail });
  }
  return payload;
}

// ------------------------------------------------------------
// In-memory cache for vulnerability list responses
// ------------------------------------------------------------
const CACHE_TTL_MS = 60_000; // 1 minute — long enough to dedupe page navigation, short enough to stay fresh
const _cache = new Map(); // key -> { data, expiresAt }

function cacheGet(key) {
  const entry = _cache.get(key);
  if (!entry) return null;
  if (entry.expiresAt < Date.now()) { _cache.delete(key); return null; }
  return entry.data;
}
function cacheSet(key, data) {
  _cache.set(key, { data, expiresAt: Date.now() + CACHE_TTL_MS });
}
export function clearApiCache() { _cache.clear(); }

/**
 * Fetch vulnerabilities with optional filters.
 * Accepts: { from, to, search, cveType }. Sends cveType as 'cve_type'.
 * Cached for 1 minute by query string. Returns [] on failure (legacy behaviour).
 */
export async function fetchVulnerabilities({ from, to, search, cveType } = {}, { force = false } = {}) {
  const params = new URLSearchParams();
  if (from)     params.append("from", from);
  if (to)       params.append("to", to);
  if (search)   params.append("search", search);
  if (cveType)  params.append("cve_type", cveType);

  const qs = params.toString();
  const url = qs ? `${API_BASE}/automotive_vulnerabilities?${qs}` : `${API_BASE}/automotive_vulnerabilities`;
  const cacheKey = url;

  if (!force) {
    const cached = cacheGet(cacheKey);
    if (cached) return cached;
  }

  try {
    const data = await fetchJSON(url);
    const list = Array.isArray(data) ? data : [];
    cacheSet(cacheKey, list);
    return list;
  } catch (err) {
    console.error("Failed to fetch vulnerabilities:", err);
    return [];
  }
}

/**
 * Fetch a single vulnerability by CVE id or internal id (used by details + branddetails).
 * Cached per identifier.
 */
export async function fetchVulnerabilityDetails(identifier) {
  if (!identifier) return null;
  const baseUrl = `${API_BASE}/automotive_vulnerabilities`;
  const url = identifier.startsWith("internal-")
    ? `${baseUrl}/id/${identifier.replace("internal-", "")}`
    : `${baseUrl}/cve/${encodeURIComponent(identifier)}`;

  const cached = cacheGet(url);
  if (cached) return cached;

  try {
    const data = await fetchJSON(url);
    cacheSet(url, data);
    return data;
  } catch (err) {
    console.error("Failed to fetch details:", err);
    return null;
  }
}

/**
 * postData(endpoint, data) — kept for login/signup.
 * Returns { ok, result } shape (legacy). Internally routes through fetchJSON.
 */
export async function postData(endpoint, data) {
  try {
    const result = await fetchJSON(`${API_BASE}${endpoint}`, { method: "POST", body: data });
    return { ok: true, result };
  } catch (err) {
    if (err instanceof ApiError) {
      return { ok: false, result: { detail: err.detail || err.message || "Something went wrong. Please try again." } };
    }
    return { ok: false, result: { detail: "Cannot connect to server. Please check your network." } };
  }
}
