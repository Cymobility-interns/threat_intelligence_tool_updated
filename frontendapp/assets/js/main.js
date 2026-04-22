import { fetchVulnerabilities } from "./api.js";
import { renderVulnerabilities, setupLedgerFilters } from "./ledger.js";

console.log("main.js loaded");

// ── Full dataset cached on page load (never re-fetched)
let allVulnerabilities = [];

/* ─────────────────────────────────────────────
   Load Navbar
   ledger.html uses id="navbar" (not "navbar-container")
───────────────────────────────────────────── */
async function loadNavbar() {
  try {
    const response = await fetch("components/navbar.html");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const html = await response.text();
    const el = document.getElementById("navbar") || document.getElementById("navbar-container");
    if (el) el.innerHTML = html;
    if (typeof window.initNavbar === "function") window.initNavbar();
  } catch (err) {
    console.error("Failed to load navbar:", err);
  }
}

/* ─────────────────────────────────────────────
   Apply filters and render.
   filters = { search, from, to, cveType }
───────────────────────────────────────────── */
function applyAndRender(filters) {
  let data = [...allVulnerabilities];

  const { search = "", from = "", to = "", cveType = "" } = filters;

  // 1. CVE Type filter
  if (cveType === "CVE") {
    data = data.filter(v => v.cve_id && /^CVE-/i.test(String(v.cve_id).trim()));
  } else if (cveType === "Non-CVE") {
    data = data.filter(v => {
      const c = String(v.cve_id || "").trim().toLowerCase();
      return !c || c === "not available" || c === "n/a" || c === "null" || c === "none";
    });
  }

  // 2. Date range filter
  if (from) {
    const fromDt = new Date(from);
    data = data.filter(v => v.published_date && new Date(v.published_date) >= fromDt);
  }
  if (to) {
    const toDt = new Date(to);
    toDt.setHours(23, 59, 59, 999);
    data = data.filter(v => v.published_date && new Date(v.published_date) <= toDt);
  }

  // 3. Text search handled inside renderVulnerabilities
  renderVulnerabilities(data, search);
}

/* ─────────────────────────────────────────────
   Page Init
───────────────────────────────────────────── */
async function init() {
  // 1. Inject navbar
  await loadNavbar();

  // 2. Fetch full dataset once — no backend params
  console.log("INIT: fetching full dataset...");
  allVulnerabilities = await fetchVulnerabilities();
  console.log("Full dataset:", allVulnerabilities.length, "records");

  // 3. If arriving via pie-chart click (?filter=Bluetooth) pre-fill search box
  const urlFilter = new URLSearchParams(window.location.search).get("filter");
  const initialSearch = urlFilter || "";
  if (urlFilter) {
    const si = document.getElementById("ledger-search");
    if (si) si.value = urlFilter;
  }

  // 4. First render
  applyAndRender({ search: initialSearch });

  // 5. Wire all filter/search events
  //    setupLedgerFilters always emits FULL state — no merging needed here
  setupLedgerFilters((filters) => {
    console.log("Filters →", filters);

    if (filters.resetAll) {
      applyAndRender({ search: "", from: "", to: "", cveType: "" });
      return;
    }

    applyAndRender(filters);
  });
}

// Start after DOM is ready (module scripts are deferred by default)
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
