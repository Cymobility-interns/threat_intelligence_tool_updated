import { fetchVulnerabilities } from "./api.js";
import { renderVulnerabilities, setupLedgerFilters } from "./ledger.js";

console.log("main.js loaded");

// ── Full dataset cached on page load (never re-fetched)
let allVulnerabilities = [];

// ── Store year filter from URL
let activeYearFilter = "";

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

  const { search = "", from = "", to = "", cveType = "", cvss = "", interface: attackInterface = "", level = "", company = "", countermeasures = "" } = filters;

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

  // 3. Handle URL year filter (published date OR cve-yyyy-*****)
  if (activeYearFilter) {
    data = data.filter(v => {
      const cveMatch = v.cve_id && String(v.cve_id).toUpperCase().includes(`CVE-${activeYearFilter}-`);
      const dateMatch = v.published_date && String(v.published_date).startsWith(activeYearFilter);
      return cveMatch || dateMatch;
    });
  }

  // 4. CVSS Severity Filter
  if (cvss) {
    data = data.filter(v => {
      const score = parseFloat(v.cvss_score);
      if (isNaN(score)) return false;
      if (cvss === "Critical") return score >= 9.0;
      if (cvss === "High") return score >= 7.0 && score < 9.0;
      if (cvss === "Medium") return score >= 4.0 && score < 7.0;
      if (cvss === "Low") return score >= 0.1 && score < 4.0;
      return true;
    });
  }

  // 5. Attack Interface Filter
  if (attackInterface) {
    data = data.filter(v => {
      const s = String(v.interface || "").toUpperCase();
      return s.includes(attackInterface.toUpperCase());
    });
  }

  // 6. Level of Attack Filter
  if (level) {
    data = data.filter(v => {
      const s = String(v.level_of_attack || "").toUpperCase();
      return s.includes(level.toUpperCase());
    });
  }

  // 7. Company / Brand Filter
  if (company) {
    const escapedCompany = company.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`\\b${escapedCompany}\\b`, 'i');
    data = data.filter(v => {
      const s = String(v.company || "");
      return regex.test(s);
    });
  }

  // 8. Countermeasures Filter
  if (countermeasures) {
    data = data.filter(v => {
      const hasC = Boolean(v.countermeasures && String(v.countermeasures).trim() !== "" && String(v.countermeasures).toLowerCase() !== "none" && String(v.countermeasures).toLowerCase() !== "not available");
      if (countermeasures === "Yes") return hasC;
      if (countermeasures === "No") return !hasC;
      return true;
    });
  }

  // 4. Text search handled inside renderVulnerabilities
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
  const urlParams = new URLSearchParams(window.location.search);
  const urlFilter = urlParams.get("filter");
  activeYearFilter = urlParams.get("year") || "";

  const initialSearch = urlFilter || activeYearFilter || "";
  if (initialSearch) {
    const si = document.getElementById("ledger-search");
    if (si) si.value = initialSearch;
  }

  // 4. First render
  applyAndRender({ search: initialSearch });

  // 5. Wire all filter/search events
  //    setupLedgerFilters always emits FULL state — no merging needed here
  setupLedgerFilters((filters) => {
    console.log("Filters →", filters);

    if (filters.resetAll) {
      activeYearFilter = ""; // Clear the year filter on reset
      // Optionally remove it from the URL so it doesn't persist on refresh
      window.history.replaceState({}, document.title, window.location.pathname);
      applyAndRender({ search: "", from: "", to: "", cveType: "", cvss: "", interface: "", level: "", company: "", countermeasures: "" });
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
