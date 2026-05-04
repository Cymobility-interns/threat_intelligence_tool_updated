import { fetchVulnerabilities } from "./api.js";
import { bindLogoutButton } from "./auth.js";
import { renderVulnerabilities, setupLedgerFilters } from "./ledger.js";
import { showLoader, hideLoader, toast } from "./utils.js";

// Full dataset cached on page load (never re-fetched once filters change)
let allVulnerabilities = [];
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
───────────────────────────────────────────── */
function applyAndRender(filters) {
  let data = [...allVulnerabilities];
  const {
    search = "", from = "", to = "", cveType = "", cvss = "",
    interface: attackInterface = "", level = "", company = "", countermeasures = "",
  } = filters;

  // 1. CVE Type
  if (cveType === "CVE") {
    data = data.filter(v => v.cve_id && /^CVE-/i.test(String(v.cve_id).trim()));
  } else if (cveType === "Non-CVE") {
    data = data.filter(v => {
      const c = String(v.cve_id || "").trim().toLowerCase();
      return !c || c === "not available" || c === "n/a" || c === "null" || c === "none";
    });
  }

  // 2. Date range
  if (from) {
    const fromDt = new Date(from);
    data = data.filter(v => v.published_date && new Date(v.published_date) >= fromDt);
  }
  if (to) {
    const toDt = new Date(to);
    toDt.setHours(23, 59, 59, 999);
    data = data.filter(v => v.published_date && new Date(v.published_date) <= toDt);
  }

  // 3. URL year filter
  if (activeYearFilter) {
    data = data.filter(v => {
      const cveMatch = v.cve_id && String(v.cve_id).toUpperCase().includes(`CVE-${activeYearFilter}-`);
      const dateMatch = v.published_date && String(v.published_date).startsWith(activeYearFilter);
      return cveMatch || dateMatch;
    });
  }

  // 4. CVSS Severity
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

  // 5. Attack Interface
  if (attackInterface) {
    const needle = attackInterface.toUpperCase();
    data = data.filter(v => String(v.interface || "").toUpperCase().includes(needle));
  }

  // 6. Level of Attack
  if (level) {
    const needle = level.toUpperCase();
    data = data.filter(v => String(v.level_of_attack || "").toUpperCase().includes(needle));
  }

  // 7. Company / Brand
  if (company) {
    const escapedCompany = company.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`\\b${escapedCompany}\\b`, "i");
    data = data.filter(v => regex.test(String(v.company || "")));
  }

  // 8. Countermeasures
  if (countermeasures) {
    data = data.filter(v => {
      const raw = String(v.countermeasures || "").trim().toLowerCase();
      const hasC = raw && raw !== "none" && raw !== "not available";
      if (countermeasures === "Yes") return hasC;
      if (countermeasures === "No") return !hasC;
      return true;
    });
  }

  // Text search handled inside renderVulnerabilities
  renderVulnerabilities(data, search);
}

async function init() {
  await loadNavbar();
  bindLogoutButton(document);

  // Prefer the .table-responsive wrapper — it has real height even when empty.
  const tableHost = document.getElementById("vuln-table-body")?.closest(".table-responsive")
                 || document.querySelector(".ledger-table-wrapper")
                 || document.body;

  showLoader(tableHost, "Loading vulnerabilities…");
  try {
    allVulnerabilities = await fetchVulnerabilities();
    if (!allVulnerabilities.length) {
      toast("No vulnerabilities found.", "info");
    }
  } catch (err) {
    console.error("Failed to load vulnerabilities:", err);
    toast("Failed to load vulnerabilities. Please refresh.", "error", { duration: 6000 });
    allVulnerabilities = [];
  } finally {
    hideLoader(tableHost);
  }

  // Pre-fill from URL params
  const urlParams = new URLSearchParams(window.location.search);
  const urlFilter = urlParams.get("filter");
  activeYearFilter = urlParams.get("year") || "";

  const initialSearch = urlFilter || activeYearFilter || "";
  if (initialSearch) {
    const si = document.getElementById("ledger-search");
    if (si) si.value = initialSearch;
  }

  applyAndRender({ search: initialSearch });

  setupLedgerFilters((filters) => {
    if (filters.resetAll) {
      activeYearFilter = "";
      window.history.replaceState({}, document.title, window.location.pathname);
      applyAndRender({ search: "", from: "", to: "", cveType: "", cvss: "", interface: "", level: "", company: "", countermeasures: "" });
      return;
    }
    applyAndRender(filters);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
