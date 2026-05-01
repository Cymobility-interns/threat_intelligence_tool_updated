import { API_BASE } from "./api.js";

// async function protectPage() {
//   const response = await fetch(`${API_BASE}/me`, { credentials: "include" });
//   if (!response.ok) {
//     window.location.href = `login.html?next=${window.location.pathname.split("/").pop()}`;
//   }
// }
// document.addEventListener("DOMContentLoaded", protectPage);

let currentPage = 1;
const entriesPerPage = 10;
let vulnerabilitiesData = [];

// -----------------------------
// Helper: format ISO date to DD-MM-YYYY
// -----------------------------
function formatDateToDDMMYYYY(rawDate) {
  if (!rawDate) return "Not Available";
  const date = new Date(rawDate);
  return isNaN(date) ? "Not Available" : date.toLocaleDateString("en-GB").replace(/\//g, "-");
}

// -----------------------------
// Render one page of vulnerabilities (robust CVE handling)
// -----------------------------
function renderVulnerabilitiesPage(page) {
  const tbody = document.getElementById("vuln-table-body");
  const emptyState = document.getElementById("empty-state");
  tbody.innerHTML = "";

  if (!Array.isArray(vulnerabilitiesData) || vulnerabilitiesData.length === 0) {
    emptyState.style.display = "block";
    document.getElementById("pagination").innerHTML = "";
    return;
  } else {
    emptyState.style.display = "none";
  }

  //Remember current page for back navigation
  sessionStorage.setItem('lastSource', 'ledger');
  sessionStorage.setItem('ledgerCurrentPage', currentPage);


  // helper: decide whether a cve value is valid
  function normalizeCve(val) {
    if (val === undefined || val === null) return null;
    const s = String(val).trim();
    if (!s) return null;
    const lower = s.toLowerCase();
    // treat these literal values as missing
    if (lower === "not available" || lower === "n/a" || lower === "null" || lower === "undefined") return null;
    return s;
  }

  // helper: generate a fallback unique id
  function genFallback() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return `internal-${crypto.randomUUID()}`;
    }
    // fallback if crypto.randomUUID not available
    return `internal-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  const start = (page - 1) * entriesPerPage;
  const end = start + entriesPerPage;
  const pageData = vulnerabilitiesData.slice(start, end);

  pageData.forEach((vuln, idx) => {
    const rawDate = vuln.published_date || vuln.published || vuln.date || vuln.created_at || null;
    const formattedDate = formatDateToDDMMYYYY(rawDate);

    const normalizedCve = normalizeCve(vuln.cve_id ?? vuln.cve ?? vuln.identifier);
    const fallbackId = (vuln.id || vuln._id || vuln.db_id) ? `internal-${vuln.id || vuln._id || vuln.db_id}` : genFallback();
    const uniqueId = normalizedCve || fallbackId;

    //show "Not Available" instead of ID numbers
    const displayId = normalizedCve || "Not Available";

    const title = vuln.title || vuln.summary || "Not Available";

    // Determine if this entry has a real CVE ID
    const hasCveId = !!normalizedCve;

    // Build the Identifier cell content
    // - WITH cve_id  → teal (default table color, cve-link class)
    // - WITHOUT cve_id → amber + "Date Only" badge (classified purely by published date)
    const identifierCell = hasCveId
      ? `<td>${escapeHtml(displayId)}</td>`
      : `<td class="no-cve-id">${escapeHtml(displayId)}</td>`;

    const row = document.createElement("tr");
    row.classList.add("ledger-row");
    row.innerHTML = `
      ${identifierCell}
      <td>${escapeHtml(title)}</td>
      <td>${escapeHtml(formattedDate)}</td>
    `;
    // Make entire row clickable
    const detailsUrl = `details.html?cve=${encodeURIComponent(uniqueId)}`;
    row.style.cursor = "pointer";
    row.addEventListener("click", (e) => {
      if (e.target.closest('input[type="checkbox"]')) return;
      sessionStorage.setItem('lastSource', 'ledger');
      sessionStorage.setItem('ledgerCurrentPage', currentPage);
      window.location.href = `details.html?cve=${encodeURIComponent(uniqueId)}`;
    });



    tbody.appendChild(row);
  });


  renderPagination();
}

// small helper to avoid injecting raw HTML
function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// -----------------------------
// Render pagination
// -----------------------------
function renderPagination() {
  const pagination = document.getElementById("pagination");
  pagination.innerHTML = "";

  const totalPages = Math.ceil(vulnerabilitiesData.length / entriesPerPage);
  if (totalPages <= 1) return;

  const maxVisiblePages = 5;

  // Previous
  const prevLi = document.createElement("li");
  prevLi.className = `page-item ${currentPage === 1 ? "disabled" : ""}`;
  prevLi.innerHTML = `<a class="page-link" href="#">Previous</a>`;
  prevLi.addEventListener("click", e => {
    e.preventDefault();
    if (currentPage > 1) {
      currentPage--;
      renderVulnerabilitiesPage(currentPage);
    }
  });
  pagination.appendChild(prevLi);

  // Page numbers
  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  startPage = Math.max(1, endPage - maxVisiblePages + 1);

  for (let i = startPage; i <= endPage; i++) {
    const li = document.createElement("li");
    li.className = `page-item ${i === currentPage ? "active" : ""}`;
    li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
    li.addEventListener("click", e => {
      e.preventDefault();
      currentPage = i;
      renderVulnerabilitiesPage(currentPage);
    });
    pagination.appendChild(li);
  }

  // Next
  const nextLi = document.createElement("li");
  nextLi.className = `page-item ${currentPage === totalPages ? "disabled" : ""}`;
  nextLi.innerHTML = `<a class="page-link" href="#">Next</a>`;
  nextLi.addEventListener("click", e => {
    e.preventDefault();
    if (currentPage < totalPages) {
      currentPage++;
      renderVulnerabilitiesPage(currentPage);
    }
  });
  pagination.appendChild(nextLi);
}

// -----------------------------
// Entry: render vulnerabilities (with optional filtering)
// -----------------------------
export function renderVulnerabilities(data, searchTerm) {
  // ── URL filter: only respected on FIRST load (when called from init without searchTerm)
  // ── When called from the search button, searchTerm is passed explicitly
  let filter = (searchTerm !== undefined)
    ? searchTerm
    : new URLSearchParams(window.location.search).get("filter") || "";

  const originalFilter = filter.trim();

  // ── Normalize: lowercase + replace hyphens/underscores with SPACES.
  // Replacing (not removing) preserves word boundaries so:
  //   "CVE-2025-5833" → "cve 2025 5833"  (numbers become separate words)
  //   "anti-theft"    → "anti theft"
  const normalize = (str) =>
    String(str || "").toLowerCase().replace(/[-_]/g, " ");

  const normFilter = normalize(originalFilter).trim();

  if (normFilter) {
    // Escape any regex special characters in user input
    const escaped = normFilter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    // \b around the term = must match a full word.
    // "hero" → matches "hero", "hero motocorp"
    //        → does NOT match "heroic"
    const searchRegex = new RegExp(`\\b${escaped}\\b`, "i");

    data = data.filter(vul => {
      // ── Full raw text (for special-case handlers that need original casing) ──
      const rawText = [
        vul.cve_id, vul.source, vul.company, vul.title,
        vul.description, vul.attack_path, vul.interface,
        vul.tools_used, vul.types_of_attack, vul.level_of_attack,
        vul.damage_scenario, vul.cia, vul.impact, vul.feasibility,
        vul.countermeasures, vul.model_name, vul.model_year,
        vul.ecu_name, vul.library_name,
        vul.cvss_score != null ? String(vul.cvss_score) : "",
        (() => {
          if (!vul.published_date) return "";
          const d = new Date(vul.published_date);
          return isNaN(d) ? "" : `${d.toLocaleDateString("en-GB").replace(/\//g, "-")} ${d.getFullYear()}`;
        })(),
      ].filter(Boolean).join(" ");

      // ── Special: Wi-Fi / wifi ──
      if (originalFilter.toLowerCase().replace(/-/g, "").includes("wifi")) {
        return /\bwi.?fi\b/i.test(rawText) || normalize(rawText).includes("wifi");
      }

      // ── Special: CAN — strip ZDI-CAN-xxxxx entries so they don't false-match ──
      if (originalFilter.trim().toUpperCase() === "CAN") {
        return /\bCAN\b/.test(rawText.replace(/ZDI-CAN-\d+/gi, ""));
      }

      // ── Generic: word-boundary regex on normalized full text ──
      return searchRegex.test(normalize(rawText));
    });
  }

  // ── Sort: newest first (CVE year if present, else published_date)
  data.sort((a, b) => {
    const getTs = (vul) => {
      if (vul.cve_id && /CVE-\d{4}-/i.test(vul.cve_id)) {
        const m = vul.cve_id.match(/CVE-(\d{4})-/i);
        if (m) return parseInt(m[1], 10) * 10000 +
          (vul.published_date ? new Date(vul.published_date).getTime() / 1e10 : 0);
      }
      return vul.published_date ? new Date(vul.published_date).getTime() / 1e10 : 0;
    };
    return getTs(b) - getTs(a);
  });

  vulnerabilitiesData = Array.isArray(data) ? data : [];

  if (normFilter) {
    currentPage = 1;
  } else {
    const savedPage = parseInt(sessionStorage.getItem("ledgerCurrentPage")) || 1;
    currentPage = savedPage;
  }

  renderVulnerabilitiesPage(currentPage);
}


// -----------------------------
// Setup Ledger Filters
// -----------------------------
/**
 * setupLedgerFilters(onFilterChange)
 * Always calls onFilterChange with the COMPLETE filter state:
 *   { search, from, to, cveType, resetAll? }
 * Never sends partial objects — eliminates stale-state bugs.
 */
export function setupLedgerFilters(onFilterChange) {
  const sidebar = document.getElementById("filter-sidebar");
  const filterBtn = document.getElementById("filter-btn");
  const closeBtn = document.getElementById("close-filter");
  const applyBtn = document.getElementById("apply-filters-btn");
  const resetFiltersBtn = document.getElementById("reset-filters-btn");
  const resetAllBtn = document.getElementById("reset-all-btn");
  const searchInput = document.getElementById("ledger-search");
  const searchBtn = document.getElementById("ledger-search-btn");
  const fromInput = document.getElementById("filter-from");
  const toInput = document.getElementById("filter-to");
  const cveTypeSelect = document.getElementById("filter-cve-type");
  const cvssSelect = document.getElementById("filter-cvss");
  const interfaceSelect = document.getElementById("filter-interface");
  const levelSelect = document.getElementById("filter-level");
  const companyInput = document.getElementById("filter-company");
  const countermeasuresSelect = document.getElementById("filter-countermeasures");

  // ── Internal state (single source of truth inside this function) ──
  let state = { search: "", from: "", to: "", cveType: "", cvss: "", interface: "", level: "", company: "", countermeasures: "" };

  const emit = () => {
    if (typeof onFilterChange === "function") {
      onFilterChange({ ...state });
    }
  };

  // ── Overlay for sidebar backdrop ──
  let overlay = document.getElementById("filter-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "filter-overlay";
    document.body.appendChild(overlay);
  }

  const openSidebar = () => { sidebar?.classList.add("open"); overlay.classList.add("active"); };
  const closeSidebar = () => { sidebar?.classList.remove("open"); overlay.classList.remove("active"); };

  filterBtn?.addEventListener("click", openSidebar);
  closeBtn?.addEventListener("click", closeSidebar);
  overlay?.addEventListener("click", closeSidebar);

  // ── Live search: filter as user types (debounced 250ms) ──
  let debounceTimer = null;
  searchInput?.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      state.search = searchInput.value.trim();
      emit();
    }, 250);
  });

  // ── Search button click ──
  searchBtn?.addEventListener("click", () => {
    clearTimeout(debounceTimer);
    state.search = searchInput?.value?.trim() ?? "";
    emit();
  });

  // ── Enter key in search box ──
  searchInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      clearTimeout(debounceTimer);
      state.search = searchInput.value.trim();
      emit();
    }
  });

  // ── Apply sidebar filters (preserves current search) ──
  applyBtn?.addEventListener("click", () => {
    state.from = fromInput?.value ?? "";
    state.to = toInput?.value ?? "";
    state.cveType = cveTypeSelect?.value ?? "";
    state.cvss = cvssSelect?.value ?? "";
    state.interface = interfaceSelect?.value ?? "";
    state.level = levelSelect?.value ?? "";
    state.company = companyInput?.value ?? "";
    state.countermeasures = countermeasuresSelect?.value ?? "";
    // state.search stays unchanged — keeps the text search active
    closeSidebar();
    emit();
  });

  // ── Reset inside sidebar (clears everything except search) ──
  resetFiltersBtn?.addEventListener("click", () => {
    if (fromInput) fromInput.value = "";
    if (toInput) toInput.value = "";
    if (cveTypeSelect) cveTypeSelect.value = "";
    if (cvssSelect) cvssSelect.value = "";
    if (interfaceSelect) interfaceSelect.value = "";
    if (levelSelect) levelSelect.value = "";
    if (companyInput) companyInput.value = "";
    if (countermeasuresSelect) countermeasuresSelect.value = "";
    
    state.from = "";
    state.to = "";
    state.cveType = "";
    state.cvss = "";
    state.interface = "";
    state.level = "";
    state.company = "";
    state.countermeasures = "";
    emit();
  });

  // ── Reset ALL (clears everything) ──
  resetAllBtn?.addEventListener("click", () => {
    if (fromInput) fromInput.value = "";
    if (toInput) toInput.value = "";
    if (cveTypeSelect) cveTypeSelect.value = "";
    if (cvssSelect) cvssSelect.value = "";
    if (interfaceSelect) interfaceSelect.value = "";
    if (levelSelect) levelSelect.value = "";
    if (companyInput) companyInput.value = "";
    if (countermeasuresSelect) countermeasuresSelect.value = "";
    if (searchInput) searchInput.value = "";
    
    state = { search: "", from: "", to: "", cveType: "", cvss: "", interface: "", level: "", company: "", countermeasures: "" };
    if (typeof onFilterChange === "function") {
      onFilterChange({ ...state, resetAll: true });
    }
  });
}

