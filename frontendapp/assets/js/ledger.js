import {
  escapeHtml,
  debounce,
  safeSession,
  formatDateDDMMYYYY,
  normalizeCve,
  genFallbackId,
} from "./utils.js";

let currentPage = 1;
const entriesPerPage = 10;
let vulnerabilitiesData = [];

// -----------------------------
// Render one page of vulnerabilities (robust CVE handling)
// -----------------------------
function renderVulnerabilitiesPage(page) {
  const tbody = document.getElementById("vuln-table-body");
  const emptyState = document.getElementById("empty-state");
  if (!tbody) return;
  tbody.innerHTML = "";

  if (!Array.isArray(vulnerabilitiesData) || vulnerabilitiesData.length === 0) {
    if (emptyState) emptyState.style.display = "block";
    const pag = document.getElementById("pagination");
    if (pag) pag.innerHTML = "";
    return;
  }
  if (emptyState) emptyState.style.display = "none";

  // Remember current page for back-navigation
  safeSession.set("lastSource", "ledger");
  safeSession.set("ledgerCurrentPage", String(currentPage));

  const start = (page - 1) * entriesPerPage;
  const end = start + entriesPerPage;
  const pageData = vulnerabilitiesData.slice(start, end);

  // Build rows in a fragment to minimise reflow
  const frag = document.createDocumentFragment();

  pageData.forEach((vuln) => {
    const rawDate = vuln.published_date || vuln.published || vuln.date || vuln.created_at || null;
    const formattedDate = formatDateDDMMYYYY(rawDate);

    const normalizedCve = normalizeCve(vuln.cve_id ?? vuln.cve ?? vuln.identifier);
    const fallbackId = (vuln.id || vuln._id || vuln.db_id)
      ? `internal-${vuln.id || vuln._id || vuln.db_id}`
      : genFallbackId();
    const uniqueId = normalizedCve || fallbackId;
    const displayId = normalizedCve || "Not Available";
    const title = vuln.title || vuln.summary || "Not Available";
    const hasCveId = !!normalizedCve;

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
    row.style.cursor = "pointer";
    row.addEventListener("click", (e) => {
      if (e.target.closest('input[type="checkbox"]')) return;
      safeSession.set("lastSource", "ledger");
      safeSession.set("ledgerCurrentPage", String(currentPage));
      window.location.href = `details.html?cve=${encodeURIComponent(uniqueId)}`;
    });

    frag.appendChild(row);
  });

  tbody.appendChild(frag);
  renderPagination();
}

// -----------------------------
// Render pagination
// -----------------------------
function renderPagination() {
  const pagination = document.getElementById("pagination");
  if (!pagination) return;
  pagination.innerHTML = "";

  const totalPages = Math.ceil(vulnerabilitiesData.length / entriesPerPage);
  if (totalPages <= 1) return;

  const maxVisiblePages = 5;

  const makePageItem = (label, disabled, active, onClick) => {
    const li = document.createElement("li");
    li.className = `page-item${disabled ? " disabled" : ""}${active ? " active" : ""}`;
    const a = document.createElement("a");
    a.className = "page-link";
    a.href = "#";
    a.textContent = label;
    li.appendChild(a);
    li.addEventListener("click", (e) => {
      e.preventDefault();
      if (!disabled) onClick();
    });
    return li;
  };

  pagination.appendChild(makePageItem("Previous", currentPage === 1, false, () => {
    currentPage--;
    renderVulnerabilitiesPage(currentPage);
  }));

  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  startPage = Math.max(1, endPage - maxVisiblePages + 1);

  for (let i = startPage; i <= endPage; i++) {
    pagination.appendChild(makePageItem(String(i), false, i === currentPage, () => {
      currentPage = i;
      renderVulnerabilitiesPage(currentPage);
    }));
  }

  pagination.appendChild(makePageItem("Next", currentPage === totalPages, false, () => {
    currentPage++;
    renderVulnerabilitiesPage(currentPage);
  }));
}

// -----------------------------
// Entry: render vulnerabilities (with optional filtering)
// -----------------------------
export function renderVulnerabilities(data, searchTerm) {
  // ── URL filter: only respected on FIRST load (when called from init without searchTerm)
  // ── When called from the search button, searchTerm is passed explicitly
  const filter = (searchTerm !== undefined)
    ? searchTerm
    : new URLSearchParams(window.location.search).get("filter") || "";
  const originalFilter = filter.trim();

  // Normalise: lowercase + replace hyphens/underscores with SPACES so word boundaries survive
  const normalize = (str) => String(str || "").toLowerCase().replace(/[-_]/g, " ");
  const normFilter = normalize(originalFilter).trim();

  if (normFilter) {
    const escaped = normFilter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const searchRegex = new RegExp(`\\b${escaped}\\b`, "i");

    data = data.filter((vul) => {
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

      // Special: Wi-Fi / wifi
      if (originalFilter.toLowerCase().replace(/-/g, "").includes("wifi")) {
        return /\bwi.?fi\b/i.test(rawText) || normalize(rawText).includes("wifi");
      }
      // Special: CAN — strip ZDI-CAN-xxxxx so they don't false-match
      if (originalFilter.trim().toUpperCase() === "CAN") {
        return /\bCAN\b/.test(rawText.replace(/ZDI-CAN-\d+/gi, ""));
      }
      return searchRegex.test(normalize(rawText));
    });
  }

  // Newest first (CVE year if present, else published_date)
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
    currentPage = parseInt(safeSession.get("ledgerCurrentPage"), 10) || 1;
  }

  renderVulnerabilitiesPage(currentPage);
}

// -----------------------------
// Setup Ledger Filters
// -----------------------------
/**
 * setupLedgerFilters(onFilterChange)
 * Always calls onFilterChange with the COMPLETE filter state — never partials.
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

  const initialState = () => ({
    search: "", from: "", to: "", cveType: "", cvss: "",
    interface: "", level: "", company: "", countermeasures: "",
  });
  let state = initialState();

  const emit = () => {
    if (typeof onFilterChange === "function") onFilterChange({ ...state });
  };

  // Sidebar overlay
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

  // Live search — debounced 250ms via shared util
  const debouncedSearch = debounce(() => {
    state.search = searchInput?.value.trim() ?? "";
    emit();
  }, 250);
  searchInput?.addEventListener("input", debouncedSearch);

  searchBtn?.addEventListener("click", () => {
    debouncedSearch.cancel();
    state.search = searchInput?.value?.trim() ?? "";
    emit();
  });

  searchInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      debouncedSearch.cancel();
      state.search = searchInput.value.trim();
      emit();
    }
  });

  applyBtn?.addEventListener("click", () => {
    state.from = fromInput?.value ?? "";
    state.to = toInput?.value ?? "";
    state.cveType = cveTypeSelect?.value ?? "";
    state.cvss = cvssSelect?.value ?? "";
    state.interface = interfaceSelect?.value ?? "";
    state.level = levelSelect?.value ?? "";
    state.company = companyInput?.value ?? "";
    state.countermeasures = countermeasuresSelect?.value ?? "";
    closeSidebar();
    emit();
  });

  resetFiltersBtn?.addEventListener("click", () => {
    [fromInput, toInput, cveTypeSelect, cvssSelect, interfaceSelect, levelSelect, companyInput, countermeasuresSelect]
      .forEach(el => { if (el) el.value = ""; });
    Object.assign(state, initialState(), { search: state.search });
    emit();
  });

  resetAllBtn?.addEventListener("click", () => {
    [fromInput, toInput, cveTypeSelect, cvssSelect, interfaceSelect, levelSelect, companyInput, countermeasuresSelect, searchInput]
      .forEach(el => { if (el) el.value = ""; });
    state = initialState();
    if (typeof onFilterChange === "function") {
      onFilterChange({ ...state, resetAll: true });
    }
  });
}
