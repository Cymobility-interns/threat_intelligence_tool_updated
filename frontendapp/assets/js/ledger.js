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
    return `internal-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
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

    const row = document.createElement("tr");
    row.classList.add("ledger-row");
    row.innerHTML = `
      <td>${escapeHtml(displayId)}</td>
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
export function renderVulnerabilities(data) {
  // const filter = new URLSearchParams(window.location.search).get("filter");
  let filter = new URLSearchParams(window.location.search).get("filter");
  console.log("URL filter received:", filter);
  const originalFilter = filter;  // keep original for debugging

  if (filter) {
      filter = filter.toLowerCase().replace(/-/g, "").replace(/\s+/g, "");
  }


  if (filter && filter !== "Others") {

  data = data.filter(vul => {
    const fields = [
      vul.description || "",
      vul.interface || "",
      vul.title || "",
      vul.ecu_name || ""
    ];

    // UNIVERSAL WIFI MATCHER — works for wifi, wi-fi, wi fi, WiFi, WI-FI...
    if (originalFilter.toLowerCase().includes("wi")) {
      return fields.some(text => {
        const t = text.toLowerCase().replace(/-/g, "").replace(/\s+/g, "");
        return t.includes("wifi");
      });
    }


    // NORMAL logic for CAN, LIN, Ethernet, Bluetooth, etc.
    const normalize = (str) =>
    str.toLowerCase().replace(/[\s\-_]/g, "");

  return fields.some(text =>
    normalize(text).includes(normalize(filter))
  );

  })
  
  } else if (filter === "Others") {
    const labels = ["CAN", "LIN", "Ethernet", "Wifi", "Bluetooth", "Telematics"];
    data = data.filter(vul =>
      !labels.some(label =>
        (vul.description && vul.description.includes(label)) ||
        (vul.interface && vul.interface.includes(label)) ||
        (vul.title && vul.title.includes(label)) ||
        (vul.ecu_name && vul.ecu_name.includes(label))
      )
    );
  }

  // Sort newest first
  data.sort((a, b) =>
    new Date(b.published_date || b.published || b.date || b.created_at || 0) -
    new Date(a.published_date || a.published || a.date || a.created_at || 0)
  );

  vulnerabilitiesData = Array.isArray(data) ? data : [];
  
  if (filter) {
      currentPage = 1;   // always start from page 1 for filtered results
  } else {
      const savedPage = parseInt(sessionStorage.getItem('ledgerCurrentPage')) || 1;
      currentPage = savedPage;
  }

  renderVulnerabilitiesPage(currentPage);

}

// -----------------------------
// Setup Ledger Filters
// -----------------------------
/**
 * setupLedgerFilters(onFilterChange)
 * onFilterChange: function(filters) -> will be called when user performs:
 *   - search (click search button)           -> { search }
 *   - apply filters (Apply button)           -> { from, to, cveType }
 *   - reset filters inside sidebar           -> clears fields only (no fetch)
 *   - reset all (top reset button)           -> { resetAll: true }
 *
 * main.js should pass a function that performs the fetch using combined state.
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

  // ---- Create background overlay for dimming and outside-click ----
  let overlay = document.getElementById("filter-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "filter-overlay";
    document.body.appendChild(overlay);
  }

  // ---- Helper functions for sidebar open/close ----
  const openSidebar = () => {
    sidebar?.classList.add("open");
    overlay.classList.add("active");
  };

  const closeSidebar = () => {
    sidebar?.classList.remove("open");
    overlay.classList.remove("active");
  };

  // ---- Event Listeners ----
  filterBtn?.addEventListener("click", openSidebar);
  closeBtn?.addEventListener("click", closeSidebar);
  overlay?.addEventListener("click", closeSidebar); // click outside to close

  // ---- Search button logic ----
  searchBtn?.addEventListener("click", () => {
    const query = searchInput?.value?.trim() ?? "";
    if (typeof onFilterChange === "function") {
      onFilterChange({ search: query });
    }
  });

  // ✅ Trigger search on Enter key
  searchInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const query = searchInput?.value?.trim() ?? "";
      if (typeof onFilterChange === "function") {
        onFilterChange({ search: query });
      }
    }
  });

  // ---- Apply filters ----
  applyBtn?.addEventListener("click", () => {
    const from = document.getElementById("filter-from")?.value ?? "";
    const to = document.getElementById("filter-to")?.value ?? "";
    const cveType = document.getElementById("filter-cve-type")?.value ?? "";

    closeSidebar();

    if (typeof onFilterChange === "function") {
      onFilterChange({ from, to, cveType });
    }
  });

  // ---- Reset filters (inside sidebar only) ----
  resetFiltersBtn?.addEventListener("click", () => {
    document.getElementById("filter-cve-type").value = "";
    document.getElementById("filter-from").value = "";
    document.getElementById("filter-to").value = "";
  });

  // ---- Reset All (top-right) ----
  resetAllBtn?.addEventListener("click", () => {
    // Clear sidebar inputs
    if (document.getElementById("filter-cve-type"))
      document.getElementById("filter-cve-type").value = "";
    if (document.getElementById("filter-from"))
      document.getElementById("filter-from").value = "";
    if (document.getElementById("filter-to"))
      document.getElementById("filter-to").value = "";

    // Clear search boxes
    if (searchInput) searchInput.value = "";
    const navSearchInput = document.getElementById("search-input");
    if (navSearchInput) navSearchInput.value = "";

    // Notify main.js to reload all data
    if (typeof onFilterChange === "function") {
      onFilterChange({
        resetAll: true,
        search: "",
        from: "",
        to: "",
        cveType: "",
      });
    }
  });
}
