let currentPage = 1;
const entriesPerPage = 12;
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
// Render one page of vulnerabilities
// -----------------------------
function renderVulnerabilitiesPage(page) {
  const tbody = document.getElementById("vuln-table-body");
  const emptyState = document.getElementById("empty-state");
  tbody.innerHTML = "";

  if (!vulnerabilitiesData.length) {
    emptyState.style.display = "block";
    document.getElementById("pagination").innerHTML = "";
    return;
  } else {
    emptyState.style.display = "none";
  }

  const start = (page - 1) * entriesPerPage;
  const end = start + entriesPerPage;
  const pageData = vulnerabilitiesData.slice(start, end);

  pageData.forEach(vuln => {
    const rawDate = vuln.published_date || vuln.published || vuln.date || vuln.created_at || null;
    const formattedDate = formatDateToDDMMYYYY(rawDate);

    const cveId = vuln.cve_id || null;
    const title = vuln.title || "Not Available";

    // Use DB id if CVE missing
    const uniqueId = cveId || `internal-${vuln.id}`;
    const displayId = cveId || `ID: ${vuln.id}`;

    const cveCell = `<a href="details.html?cve=${encodeURIComponent(uniqueId)}" class="cve-link">${displayId}</a>`;

    const row = `<tr>
      <td>${cveCell}</td>
      <td>${title}</td>
      <td>${formattedDate}</td>
    </tr>`;
    tbody.insertAdjacentHTML("beforeend", row);
  });

  renderPagination();
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
  const filter = new URLSearchParams(window.location.search).get("filter");

  if (filter && filter !== "Others") {
    data = data.filter(vul =>
      (vul.description && vul.description.includes(filter)) ||
      (vul.interface && vul.interface.includes(filter)) ||
      (vul.title && vul.title.includes(filter)) ||
      (vul.ecu_name && vul.ecu_name.includes(filter))
    );
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
  data.sort((a, b) => new Date(b.published_date || b.published || b.date || b.created_at || 0) -
                     new Date(a.published_date || a.published || a.date || a.created_at || 0));

  vulnerabilitiesData = Array.isArray(data) ? data : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
}
