
import { API_BASE } from "./api.js";

async function protectPage() {
  const response = await fetch(`${API_BASE}/me`, { credentials: "include" });
  if (!response.ok) {
    window.location.href = `login.html?next=${window.location.pathname.split("/").pop()}`;
  }
}
document.addEventListener("DOMContentLoaded", protectPage);


let currentPage = 1;
const entriesPerPage = 11;
let vulnerabilitiesData = [];

// Helper: format ISO date (or other parseable date) to DD-MM-YYYY
function formatDateToDDMMYYYY(rawDate) {
  if (!rawDate) return "N/A";

  // Some values may already be Date objects, strings, or numbers
  let date;
  try {
    date = new Date(rawDate);
    if (isNaN(date)) return "N/A";
  } catch (e) {
    console.error("Date parse error:", rawDate, e);
    return "N/A";
  }

  // Use en-GB to get DD/MM/YYYY then replace slashes with hyphens
  return date.toLocaleDateString("en-GB").replace(/\//g, "-");
}

// Render the table page
function renderVulnerabilitiesPage(page) {
  const tbody = document.getElementById("vuln-table-body");
  const emptyState = document.getElementById("empty-state");
  tbody.innerHTML = "";

  if (!vulnerabilitiesData || vulnerabilitiesData.length === 0) {
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
    // Use published_date primarily; fallbacks included
    const rawDate = vuln.published_date || vuln.published || vuln.date || vuln.created_at || null;
    const formattedDate = formatDateToDDMMYYYY(rawDate);

    // Use cve_id (your object has cve_id) and title
    const cveId = vuln.cve_id || vuln.id || "N/A";
    const title = vuln.title || "No title available";

    const row = `
      <tr>
        <td><a href="details.html?cve=${encodeURIComponent(cveId)}" class="cve-link">${cveId}</a></td>
        <td>${title}</td>
        <td>${formattedDate}</td>
      </tr>
    `;
    tbody.insertAdjacentHTML("beforeend", row);
  });

  renderPagination();
}

// Render pagination with Previous / Next and limited page numbers
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
  prevLi.addEventListener("click", (e) => {
    e.preventDefault();
    if (currentPage > 1) {
      currentPage--;
      renderVulnerabilitiesPage(currentPage);
    }
  });
  pagination.appendChild(prevLi);

  // Calculate sliding window for visible pages
  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = startPage + maxVisiblePages - 1;
  if (endPage > totalPages) {
    endPage = totalPages;
    startPage = Math.max(1, endPage - maxVisiblePages + 1);
  }

  // Page numbers
  for (let i = startPage; i <= endPage; i++) {
    const li = document.createElement("li");
    li.className = `page-item ${i === currentPage ? "active" : ""}`;
    li.innerHTML = `<a class="page-link" href="#">${i}</a>`;
    li.addEventListener("click", (e) => {
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
  nextLi.addEventListener("click", (e) => {
    e.preventDefault();
    if (currentPage < totalPages) {
      currentPage++;
      renderVulnerabilitiesPage(currentPage);
    }
  });
  pagination.appendChild(nextLi);
}

// Public entry: set data and render first page
export function renderVulnerabilities(data) {
  // Optionally sort by published_date descending (newest first)
  // If you want sorting, uncomment below block.
  
  data.sort((a, b) => {
    const da = new Date(a.published_date || a.published || a.date || a.created_at || 0);
    const db = new Date(b.published_date || b.published || b.date || b.created_at || 0);
    return db - da; // newest first
  });


  vulnerabilitiesData = Array.isArray(data) ? data : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
}

// // Render vulnerabilities and reset to page 1
// function renderVulnerabilities(vulnerabilities) {
//   vulnerabilitiesData = vulnerabilities || [];
//   currentPage = 1;
//   renderVulnerabilitiesPage(currentPage);
// }