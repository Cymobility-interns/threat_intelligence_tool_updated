// assets/js/branddetails.js
import { fetchVulnerabilities, API_BASE } from "./api.js";

// =========================
// Get brand from URL
// =========================
const urlParams = new URLSearchParams(window.location.search);
const brand = urlParams.get("brand")?.toLowerCase() || "";

// =========================
// DOM Elements
// =========================
const brandLogo = document.getElementById("brand-logo");
const emptyState = document.getElementById("empty-state");
const tableBody = document.getElementById("vuln-table-body");
const selectAllCheckbox = document.getElementById("select-all");
const downloadBtn = document.getElementById("download-selected");


let currentPage = 1;
const entriesPerPage = 9;
let vulnerabilitiesData = [];


// =========================
// Brand Logos
// =========================
const brandLogos = {
  toyota: "assets/images/toyota.png",
  hyundai: "assets/images/hyundai.png",
  kia: "assets/images/kia.png",
  honda: "assets/images/hondalogo.png",
  volkswagen: "assets/images/volkswagen.png",
  bmw: "assets/images/bmw.png",
  nissan: "assets/images/nissan.png",
  audi: "assets/images/audi.png",
  chevrolet: "assets/images/chevrolet.png",
  tesla: "assets/images/tesla.png",
  jeep: "assets/images/jeep.png",
  ford: "assets/images/ford.png",
  renault: "assets/images/renault.png",
  suzuki: "assets/images/suzuki.png",
  skoda: "assets/images/skoda.png",
  mahindra: "assets/images/mahindra.png",
  bosch: "assets/images/bosch.png",
  continental: "assets/images/continental.png",
  harman: "assets/images/harman.png",
  magna: "assets/images/magna.png",
  nxp: "assets/images/nxp.png",
  qualcomm: "assets/images/qualcomm.png",
  aptiv: "assets/images/aptiv.png",
};

// =========================
// Helpers
// =========================

// Fetch full vulnerability details (same as details.js)
async function fetchDetails(identifier) {
  if (!identifier) return null;

  const baseUrl = `${ API_BASE }/automotive_vulnerabilities`;
  const url = identifier.startsWith("internal-")
    ? `${baseUrl}/id/${identifier.replace("internal-", "")}`
    : `${baseUrl}/cve/${identifier}`;

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    console.error("Failed to fetch details:", err);
    return null;
  }
}

// ============================================
// Generate PDF with IMAGE Watermark + Table
// ============================================
// Utility: convert image to Base64
function loadImageAsBase64(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "anonymous"; // try lowercase 'anonymous'
    img.src = url;

    img.onload = function () {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        const base64 = canvas.toDataURL("image/png");
        resolve(base64);
      } catch (err) {
        reject(err);
      }
    };

    img.onerror = function (err) {
      console.error("Image load failed:", url, err);
      reject(new Error("Failed to load image: " + url));
    };
  });
}

// -----------------------------
// Helper: format ISO date to DD-MM-YYYY
// -----------------------------
function formatDateToDDMMYYYY(rawDate) {
  if (!rawDate) return "Not Available";
  const date = new Date(rawDate);
  return isNaN(date) ? "Not Available" : date.toLocaleDateString("en-GB").replace(/\//g, "-");
}

// =========================
// Load vulnerabilities for brand
// =========================
async function loadVulnerabilities() {
  try {
    const vulns = await fetchVulnerabilities({ search: brand });

    if (!vulns || !vulns.length) {
      emptyState.style.display = "block";
      emptyState.textContent = "No vulnerabilities found.";
      return [];
    }

    emptyState.style.display = "none";
    renderVulnerabilitiesWithCheckbox(vulns);
    return vulns; // ✅ important: so .then() can chain
  } catch (error) {
    console.error("Error loading vulnerabilities:", error);
    emptyState.style.display = "block";
    emptyState.textContent = "⚠️ Failed to load vulnerabilities.";
    return [];
  }
}


// =========================
// Render vulnerabilities table
// =========================
function renderVulnerabilitiesWithCheckbox(vulns) {
  vulnerabilitiesData = Array.isArray(vulns) ? vulns : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
}

// =========================
// Render one page of vulnerabilities (paginated + clickable row)
// =========================
function renderVulnerabilitiesPage(page) {
  const tbody = document.getElementById("vuln-table-body");
  const emptyState = document.getElementById("empty-state");
  tbody.innerHTML = "";

  if (!Array.isArray(vulnerabilitiesData) || vulnerabilitiesData.length === 0) {
    emptyState.style.display = "block";
    const paginationEl = document.getElementById("pagination");
    if (paginationEl) paginationEl.innerHTML = "";
    return;
  } else {
    emptyState.style.display = "none";
  }

  sessionStorage.setItem('lastSource', 'branddetails');
  sessionStorage.setItem('branddetailsCurrentPage', currentPage);

  // helper: decide whether a cve value is valid (same logic as ledger)
  function normalizeCve(val) {
    if (val === undefined || val === null) return null;
    const s = String(val).trim();
    if (!s) return null;
    const lower = s.toLowerCase();
    if (lower === "not available" || lower === "n/a" || lower === "null" || lower === "undefined") return null;
    return s;
  }

  // helper: generate a fallback unique id (same as ledger)
  function genFallback() {
    if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
      return `internal-${crypto.randomUUID()}`;
    }
    return `internal-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,10)}`;
  }

  const start = (page - 1) * entriesPerPage;
  const end = start + entriesPerPage;
  const pageData = vulnerabilitiesData.slice(start, end);

  pageData.forEach(vuln => {
    // Normalize CVE and create a reliable unique id (used for links & checkboxes)
    const normalizedCve = normalizeCve(vuln.cve_id ?? vuln.cve ?? vuln.identifier);
    const fallbackId = (vuln.id || vuln._id || vuln.db_id) ? `internal-${vuln.id || vuln._id || vuln.db_id}` : genFallback();
    const uniqueId = normalizedCve || fallbackId;

    // display value (what the user sees in the table)
    const displayId = normalizedCve || "Not Available";

    const published = formatDateToDDMMYYYY(vuln.published_date);
    const title = vuln.title || "—";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td><input type="checkbox" class="select-row" data-id="${escapeHtml(uniqueId)}"></td>
      <td>${escapeHtml(displayId)}</td>
      <td>${escapeHtml(title)}</td>
      <td>${escapeHtml(published)}</td>
    `;

    // Make the entire row clickable (but not when clicking the checkbox)
    row.style.cursor = "pointer";
    row.addEventListener("click", (e) => {
      if (e.target.closest('input[type="checkbox"]')) return;
      sessionStorage.setItem('lastSource', 'branddetails');
      sessionStorage.setItem('branddetailsCurrentPage', currentPage);
      sessionStorage.setItem('brandName', brand); // store current brand for return
      window.location.href = `details.html?cve=${encodeURIComponent(uniqueId)}`;
    });


    tbody.appendChild(row);
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
  data.sort((a, b) =>
    new Date(b.published_date || b.published || b.date || b.created_at || 0) -
    new Date(a.published_date || a.published || a.date || a.created_at || 0)
  );

  vulnerabilitiesData = Array.isArray(data) ? data : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
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

// =========================
// Handle Select All
// =========================
selectAllCheckbox.addEventListener("change", () => {
  const allCheckboxes = document.querySelectorAll(".select-row");
  allCheckboxes.forEach(cb => (cb.checked = selectAllCheckbox.checked));
});

// =========================
// Handle Download Button
// =========================
downloadBtn.addEventListener("click", async () => {
  const selected = [...document.querySelectorAll(".select-row:checked")].map(cb => cb.dataset.id);
  if (selected.length === 0) {
    alert("Please select at least one vulnerability to download the report.");
    return;
  }

  downloadBtn.disabled = true;
  // downloadBtn.innerHTML = "⏳ Generating PDF...";

  // const { jsPDF } = window.jspdf;
  const jsPDF = window.jspdf.jsPDF;
  const doc = new jsPDF();
  const logoBase64 = await loadImageAsBase64("assets/images/logopdf.png");

  const fields = [
    "cve_id","source","published_date","company","title","description","attack_path","interface",
    "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","cvss_score","impact","feasibility",
    "countermeasures","model_name","model_year","ecu_name","library_name"
  ];

  for (let i = 0; i < selected.length; i++) {
    const identifier = selected[i];
    const data = await fetchDetails(identifier);
    if (!data) continue;

    if (i > 0) doc.addPage();

    // Add logo + title
    doc.addImage(logoBase64, "PNG", 10, -5, 60, 30);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("Vulnerability Report", 105, 25, { align: "center" });

     // Custom label overrides (Acronyms)
      const labelOverrides = {
        cve_id: "CVE ID",
        ecu_name: "ECU Name",
        cia: "CIA",
        cvss_score: "CVSS Score"
      };

      // Build rows dynamically
      const rows = fields.map(key => {
        let value = data[key];
        if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
        if (!value) value = "Not Available";

        const label = labelOverrides[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
        return [label, String(value)];
      });

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    // Draw table + watermark (watermark AFTER content so it is visible)
    doc.autoTable({
      startY: 40,
      head: [["Field", "Value"]],
      body: rows,
      theme: "grid",
      styles: { fontSize: 10 },
      columnStyles: { 0: { fontStyle: "bold" } },

       didParseCell: function (data) {
        if (data.section === 'head') {
          data.cell.styles.fillColor = [0, 0, 102];
          data.cell.styles.textColor = 255;            
          data.cell.styles.fontStyle = 'bold';
          data.cell.styles.halign = 'center';
        }
      },

      didDrawPage: (data) => {
        try {
          // Enable transparency
          if (doc.setGState) {
            doc.setGState(new doc.GState({ opacity: 0.1 }));
          }

          // === Page layout ===
          const pageWidth = doc.internal.pageSize.getWidth();
          const pageHeight = doc.internal.pageSize.getHeight();

          const centerX = pageWidth / 2;   // horizontal center
          const centerY = pageHeight / 2;  // vertical center
          const offsetY = 90;              // space between top/mid/bottom

          // === Global shifts (move all together) ===
          const shiftX = 70;   // move all left (-) or right (+)
          const shiftY = 50;   // move all up (-) or down (+)

          // === Individual fine-tuning for each ===
          const topOffset = { x: 0, y: 0 };      // move top watermark
          const middleOffset = { x: 0, y: 0 };   // move middle watermark
          const bottomOffset = { x: 0, y: 0 };   // move bottom watermark

          // 💡 Example tweaks:
          topOffset.x = -20;  // move top left
          topOffset.y = 20;  // move top up
          bottomOffset.x = 20; // move bottom right
          bottomOffset.y = -20; // move bottom down

          // === Watermark appearance ===
          const wmWidth = 200;
          const wmHeight = 120;
          const rotationAngle = 45;  // diagonal rotation

          // Helper to draw one rotated image watermark
          const drawWatermark = (x, y) => {
            doc.addImage(
              logoBase64,
              "PNG",
              x - wmWidth / 2,
              y - wmHeight / 2,
              wmWidth,
              wmHeight,
              "",
              "FAST",
              rotationAngle
            );
          };

          // === Draw 3 watermarks ===
          // Combine global shift + individual offsets
          drawWatermark(
            centerX + shiftX + topOffset.x,
            centerY - offsetY + shiftY + topOffset.y
          ); // top

          drawWatermark(
            centerX + shiftX + middleOffset.x,
            centerY + shiftY + middleOffset.y
          ); // middle

          drawWatermark(
            centerX + shiftX + bottomOffset.x,
            centerY + offsetY + shiftY + bottomOffset.y
          ); // bottom

          // Reset transparency
          if (doc.setGState) {
            doc.setGState(new doc.GState({ opacity: 1 }));
          }
        } catch (e) {
          console.error("Watermark render error:", e);
        }
      }
    });
  }

  doc.save(`Selected_Vulnerabilities_${brand || "Report"}.pdf`);
  downloadBtn.disabled = false;
  // downloadBtn.innerHTML = "⬇️ Download Selected";
});

// =========================
// Init
// =========================
function updateBrandLogo(brand) {
  brandLogo.src = brandLogos[brand] || "assets/images/default.png";
}

updateBrandLogo(brand);

const savedPage = parseInt(sessionStorage.getItem('branddetailsCurrentPage')) || 1;

// Load vulnerabilities first, then restore pagination
loadVulnerabilities().then(() => {
  // After vulnerabilitiesData is fetched and set
  if (savedPage > 1) {
    currentPage = savedPage;
    renderVulnerabilitiesPage(currentPage);
  }
});

