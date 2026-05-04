// assets/js/branddetails.js
import { fetchVulnerabilities, fetchVulnerabilityDetails } from "./api.js";
import {
  escapeHtml, formatDateDDMMYYYY, normalizeCve, genFallbackId,
  safeSession, toast, showLoader, hideLoader, withButtonBusy,
} from "./utils.js";

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
  mercedesbenz: "assets/images/mercedesbenz.png",
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
// PDF helpers
// =========================
function loadImageAsBase64(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "anonymous";
    img.src = url;
    img.onload = () => {
      try {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        canvas.getContext("2d").drawImage(img, 0, 0);
        resolve(canvas.toDataURL("image/png"));
      } catch (err) { reject(err); }
    };
    img.onerror = (err) => {
      console.error("Image load failed:", url, err);
      reject(new Error("Failed to load image: " + url));
    };
  });
}

function sanitizeText(text) {
  if (!text) return "";
  return String(text)
    .replace(/→|⟶|⇒|➝|➜/g, " -> ")
    .replace(/[’‘]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/—|–/g, "-")
    .replace(/\s+/g, " ")
    .trim();
}

// =========================
// Load vulnerabilities for brand
// =========================
async function loadVulnerabilities() {
  const tableHost = tableBody?.closest(".table-responsive") || tableBody?.closest("table") || document.body;
  showLoader(tableHost, "Loading vulnerabilities…");
  try {
    const vulns = await fetchVulnerabilities({ search: brand });
    if (!vulns || !vulns.length) {
      if (emptyState) {
        emptyState.style.display = "block";
        emptyState.textContent = "No vulnerabilities found.";
      }
      return [];
    }
    if (emptyState) emptyState.style.display = "none";
    renderVulnerabilitiesWithCheckbox(vulns);
    return vulns;
  } catch (error) {
    console.error("Error loading vulnerabilities:", error);
    if (emptyState) {
      emptyState.style.display = "block";
      emptyState.textContent = "Failed to load vulnerabilities.";
    }
    toast("Failed to load vulnerabilities.", "error");
    return [];
  } finally {
    hideLoader(tableHost);
  }
}

// =========================
// Render
// =========================
function renderVulnerabilitiesWithCheckbox(vulns) {
  vulnerabilitiesData = Array.isArray(vulns) ? vulns : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
}

function renderVulnerabilitiesPage(page) {
  if (!tableBody) return;
  tableBody.innerHTML = "";

  if (!Array.isArray(vulnerabilitiesData) || vulnerabilitiesData.length === 0) {
    if (emptyState) emptyState.style.display = "block";
    const pag = document.getElementById("pagination");
    if (pag) pag.innerHTML = "";
    return;
  }
  if (emptyState) emptyState.style.display = "none";

  safeSession.set("lastSource", "branddetails");
  safeSession.set("branddetailsCurrentPage", String(currentPage));

  const start = (page - 1) * entriesPerPage;
  const end = start + entriesPerPage;
  const pageData = vulnerabilitiesData.slice(start, end);

  const frag = document.createDocumentFragment();

  pageData.forEach((vuln) => {
    const normalizedCve = normalizeCve(vuln.cve_id ?? vuln.cve ?? vuln.identifier);
    const fallbackId = (vuln.id || vuln._id || vuln.db_id)
      ? `internal-${vuln.id || vuln._id || vuln.db_id}`
      : genFallbackId();
    const uniqueId = normalizedCve || fallbackId;
    const displayId = normalizedCve || "Not Available";
    const published = formatDateDDMMYYYY(vuln.published_date);
    const title = vuln.title || "—";

    const row = document.createElement("tr");
    row.innerHTML = `
      <td><input type="checkbox" class="select-row" data-id="${escapeHtml(uniqueId)}"></td>
      <td>${escapeHtml(displayId)}</td>
      <td>${escapeHtml(title)}</td>
      <td>${escapeHtml(published)}</td>
    `;
    row.style.cursor = "pointer";
    row.addEventListener("click", (e) => {
      if (e.target.closest('input[type="checkbox"]')) return;
      safeSession.set("lastSource", "branddetails");
      safeSession.set("branddetailsCurrentPage", String(currentPage));
      safeSession.set("brandName", brand);
      window.location.href = `details.html?cve=${encodeURIComponent(uniqueId)}`;
    });

    frag.appendChild(row);
  });

  tableBody.appendChild(frag);
  renderPagination();
}

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
    currentPage--; renderVulnerabilitiesPage(currentPage);
  }));

  let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
  let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
  startPage = Math.max(1, endPage - maxVisiblePages + 1);

  for (let i = startPage; i <= endPage; i++) {
    pagination.appendChild(makePageItem(String(i), false, i === currentPage, () => {
      currentPage = i; renderVulnerabilitiesPage(currentPage);
    }));
  }

  pagination.appendChild(makePageItem("Next", currentPage === totalPages, false, () => {
    currentPage++; renderVulnerabilitiesPage(currentPage);
  }));
}

// Optional alternative entry kept for backwards compat
export function renderVulnerabilities(data) {
  const filter = new URLSearchParams(window.location.search).get("filter");

  if (filter && filter !== "Others") {
    data = data.filter((vul) =>
      (vul.description && vul.description.includes(filter)) ||
      (vul.interface && vul.interface.includes(filter)) ||
      (vul.title && vul.title.includes(filter)) ||
      (vul.ecu_name && vul.ecu_name.includes(filter)));
  } else if (filter === "Others") {
    const labels = ["CAN", "LIN", "Ethernet", "Wifi", "Bluetooth", "Telematics"];
    data = data.filter((vul) => !labels.some((label) =>
      (vul.description && vul.description.includes(label)) ||
      (vul.interface && vul.interface.includes(label)) ||
      (vul.title && vul.title.includes(label)) ||
      (vul.ecu_name && vul.ecu_name.includes(label))));
  }

  data.sort((a, b) =>
    new Date(b.published_date || b.published || b.date || b.created_at || 0) -
    new Date(a.published_date || a.published || a.date || a.created_at || 0));

  vulnerabilitiesData = Array.isArray(data) ? data : [];
  currentPage = 1;
  renderVulnerabilitiesPage(currentPage);
}

// =========================
// Select All
// =========================
selectAllCheckbox?.addEventListener("change", () => {
  document.querySelectorAll(".select-row").forEach((cb) => { cb.checked = selectAllCheckbox.checked; });
});

// =========================
// Download Selected
// =========================
downloadBtn?.addEventListener("click", async () => {
  const selected = [...document.querySelectorAll(".select-row:checked")].map((cb) => cb.dataset.id);
  if (selected.length === 0) {
    toast("Please select at least one vulnerability to download.", "warning");
    return;
  }

  await withButtonBusy(downloadBtn, "Generating PDF…", async () => {
    try {
      const jsPDF = window.jspdf.jsPDF;
      const doc = new jsPDF();
      const logoBase64 = await loadImageAsBase64("assets/images/logopdf.png");

      const fields = [
        "cve_id","source","published_date","company","title","description","attack_path","interface",
        "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","cvss_score","impact","feasibility",
        "countermeasures","model_name","model_year","ecu_name","library_name",
      ];
      const labelOverrides = { cve_id: "CVE ID", ecu_name: "ECU Name", cia: "CIA", cvss_score: "CVSS Score" };

      // Fetch all selected details in parallel — was sequential before
      const allDetails = await Promise.all(selected.map((id) => fetchVulnerabilityDetails(id)));
      let firstPage = true;

      for (const data of allDetails) {
        if (!data) continue;
        if (!firstPage) doc.addPage();
        firstPage = false;

        doc.addImage(logoBase64, "PNG", 10, -5, 60, 30);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(16);
        doc.text("Vulnerability Report", 105, 25, { align: "center" });

        const downloadedDate = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
        if (doc.setGState) doc.setGState(new doc.GState({ opacity: 0.5 }));
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.text(`${downloadedDate}`, doc.internal.pageSize.getWidth() - 10, 15, { align: "right" });
        if (doc.setGState) doc.setGState(new doc.GState({ opacity: 1 }));

        const rows = fields.map((key) => {
          let value = data[key];
          if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
          if (!value) value = "Not Available";
          value = sanitizeText(String(value));
          const label = labelOverrides[key] || key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
          return [label, String(value)];
        });

        doc.autoTable({
          startY: 40,
          head: [["Field", "Value"]],
          body: rows,
          theme: "grid",
          styles: { fontSize: 10 },
          columnStyles: { 0: { fontStyle: "bold" } },
          didParseCell(d) {
            if (d.section === "head") {
              d.cell.styles.fillColor = [0, 0, 102];
              d.cell.styles.textColor = 255;
              d.cell.styles.fontStyle = "bold";
              d.cell.styles.halign = "center";
            }
          },
          didDrawPage() { drawWatermarks(doc, logoBase64); },
        });
      }

      doc.save(`Selected_Vulnerabilities_${brand || "Report"}.pdf`);
      toast(`Generated report for ${selected.length} item(s).`, "success");
    } catch (err) {
      console.error(err);
      toast("Failed to generate PDF.", "error");
    }
  });
});

function drawWatermarks(doc, logoBase64) {
  try {
    if (doc.setGState) doc.setGState(new doc.GState({ opacity: 0.1 }));
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const centerX = pageWidth / 2, centerY = pageHeight / 2, offsetY = 90;
    const shiftX = 70, shiftY = 50;
    const topOffset = { x: -20, y: 20 }, middleOffset = { x: 0, y: 0 }, bottomOffset = { x: 20, y: -20 };
    const wmWidth = 200, wmHeight = 120, rotationAngle = 45;

    const drawWatermark = (x, y) => {
      doc.addImage(logoBase64, "PNG", x - wmWidth / 2, y - wmHeight / 2, wmWidth, wmHeight, "", "FAST", rotationAngle);
    };

    drawWatermark(centerX + shiftX + topOffset.x,    centerY - offsetY + shiftY + topOffset.y);
    drawWatermark(centerX + shiftX + middleOffset.x, centerY + shiftY + middleOffset.y);
    drawWatermark(centerX + shiftX + bottomOffset.x, centerY + offsetY + shiftY + bottomOffset.y);

    if (doc.setGState) doc.setGState(new doc.GState({ opacity: 1 }));
  } catch (e) {
    console.error("Watermark render error:", e);
  }
}

// =========================
// Init
// =========================
function updateBrandLogo(brand) {
  if (brandLogo) brandLogo.src = brandLogos[brand] || "assets/images/default.png";
}

updateBrandLogo(brand);

const savedPage = parseInt(safeSession.get("branddetailsCurrentPage"), 10) || 1;

loadVulnerabilities().then(() => {
  if (savedPage > 1) {
    currentPage = savedPage;
    renderVulnerabilitiesPage(currentPage);
  }
});
