import { fetchVulnerabilityDetails } from "./api.js";
import { escapeHtml, toast, showLoader, hideLoader, withButtonBusy } from "./utils.js";

// Get CVE parameter from URL (?cve=...)
const params = new URLSearchParams(window.location.search);
const cveParam = params.get("cve");

// ============================================
// Render Vulnerability Details on Page
// ============================================
async function renderDetails() {
  const container = document.getElementById("details-container");
  if (!container) return;

  if (!cveParam) {
    container.innerHTML = `<div class="text-danger">No CVE ID provided in the URL.</div>`;
    return;
  }

  container.innerHTML = "";
  container.dataset.appLoaderTheme = "light";
  const stop = showLoader(container, "Loading details…");
  let data = null;
  try {
    data = await fetchVulnerabilityDetails(cveParam);
  } finally {
    stop();
  }

  if (!data) {
    container.innerHTML = `<div class="text-danger">No details found for <strong>${escapeHtml(cveParam)}</strong>.</div>`;
    return;
  }

  const fieldLabels = {
    cve_id: "CVE ID",
    cia: "CIA",
    cvss_score: "CVSS Score",
    ecu_name: "ECU Name",
  };

  const fields = [
    "cve_id","source","published_date","company","title","description","attack_path","interface",
    "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","cvss_score","impact","feasibility",
    "countermeasures","model_name","model_year","ecu_name","library_name",
  ];

  // Build HTML safely — every dynamic value goes through escapeHtml.
  // The only places we emit raw HTML are explicit, internally-built <a> tags.
  const titleHtml = `<h5 class="mb-3 text-center">${escapeHtml(data.title || "Vulnerability Details")}</h5>`;

  const rowsHtml = fields.map((key) => {
    let value = data[key];
    if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
    if (!value) value = "Not Available";

    const label = fieldLabels[key] || key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

    let valueHtml;
    if (key === "source") {
      const raw = String(value);
      if (raw.trim().toUpperCase() === "NVD" && data.cve_id) {
        const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(data.cve_id)}`;
        valueHtml = `<a href="${escapeHtml(nvdUrl)}" target="_blank" rel="noopener noreferrer" class="text-info text-decoration-underline">NVD</a>`;
      } else if (/^https?:\/\//i.test(raw)) {
        // Only http/https URLs become links — keeps javascript: and data: out
        valueHtml = `<a href="${escapeHtml(raw)}" target="_blank" rel="noopener noreferrer" class="text-info text-decoration-underline">${escapeHtml(raw)}</a>`;
      } else {
        valueHtml = escapeHtml(raw);
      }
    } else {
      valueHtml = escapeHtml(value);
    }

    return `<dt class="col-sm-3">${escapeHtml(label)}</dt><dd class="col-sm-9">${valueHtml}</dd>`;
  }).join("");

  container.innerHTML = `${titleHtml}<dl class="row">${rowsHtml}</dl>`;
}

// ============================================
// PDF generation helpers
// ============================================
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

// ============================================
// Download button
// ============================================
const downloadBtn = document.getElementById("download-btn");
if (downloadBtn) {
  downloadBtn.addEventListener("click", async () => {
    await withButtonBusy(downloadBtn, "Generating PDF…", async () => {
      const data = await fetchVulnerabilityDetails(cveParam);
      if (!data) {
        toast("No details available to download.", "warning");
        return;
      }

      const { jsPDF } = window.jspdf;
      const doc = new jsPDF();

      try {
        const logoBase64 = await loadImageAsBase64("assets/images/logopdf.png");

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

        const fields = [
          "cve_id","source","published_date","company","title","description","attack_path","interface",
          "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","cvss_score","impact","feasibility",
          "countermeasures","model_name","model_year","ecu_name","library_name",
        ];
        const labelOverrides = { cve_id: "CVE ID", cvss_score: "CVSS Score", ecu_name: "ECU Name", cia: "CIA" };

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

        doc.save(`${data.cve_id || `internal-${data.id}` || "report"}.pdf`);
        toast("Report downloaded.", "success");
      } catch (err) {
        console.error(err);
        toast("Failed to generate PDF.", "error");
      }
    });
  });
}

function drawWatermarks(doc, logoBase64) {
  try {
    if (doc.setGState) doc.setGState(new doc.GState({ opacity: 0.1 }));
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const centerX = pageWidth / 2;
    const centerY = pageHeight / 2;
    const offsetY = 90;
    const shiftX = 70, shiftY = 50;
    const topOffset = { x: -20, y: 20 };
    const middleOffset = { x: 0, y: 0 };
    const bottomOffset = { x: 20, y: -20 };
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

renderDetails();
