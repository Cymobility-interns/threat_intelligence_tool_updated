import { API_BASE } from "./api.js";
// ============================================
// Get CVE parameter from URL (?cve=...)
// ============================================
const params = new URLSearchParams(window.location.search);
const cveParam = params.get("cve");

// ============================================
// API: Fetch CVE or Internal Vulnerability Details
// ============================================
async function fetchDetails(cve) {
  if (!cve) return null;

  const baseUrl = `${ API_BASE }/automotive_vulnerabilities`;
  const url = cve.startsWith("internal-")
    ? `${baseUrl}/id/${cve.replace("internal-", "")}`
    : `${baseUrl}/cve/${cve}`;

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
// Render Vulnerability Details on Page
// ============================================
async function renderDetails() {
  const container = document.getElementById("details-container");
  container.innerHTML = "Loading details...";

  if (!cveParam) {
    container.innerHTML = `<div class="text-danger">No CVE ID provided in the URL.</div>`;
    return;
  }

  const data = await fetchDetails(cveParam);
  if (!data) {
    container.innerHTML = `<div class="text-danger">No details found for <strong>${cveParam}</strong>.</div>`;
    return;
  }

  const fieldLabels = {
    cve_id: "CVE ID",
    cia: "CIA",
    ecu_name: "ECU Name",
  };

  const fields = [
    "cve_id","source","published_date","company","title","description","attack_path","interface",
    "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","impact","feasibility",
    "countermeasures","model_name","model_year","ecu_name","library_name"
  ];

  let html = `
    <h5 class="mb-3 text-center">${data.title || "Vulnerability Details"}</h5>
    <dl class="row">
  `;

  fields.forEach(key => {
  let value = data[key];
  if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
  if (!value) value = "Not Available";

  const label = fieldLabels[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());

  // --- Source field logic ---
  if (key === "source") {
    if (String(value).trim().toUpperCase() === "NVD" && data.cve_id) {
      const nvdUrl = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(data.cve_id)}`;
      value = `<a href="${nvdUrl}" target="_blank" rel="noopener noreferrer" class="text-info text-decoration-underline">NVD</a>`;
    } else if (/^https?:\/\//i.test(value)) {
      value = `<a href="${value}" target="_blank" rel="noopener noreferrer" class="text-info text-decoration-underline">${value}</a>`;
    }
  }

  html += `<dt class="col-sm-3">${label}</dt><dd class="col-sm-9">${value}</dd>`;
});


  html += `</dl>`;
  container.innerHTML = html;
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


document.getElementById("download-btn").addEventListener("click", async () => {
  const data = await fetchDetails(cveParam);
  if (!data) return alert("No details available to download.");

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  try {
    // Load logo/watermark
    const logoBase64 = await loadImageAsBase64("assets/images/logopdf.png");

    // Add logo (top-left)
    doc.addImage(logoBase64, "PNG", 10, -5, 60, 30);

    // Title
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("Vulnerability Report", 105, 25, { align: "center" });

    // Page size
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const wmWidth = 200;
    const wmHeight = 120;

    // Prepare table data
    const fields = [
      "cve_id","source","published_date","company","title","description","attack_path","interface",
      "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","impact","feasibility",
      "countermeasures","model_name","model_year","ecu_name","library_name"
    ];

    const rows = fields.map(key => {
      let value = data[key];
      if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
      if (!value) value = "Not Available";
      const label = key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
      return [label, String(value)];
    });

    // Draw table + watermark (watermark AFTER content so it is visible)
    doc.autoTable({
      startY: 40,
      head: [["Field", "Value"]],
      body: rows,
      theme: "grid",
      styles: { fontSize: 10 },
      columnStyles: { 0: { fontStyle: "bold" } },
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

    // Save file
    doc.save(`${data.cve_id || `internal-${data.id}` || "report"}.pdf`);

  } catch (err) {
    console.error(err);
    alert("Failed to load image for PDF");
  }
});

// ============================================
// Init Render
// ============================================
renderDetails();
