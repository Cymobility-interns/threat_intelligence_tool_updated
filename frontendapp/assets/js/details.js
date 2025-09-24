// -----------------------------
// Get CVE ID from URL (?cve=...)
// -----------------------------
const params = new URLSearchParams(window.location.search);
const cveId = params.get("cve");

// -----------------------------
// API: Fetch CVE Details
// -----------------------------
async function fetchCveDetails(cveId) {
  try {
    const response = await fetch(
      `http://192.168.0.27:8000/automotive_vulnerabilities/cve/${encodeURIComponent(cveId)}`
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    console.error("Failed to fetch details:", err);
    return null;
  }
}

// -----------------------------
// UI: Render Details on Page
// -----------------------------
async function renderDetails() {
  const container = document.getElementById("details-container");

  if (!cveId) {
    container.innerHTML = `<div class="text-danger">No CVE ID provided in the URL.</div>`;
    return;
  }

  const data = await fetchCveDetails(cveId);
  if (!data) {
    container.innerHTML = `<div class="text-danger">Error loading details for ${cveId}</div>`;
    return;
  }

  // Labels override
  const fieldLabels = {
    cve_id: "CVE ID",
    cia: "CIA",
    ecu_name: "ECU Name",
  };

  // Display order
  const fields = [
    "cve_id","source","published_date","company","title","description","attack_path","interface",
    "tools_used","types_of_attack","level_of_attack","damage_scenario","cia","impact","feasibility",
    "countermeasures","model_name","model_year","ecu_name","library_name"
  ];

  // Build HTML details
  let html = `<h5 class="mb-3 text-center">${data.title || data.cve_id}</h5><dl class="row">`;

  fields.forEach(key => {
    if (data[key]) {
      const label = fieldLabels[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
      html += `
        <dt class="col-sm-3">${label}</dt>
        <dd class="col-sm-9">${data[key]}</dd>
      `;
    }
  });

  html += `</dl>`;
  container.innerHTML = html;
}

// Call render
renderDetails();

// -----------------------------
// PDF: Download Report
// -----------------------------
document.getElementById("download-btn").addEventListener("click", async () => {
  if (!cveId) return;

  const data = await fetchCveDetails(cveId);
  if (!data) {
    alert("Error fetching details.");
    return;
  }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  // Load logo
  const logoUrl = "assets/images/logopdf.png";
  const img = new Image();
  img.src = logoUrl;

  img.onload = function () {
    // Header Logo
    doc.addImage(img, "PNG", 10, -5, 60, 30);

    // Title
    doc.setFont("helvetica", "bold"); // set font to bold
    doc.setFontSize(16);
    doc.setFontSize(16);
    doc.text("Vulnerability Report", 105, 25, { align: "center" });

    // Labels & fields
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

    // Table rows
    const rows = fields
      .filter(key => data[key])
      .map(key => [
        fieldLabels[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
        String(data[key])
      ]);

    // Table with optional watermark
    doc.autoTable({
  startY: 40,
  head: [["Field", "Value"]],
  body: rows,
  theme: "grid",
  styles: { fontSize: 10 },
  columnStyles: {
      0: { fontStyle: "bold" }   // Field column bold
    },
  didDrawPage: function () {
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    // Set transparency (0.1 = 10% opacity)
    doc.setGState(new doc.GState({ opacity: 0.2 }));

    // Draw watermark logo in the center
    doc.addImage(img, "PNG", pageWidth / 2 - 40, pageHeight / 2 - 40, 100, 100);

    // Reset opacity back to normal for other elements
    doc.setGState(new doc.GState({ opacity: 1 }));
  }
});


    // Save
    doc.save(`${data.cve_id || "report"}.pdf`);
  };
});
