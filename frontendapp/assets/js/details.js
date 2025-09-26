const params = new URLSearchParams(window.location.search);
const cveParam = params.get("cve");

// -----------------------------
// API: Fetch CVE or Internal Details
// -----------------------------
async function fetchDetails(cve) {
  if (!cve) return null;
  let url = cve.startsWith("internal-")
    ? `http://192.168.0.15:8000/automotive_vulnerabilities/id/${cve.replace("internal-", "")}`
    : `http://192.168.0.15:8000/automotive_vulnerabilities/cve/${cve}`;

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    console.error("Failed to fetch details:", err);
    return null;
  }
}

// -----------------------------
// Render Details
// -----------------------------
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

  let html = `<h5 class="mb-3 text-center">${data.title || "Vulnerability Details"}</h5><dl class="row">`;

  fields.forEach(key => {
    let value = data[key];
    if (key === "cve_id" && !value) value = data.id ? `ID: ${data.id}` : "Not Available";
    if (!value) value = "Not Available";
    const label = fieldLabels[key] || key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    html += `<dt class="col-sm-3">${label}</dt><dd class="col-sm-9">${value}</dd>`;
  });

  html += `</dl>`;
  container.innerHTML = html;
}

// -----------------------------
// PDF Download
// -----------------------------
document.getElementById("download-btn").addEventListener("click", async () => {
  const data = await fetchDetails(cveParam);
  if (!data) return alert("No details available to download.");

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  const img = new Image();
  img.src = "assets/images/logopdf.png";

  img.onload = function () {
    doc.addImage(img, "PNG", 10, -5, 60, 30);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.text("Vulnerability Report", 105, 25, { align: "center" });

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

    doc.autoTable({ startY: 40, head: [["Field", "Value"]], body: rows, theme: "grid", styles: { fontSize: 10 }, columnStyles: { 0: { fontStyle: "bold" } } });
    doc.save(`${data.cve_id || `internal-${data.id}` || "report"}.pdf`);
  };
});

// Call render
renderDetails();
