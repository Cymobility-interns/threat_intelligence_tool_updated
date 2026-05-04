import { fetchVulnerabilities } from "./api.js";
import { escapeHtml, showLoader, hideLoader, toast } from "./utils.js";

// ── Single fetch shared across all renderers (was being called 5x) ──
let _vulnsPromise = null;
function getVulnerabilities() {
  if (!_vulnsPromise) _vulnsPromise = fetchVulnerabilities();
  return _vulnsPromise;
}

// ── Counters ────────────────────────────────────────────────────────
function getInterfaceCounts(vulnerabilities) {
  const labels = ["CAN", "LIN", "Ethernet", "Wi-Fi", "Bluetooth"];
  const counts = { CAN: 0, LIN: 0, Ethernet: 0, "Wi-Fi": 0, Bluetooth: 0 };

  vulnerabilities.forEach(vul => {
    const allText = Object.values(vul).filter(val => typeof val === "string").join(" ");
    const allTextLower = allText.toLowerCase();

    labels.forEach(label => {
      if (label === "Wi-Fi") {
        if (allTextLower.replace(/-/g, "").includes("wifi")) counts["Wi-Fi"]++;
        return;
      }
      if (label === "CAN") {
        const cleaned = allText.replace(/ZDI-CAN-\d+/gi, "");
        if (cleaned.includes("CAN")) counts.CAN++;
        return;
      }
      if (label === "LIN") {
        if (/\blin\b/i.test(allText)) counts.LIN++;
        return;
      }
      if (allTextLower.includes(label.toLowerCase())) counts[label]++;
    });
  });
  return counts;
}

function countByLabels(vulnerabilities, labels) {
  const counts = Object.fromEntries(labels.map(l => [l, 0]));
  vulnerabilities.forEach(vul => {
    const allTextLower = Object.values(vul).filter(val => typeof val === "string").join(" ").toLowerCase();
    labels.forEach(label => {
      if (allTextLower.includes(label.toLowerCase())) counts[label]++;
    });
  });
  return counts;
}

// ── Pie chart factory (was 3 nearly-identical functions) ────────────
function makePieChart(canvasId, legendId, labels, colors, counts) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return null;
  const ctx = canvas.getContext("2d");

  const data = labels.map(l => counts[l] || 0);
  const chart = new Chart(ctx, {
    type: "pie",
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors,
        borderWidth: 2,
        borderColor: "#ffffff",
        radius: "70%",
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const i = elements[0].index;
          const selectedLabel = chart.data.labels[i];
          window.location.href = `ledger.html?filter=${encodeURIComponent(selectedLabel)}`;
        }
      },
    },
  });
  generateCustomLegend(chart, legendId);
  return chart;
}

// ── Custom legend ───────────────────────────────────────────────────
function generateCustomLegend(chart, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = "";

  const labels = chart.data.labels;
  const colors = chart.data.datasets[0].backgroundColor;

  labels.forEach((label, index) => {
    const item = document.createElement("div");
    item.className = "legend-item";
    item.addEventListener("click", () => {
      window.location.href = `ledger.html?filter=${encodeURIComponent(label)}`;
    });

    const colorBox = document.createElement("div");
    colorBox.className = "legend-color";
    colorBox.style.backgroundColor = colors[index];

    const text = document.createElement("div");
    text.className = "legend-label";
    text.textContent = label; // textContent — XSS safe

    item.appendChild(colorBox);
    item.appendChild(text);
    container.appendChild(item);
  });
}

// ── Yearly stacked bar chart ────────────────────────────────────────
function renderYearlyChart(vulnerabilities) {
  const canvas = document.getElementById("yearlyChart");
  if (!canvas) return;

  const EMPTY_VALUES = new Set(["", "not available", "n/a", "null", "none", "undefined", "na"]);
  const isRealCveId = (val) => {
    if (!val) return false;
    return !EMPTY_VALUES.has(String(val).trim().toLowerCase());
  };

  const cveYearCounts = {};
  const dateYearCounts = {};

  vulnerabilities.forEach(vul => {
    if (isRealCveId(vul.cve_id)) {
      const match = vul.cve_id.match(/\d{4}/);
      if (match) {
        const year = match[0];
        cveYearCounts[year] = (cveYearCounts[year] || 0) + 1;
      }
    } else if (vul.published_date) {
      const parsed = new Date(vul.published_date);
      if (!isNaN(parsed)) {
        const year = String(parsed.getFullYear());
        dateYearCounts[year] = (dateYearCounts[year] || 0) + 1;
      }
    }
  });

  const allYears = Array.from(
    new Set([...Object.keys(cveYearCounts), ...Object.keys(dateYearCounts)])
  ).sort((a, b) => a - b);

  const cveCounts = allYears.map(y => cveYearCounts[y] || 0);
  const dateOnlyCounts = allYears.map(y => dateYearCounts[y] || 0);

  const ctx = canvas.getContext("2d");
  const barChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: allYears,
      datasets: [
        { label: "CVE Identified",     data: cveCounts,      backgroundColor: "rgba(0, 255, 255, 0.45)", borderColor: "#00FFFF", borderWidth: 2, stack: "vuln" },
        { label: "Non CVE Identified", data: dateOnlyCounts, backgroundColor: "rgba(255, 179, 71, 0.75)", borderColor: "#FFB347", borderWidth: 2, stack: "vuln" },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const selectedYear = barChart.data.labels[elements[0].index];
          window.location.href = `ledger.html?year=${encodeURIComponent(selectedYear)}`;
        }
      },
      plugins: {
        legend: { labels: { color: "#ffffff", font: { weight: "bold", size: 13 }, usePointStyle: false } },
        tooltip: { callbacks: { footer: (items) => `Total: ${items.reduce((s, i) => s + i.parsed.y, 0)}` } },
      },
      scales: {
        x: { stacked: true, ticks: { color: "#ffffff", font: { size: 12, weight: "bold" } }, grid: { color: "rgba(255,255,255,0.1)" } },
        y: { stacked: true, ticks: { color: "#ffffff", font: { size: 12, weight: "bold" } }, grid: { color: "rgba(255,255,255,0.1)" } },
      },
    },
  });
}

// ── Recent attacks table ────────────────────────────────────────────
function renderRecentAttacks(vulnerabilities) {
  const tableBody = document.getElementById("recentAttacksBody");
  if (!tableBody) return;

  const recentAttacks = vulnerabilities
    .filter(vul => vul.cve_id || vul.published_date)
    .sort((a, b) => {
      const getYear = (vul) => {
        if (vul.cve_id && String(vul.cve_id).startsWith("CVE-")) {
          const match = vul.cve_id.match(/CVE-(\d{4})-/);
          if (match) return parseInt(match[1], 10);
        }
        if (vul.published_date) return new Date(vul.published_date).getFullYear();
        return 0;
      };
      const yearDiff = getYear(b) - getYear(a);
      if (yearDiff !== 0) return yearDiff;
      const dateA = a.published_date ? new Date(a.published_date).getTime() : 0;
      const dateB = b.published_date ? new Date(b.published_date).getTime() : 0;
      return dateB - dateA;
    })
    .slice(0, 5);

  tableBody.innerHTML = "";
  const frag = document.createDocumentFragment();

  recentAttacks.forEach(attack => {
    const cveId = attack.cve_id || attack.id || "N/A";
    const title = attack.title || "Unknown";
    const attackType = attack.types_of_attack || attack.attack_type || attack.type || "N/A";
    const urlParam = attack.cve_id ? attack.cve_id : (attack.id ? `internal-${attack.id}` : "");
    const hasCveId = !!attack.cve_id;

    const row = document.createElement("tr");
    const identifierCell = hasCveId
      ? `<td><a href="details.html?cve=${encodeURIComponent(urlParam)}" class="cve-link">${escapeHtml(cveId)}</a></td>`
      : `<td class="no-cve-id"><a href="details.html?cve=${encodeURIComponent(urlParam)}" style="color:inherit;text-decoration:none;">N/A</a></td>`;

    row.innerHTML = `
      ${identifierCell}
      <td>${escapeHtml(title)}</td>
      <td>${escapeHtml(attackType)}</td>
    `;
    frag.appendChild(row);
  });
  tableBody.appendChild(frag);
}

// ── Init: fetch once, render everything ─────────────────────────────
async function initDashboard() {
  showLoader(document.body, "Loading dashboard…");
  let vulns = [];
  try {
    vulns = await getVulnerabilities();
  } catch (err) {
    console.error("Dashboard load failed:", err);
    toast("Failed to load dashboard data.", "error", { duration: 6000 });
  } finally {
    hideLoader(document.body);
  }
  if (!vulns.length) return;

  makePieChart("interfaceChart", "interfaceLegend",
    ["CAN", "LIN", "Ethernet", "Wi-Fi", "Bluetooth"],
    ["#4FFAEE", "#082c2eff", "#31A49C", "#B8BEBD", "#147A73"],
    getInterfaceCounts(vulns));

  makePieChart("ecuChart", "ecuLegend",
    ["Infotainment", "ADAS", "Telematics", "Body Control Unit"],
    ["#FF6B9D", "#C44569", "#FFA07A", "#FA8072"],
    countByLabels(vulns, ["Infotainment", "ADAS", "Telematics", "Body Control Unit"]));

  makePieChart("protocolChart", "protocolLegend",
    ["Linux", "Bootloader", "Secure Storage firmware", "ECU Firmware", "Sensor Firmware"],
    ["#FFD700", "#FFA500", "#FF8C00", "#FF7F50", "#FF6347"],
    countByLabels(vulns, ["Linux", "Bootloader", "Secure Storage firmware", "ECU Firmware", "Sensor Firmware"]));

  renderYearlyChart(vulns);
  renderRecentAttacks(vulns);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initDashboard);
} else {
  initDashboard();
}
