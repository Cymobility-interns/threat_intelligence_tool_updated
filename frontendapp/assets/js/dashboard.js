import { fetchVulnerabilities } from "./api.js";

// Function to count vulnerabilities for Chart 1: Interface Distribution
async function getInterfaceCounts() {
  const vulnerabilities = await fetchVulnerabilities();
  console.log("Fetched vulnerabilities:", vulnerabilities);

  const labels = ["CAN", "LIN", "Ethernet", "Wi-Fi", "Bluetooth"];
  const counts = { CAN: 0, LIN: 0, Ethernet: 0, "Wi-Fi": 0, Bluetooth: 0 };

  vulnerabilities.forEach(vul => {
    const allText = Object.values(vul)
      .filter(val => typeof val === 'string')
      .join(' ');
    const allTextLower = allText.toLowerCase();

    labels.forEach(label => {
      // ---------------------------------------
      // WIFI logic
      // ---------------------------------------
      if (label === "Wi-Fi") {
        const normalized = allTextLower.replace(/-/g, "");
        if (normalized.includes("wifi")) counts["Wi-Fi"]++;
        return;
      }

      // ---------------------------------------
      // CAN PROTOCOL MATCH (Option D + ZDI Fix)
      // ---------------------------------------
      if (label === "CAN") {
        const cleaned = allText.replace(/ZDI-CAN-\d+/gi, "");
        if (cleaned.includes("CAN")) counts.CAN++;
        return;
      }

      // ---------------------------------------
      // LIN MATCH
      // ---------------------------------------
      if (label === "LIN") {
        if (/\blin\b/i.test(allText)) counts.LIN++;
        return;
      }

      // ---------------------------------------
      // DEFAULT logic for other protocols (Ethernet, Bluetooth)
      // ---------------------------------------
      if (allTextLower.includes(label.toLowerCase())) {
        counts[label]++;
      }
    });
  });

  return counts;
}


// Function to count vulnerabilities for Chart 2: ECU/System Distribution
async function getECUCounts() {
  const vulnerabilities = await fetchVulnerabilities();

  const labels = ["Infotainment", "ADAS", "Telematics", "Body Control Unit"];
  const counts = { Infotainment: 0, ADAS: 0, Telematics: 0, "Body Control Unit": 0 };

  vulnerabilities.forEach(vul => {
    const allTextLower = Object.values(vul)
      .filter(val => typeof val === 'string')
      .join(' ')
      .toLowerCase();

    labels.forEach(label => {
      const searchText = label.toLowerCase();
      if (allTextLower.includes(searchText)) {
        counts[label]++;
      }
    });
  });

  return counts;
}

// Function to count vulnerabilities for Chart 3: Protocol Distribution
async function getProtocolCounts() {
  const vulnerabilities = await fetchVulnerabilities();

  const labels = ["Linux", "Bootloader", "Secure Storage firmware", "ECU Firmware", "Sensor Firmware"];
  const counts = { Linux: 0, Bootloader: 0, "Secure Storage firmware": 0, "ECU Firmware": 0, "Sensor Firmware": 0 };

  vulnerabilities.forEach(vul => {
    const allTextLower = Object.values(vul)
      .filter(val => typeof val === 'string')
      .join(' ')
      .toLowerCase();

    labels.forEach(label => {
      const searchText = label.toLowerCase();
      if (allTextLower.includes(searchText)) {
        counts[label]++;
      }
    });
  });

  return counts;
}

// Render Chart 1: Interface Distribution
async function renderInterfaceChart() {
  const counts = await getInterfaceCounts();
  const chartLabels = ["CAN", "LIN", "Ethernet", "Wi-Fi", "Bluetooth"];
  const chartData = chartLabels.map(label => counts[label] || 0);

  const ctx = document.getElementById("interfaceChart").getContext("2d");
  const pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: chartLabels,
      datasets: [{
        data: chartData,
        backgroundColor: ["#4FFAEE", "#082c2eff", "#31A49C", "#B8BEBD", "#147A73"],
        borderWidth: 2,
        borderColor: "#ffffff",
        radius: "70%"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const chartIndex = elements[0].index;
          const selectedLabel = pieChart.data.labels[chartIndex];
          window.location.href = `ledger.html?filter=${encodeURIComponent(selectedLabel)}`;
        }
      }
    }
  });

  generateCustomLegend(pieChart, 'interfaceLegend');
}

// Render Chart 2: ECU/System Distribution
async function renderECUChart() {
  const counts = await getECUCounts();
  const chartLabels = ["Infotainment", "ADAS", "Telematics", "Body Control Unit"];
  const chartData = chartLabels.map(label => counts[label] || 0);

  const ctx = document.getElementById("ecuChart").getContext("2d");
  const pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: chartLabels,
      datasets: [{
        data: chartData,
        backgroundColor: ["#FF6B9D", "#C44569", "#FFA07A", "#FA8072"],
        borderWidth: 2,
        borderColor: "#ffffff",
        radius: "70%"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const chartIndex = elements[0].index;
          const selectedLabel = pieChart.data.labels[chartIndex];
          window.location.href = `ledger.html?filter=${encodeURIComponent(selectedLabel)}`;
        }
      }
    }
  });

  generateCustomLegend(pieChart, 'ecuLegend');
}

// Render Chart 3: Protocol Distribution
async function renderProtocolChart() {
  const counts = await getProtocolCounts();
  const chartLabels = ["Linux", "Bootloader", "Secure Storage firmware", "ECU Firmware", "Sensor Firmware"];
  const chartData = chartLabels.map(label => counts[label] || 0);

  const ctx = document.getElementById("protocolChart").getContext("2d");
  const pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: chartLabels,
      datasets: [{
        data: chartData,
        backgroundColor: ["#FFD700", "#FFA500", "#FF8C00", "#FF7F50", "#FF6347"],
        borderWidth: 2,
        borderColor: "#ffffff",
        radius: "70%"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        }
      },
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const chartIndex = elements[0].index;
          const selectedLabel = pieChart.data.labels[chartIndex];
          window.location.href = `ledger.html?filter=${encodeURIComponent(selectedLabel)}`;
        }
      }
    }
  });

  generateCustomLegend(pieChart, 'protocolLegend');
}

// Custom Legend Generator
function generateCustomLegend(chart, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';

  const labels = chart.data.labels;
  const colors = chart.data.datasets[0].backgroundColor;

  labels.forEach((label, index) => {
    const item = document.createElement('div');
    item.className = 'legend-item';
    item.onclick = () => {
      window.location.href = `ledger.html?filter=${encodeURIComponent(label)}`;
    };

    const colorBox = document.createElement('div');
    colorBox.className = 'legend-color';
    colorBox.style.backgroundColor = colors[index];

    const text = document.createElement('div');
    text.className = 'legend-label';
    text.innerText = label;

    item.appendChild(colorBox);
    item.appendChild(text);
    container.appendChild(item);
  });
}

// Render Bar Chart: Yearly Vulnerabilities Trend (stacked — CVE vs Date-Only)
async function renderYearlyChart() {
  const vulnerabilities = await fetchVulnerabilities();

  // Guard: treat placeholder strings as "no cve_id"
  function isRealCveId(val) {
    if (!val) return false;
    const s = String(val).trim().toLowerCase();
    const EMPTY_VALUES = ["", "not available", "n/a", "null", "none", "undefined", "na"];
    return !EMPTY_VALUES.includes(s);
  }

  // Separate counts: entries WITH a real cve_id vs entries WITHOUT (date-only)
  const cveYearCounts = {};   // year derived from CVE ID string
  const dateYearCounts = {};   // year derived from published_date (no real cve_id)

  vulnerabilities.forEach(vul => {
    if (isRealCveId(vul.cve_id)) {
      // Has a genuine CVE ID → extract year from the ID itself
      const match = vul.cve_id.match(/\d{4}/);
      if (match) {
        const year = match[0];
        cveYearCounts[year] = (cveYearCounts[year] || 0) + 1;
      }
    } else if (vul.published_date) {
      // No real CVE ID → classify by published_date year (amber bucket)
      const parsed = new Date(vul.published_date);
      if (!isNaN(parsed)) {
        const year = String(parsed.getFullYear());
        dateYearCounts[year] = (dateYearCounts[year] || 0) + 1;
      }
    }
  });

  console.log("CVE year counts:", cveYearCounts);
  console.log("Date-only year counts:", dateYearCounts);

  // Merge all years and sort chronologically
  const allYears = Array.from(
    new Set([...Object.keys(cveYearCounts), ...Object.keys(dateYearCounts)])
  ).sort((a, b) => a - b);

  const cveCounts = allYears.map(y => cveYearCounts[y] || 0);
  const dateOnlyCounts = allYears.map(y => dateYearCounts[y] || 0);

  const ctx = document.getElementById("yearlyChart").getContext("2d");
  const barChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels: allYears,
      datasets: [
        {
          label: "CVE Identified",
          data: cveCounts,
          backgroundColor: "rgba(0, 255, 255, 0.45)",
          borderColor: "#00FFFF",
          borderWidth: 2,
          stack: "vuln"
        },
        {
          label: "Non CVE Identified",
          data: dateOnlyCounts,
          backgroundColor: "rgba(255, 179, 71, 0.75)",
          borderColor: "#FFB347",
          borderWidth: 2,
          stack: "vuln"
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const chartIndex = elements[0].index;
          const selectedYear = barChart.data.labels[chartIndex];
          window.location.href = `ledger.html?year=${encodeURIComponent(selectedYear)}`;
        }
      },
      plugins: {
        legend: {
          labels: {
            color: "#ffffff",
            font: { weight: "bold", size: 13 },
            // Draw custom colored boxes in the legend
            usePointStyle: false
          }
        },
        tooltip: {
          callbacks: {
            // Show total in tooltip footer
            footer: (items) => {
              const total = items.reduce((sum, i) => sum + i.parsed.y, 0);
              return `Total: ${total}`;
            }
          }
        }
      },
      scales: {
        x: {
          stacked: true,
          ticks: { color: "#ffffff", font: { size: 12, weight: "bold" } },
          grid: { color: "rgba(255,255,255,0.1)" }
        },
        y: {
          stacked: true,
          ticks: { color: "#ffffff", font: { size: 12, weight: "bold" } },
          grid: { color: "rgba(255,255,255,0.1)" }
        }
      }
    }
  });
}

// Render Recent Attacks Table
async function renderRecentAttacks() {
  const vulnerabilities = await fetchVulnerabilities();

  // Sort by CVE ID year first, fallback to published_date
  const recentAttacks = vulnerabilities
    .filter(vul => vul.cve_id || vul.published_date)
    .sort((a, b) => {
      // Helper to extract year from cve_id or published_date
      const getYear = (vul) => {
        if (vul.cve_id && vul.cve_id.startsWith("CVE-")) {
          const match = vul.cve_id.match(/CVE-(\d{4})-/);
          if (match) return parseInt(match[1], 10);
        }
        if (vul.published_date) return new Date(vul.published_date).getFullYear();
        return 0;
      };

      const yearA = getYear(a);
      const yearB = getYear(b);

      // 1. Sort by year descending
      if (yearA !== yearB) {
        return yearB - yearA;
      }

      // 2. If years are exactly the same, use published_date as tie-breaker (most precise)
      const dateA = a.published_date ? new Date(a.published_date).getTime() : 0;
      const dateB = b.published_date ? new Date(b.published_date).getTime() : 0;
      return dateB - dateA;
    })
    .slice(0, 5);

  const tableBody = document.getElementById("recentAttacksBody");
  tableBody.innerHTML = "";

  recentAttacks.forEach(attack => {
    const row = document.createElement("tr");

    const cveId = attack.cve_id || attack.id || "N/A";
    const title = attack.title || "Unknown";
    const attackType = attack.types_of_attack || attack.attack_type || attack.type || "N/A";

    // Use cve_id if available, otherwise use internal-{id} format
    let urlParam;
    if (attack.cve_id) {
      urlParam = attack.cve_id;
    } else if (attack.id) {
      urlParam = `internal-${attack.id}`;
    } else {
      urlParam = "";
    }

    // Identifier cell:
    //  - WITH cve_id  → teal cve-link (existing style)
    //  - WITHOUT cve_id → amber "Not Available" + "Date Only" badge
    const hasCveId = !!attack.cve_id;
    const identifierCell = hasCveId
      ? `<td><a href="details.html?cve=${encodeURIComponent(urlParam)}" class="cve-link">${cveId}</a></td>`
      : `<td class="no-cve-id"><a href="details.html?cve=${encodeURIComponent(urlParam)}" style="color:inherit;text-decoration:none;">N/A</a></td>`;

    row.innerHTML = `
      ${identifierCell}
      <td>${title}</td>
      <td>${attackType}</td>
    `;

    tableBody.appendChild(row);
  });
}

// Initialize all charts and table
renderInterfaceChart();
renderECUChart();
renderProtocolChart();
renderYearlyChart();
renderRecentAttacks();