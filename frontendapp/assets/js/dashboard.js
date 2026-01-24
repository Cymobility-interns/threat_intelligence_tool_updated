import { fetchVulnerabilities } from "./api.js";

// Function to count vulnerabilities for Chart 1: Interface Distribution
async function getInterfaceCounts() {
  const vulnerabilities = await fetchVulnerabilities();
  console.log("Fetched vulnerabilities:", vulnerabilities);

  const labels = ["CAN", "LIN", "Ethernet", "Wi-Fi", "Bluetooth"];
  const counts = { CAN: 0, LIN: 0, Ethernet: 0, "Wi-Fi": 0, Bluetooth: 0 };

  vulnerabilities.forEach(vul => {

    const fields = [
      vul.description || "",
      vul.interface || "",
      vul.title || "",
      vul.ecu_name || ""
    ];

    labels.forEach(label => {

      // ---------------------------------------
      // WIFI logic (already working)
      // ---------------------------------------
      if (label === "Wi-Fi") {
        const match = fields.some(text => {
          const normalized = text.toLowerCase().replace(/-/g, "");
          return normalized.includes("wifi");
        });
        if (match) counts["Wi-Fi"]++;
        return;
      }

      // ---------------------------------------
      // CAN PROTOCOL MATCH (Option D + ZDI Fix)
      // ---------------------------------------
      if (label === "CAN") {
        const match = fields.some(text => {
          const hasZDI = /ZDI-CAN-\d+/i.test(text);

          // Remove ZDI-CAN-xxxx part from the text
          const cleaned = text.replace(/ZDI-CAN-\d+/gi, "");

          // Check if cleaned text still contains real CAN reference
          const hasRealCAN = cleaned.includes("CAN");

          // If real CAN exists → count
          if (hasRealCAN) return true;

          // If only ZDI-CAN remains → do not count
          return false;
        });

        if (match) counts.CAN++;
        return;
      }


      // ---------------------------------------
      // DEFAULT logic for other protocols (LIN, Ethernet, Bluetooth)
      // CASE-SENSITIVE contains()
      // ---------------------------------------
      const match = fields.some(text => text.includes(label));
      if (match) counts[label]++;
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
    labels.forEach(label => {
      const searchText = label.toLowerCase();
      if (
        (vul.description && vul.description.toLowerCase().includes(searchText)) ||
        (vul.interface && vul.interface.toLowerCase().includes(searchText)) ||
        (vul.title && vul.title.toLowerCase().includes(searchText)) ||
        (vul.ecu_name && vul.ecu_name.toLowerCase().includes(searchText)) ||
        (vul.component && vul.component.toLowerCase().includes(searchText))
      ) counts[label]++;
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
    labels.forEach(label => {
      const searchText = label.toLowerCase();
      if (
        (vul.description && vul.description.toLowerCase().includes(searchText)) ||
        (vul.interface && vul.interface.toLowerCase().includes(searchText)) ||
        (vul.title && vul.title.toLowerCase().includes(searchText)) ||
        (vul.protocol && vul.protocol.toLowerCase().includes(searchText)) ||
        (vul.component && vul.component.toLowerCase().includes(searchText))
      ) counts[label]++;
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
        backgroundColor: ["#4FFAEE", "#CEF9F6", "#31A49C", "#B8BEBD", "#147A73"],
        borderWidth: 2,
        borderColor: "#ffffff"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { 
        legend: { 
          position: "left", 
          labels: { 
            font: { weight: 'bold', size: 11 },
            color: "#ffffff"
          } 
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
        borderColor: "#ffffff"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { 
        legend: { 
          position: "left", 
          labels: { 
            font: { weight: 'bold', size: 11 },
            color: "#ffffff"
          } 
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
        borderColor: "#ffffff"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { 
        legend: { 
          position: "left", 
          labels: { 
            font: { weight: 'bold', size: 11 },
            color: "#ffffff"
          } 
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
}

// Render Line Chart: Yearly Vulnerabilities Trend
async function renderYearlyChart() {
  const vulnerabilities = await fetchVulnerabilities();

  // Count vulnerabilities by year
  const yearCounts = {};
  vulnerabilities.forEach(vul => {
    if (vul.published_date) {
      const year = new Date(vul.published_date).getFullYear();
      yearCounts[year] = (yearCounts[year] || 0) + 1;
    }
  });

  // Sort years in ascending order
  const years = Object.keys(yearCounts).sort((a, b) => a - b);
  const counts = years.map(year => yearCounts[year]);

  const ctx = document.getElementById("yearlyChart").getContext("2d");
  new Chart(ctx, {
    type: "bar",
    data: {
      labels: years,
      datasets: [{
        label: "Vulnerabilities by Year",
        data: counts,
        borderColor: "#00FFFF",
        backgroundColor: "rgba(0, 255, 255, 0.2)",
        borderWidth: 3,
        pointBackgroundColor: "#FFD700",
        pointBorderColor: "#00003b",
        pointBorderWidth: 2,
        pointRadius: 5,
        tension: 0.4,
        fill: true
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#ffffff",
            font: { weight: "bold", size: 14 }
          }
        }
      },
      scales: {
        x: {
          ticks: { 
            color: "#ffffff",
            font: { size: 12, weight: "bold" }
          },
          grid: { color: "rgba(255,255,255,0.1)" }
        },
        y: {
          ticks: { 
            color: "#ffffff",
            font: { size: 12, weight: "bold" }
          },
          grid: { color: "rgba(255,255,255,0.1)" }
        }
      }
    }
  });
}

// Render Recent Attacks Table
async function renderRecentAttacks() {
  const vulnerabilities = await fetchVulnerabilities();
  
  // Sort by published_date (most recent first) and get top 5
  const recentAttacks = vulnerabilities
    .filter(vul => vul.published_date)
    .sort((a, b) => new Date(b.published_date) - new Date(a.published_date))
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
    
    row.innerHTML = `
      <td><a href="details.html?cve=${encodeURIComponent(urlParam)}" class="cve-link">${cveId}</a></td>
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