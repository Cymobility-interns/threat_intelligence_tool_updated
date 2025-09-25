import { fetchVulnerabilities } from "./api.js";

async function getInterfaceCounts() {
  const vulnerabilities = await fetchVulnerabilities();
  console.log("Fetched vulnerabilities:", vulnerabilities);

  const labels = ["CAN", "LIN", "Ethernet", "Wi-Fi","Infotainment", "Telematics","Bluetooth"];
  const counts = { CAN: 0, LIN: 0, Ethernet: 0, "Wi-Fi": 0, Infotainment:0, Telematics:0, Bluetooth:0};

  vulnerabilities.forEach(vul => {
    labels.forEach(label => {
      if (
        (vul.description && vul.description.includes(label)) ||
        (vul.interface && vul.interface.includes(label)) ||
        (vul.title && vul.title.includes(label)) ||
        (vul.ecu_name && vul.ecu_name.includes(label))
      ) counts[label]++;
    });
  });

  const total = vulnerabilities.length;
  counts.Others = total - Object.values(counts).reduce((a, b) => a + b, 0);

  return counts;
}

async function renderInterfaceChart() {
  const counts = await getInterfaceCounts();
  const chartLabels = ["CAN", "LIN", "Ethernet", "Wi-Fi", "Infotainment", "Telematics", "Bluetooth"];
  const chartData = chartLabels.map(label => counts[label] || 0);

  const ctx = document.getElementById("interfaceChart").getContext("2d");
  const pieChart = new Chart(ctx, {
    type: "pie",
    data: {
      labels: chartLabels,
      datasets: [{
        data: chartData,
        backgroundColor: ["#4FFAEE", "#CEF9F6", "#31A49C", "#B8BEBD", "#107FE4", "#2969A4", "#147A73"],
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { 
        legend: { 
          position: "left", 
          labels: { font: { weight: 'bold' } } 
        } 
      },
      // 👇 Add interaction
      onClick: (evt, elements) => {
        if (elements.length > 0) {
          const chartIndex = elements[0].index;
          const selectedLabel = pieChart.data.labels[chartIndex];
          // Redirect with filter query
          window.location.href = `ledger.html?filter=${encodeURIComponent(selectedLabel)}`;
        }
      }
    }
  });
}



// Render recent attacks (first 8 for example)
async function renderRecentAttacks() {
  const vulnerabilities = await fetchVulnerabilities();
  // Sort by published_date descending (most recent first)
  vulnerabilities.sort((a, b) => {
    const dateA = new Date(a.published_date);
    const dateB = new Date(b.published_date);
    return dateB - dateA; // newest first
  });

  const attackList = document.getElementById("attack-list");
  attackList.innerHTML = "";

  // Create table
  const table = document.createElement("table");
  table.classList.add("table", "table-bordered", "table-sm");
  table.style.backgroundColor = "#0a0f1a"; // dark navy (from your screenshot)
  table.style.color = "#ffffff"; // white text
  table.style.borderCollapse = "collapse"; // clean look
  table.style.width = "100%";

  // Table header
  const thead = document.createElement("thead");
  thead.innerHTML = `
    <tr style="background-color: #0a0f1a; color: #ffffff; border-bottom: 1px solid #555;">
      <th style="padding: 12px;">CVE ID</th>
      <th style="padding: 12px;">Title</th>
    </tr>
  `;
  table.appendChild(thead);

  // Table body
  const tbody = document.createElement("tbody");

  vulnerabilities.slice(0, 8).forEach(vul => {
    const tr = document.createElement("tr");
    tr.style.borderBottom = "1px solid #555"; // grey row divider

    // CVE ID column
    const tdCve = document.createElement("td");
    tdCve.style.padding = "12px"; // increase row height
    if (vul.cve_id) {
      const link = document.createElement("a");
      link.href = `details.html?cve=${encodeURIComponent(vul.cve_id)}`;

      link.textContent = vul.cve_id;
      link.style.color = "#ffffff"; 
      link.style.fontWeight = "bold";
      link.style.textDecoration = "none";
      tdCve.appendChild(link);
    } else {
      tdCve.textContent = "N/A";
    }
    tr.appendChild(tdCve);

    // Title column
    const tdTitle = document.createElement("td");
    tdTitle.textContent = vul.title || "Untitled Attack";
    tdTitle.style.padding = "12px"; // increase row height
    tr.appendChild(tdTitle);

    tbody.appendChild(tr);
  });

  table.appendChild(tbody);
  attackList.appendChild(table);
}





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
    type: "line",
    data: {
      labels: years,
      datasets: [{
        label: "Vulnerabilities by Year",
        data: counts,
        borderColor: "#00FFFF",   // cyan line
        backgroundColor: "rgba(0, 255, 255, 0.2)", // light fill under curve
        borderWidth: 2,
        pointBackgroundColor: "#FFD700", // gold points
        tension: 0.3   // smooth curve
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: {
            color: "#ffffff",   // white text for dark background
            font: { weight: "bold" }
          }
        }
      },
      scales: {
        x: {
          ticks: { color: "#ffffff" },
          grid: { color: "rgba(255,255,255,0.2)" }
        },
        y: {
          ticks: { color: "#ffffff" },
          grid: { color: "rgba(255,255,255,0.2)" }
        }
      }
    }
  });
}


renderInterfaceChart();
renderRecentAttacks();
renderYearlyChart();
