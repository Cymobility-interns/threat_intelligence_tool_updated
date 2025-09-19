
import { fetchVulnerabilities, postData } from "./api.js";
import { renderVulnerabilities } from "./ledger.js";

console.log("Dashboard script loaded");

// Example: Logout function
document.getElementById("logoutBtn")?.addEventListener("click", () => {
  window.location.href = "login.html";
});


// Load navbar component
async function loadNavbar() {
  try {
    const response = await fetch("components/navbar.html");
    const navbarHtml = await response.text();
    document.getElementById("navbar-container").innerHTML = navbarHtml;

    // Attach all toolbar event listeners
    setupNavbarControls();
    setupCalendarIconClick();
  } catch (err) {
    console.error("Failed to load navbar:", err);
  }
}

// // Make calendar icons clickable to open native date picker
// function setupCalendarIconClick() {
//   document.querySelectorAll('.calendar-icon').forEach(icon => {
//     icon.addEventListener('click', () => {
//       const input = icon.closest('.input-group').querySelector('input[type="date"]');
//       if (input.showPicker) input.showPicker(); // Chrome & modern browsers
//       input.focus(); // fallback for older browsers
//     });
//   });
// }

// // Toolbar functionality
// function setupNavbarControls() {
//   const refreshBtn = document.getElementById("refresh-btn");
//   const fromDate = document.getElementById("from-date");
//   const toDate = document.getElementById("to-date");
//   const searchInput = document.getElementById("search-input");

//   // Refresh → reset filters
//   refreshBtn?.addEventListener("click", async () => {
//     fromDate.value = "";
//     toDate.value = "";
//     searchInput.value = "";
//     const vulnerabilities = await fetchVulnerabilities();
//     renderVulnerabilities(vulnerabilities);
//   });

//   // Date pickers → fetch when both set
//   [fromDate, toDate].forEach(el => {
//     el?.addEventListener("change", async () => {
//       if (fromDate.value && toDate.value) {
//         const vulnerabilities = await fetchVulnerabilities({
//           from: fromDate.value,
//           to: toDate.value,
//           search: searchInput.value.trim()
//         });
//         renderVulnerabilities(vulnerabilities);
//       }
//     });
//   });

//   // Search → fetch on Enter
//   searchInput?.addEventListener("keyup", async (e) => {
//     if (e.key === "Enter") {
//       const vulnerabilities = await fetchVulnerabilities({
//         from: fromDate.value,
//         to: toDate.value,
//         search: searchInput.value.trim()
//       });
//       renderVulnerabilities(vulnerabilities);
//     }
//   });
// }

// Initialize page
async function init() {
  await loadNavbar();
  const vulnerabilities = await fetchVulnerabilities();
  renderVulnerabilities(vulnerabilities);
}

init();

