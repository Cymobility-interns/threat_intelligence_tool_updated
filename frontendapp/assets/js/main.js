import { fetchVulnerabilities } from "./api.js";



// import { fetchVulnerabilities, postData } from "./api.js";

import { renderVulnerabilities } from "./ledger.js";

console.log("Dashboard script loaded");

// Logout button (if present)
document.getElementById("logoutBtn")?.addEventListener("click", () => {
  window.location.href = "login.html";
});

// Load navbar and inject search bar (ledger page only)

// Load navbar component
async function loadNavbar() {
  try {
    const response = await fetch("components/navbar.html");
    const navbarHtml = await response.text();
    document.getElementById("navbar-container").innerHTML = navbarHtml;

    if (window.location.pathname.includes("ledger.html")) {
      const searchBarResponse = await fetch("components/searchbar.html");
      const searchBarHtml = await searchBarResponse.text();

      const navbar = document.querySelector("#navbar-container nav");
      const menu = navbar?.querySelector(".dropdown");

      if (navbar && menu) {
        menu.insertAdjacentHTML("beforebegin", searchBarHtml);
        setupLedgerSearch(); // wire after injection
      }
    }
  } catch (err) {
    console.error("Failed to load navbar:", err);
  }
}

// Attach search handler
function setupLedgerSearch() {
  const searchForm = document.querySelector(".search-bar");
  const searchInput = document.getElementById("search-input");

  if (!searchForm || !searchInput) return;

  searchForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const query = searchInput.value.trim();
    if (!query) return;

    console.log("Search triggered with:", query);
    const vulnerabilities = await fetchVulnerabilities({ search: query });
    renderVulnerabilities(vulnerabilities);
  });
}

// Initialize page
async function init() {
  await loadNavbar();

  // Load vulnerabilities initially
  const vulnerabilities = await fetchVulnerabilities();
  renderVulnerabilities(vulnerabilities);
}

init();

