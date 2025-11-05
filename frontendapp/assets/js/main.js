import { fetchVulnerabilities } from "./api.js";
import { renderVulnerabilities, setupLedgerFilters } from "./ledger.js";

console.log("Dashboard script loaded");

// Track current filters/search centrally
let currentSearch = "";
let currentFrom = "";
let currentTo = "";
let currentCveType = "";

// Logout button (if present)
document.getElementById("logoutBtn")?.addEventListener("click", () => {
  window.location.href = "login.html";
});

// Load navbar and inject search bar (ledger page only)
async function loadNavbar() {
  try {
    const response = await fetch("components/navbar.html");
    const navbarHtml = await response.text();
    document.getElementById("navbar-container").innerHTML = navbarHtml;

    // if (window.location.pathname.includes("ledger.html")) {
    //   const searchBarResponse = await fetch("components/searchbar.html");
    //   const searchBarHtml = await searchBarResponse.text();

    //   const navbar = document.querySelector("#navbar-container nav");
    //   const menu = navbar?.querySelector(".dropdown");

    //   if (navbar && menu) {
    //     menu.insertAdjacentHTML("beforebegin", searchBarHtml);
    //     setupLedgerSearch(); // wire after injection (see below)
    //   }
    // }
  } catch (err) {
    console.error("Failed to load navbar:", err);
  }
}

// // Attach search handler from the navbar searchbar.html
// function setupLedgerSearch() {
//   const searchForm = document.querySelector(".search-bar");
//   const searchInput = document.getElementById("search-input");

//   if (!searchForm || !searchInput) return;

//   searchForm.addEventListener("submit", async (e) => {
//     e.preventDefault();
//     currentSearch = searchInput.value.trim();

//     // Fetch with combined filters
//     await fetchAndRender();
//   });
// }

// Centralized fetch + render using current filter state
async function fetchAndRender() {
  const data = await fetchVulnerabilities({
    search: currentSearch || undefined,
    from: currentFrom || undefined,
    to: currentTo || undefined,
    cveType: currentCveType || undefined,
  });

  renderVulnerabilities(data);
}

// Initialize page
async function init() {
  await loadNavbar();

  // Initial load (no filters)
  currentSearch = "";
  currentFrom = "";
  currentTo = "";
  currentCveType = "";

  await fetchAndRender();

  // Provide setupLedgerFilters with a callback that updates central state
  setupLedgerFilters(async (filters) => {
    // filters: { search?, from?, to?, cveType?, resetAll?: boolean }
    if (filters.resetAll) {
      currentSearch = "";
      // if navbar search input exists, clear it
      const navSearchInput = document.getElementById("search-input");
      if (navSearchInput) navSearchInput.value = "";
    } else {
      if ("search" in filters) currentSearch = filters.search ?? "";
    }

    if ("from" in filters) currentFrom = filters.from ?? "";
    if ("to" in filters) currentTo = filters.to ?? "";
    if ("cveType" in filters) currentCveType = filters.cveType ?? "";

    await fetchAndRender();
  });
}

init();
