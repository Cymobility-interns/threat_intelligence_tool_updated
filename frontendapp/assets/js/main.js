import { fetchVulnerabilities } from "./api.js";
import { renderVulnerabilities, setupLedgerFilters } from "./ledger.js";

console.log("Dashboard script loaded");

// Track current filters/search centrally
let currentSearch = "";
let currentFrom = "";
let currentTo = "";
let currentCveType = "";

/* -------------------------
   Load Navbar
------------------------- */
async function loadNavbar() {
  try {
    const response = await fetch("components/navbar.html");
    const navbarHtml = await response.text();
    document.getElementById("navbar-container").innerHTML = navbarHtml;
  } catch (err) {
    console.error("Failed to load navbar:", err);
  }
}

/* -------------------------
   FIX #1
   fetchAndRender() now ONLY sends filters that have values
------------------------- */
async function fetchAndRender() {
  const params = {};

  if (currentSearch) params.search = currentSearch;
  if (currentFrom) params.from = currentFrom;
  if (currentTo) params.to = currentTo;
  if (currentCveType) params.cveType = currentCveType;

  console.log("FETCHING with params:", params);

  const data = await fetchVulnerabilities(params);

  console.log("Data received by fetchAndRender():", data.length);

  renderVulnerabilities(data);

  console.log("✔ renderVulnerabilities() finished for:", data.length, "records");
}

/* -------------------------
   FIX #2 + FIX #3
   - Detect URL filter (?filter=Infotainment)
   - Prevent double rendering
   - Render ONLY once on page load
------------------------- */
async function init() {
  await loadNavbar();

  console.log("INIT: loading ledger...");

  // Reset filters
  currentSearch = "";
  currentFrom = "";
  currentTo = "";
  currentCveType = "";

  // Check if URL contains ?filter=XYZ
  const urlFilter = new URLSearchParams(window.location.search).get("filter");

  if (urlFilter) {
    console.log("URL filter detected:", urlFilter);
    currentSearch = urlFilter;

    console.log("Fetching data with URL filter:", urlFilter);
    await fetchAndRender();      // ONLY render ONCE with filtered data
  } 
  else {
    console.log("Fetching full dataset (no URL filter)...");
    const initialData = await fetchVulnerabilities();
    console.log("FULL dataset on init():", initialData.length);

    renderVulnerabilities(initialData);   // ONLY render ONCE with full data
    console.log("✔ Ledger rendered with FULL dataset on init");
  }

  /* -------------------------
      Sidebar Filter System
  ------------------------- */
  setupLedgerFilters(async (filters) => {
    console.log("Filter callback triggered:", filters);

    if (filters.resetAll) {
      currentSearch = "";
      currentFrom = "";
      currentTo = "";
      currentCveType = "";

      const navSearchInput = document.getElementById("search-input");
      if (navSearchInput) navSearchInput.value = "";
    } 
    else {
      if ("search" in filters) currentSearch = filters.search ?? "";
    }

    if ("from" in filters) currentFrom = filters.from ?? "";
    if ("to" in filters) currentTo = filters.to ?? "";
    if ("cveType" in filters) currentCveType = filters.cveType ?? "";

    console.log("Updated filter state:", {
      currentSearch,
      currentFrom,
      currentTo,
      currentCveType
    });

    await fetchAndRender();
  });
}

init();
