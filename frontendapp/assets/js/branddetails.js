// assets/js/branddetails.js
import { fetchVulnerabilities } from "./api.js";
import { renderVulnerabilities } from "./ledger.js"; // reuse ledger rendering

// ----------------------
// Utility: Get brand from URL
// ----------------------
const urlParams = new URLSearchParams(window.location.search);
const brand = urlParams.get("brand")?.toLowerCase() || "";

// ----------------------
// DOM Elements
// ----------------------
const brandLogo = document.getElementById("brand-logo");
const brandTitle = document.querySelector(".container h3");
const emptyState = document.getElementById("empty-state");

// ----------------------
// Mapping of brand → logo path
// ----------------------
const brandLogos = {
  toyota: "assets/images/toyota.png",
  hyundai: "assets/images/hyundai.png",
  kia: "assets/images/kia.png",
  honda: "assets/images/hondalogo.png",
  volkswagen: "assets/images/volkswagen.png",
  bmw: "assets/images/bmw.png",
  nissan: "assets/images/nissan.png",
  audi: "assets/images/audi.png",
  chevrolet: "assets/images/chevrolet.png",
  tesla: "assets/images/tesla.png",
  jeep: "assets/images/jeep.png",
  ford: "assets/images/ford.png",
  renault: "assets/images/renault.png",
  suzuki: "assets/images/suzuki.png",
  skoda: "assets/images/skoda.png",
  mahindra: "assets/images/mahindra.png"
};

// ----------------------
// Update Logo (no brand name in heading)
// ----------------------
function updateBrandLogo(brand) {
  if (brand && brandLogos[brand]) {
    brandLogo.src = brandLogos[brand];
  } else {
    brandLogo.src = "assets/images/default.png";
  }
}

// ----------------------
// Fetch + Display Vulnerabilities
// ----------------------
async function loadVulnerabilities() {
  try {
    const vulns = await fetchVulnerabilities({ search: brand });

    if (!vulns || !vulns.length) {
      emptyState.style.display = "block";
      emptyState.textContent = "No vulnerabilities found.";
      return;
    }

    emptyState.style.display = "none";
    renderVulnerabilities(vulns); // use ledger.js rendering (pagination + clickable links)
  } catch (error) {
    console.error("Error loading vulnerabilities:", error);
    emptyState.style.display = "block";
    emptyState.textContent = "⚠️ Failed to load vulnerabilities.";
  }
}

// ----------------------
// Init
// ----------------------
updateBrandLogo(brand);
loadVulnerabilities();
