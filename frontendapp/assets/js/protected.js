import { requireLogin, logoutUser } from "./auth.js";

document.addEventListener("DOMContentLoaded", async () => {
  const user = await requireLogin();
  if (!user) return;

  // Navbar logic
  const userSection = document.getElementById("userSection");
  const userName = document.getElementById("userName");
  const logoutBtn = document.getElementById("logoutBtn");

  if (userSection && userName) {
    userSection.style.display = "block";
    userName.innerText = user.name;
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", logoutUser);
  }
});
