import { requireLogin, bindLogoutButton } from "./auth.js";

document.addEventListener("DOMContentLoaded", async () => {
  const user = await requireLogin();
  if (!user) return;

  const userSection = document.getElementById("userSection");
  const userName = document.getElementById("userName");

  if (userSection && userName) {
    userSection.style.display = "block";
    userName.textContent = user.name; // textContent — XSS safe
  }

  bindLogoutButton(document);
});
