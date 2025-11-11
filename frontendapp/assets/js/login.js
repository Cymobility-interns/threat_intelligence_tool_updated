// assets/js/login.js
import { postData } from "./api.js";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  const msg = document.getElementById("loginMessage");

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const data = {
      username: this.username.value.trim(),
      password: this.password.value.trim(),
    };

    const { ok, result } = await postData("/login", data);

    msg.innerHTML = ok
      ? `<span class="text-success">${result.message}</span>`
      : `<span class="text-danger">${result.detail}</span>`;

    if (ok) {
      handleLoginRedirect();
    }
  });

  // --- password toggle logic ---
  document.querySelectorAll(".toggle-password").forEach((icon) => {
    const targetId = icon.getAttribute("data-target");
    const input = document.getElementById(targetId);

    input.addEventListener("input", () => {
      if (input.value.length > 0) {
        icon.classList.remove("d-none");
      } else {
        icon.classList.add("d-none");
        input.type = "password";
        icon.classList.replace("bi-eye-slash", "bi-eye");
      }
    });

    icon.addEventListener("click", function () {
      if (input.type === "password") {
        input.type = "text";
        this.classList.replace("bi-eye", "bi-eye-slash");
      } else {
        input.type = "password";
        this.classList.replace("bi-eye-slash", "bi-eye");
      }
    });
  });
});

// --- helper for redirect after login ---
function handleLoginRedirect() {
  const params = new URLSearchParams(window.location.search);
  const nextPage = params.get("next") || "dashboard.html";
  window.location.href = nextPage;
}
