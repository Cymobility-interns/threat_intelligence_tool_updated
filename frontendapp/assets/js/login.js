// assets/js/login.js
import { postData } from "./api.js";
import { toast, withButtonBusy, escapeHtml } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  const msg = document.getElementById("loginMessage");
  if (!form) return;
  const submitBtn = form.querySelector('button[type="submit"]');

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const username = this.username.value.trim();
    const password = this.password.value; // do NOT trim password — significant whitespace is part of secret

    if (!username || !password) {
      toast("Please enter both username and password.", "warning");
      return;
    }

    msg.innerHTML = "";

    const { ok, result } = await withButtonBusy(submitBtn, "Signing in…", () =>
      postData("/login", { username, password })
    );

    if (ok) {
      msg.innerHTML = `<span class="text-success">${escapeHtml(result.message || "Logged in")}</span>`;
      toast(result.message || "Logged in successfully.", "success");
      handleLoginRedirect();
    } else {
      const detail = result?.detail || "Login failed.";
      msg.innerHTML = `<span class="text-danger">${escapeHtml(detail)}</span>`;
      toast(detail, "error");
    }
  });

  // --- password toggle logic ---
  document.querySelectorAll(".toggle-password").forEach((icon) => {
    const targetId = icon.getAttribute("data-target");
    const input = document.getElementById(targetId);
    if (!input) return;

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

function handleLoginRedirect() {
  const params = new URLSearchParams(window.location.search);
  const nextPage = sanitizeNext(params.get("next")) || "dashboard.html";
  window.location.href = nextPage;
}

// Open-redirect guard — only allow same-origin relative paths
function sanitizeNext(next) {
  if (!next) return null;
  try {
    const u = new URL(next, window.location.origin);
    if (u.origin !== window.location.origin) return null;
    return u.pathname + u.search + u.hash;
  } catch {
    return null;
  }
}
