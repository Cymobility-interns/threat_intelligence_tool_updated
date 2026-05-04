// assets/js/signup.js
import { postData } from "./api.js";
import { toast, withButtonBusy, escapeHtml } from "./utils.js";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("signupForm");
  if (!form) return;
  const msg = document.getElementById("signupMessage");
  const submitBtn = form.querySelector('button[type="submit"]');

  form.addEventListener("submit", async function (e) {
    e.preventDefault();

    const data = {
      name: this.name.value.trim(),
      username: this.username.value.trim(),
      email: this.email.value.trim(),
      password: this.password.value,
      confirm_password: this.confirm_password.value,
    };

    // Client-side validation — keep light, server is source of truth
    if (!data.name || !data.username || !data.email || !data.password) {
      toast("Please fill in all required fields.", "warning");
      return;
    }
    if (data.password !== data.confirm_password) {
      toast("Passwords do not match.", "warning");
      return;
    }
    if (data.password.length < 8) {
      toast("Password must be at least 8 characters.", "warning");
      return;
    }

    if (msg) msg.innerHTML = "";

    const { ok, result } = await withButtonBusy(submitBtn, "Creating account…", () =>
      postData("/signup", data)
    );

    if (ok) {
      const text = result.message || "Account created.";
      if (msg) msg.innerHTML = `<span class="text-success">${escapeHtml(text)}</span>`;
      toast(text + " Redirecting to login…", "success");
      setTimeout(() => { window.location.href = "login.html"; }, 1500);
    } else {
      const detail = result?.detail || "Signup failed.";
      if (msg) msg.innerHTML = `<span class="text-danger">${escapeHtml(detail)}</span>`;
      toast(detail, "error");
    }
  });

  // password toggle (same behaviour as login)
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
