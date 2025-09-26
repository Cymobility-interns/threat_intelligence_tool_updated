import { postData } from "./api.js";

document.getElementById("loginForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const data = {
    username: this.username.value,
    password: this.password.value,
  };

  const { ok, result } = await postData("/login", data);

  const msg = document.getElementById("loginMessage");
  msg.innerHTML = ok
    ? `<span class="text-success">${result.message}</span>`
    : `<span class="text-danger">${result.detail}</span>`;

  if (ok) handleLoginRedirect(result); // pass user info
});

// --- helper for redirect after login ---
function handleLoginRedirect(user) {
  const params = new URLSearchParams(window.location.search);
  const nextPage = params.get("next");

  if (nextPage) {
    window.location.href = nextPage;
  } else {
    window.location.href = "dashboard.html";
  }
}

// --- password toggle logic ---
document.querySelectorAll('.toggle-password').forEach(icon => {
  const targetId = icon.getAttribute('data-target');
  const input = document.getElementById(targetId);

  input.addEventListener('input', () => {
    if (input.value.length > 0) {
      icon.classList.remove('d-none');
    } else {
      icon.classList.add('d-none');
      input.type = "password";
      icon.classList.replace("bi-eye-slash", "bi-eye");
    }
  });

  icon.addEventListener('click', function () {
    if (input.type === "password") {
      input.type = "text";
      this.classList.replace("bi-eye", "bi-eye-slash");
    } else {
      input.type = "password";
      this.classList.replace("bi-eye-slash", "bi-eye");
    }
  });
});
