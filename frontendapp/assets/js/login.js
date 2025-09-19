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

  if (ok) setTimeout(() => window.location.href = "ledger.html", 1000);
});

document.querySelectorAll('.toggle-password').forEach(icon => {
  const targetId = icon.getAttribute('data-target');
  const input = document.getElementById(targetId);

  // Show/hide eye when user types
  input.addEventListener('input', () => {
    if (input.value.length > 0) {
      icon.classList.remove('d-none');
    } else {
      icon.classList.add('d-none');
      // Reset to password type when cleared
      input.type = "password";
      icon.classList.replace("bi-eye-slash", "bi-eye");
    }
  });

  // Toggle password visibility on click
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

