import { postData } from "./api.js";

document.getElementById("signupForm").addEventListener("submit", async function (e) {
  e.preventDefault();

  const data = {
    name: this.name.value,
    username: this.username.value,
    email: this.email.value,
    password: this.password.value,
    confirm_password: this.confirm_password.value,
  };

  const { ok, result } = await postData("/signup", data);

  const msg = document.getElementById("signupMessage");
  msg.innerHTML = ok
    ? `<span class="text-success">${result.message}</span>`
    : `<span class="text-danger">${result.detail}</span>`;

  if (ok) setTimeout(() => window.location.href = "login.html", 2000);
});

document.querySelectorAll('.toggle-password').forEach(icon => {
  const targetId = icon.getAttribute('data-target');
  const input = document.getElementById(targetId);

  // Show/hide eye based on input value
  input.addEventListener('input', () => {
    if (input.value.length > 0) {
      icon.classList.remove('d-none');
    } else {
      icon.classList.add('d-none');
      // Reset back to password type and eye icon when cleared
      input.type = "password";
      icon.classList.replace("bi-eye-slash", "bi-eye");
    }
  });

  // Toggle visibility
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

