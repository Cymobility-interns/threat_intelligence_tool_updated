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
