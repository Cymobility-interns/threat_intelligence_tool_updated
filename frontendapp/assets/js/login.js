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

  if (ok) setTimeout(() => window.location.href = "index.html", 1000);
});
