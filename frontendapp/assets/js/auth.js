// assets/js/auth.js
import { API_BASE } from "./api.js";

/** Check login state. If not logged in, redirect to login.html */
export async function requireLogin() {
  try {
    const response = await fetch(`${API_BASE}/me`, { credentials: "include" });
    if (!response.ok) {
      window.location.href = `login.html?next=${encodeURIComponent(window.location.pathname)}`;
      return null;
    }
    return await response.json();
  } catch {
    window.location.href = "login.html";
    return null;
  }
}

/** Logout current user and redirect to login */
export async function logoutUser() {
  await fetch(`${API_BASE}/logout`, { method: "POST", credentials: "include" });
  window.location.href = "login.html";
}
