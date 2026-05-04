// assets/js/auth.js
import { API_BASE, fetchJSON, clearApiCache } from "./api.js";
import { confirmModal, toast, showLoader, hideLoader } from "./utils.js";

// In-memory de-dupe so multiple modules calling requireLogin() in parallel
// only hit /me once per page-load.
let _meRequest = null;

/** Check login state. If not logged in, redirect to login.html and return null. */
export async function requireLogin() {
  if (!_meRequest) {
    _meRequest = fetchJSON(`${API_BASE}/me`).catch(() => null);
  }
  const user = await _meRequest;
  if (!user) {
    const next = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.href = `login.html?next=${next}`;
    return null;
  }
  return user;
}

/**
 * Log the user out. By default a confirmation modal is shown; pass { confirm: false }
 * to skip (e.g. for forced logouts after token expiry).
 */
export async function logoutUser({ confirm = true } = {}) {
  if (confirm) {
    const ok = await confirmModal("Are you sure you want to logout?", { title: "Logout", okText: "Logout", cancelText: "Cancel" });
    if (!ok) return false;
  }

  showLoader(document.body, "Logging out…");
  try {
    await fetchJSON(`${API_BASE}/logout`, { method: "POST" });
  } catch (err) {
    // Even if the server call fails we still want to redirect — but warn the user
    console.warn("Logout request failed:", err);
    toast("Logout request failed; redirecting anyway.", "warning");
  } finally {
    clearApiCache();
    hideLoader(document.body);
    window.location.href = "login.html";
  }
  return true;
}

/**
 * Wire up logout. Uses event delegation on document so it works even when the
 * navbar is injected asynchronously (which is the common case in this app).
 * Idempotent — calling multiple times is safe.
 */
let _logoutDelegated = false;
export function bindLogoutButton(/* root unused, kept for API compat */) {
  if (_logoutDelegated) return;
  _logoutDelegated = true;
  document.addEventListener("click", (e) => {
    const btn = e.target.closest("#logoutBtn");
    if (!btn) return;
    e.preventDefault();
    logoutUser();
  });
}
