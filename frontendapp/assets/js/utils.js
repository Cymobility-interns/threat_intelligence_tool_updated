// assets/js/utils.js
// Shared utilities: XSS-safe escape, debounce, toasts, modal confirm, loaders,
// safe storage, date/CVE normalisers. Imported across all module scripts.

// Auto-inject the matching stylesheet so every importer gets toast/modal/loader styles
(function injectUtilsCss() {
  if (typeof document === "undefined") return;
  const HREF = "assets/css/utils.css";
  const already = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
    .some(l => l.getAttribute("href") === HREF);
  if (already) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = HREF;
  document.head.appendChild(link);
})();

// ------------------------------------------------------------
// XSS: always pass user/server text through this before innerHTML
// ------------------------------------------------------------
export function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ------------------------------------------------------------
// Debounce
// ------------------------------------------------------------
export function debounce(fn, wait = 250) {
  let t;
  const debounced = (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), wait);
  };
  debounced.cancel = () => clearTimeout(t);
  return debounced;
}

// ------------------------------------------------------------
// Safe storage — sessionStorage/localStorage can throw in private mode
// ------------------------------------------------------------
function makeSafeStorage(backing) {
  return {
    get(key, fallback = null) {
      try { const v = backing.getItem(key); return v === null ? fallback : v; }
      catch { return fallback; }
    },
    set(key, value) {
      try { backing.setItem(key, value); } catch { /* ignore */ }
    },
    remove(key) {
      try { backing.removeItem(key); } catch { /* ignore */ }
    },
  };
}
export const safeSession = makeSafeStorage(typeof sessionStorage !== "undefined" ? sessionStorage : { getItem(){return null;}, setItem(){}, removeItem(){} });
export const safeLocal   = makeSafeStorage(typeof localStorage   !== "undefined" ? localStorage   : { getItem(){return null;}, setItem(){}, removeItem(){} });

// ------------------------------------------------------------
// Date helpers
// ------------------------------------------------------------
export function formatDateDDMMYYYY(rawDate) {
  if (!rawDate) return "Not Available";
  const date = new Date(rawDate);
  return isNaN(date) ? "Not Available" : date.toLocaleDateString("en-GB").replace(/\//g, "-");
}

// ------------------------------------------------------------
// CVE normaliser — used by ledger + branddetails + dashboard
// ------------------------------------------------------------
const EMPTY_CVE = new Set(["", "not available", "n/a", "null", "none", "undefined", "na"]);
export function normalizeCve(val) {
  if (val === undefined || val === null) return null;
  const s = String(val).trim();
  if (!s) return null;
  return EMPTY_CVE.has(s.toLowerCase()) ? null : s;
}

export function genFallbackId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return `internal-${crypto.randomUUID()}`;
  }
  return `internal-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

// ------------------------------------------------------------
// Toast container (created lazily, single instance)
// ------------------------------------------------------------
function getToastContainer() {
  let c = document.getElementById("app-toast-container");
  if (!c) {
    c = document.createElement("div");
    c.id = "app-toast-container";
    c.setAttribute("role", "status");
    c.setAttribute("aria-live", "polite");
    document.body.appendChild(c);
  }
  return c;
}

/**
 * toast(message, type, opts)
 *   type: "info" | "success" | "warning" | "error"
 *   opts.duration: ms (default 3500); 0 = sticky
 */
export function toast(message, type = "info", { duration = 3500 } = {}) {
  const c = getToastContainer();
  const el = document.createElement("div");
  el.className = `app-toast app-toast--${type}`;
  el.textContent = String(message); // textContent — never inject HTML

  const close = document.createElement("button");
  close.className = "app-toast__close";
  close.setAttribute("aria-label", "Close");
  close.textContent = "×";
  close.addEventListener("click", () => dismiss());
  el.appendChild(close);

  c.appendChild(el);
  // trigger transition
  requestAnimationFrame(() => el.classList.add("app-toast--visible"));

  let timer = null;
  function dismiss() {
    if (!el.isConnected) return;
    el.classList.remove("app-toast--visible");
    setTimeout(() => el.remove(), 250);
    if (timer) clearTimeout(timer);
  }
  if (duration > 0) timer = setTimeout(dismiss, duration);
  return dismiss;
}

// ------------------------------------------------------------
// Promise-based confirm modal (replaces window.confirm)
// ------------------------------------------------------------
export function confirmModal(message, { title = "Confirm", okText = "OK", cancelText = "Cancel" } = {}) {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "app-modal-overlay";
    overlay.innerHTML = `
      <div class="app-modal" role="dialog" aria-modal="true" aria-labelledby="app-modal-title">
        <h5 class="app-modal__title" id="app-modal-title"></h5>
        <p class="app-modal__body"></p>
        <div class="app-modal__actions">
          <button type="button" class="app-modal__btn app-modal__btn--cancel"></button>
          <button type="button" class="app-modal__btn app-modal__btn--ok"></button>
        </div>
      </div>
    `;
    // populate via textContent (XSS safe)
    overlay.querySelector(".app-modal__title").textContent = title;
    overlay.querySelector(".app-modal__body").textContent = message;
    const cancelBtn = overlay.querySelector(".app-modal__btn--cancel");
    const okBtn = overlay.querySelector(".app-modal__btn--ok");
    cancelBtn.textContent = cancelText;
    okBtn.textContent = okText;

    function close(result) {
      overlay.remove();
      document.removeEventListener("keydown", onKey);
      resolve(result);
    }
    function onKey(e) {
      if (e.key === "Escape") close(false);
      if (e.key === "Enter") close(true);
    }

    okBtn.addEventListener("click", () => close(true));
    cancelBtn.addEventListener("click", () => close(false));
    overlay.addEventListener("click", (e) => { if (e.target === overlay) close(false); });
    document.addEventListener("keydown", onKey);

    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.add("app-modal-overlay--visible"));
    okBtn.focus();
  });
}

// ------------------------------------------------------------
// Loading overlay — full-page or scoped to a target element
// ------------------------------------------------------------
export function showLoader(target, label = "Loading…") {
  const host = resolveTarget(target) || document.body;
  // Scoped overlays need a positioned host
  if (host !== document.body) {
    const cs = window.getComputedStyle(host);
    if (cs.position === "static") host.dataset.appLoaderPositioned = "1", host.style.position = "relative";
  }
  // Reuse an existing loader on the same host
  let loader = host.querySelector(":scope > .app-loader");
  if (!loader) {
    loader = document.createElement("div");
    loader.className = "app-loader";
    loader.innerHTML = `<div class="app-loader__spinner" aria-hidden="true"></div><div class="app-loader__label"></div>`;
    host.appendChild(loader);
  }
  loader.querySelector(".app-loader__label").textContent = label;
  loader.classList.add("app-loader--visible");
  return () => hideLoader(host);
}

export function hideLoader(target) {
  const host = resolveTarget(target) || document.body;
  const loader = host.querySelector(":scope > .app-loader");
  if (loader) {
    loader.classList.remove("app-loader--visible");
    setTimeout(() => loader.remove(), 200);
  }
  if (host.dataset.appLoaderPositioned === "1") {
    host.style.position = "";
    delete host.dataset.appLoaderPositioned;
  }
}

function resolveTarget(target) {
  if (!target) return null;
  if (typeof target === "string") return document.querySelector(target);
  if (target instanceof Element) return target;
  return null;
}

// ------------------------------------------------------------
// Button busy-state helper — disables and swaps label while async work runs
// ------------------------------------------------------------
export async function withButtonBusy(button, label, fn) {
  if (!button) return fn();
  const originalText = button.innerHTML;
  const originalDisabled = button.disabled;
  button.disabled = true;
  button.innerHTML = `<span class="app-btn-spinner" aria-hidden="true"></span> ${escapeHtml(label)}`;
  try {
    return await fn();
  } finally {
    button.disabled = originalDisabled;
    button.innerHTML = originalText;
  }
}
