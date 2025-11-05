// components/navbar.js
(function () {
  window.initNavbar = function initNavbar() {
    const toggle = document.getElementById("menuToggle");
    const menu = document.getElementById("horizontalMenu");
    const closeIcon = document.getElementById("closeMenu");
    if (!toggle || !menu || !closeIcon) return;

    const icon = toggle.querySelector("i");
    const label = toggle.querySelector(".menu-label");

    toggle.addEventListener("click", () => {
      menu.classList.add("show");
      icon.style.display = "none";
      if (label) label.style.display = "none";
    });

    closeIcon.addEventListener("click", () => {
      menu.classList.remove("show");
      icon.style.display = "inline";
      if (label) label.style.display = "inline";
    });

    // Close menu on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && menu.classList.contains('show')) {
        menu.classList.remove('show');
        icon.style.display = "inline";
        if (label) label.style.display = "inline";
      }
    });
  };
})();
