import { API_BASE } from "./api.js";

// async function protectPage() {
//   const response = await fetch(`${API_BASE}/me`, { credentials: "include" });
//   if (!response.ok) {
//     window.location.href = `login.html?next=${window.location.pathname.split("/").pop()}`;
//   }
// }
// document.addEventListener("DOMContentLoaded", protectPage);
 
    const orbit = document.getElementById('brand-orbit');
    const logos = document.querySelectorAll('.brand-logo');
    const carouselContainer = document.getElementById('carousel-container');
    const totalLogos = logos.length;
    let isHighlightingActive = true;

    // Position logos around the circle
    function positionLogos() {
      const containerWidth = carouselContainer.offsetWidth;
      const radius = containerWidth * 0.4; // 40% of container width

      logos.forEach((logo, index) => {
        const angle = (360 / totalLogos) * index;
        const radian = (angle * Math.PI) / 180;
        const x = radius * Math.cos(radian);
        const y = radius * Math.sin(radian);
        
        logo.style.left = `calc(50% + ${x}px - ${logo.offsetWidth / 2}px)`;
        logo.style.top = `calc(50% + ${y}px - ${logo.offsetHeight / 2}px)`;
      });
    }

    // Initial position
    positionLogos();

    // Re-position on resize
    window.addEventListener('resize', positionLogos);

    // Highlight the logo at the bottom center (only when not paused)
    function highlightCenterLogo() {
      if (!isHighlightingActive) return;
      
      const orbitRect = orbit.getBoundingClientRect();
      const centerX = orbitRect.left + orbitRect.width / 2;
      const bottomY = orbitRect.bottom - 50;
      
      let closestLogo = null;
      let minDistance = Infinity;
      
      logos.forEach(logo => {
        const logoRect = logo.getBoundingClientRect();
        const logoCenterX = logoRect.left + logoRect.width / 2;
        const logoCenterY = logoRect.top + logoRect.height / 2;
        
        const distance = Math.sqrt(
          Math.pow(centerX - logoCenterX, 2) + 
          Math.pow(bottomY - logoCenterY, 2)
        );
        
        if (distance < minDistance) {
          minDistance = distance;
          closestLogo = logo;
        }
      });
      
      // Remove highlight from all logos
      logos.forEach(logo => logo.classList.remove('highlighted'));
      
      // Add highlight to closest logo
      if (closestLogo) {
        closestLogo.classList.add('highlighted');
      }
    }

    // Pause/Resume functionality
    function pauseCarousel() {
      orbit.classList.add('paused');
      logos.forEach(logo => logo.classList.add('paused'));
      carouselContainer.classList.add('paused');
      isHighlightingActive = false;
    }

    function resumeCarousel() {
      orbit.classList.remove('paused');
      logos.forEach(logo => logo.classList.remove('paused'));
      carouselContainer.classList.remove('paused');
      isHighlightingActive = true;
    }

    // Add hover and click event listeners to each logo
    logos.forEach(logo => {
      // Pause on hover
      logo.addEventListener('mouseenter', () => {
        pauseCarousel();
      });

      // Resume on mouse leave
      logo.addEventListener('mouseleave', () => {
        resumeCarousel();
      });

      // Navigate to brand details on click
      logo.addEventListener('click', (e) => {
        e.preventDefault();
        const brandName = logo.getAttribute('data-brand');

        //Remember that this branddetails page came from brand.html
        sessionStorage.setItem('branddetailsSource', 'brand');

        //Go to branddetails.html with selected brand
        window.location.href = `branddetails.html?brand=${encodeURIComponent(brandName)}`;
      });

    });

    // Update highlighting every 100ms for smooth transitions (only when active)
    setInterval(highlightCenterLogo, 100);
    
    // Initial highlight
    highlightCenterLogo();