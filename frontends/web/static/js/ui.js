/* Site-wide behaviour: nav background on scroll, reveal-on-scroll, rail arrows. */
'use strict';

(function () {
  const nav = document.getElementById('nav');
  if (nav && !nav.classList.contains('always')) {
    const onScroll = function () { nav.classList.toggle('solid', window.scrollY > 40); };
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
  }

  const items = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0, rootMargin: '0px 0px -8% 0px' });
    items.forEach(function (el, i) {
      el.style.transitionDelay = (i % 4) * 70 + 'ms';
      io.observe(el);
    });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }

  const rail = document.getElementById('rail');
  if (rail) {
    const buttons = document.querySelectorAll('[data-rail]');
    const sync = function () {
      buttons[0].disabled = rail.scrollLeft <= 4;
      buttons[1].disabled = rail.scrollLeft + rail.clientWidth >= rail.scrollWidth - 4;
    };
    buttons.forEach(function (b) {
      b.addEventListener('click', function () {
        rail.scrollBy({ left: Number(b.dataset.rail) * rail.clientWidth * 0.8, behavior: 'smooth' });
      });
    });
    rail.addEventListener('scroll', sync, { passive: true });
    window.addEventListener('resize', sync);
    sync();
  }
})();
