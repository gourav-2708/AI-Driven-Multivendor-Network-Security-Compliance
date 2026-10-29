/* Site-wide behaviour: reveal-on-scroll, section-nav scroll spy, rail arrows. */
'use strict';

(function () {
  /* Reveal: fade elements in, and let rings and bars fill, as they appear. */
  const items = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -6% 0px' });
    items.forEach(function (el, i) {
      el.style.transitionDelay = (i % 3) * 80 + 'ms';
      io.observe(el);
    });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }

  /* Scroll spy: underline the section-nav link of the section in view. */
  const links = Array.from(document.querySelectorAll('.subnav-links a[data-spy]'));
  const targets = links.map(function (a) { return document.getElementById(a.dataset.spy); });
  if (links.length) {
    const bar = links[0].parentElement;
    let shown = -1;
    const spy = function () {
      const line = window.innerHeight * 0.35;
      let current = -1;
      targets.forEach(function (t, i) {
        if (t && t.getBoundingClientRect().top <= line) current = i;
      });
      links.forEach(function (a, i) { a.classList.toggle('active', i === current); });
      /* On narrow screens the nav scrolls sideways: keep the active link visible. */
      if (current !== shown && current >= 0 && bar.scrollWidth > bar.clientWidth) {
        bar.scrollTo({ left: links[current].offsetLeft - 16, behavior: 'smooth' });
      }
      shown = current;
    };
    spy();
    window.addEventListener('scroll', spy, { passive: true });
    window.addEventListener('resize', spy);
  }

  /* Horizontal rails with prev/next buttons. */
  document.querySelectorAll('.rail').forEach(function (rail) {
    const buttons = document.querySelectorAll('[data-rail="' + rail.id + '"]');
    if (!buttons.length) return;
    const sync = function () {
      buttons.forEach(function (b) {
        b.disabled = Number(b.dataset.dir) < 0
          ? rail.scrollLeft <= 4
          : rail.scrollLeft + rail.clientWidth >= rail.scrollWidth - 4;
      });
    };
    buttons.forEach(function (b) {
      b.addEventListener('click', function () {
        rail.scrollBy({ left: Number(b.dataset.dir) * rail.clientWidth * 0.8, behavior: 'smooth' });
      });
    });
    rail.addEventListener('scroll', sync, { passive: true });
    window.addEventListener('resize', sync);
    sync();
  });
})();
