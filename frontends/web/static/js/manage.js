/* Shared by every signed-in page: the CSRF token for fetch(), confirmations,
   and submitting filter forms when a choice changes. */
'use strict';

window.csrfToken = function () {
  const meta = document.querySelector('meta[name="csrf-token"]');
  return meta ? meta.content : '';
};

(function () {
  /* <form data-confirm="..."> asks before it submits. */
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  /* <select data-autosubmit> and checkboxes in a filter bar apply at once. */
  document.querySelectorAll('[data-autosubmit]').forEach(function (el) {
    el.addEventListener('change', function () { el.form.submit(); });
  });

  /* A long-running form says so and cannot be sent twice. */
  document.querySelectorAll('form[data-busy]').forEach(function (form) {
    form.addEventListener('submit', function () {
      const btn = form.querySelector('button[type=submit]');
      if (btn) { btn.disabled = true; btn.textContent = form.dataset.busy; }
    });
  });

  /* Source form: show only the fields the chosen kind of source uses. */
  const kind = document.getElementById('source-type');
  if (kind) {
    const sync = function () {
      document.querySelectorAll('[data-for]').forEach(function (el) {
        el.hidden = el.dataset.for.split(' ').indexOf(kind.value) < 0;
      });
      const loc = document.getElementById('source-location');
      if (loc) loc.placeholder = kind.selectedOptions[0].dataset.hint || '';
    };
    kind.addEventListener('change', sync);
    sync();
  }
})();
