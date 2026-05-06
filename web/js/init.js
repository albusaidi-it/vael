  // ── Init ──────────────────────────────────────────────────────────────
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const v = t(el.getAttribute('data-i18n'));
    if (v) el.textContent = v;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const v = t(el.getAttribute('data-i18n-placeholder'));
    if (v) el.placeholder = v;
  });
