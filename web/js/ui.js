  // ── Shared state ──────────────────────────────────────────────────────
  let _activeSource = null;
  let _currentSoftware = null, _currentVersion = null;

  // ── Label maps ────────────────────────────────────────────────────────
  const TIER_LABELS = {
    T0_PATCH_NOW: 'PATCH NOW',
    T1_HIGH:      'HIGH',
    T2_MONITOR:   'MONITOR',
    T3_DEFER:     'DEFER',
    T_UNKNOWN:    'UNKNOWN',
  };

  const COMPAT_LABELS = {
    CONFIRMED:    '✓ Confirmed',
    LIKELY:       '~ Likely',
    UNKNOWN:      '? Unknown',
    INCOMPATIBLE: '✗ Incompatible',
  };

  function maturityLabel(raw) {
    return raw.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  }

  // ── Tab management ────────────────────────────────────────────────────
  function switchTab(name) {
    const names = ['stage1','stage2','stage3','exposure','attack','verdict','delta'];
    document.querySelectorAll('.tab').forEach((tab, i) => {
      tab.classList.toggle('active', names[i] === name);
    });
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.classList.toggle('active', p.id === `tab-${name}`);
    });
    if (name === 'delta')  _checkDeltaBaseline();
    if (name === 'attack') _maybeAutoRunAttack();
  }

  function setStatus(msg, type = 'info') {
    const bar = document.getElementById('statusBar');
    bar.className = `status-bar ${type}`;
    bar.innerHTML = msg;
    bar.classList.remove('hidden');
  }

  function clearResults() {
    document.getElementById('results').classList.add('hidden');
    document.getElementById('statusBar').classList.add('hidden');
    document.getElementById('rateLimitBanner').classList.add('hidden');
    document.getElementById('rateLimitList').innerHTML = '';
    document.getElementById('exposureOutput').innerHTML = '';
    _currentSoftware = null;
    _currentVersion  = null;
  }

  function showRateLimitWarnings(warnings) {
    if (!warnings || !warnings.length) return;
    const banner = document.getElementById('rateLimitBanner');
    const list   = document.getElementById('rateLimitList');
    const existing = new Set(Array.from(list.querySelectorAll('li')).map(li => li.textContent));
    warnings.forEach(w => {
      if (!existing.has(w)) {
        const li = document.createElement('li');
        li.textContent = w;
        list.appendChild(li);
        existing.add(w);
      }
    });
    banner.classList.remove('hidden');
  }
