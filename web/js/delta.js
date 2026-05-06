  // ── Delta Tracker ─────────────────────────────────────────────────────
  const _DELTA_BADGE = {
    NEW_CVE:        ['new-cve',    '+ NEW CVE'],
    TIER_UPGRADE:   ['tier-up',    '▲ TIER UP'],
    TIER_DOWNGRADE: ['tier-down',  '▼ TIER DOWN'],
    KEV_ADDED:      ['kev-added',  '🔴 KEV ADDED'],
    KEV_REMOVED:    ['kev-removed','KEV REMOVED'],
    EPSS_SPIKE:     ['epss-spike', '▲ EPSS SPIKE'],
    EPSS_DROP:      ['epss-drop',  '▼ EPSS DROP'],
    MATURITY_CHANGE:['maturity',   '⚠ MATURITY'],
    NEW_POC:        ['new-poc',    '+ NEW POC'],
    NEW_WEAPON:     ['new-weapon', '⚠ WEAPONIZED'],
    REMOVED_CVE:    ['removed',    '− REMOVED'],
  };

  async function _checkDeltaBaseline() {
    const sw  = _currentSoftware;
    const ver = _currentVersion;
    const info = document.getElementById('deltaBaselineInfo');
    if (!sw || !ver) {
      info.innerHTML = `<p style="color:var(--muted);font-size:0.85rem">${t('deltaNoSoftware')}</p>`;
      return;
    }
    info.innerHTML = `<p style="color:var(--muted);font-size:0.85rem">${t('deltaChecking')}</p>`;
    try {
      const r = await fetch(`/monitor/${encodeURIComponent(sw)}/${encodeURIComponent(ver)}`);
      const d = await r.json();
      if (d.has_baseline) {
        const saved = d.saved_at ? new Date(d.saved_at).toLocaleString() : '—';
        info.innerHTML = `<div style="padding:10px 14px;background:rgba(48,209,88,0.07);border:1px solid rgba(48,209,88,0.25);border-radius:var(--radius-sm);font-size:0.84rem;">
          <span style="color:var(--green);font-weight:600">${t('deltaHasBaseline')}</span>
          <span style="color:var(--muted);margin-left:12px">${sw} ${ver} · ${saved} · ${d.cve_count ?? 0} CVEs</span>
        </div>`;
      } else {
        info.innerHTML = `<div style="padding:10px 14px;background:rgba(255,159,10,0.06);border:1px solid rgba(255,159,10,0.25);border-radius:var(--radius-sm);font-size:0.84rem;color:var(--orange)">${t('deltaNoBaseline')}</div>`;
      }
    } catch (e) {
      info.innerHTML = '';
    }
  }

  async function runDeltaAnalysis() {
    const sw  = _currentSoftware || document.getElementById('software').value.trim();
    const ver = _currentVersion  || document.getElementById('version').value.trim();
    if (!sw || !ver) {
      document.getElementById('deltaOutput').innerHTML =
        `<p style="color:var(--muted);font-size:0.85rem">${t('deltaNoSoftware')}</p>`;
      return;
    }
    const btn = document.getElementById('deltaRunBtn');
    btn.disabled = true;
    document.getElementById('deltaOutput').innerHTML =
      `<p style="color:var(--muted);font-size:0.85rem">${t('deltaRunning')}</p>`;

    try {
      const body = { software: sw, version: ver };
      const r = await fetch('/analyze/delta', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const err = await r.json().catch(() => ({ detail: r.statusText }));
        document.getElementById('deltaOutput').innerHTML =
          `<p style="color:var(--red);font-size:0.85rem">Error: ${err.detail || r.statusText}</p>`;
        return;
      }
      const report = await r.json();
      _renderDelta(report);
      await _checkDeltaBaseline();
    } catch (e) {
      document.getElementById('deltaOutput').innerHTML =
        `<p style="color:var(--red);font-size:0.85rem">Request failed: ${e.message}</p>`;
    } finally {
      btn.disabled = false;
    }
  }

  function _renderDelta(r) {
    const out = document.getElementById('deltaOutput');
    const changes = r.changes || [];

    if (!changes.length) {
      out.innerHTML = `<p style="color:var(--green);font-size:0.9rem;padding:16px 0">${t('deltaNoChanges')}</p>`;
      return;
    }

    const baseFmt = r.baseline_ts ? new Date(r.baseline_ts).toLocaleString() : null;
    const curFmt  = r.current_ts  ? new Date(r.current_ts).toLocaleString()  : new Date().toLocaleString();

    const timeline = baseFmt
      ? `<div class="delta-timeline">
           <strong>${baseFmt}</strong>
           <span style="font-size:1rem">→</span>
           <strong>${curFmt}</strong>
         </div>`
      : `<div class="delta-timeline"><strong>First analysis — baseline established at ${curFmt}</strong></div>`;

    const highSignal = changes.filter(c =>
      ['NEW_CVE','TIER_UPGRADE','KEV_ADDED','EPSS_SPIKE','NEW_WEAPON','MATURITY_CHANGE'].includes(c.change_type)
    );

    const statItems = [
      { num: r.new_cves,       lbl: 'New CVEs',       color: r.new_cves     ? 'var(--red)'    : '' },
      { num: r.tier_upgrades,  lbl: 'Tier Upgrades',  color: r.tier_upgrades? 'var(--orange)' : '' },
      { num: r.kev_additions,  lbl: 'KEV Added',      color: r.kev_additions? 'var(--red)'    : '' },
      { num: r.epss_spikes,    lbl: 'EPSS Spikes',    color: r.epss_spikes  ? 'var(--orange)' : '' },
      { num: r.new_pocs,       lbl: 'New PoCs',       color: r.new_pocs     ? 'var(--purple)' : '' },
      { num: r.new_weapons,    lbl: 'Weaponized',     color: r.new_weapons  ? 'var(--red)'    : '' },
      { num: r.removed_cves,   lbl: 'Removed',        color: '' },
    ].map(s =>
      `<div class="delta-stat">
         <div class="num" style="${s.color ? `color:${s.color}` : 'color:var(--text)'}">${s.num ?? 0}</div>
         <div class="lbl">${s.lbl}</div>
       </div>`
    ).join('');

    const sortOrder = ['NEW_WEAPON','KEV_ADDED','TIER_UPGRADE','MATURITY_CHANGE','EPSS_SPIKE','NEW_CVE','NEW_POC','EPSS_DROP','TIER_DOWNGRADE','KEV_REMOVED','REMOVED_CVE'];
    const sorted = [...changes].sort((a,b) => sortOrder.indexOf(a.change_type) - sortOrder.indexOf(b.change_type));

    const rows = sorted.map(c => {
      const [cls, label] = _DELTA_BADGE[c.change_type] || ['new-poc', c.change_type];
      const oldNew = (c.old_value && c.new_value)
        ? `<span style="color:var(--muted)">${c.old_value} → </span><strong>${c.new_value}</strong>`
        : (c.new_value ? `<strong>${c.new_value}</strong>` : '');
      return `<div class="delta-change-row">
        <div style="min-width:90px"><span class="delta-badge ${cls}">${label}</span></div>
        <div style="flex:0 0 130px;font-family:var(--mono);font-size:0.83rem;color:var(--accent-hi)">${c.cve_id}</div>
        <div style="flex:1;color:var(--muted)">${c.detail || ''} ${oldNew}</div>
      </div>`;
    }).join('');

    const criticalBanner = r.has_critical_changes
      ? `<div style="padding:12px 16px;background:rgba(255,69,58,0.08);border:1px solid rgba(255,69,58,0.3);border-radius:var(--radius-sm);margin-bottom:20px;color:var(--red);font-weight:600;font-size:0.88rem">
           ⚠ Critical changes detected — ${highSignal.length} high-signal event${highSignal.length !== 1 ? 's' : ''} require attention
         </div>`
      : '';

    out.innerHTML = `
      ${timeline}
      ${criticalBanner}
      <div class="delta-stat-row">${statItems}</div>
      <div class="section-label" style="margin-bottom:12px">Change Log (${changes.length})</div>
      <div>${rows}</div>`;
  }
