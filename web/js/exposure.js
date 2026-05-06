  // ── Stage 4 — Global Exposure ─────────────────────────────────────────
  function expLevelBadge(level) {
    const labels = { CRITICAL:'🔴 Critical', HIGH:'🟠 High', MODERATE:'🟡 Moderate',
                     LOW:'🟢 Low', NONE:'✅ None', UNKNOWN:'⬜ Unknown' };
    return `<span class="badge-sev exp-${level}" style="font-size:0.8rem">${labels[level] ?? level}</span>`;
  }

  function renderStage4(s4) {
    const el = document.getElementById('exposureOutput');
    if (!s4) {
      el.innerHTML = '<p style="color:var(--muted)">No exposure data — check API keys in .env</p>';
      return;
    }
    if (!s4.exposures || !s4.exposures.length) {
      el.innerHTML = '<p style="color:var(--muted)">No CVEs to check exposure for.</p>';
      return;
    }

    const base = s4.exposures[0];
    const srcCounts = [
      { name: 'Shodan',  val: base.shodan_count  },
      { name: 'Censys',  val: base.censys_count  },
      { name: 'FOFA',    val: base.fofa_count    },
      { name: 'ZoomEye', val: base.zoomeye_count },
    ];
    const srcBoxes = srcCounts.map(s => `
      <div class="src-count-box">
        <div class="src-name">${s.name}</div>
        <div class="src-val" style="color:${s.val > 0 ? 'var(--red)' : s.val === null ? 'var(--muted)' : 'var(--green)'}">
          ${s.val !== null && s.val !== undefined ? s.val.toLocaleString() : '—'}
        </div>
        <div style="font-size:0.71rem;color:var(--muted);margin-top:4px">exposed hosts</div>
      </div>`).join('');

    const cveRows = s4.exposures.map(exp => `
      <tr>
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${exp.cve_id}" target="_blank">${exp.cve_id ?? '—'}</a></td>
        <td style="text-align:center">${exp.shodan_count  !== null ? exp.shodan_count  : '—'}</td>
        <td style="text-align:center">${exp.censys_count  !== null ? exp.censys_count  : '—'}</td>
        <td style="text-align:center">${exp.fofa_count    !== null ? exp.fofa_count    : '—'}</td>
        <td style="text-align:center">${exp.zoomeye_count !== null ? exp.zoomeye_count : '—'}</td>
        <td style="text-align:center;font-weight:700">${exp.total_exposed.toLocaleString()}</td>
        <td>${expLevelBadge(exp.level)}</td>
      </tr>`).join('');

    const samples   = base.samples || [];
    const sampleRows = samples.slice(0, 15).map(h => `
      <tr>
        <td><code style="font-size:0.8rem">${h.ip}</code></td>
        <td>${h.port ?? '—'}</td>
        <td style="color:var(--muted)">${h.country ?? '—'}</td>
        <td style="color:var(--muted);font-size:0.79rem">${(h.org ?? '').slice(0,40) || '—'}</td>
      </tr>`).join('');

    const topCC  = Object.entries(base.top_countries || {}).sort((a,b) => b[1]-a[1]).slice(0, 8);
    const ccRows = topCC.map(([cc, n]) =>
      `<tr><td>${cc}</td><td style="text-align:right;font-weight:600">${n}</td></tr>`
    ).join('');

    const errHtml = (s4.errors || []).length
      ? `<div style="margin-top:16px;padding:10px 14px;background:rgba(255,69,58,0.06);border:1px solid rgba(255,69,58,0.22);border-radius:var(--radius-sm);font-size:0.81rem;color:var(--red)">⚠ ${s4.errors.join(' · ')}</div>` : '';

    el.innerHTML = `
      <div style="display:flex;align-items:center;gap:20px;margin-bottom:20px;flex-wrap:wrap">
        <div>
          <div class="section-label" style="margin-bottom:4px">Total Exposed (max across sources)</div>
          <div style="font-size:2.1rem;font-weight:700;letter-spacing:-0.5px;color:${s4.total_exposed > 0 ? 'var(--red)' : 'var(--green)'}">
            ${s4.total_exposed.toLocaleString()}
          </div>
        </div>
        <div>
          <div class="section-label" style="margin-bottom:4px">Peak Risk Level</div>
          ${expLevelBadge(s4.peak_level)}
        </div>
        <div style="margin-left:auto;font-size:0.77rem;color:var(--muted);text-align:right">
          Sources: ${(s4.sources_queried||[]).join(', ') || 'none configured'}<br>
          Queried: ${s4.query_ts ? new Date(s4.query_ts).toLocaleString() : '—'}
        </div>
      </div>

      <div class="src-count-grid">${srcBoxes}</div>

      <div style="margin-bottom:24px">
        <div class="section-label" style="margin-bottom:10px">Exposure by CVE</div>
        <div style="overflow-x:auto">
          <table class="vael-table">
            <thead><tr>
              <th>CVE ID</th>
              <th style="text-align:center">Shodan</th>
              <th style="text-align:center">Censys</th>
              <th style="text-align:center">FOFA</th>
              <th style="text-align:center">ZoomEye</th>
              <th style="text-align:center">Total</th>
              <th>Level</th>
            </tr></thead>
            <tbody>${cveRows}</tbody>
          </table>
        </div>
      </div>

      ${sampleRows ? `
      <div style="display:grid;grid-template-columns:${ccRows ? '2fr 1fr' : '1fr'};gap:24px;margin-bottom:8px">
        <div>
          <div class="section-label" style="margin-bottom:10px">Sample Exposed Hosts (${samples.length} found)</div>
          <div style="overflow-x:auto">
            <table class="vael-table">
              <thead><tr><th>IP</th><th>Port</th><th>Country</th><th>Organization</th></tr></thead>
              <tbody>${sampleRows}</tbody>
            </table>
          </div>
        </div>
        ${ccRows ? `
        <div>
          <div class="section-label" style="margin-bottom:10px">By Country</div>
          <table class="vael-table">
            <thead><tr><th>Country</th><th style="text-align:right">Hosts</th></tr></thead>
            <tbody>${ccRows}</tbody>
          </table>
        </div>` : ''}
      </div>` : ''}

      ${errHtml}`;
  }

  async function checkExposure() {
    const software = _currentSoftware || document.getElementById('software').value.trim();
    const version  = _currentVersion  || document.getElementById('version').value.trim();
    if (!software || !version) {
      document.getElementById('exposureOutput').innerHTML =
        '<div class="status-bar error">Run the main analysis first, or fill in Software + Version above.</div>';
      return;
    }
    const btn = document.getElementById('exposureRunBtn');
    const out = document.getElementById('exposureOutput');
    btn.disabled = true;
    btn.querySelector('[data-i18n]').textContent = 'Querying…';
    out.innerHTML = `<div class="status-bar info"><span class="spinner"></span> Querying Shodan · Censys · FOFA · ZoomEye for global exposure…</div>`;
    try {
      const resp = await fetch(`${API}/analyze/exposure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software, version, offline: false }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        out.innerHTML = `<div class="status-bar error"><b>Error:</b> ${err.detail}</div>`;
        return;
      }
      const data = await resp.json();
      renderStage4(data);
    } catch (err) {
      out.innerHTML = `<div class="status-bar error"><b>Connection error:</b> ${err.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.querySelector('[data-i18n]').textContent = t('btnCheckExposure');
    }
  }
