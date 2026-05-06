  // ── Oman Intel ────────────────────────────────────────────────────────
  function omanCopyFromMain() {
    const sw = document.getElementById('software').value.trim();
    const v  = document.getElementById('version').value.trim();
    if (sw) document.getElementById('omanSoftware').value = sw;
    if (v)  document.getElementById('omanVersion').value  = v;
    document.getElementById('omanSoftware').focus();
  }

  async function runOmanIntel() {
    const software = document.getElementById('omanSoftware').value.trim();
    const version  = document.getElementById('omanVersion').value.trim();
    if (!software) { document.getElementById('omanSoftware').focus(); return; }
    const btn = document.getElementById('omanRunBtn');
    const out = document.getElementById('omanOutput');
    btn.disabled = true;
    btn.querySelector('[data-i18n]').textContent = 'Searching…';
    out.innerHTML = `<div class="status-bar info"><span class="spinner"></span> Querying Shodan · FOFA · Censys for Oman exposure…</div>`;
    const cveIds = Array.from(document.querySelectorAll('#tab-stage2 .cve-link'))
      .slice(0, 3).map(a => a.textContent.trim()).filter(Boolean);
    try {
      const resp = await fetch(`${API}/analyze/oman`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software, version, cve_ids: cveIds }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        out.innerHTML = `<div class="status-bar error"><b>Error:</b> ${err.detail}</div>`;
        return;
      }
      const data = await resp.json();
      renderOmanIntel(data, out);
    } catch (e) {
      out.innerHTML = `<div class="status-bar error"><b>Connection error:</b> ${e.message}</div>`;
    } finally {
      btn.disabled = false;
      btn.querySelector('[data-i18n]').textContent = t('btnSearchOman');
    }
  }

  function renderOmanIntel(d, container) {
    const srcCards = (d.source_results || []).map(sr => {
      const hasError  = !!sr.error;
      const zeroFound = !hasError && sr.total_found === 0;
      const borderCol = hasError ? 'var(--red)' : zeroFound ? 'rgba(255,159,10,0.4)' : 'var(--border)';
      const countHtml = hasError
        ? `<span style="color:var(--red);font-size:0.81rem;display:block;margin:4px 0">${sr.error}</span>`
        : `<span style="font-size:1.6rem;font-weight:700;color:${zeroFound ? 'var(--orange)' : 'var(--accent-hi)'}">${sr.total_found.toLocaleString()}</span>`;
      const dbg = sr.debug_info || {};
      const diagItems = [];
      diagItems.push(`<b>Query:</b> <code style="font-size:0.75rem;word-break:break-all">${sr.query_used||'—'}</code>`);
      if (dbg.count_status !== undefined)  diagItems.push(`<b>Count:</b> HTTP ${dbg.count_status}`);
      if (dbg.count_total  !== undefined)  diagItems.push(`<b>Count returned:</b> ${dbg.count_total}`);
      if (dbg.search_status !== undefined) diagItems.push(`<b>Search:</b> HTTP ${dbg.search_status}`);
      if (dbg.hint)                        diagItems.push(`<span style="color:var(--yellow)">⚠ ${dbg.hint}</span>`);
      if (dbg.exception)                   diagItems.push(`<span style="color:var(--red)">Exception: ${dbg.exception}</span>`);
      const diagHtml = diagItems.length
        ? `<details style="margin-top:10px;text-align:left">
             <summary style="cursor:pointer;font-size:0.74rem;color:var(--muted);list-style:none">▸ Diagnostics</summary>
             <div style="font-size:0.76rem;line-height:1.7;margin-top:6px;padding:8px;background:var(--bg);border-radius:4px;color:var(--muted)">${diagItems.join('<br>')}</div>
           </details>` : '';
      return `<div style="background:var(--surface2);border:1px solid ${borderCol};border-radius:var(--radius-sm);padding:16px;text-align:center">
        <div style="font-weight:600;margin-bottom:6px;font-size:0.86rem">${sr.source}</div>
        ${countHtml}
        ${!hasError ? `<div style="font-size:0.74rem;color:var(--muted);margin-top:4px">hosts found</div>` : ''}
        ${diagHtml}
      </div>`;
    }).join('');

    const cityRows = Object.entries(d.hosts_by_city||{}).map(([city,count]) =>
      `<tr><td>${city}</td><td style="text-align:right;font-weight:600">${count}</td></tr>`).join('');
    const portRows = Object.entries(d.hosts_by_port||{}).map(([port,count]) =>
      `<tr><td>${port}</td><td style="text-align:right;font-weight:600">${count}</td></tr>`).join('');

    let cveBannerHtml = '';
    if (d.cve_ids_searched && d.cve_ids_searched.length) {
      const srcLabel = d.cve_source === 'auto_nvd' ? 'auto-fetched from NVD'
                     : d.cve_source === 'user_provided' ? 'from your analysis' : 'provided';
      const cveLinks = d.cve_ids_searched.map(id =>
        `<a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank">${id}</a>`
      ).join(', ');
      cveBannerHtml = `<div style="margin-bottom:20px;padding:10px 14px;background:rgba(0,113,227,0.06);border:1px solid rgba(0,113,227,0.22);border-radius:var(--radius-sm);font-size:0.82rem;color:var(--muted)">
        🎯 <b style="color:var(--text)">CVE-based search</b> — queried all sources for hosts exposed to: ${cveLinks}
        <span style="margin-left:6px;font-style:italic">(${srcLabel})</span>
      </div>`;
    } else {
      cveBannerHtml = `<div style="margin-bottom:20px;padding:10px 14px;background:rgba(255,159,10,0.06);border:1px solid rgba(255,159,10,0.28);border-radius:var(--radius-sm);font-size:0.82rem;color:var(--yellow)">
        ⚠ No CVEs found — fell back to product-name search. Run the main analysis pipeline first for better results.
      </div>`;
    }

    let cveHitsHtml = '';
    if (d.cve_hits && d.cve_hits.length) {
      const cveRows = d.cve_hits.map(h => {
        const riskColor = h.total > 10 ? 'var(--red)' : h.total > 0 ? 'var(--orange)' : 'var(--muted)';
        const cell = n => n > 0 ? `<b style="color:var(--red)">${n}</b>` : '<span style="color:var(--muted)">0</span>';
        return `<tr>
          <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${h.cve_id}" target="_blank">${h.cve_id}</a></td>
          <td style="text-align:center">${cell(h.shodan_count)}</td>
          <td style="text-align:center">${cell(h.fofa_count)}</td>
          <td style="text-align:center">${cell(h.censys_count)}</td>
          <td style="text-align:center">${cell(h.zoomeye_count||0)}</td>
          <td style="text-align:center;font-weight:700;color:${riskColor}">${h.total>0?h.total:'—'}</td>
        </tr>`;
      }).join('');
      cveHitsHtml = `<div style="margin-bottom:24px">
        <div class="section-label" style="margin-bottom:10px">Vulnerable Hosts in Oman — by CVE</div>
        <div style="overflow-x:auto">
          <table class="vael-table">
            <thead><tr><th>CVE ID</th><th style="text-align:center">Shodan</th><th style="text-align:center">FOFA</th><th style="text-align:center">Censys</th><th style="text-align:center">ZoomEye</th><th style="text-align:center">Total</th></tr></thead>
            <tbody>${cveRows}</tbody>
          </table>
        </div>
      </div>`;
    }

    const allHosts  = (d.source_results||[]).flatMap(sr => sr.hosts||[]);
    const seenIps   = new Set();
    const uniqHosts = allHosts.filter(h => { if (seenIps.has(h.ip)) return false; seenIps.add(h.ip); return true; });
    let hostsHtml = '';
    if (uniqHosts.length) {
      const hostRows = uniqHosts.slice(0, 50).map(h => `
        <tr>
          <td><code style="font-size:0.8rem">${h.ip}</code></td>
          <td>${h.port||'—'}</td>
          <td style="color:var(--muted)">${h.protocol||'—'}</td>
          <td>${h.city||'<span style="color:var(--muted)">—</span>'}</td>
          <td style="color:var(--muted);font-size:0.79rem">${(h.organization||'').slice(0,35)||'—'}</td>
          <td style="color:var(--muted)">${h.source}</td>
        </tr>`).join('');
      hostsHtml = `<div style="margin-top:24px">
        <div class="section-label" style="margin-bottom:10px">Sample Exposed Hosts — product search (${uniqHosts.length} unique IPs)</div>
        <div style="overflow-x:auto">
          <table class="vael-table">
            <thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>City</th><th>Organization</th><th>Source</th></tr></thead>
            <tbody>${hostRows}</tbody>
          </table>
        </div>
      </div>`;
    }

    const cveTotal = (d.cve_hits||[]).reduce((s,h) => s+h.total, 0);
    const swTotal  = d.total_exposed||0;
    const summaryHtml = `
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px">
        <div class="stat-box ${cveTotal>0?'kev':''}"><div class="stat-value">${cveTotal.toLocaleString()}</div><div class="stat-label">CVE-matched hosts in Oman</div></div>
        <div class="stat-box ${swTotal>0?'warn':''}"><div class="stat-value">${swTotal.toLocaleString()}</div><div class="stat-label">hosts running this software</div></div>
        <div class="stat-box"><div class="stat-value">${(d.unique_ips_sampled||0).toLocaleString()}</div><div class="stat-label">unique IPs sampled</div></div>
      </div>`;

    container.innerHTML = `
      ${cveBannerHtml}
      ${summaryHtml}
      ${cveHitsHtml}
      <div style="margin-bottom:8px">
        <div class="section-label" style="margin-bottom:12px">Software Exposure Search — all hosts running this product in Oman</div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px">${srcCards}</div>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:8px">
        ${cityRows ? `<div><div class="section-label" style="margin-bottom:10px">By City</div><table class="vael-table"><thead><tr><th>City</th><th>Count</th></tr></thead><tbody>${cityRows}</tbody></table></div>` : ''}
        ${portRows ? `<div><div class="section-label" style="margin-bottom:10px">Open Ports</div><table class="vael-table"><thead><tr><th>Port</th><th>Count</th></tr></thead><tbody>${portRows}</tbody></table></div>` : ''}
      </div>
      ${hostsHtml}
      ${d.rate_limit_warnings&&d.rate_limit_warnings.length ? `<div style="margin-top:16px;padding:10px 14px;background:rgba(255,159,10,0.06);border:1px solid rgba(255,159,10,0.28);border-radius:var(--radius-sm);font-size:0.82rem;color:var(--yellow)">⚠ ${d.rate_limit_warnings.join(' · ')}</div>` : ''}
      <div style="margin-top:12px;font-size:0.76rem;color:var(--muted)">
        Queried at ${d.queried_at ? new Date(d.queried_at).toLocaleString() : '—'} · Sources: ${d.sources_queried.join(', ')||'none configured'}
      </div>`;
  }
