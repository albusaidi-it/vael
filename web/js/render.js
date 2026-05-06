  function verdictCls(label) {
    return ({ 'PATCH NOW': 'patch-now', HIGH: 'high', MONITOR: 'monitor', DEFER: 'defer' })[label] || 'monitor';
  }

  function renderVerdictBanner(v) {
    document.getElementById('verdictBanner').className = `verdict-banner ${verdictCls(v.label)}`;
    document.getElementById('verdictLabel').textContent = v.label;
    document.getElementById('verdictRec').textContent   = v.recommendation;
    const pct = Math.round(v.confidence * 100);
    document.getElementById('confidenceFill').style.width = `${pct}%`;
    document.getElementById('confidenceLabel').textContent =
      `${pct}% confidence · ${v.used_ai ? 'Gemini AI' : 'Deterministic'}`;
  }

  function statBox(value, label, cls = '') {
    return `<div class="stat-box ${cls}">
      <div class="stat-value">${value}</div>
      <div class="stat-label">${label}</div>
    </div>`;
  }

  function renderStats(s1, s2, s3) {
    document.getElementById('statsRow').innerHTML =
      statBox(s1.total_cves,                 t('statTotalCVEs')) +
      statBox(s1.critical_count,             t('statCritical'),  s1.critical_count   > 0 ? 'critical' : '') +
      statBox(s1.high_count,                 t('statHigh'),      s1.high_count       > 0 ? 'warn' : '') +
      statBox(s1.version_matched_count,      t('statVerMatch'),  s1.version_matched_count > 0 ? 'warn' : '') +
      statBox(s2.kev_count,                  t('statInKEV'),     s2.kev_count        > 0 ? 'kev' : '') +
      statBox(s2.t0_patch_now_count,         t('statPatchNow'),  s2.t0_patch_now_count > 0 ? 'critical' : '') +
      statBox(s2.t1_high_count ?? '—',       t('statT1High'),   (s2.t1_high_count   > 0) ? 'warn' : '') +
      statBox(s2.t2_monitor_count ?? '—',    t('statMonitor'),   '') +
      statBox(s3 ? s3.total_pocs : '—',      t('statPoCs'),      (s3 && s3.total_pocs > 0) ? 'accent' : '') +
      statBox(s1.misconfig_flags?.length ?? '—', t('statMisconfig'), (s1.misconfig_flags?.length > 0) ? 'warn' : '');
  }

  function sevBadge(sev) {
    return `<span class="badge-sev sev-${sev}">${sev}</span>`;
  }

  // ── Source label map ──────────────────────────────────────────────────
  function sourceLabel(s) {
    const map = {
      GITHUB:            '🐙 GitHub',
      EXPLOIT_DB:        '🗃 Exploit-DB',
      PACKET_STORM:      '⚡ Packet Storm',
      NUCLEI:            '🎯 Nuclei',
      METASPLOIT:        '🔫 Metasploit',
      GITEE:             '🇨🇳 Gitee',
      SEEBUG:            '🇨🇳 Seebug',
      PASTEBIN:          '📋 Pastebin',
      OTHER:             '🔗 Other',
      NVD:               '📌 NVD',
      OSV:               '🛡 OSV',
      GHSA:              '🔐 GHSA',
      ATTACKER_KB:       '🔬 AttackerKB',
      AttackerKB:        '🔬 AttackerKB',
      ATTACKERKB:        '🔬 AttackerKB',
      VulnCheck:         '🕵 VulnCheck',
      VULNCHECK:         '🕵 VulnCheck',
      EPSS:              '📊 EPSS',
      'CISA-KEV':        '🚨 CISA KEV',
      'Patch-heuristic': '🩹 Patch',
      'CWE/CIS-local':   '📋 CWE/CIS',
    };
    return map[s] ?? s;
  }

  // ── Stage 1 ───────────────────────────────────────────────────────────
  function renderStage1(s1) {
    const el = document.getElementById('tab-stage1');
    if (!s1.cves.length) {
      el.innerHTML = '<p style="color:var(--muted)">No CVEs found for this software/version.</p>';
      return;
    }
    const sorted = [...s1.cves].sort((a, b) => (b.cvss_v3?.score ?? 0) - (a.cvss_v3?.score ?? 0));
    const rows = sorted.map(c => {
      const sev   = c.cvss_v3?.severity ?? 'UNKNOWN';
      const score = c.cvss_v3?.score != null ? c.cvss_v3.score.toFixed(1) : '—';
      const vec   = c.cvss_v3?.vector
        ? `<span title="${c.cvss_v3.vector}" style="cursor:help;border-bottom:1px dotted var(--muted)">${score}</span>`
        : score;
      const matched = c.version_matched
        ? '<span style="color:var(--green);font-weight:600">✓</span>'
        : '<span style="color:var(--muted)">—</span>';
      const cwes  = c.cwes.map(w =>
        `<code title="${w.name || ''}" style="font-size:0.76rem;cursor:help">${w.cwe_id}</code>`
      ).join(' ') || '—';
      const pubDate = c.published ? c.published.slice(0, 10) : '—';
      const desc  = (c.description ?? '').slice(0, 100);
      return `<tr>
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${c.cve_id}" target="_blank">${c.cve_id}</a></td>
        <td>${sevBadge(sev)}</td>
        <td><b>${vec}</b></td>
        <td>${matched}</td>
        <td style="color:var(--muted);font-size:0.8rem">${pubDate}</td>
        <td>${cwes}</td>
        <td style="font-size:0.79rem;color:var(--muted);max-width:280px" title="${(c.description ?? '').replace(/"/g,"'")}">
          ${desc}${desc.length >= 100 ? '…' : ''}
        </td>
      </tr>`;
    }).join('');

    el.innerHTML = `
      <p style="font-size:0.8rem;color:var(--muted);margin-bottom:12px;">
        Sources: ${s1.sources_queried.map(sourceLabel).join(', ') || '—'}
        ${s1.errors.length ? `· <span style="color:var(--red)">${s1.errors.length} error(s)</span>` : ''}
      </p>
      <div style="overflow-x:auto;">
        <table class="vael-table">
          <thead><tr>
            <th>CVE ID</th><th>Severity</th><th>CVSS v3</th>
            <th>Ver. Match</th><th>Published</th><th>CWEs</th><th>Description</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  // ── Stage 2 ───────────────────────────────────────────────────────────
  function epssCell(entry) {
    if (!entry) return '<span style="color:var(--muted)">—</span>';
    const score  = entry.epss;
    const pct    = Math.round(score * 100);
    const pctile = entry.percentile != null ? `top ${((1-entry.percentile)*100).toFixed(2)}% of CVEs` : '';
    let color = '#30d158';
    if (score > 0.7) color = '#ff453a';
    else if (score > 0.3) color = '#ff9f0a';
    else if (score > 0.05) color = '#ffd60a';
    return `<div class="epss-bar-wrap" title="${(score*100).toFixed(2)}% exploitation probability · ${pctile}">
      <div class="epss-bar-bg"><div class="epss-bar-fill" style="width:${pct}%;background:${color}"></div></div>
      <span style="font-size:0.79rem">${(score*100).toFixed(1)}%</span>
    </div>`;
  }

  function renderStage2(s2, s1) {
    const el = document.getElementById('tab-stage2');
    if (!s2.enrichments.length) {
      el.innerHTML = '<p style="color:var(--muted)">No enrichment data — EPSS/KEV feeds may be unavailable.</p>';
      return;
    }
    const sorted = [...s2.enrichments].sort((a, b) => b.vep_score - a.vep_score);

    const rows = sorted.map(e => {
      const tierLabel = TIER_LABELS[e.vep_tier] ?? e.vep_tier;
      const tierBadge = `<span class="badge-tier tier-${e.vep_tier}">${tierLabel}</span>`;
      const kevHtml = e.in_kev
        ? `<span class="kev-yes" title="${e.kev_entry?.date_added ? 'Added '+e.kev_entry.date_added : ''}">✓ KEV</span>`
        : '<span class="kev-no">—</span>';
      const patch = e.patch.patch_available
        ? `<span style="color:var(--green)">✓</span> ${e.patch.fixed_versions.slice(0,2).map(v => `<code style="font-size:0.76rem">${v}</code>`).join(' ')}`
        : '<span style="color:var(--muted)">—</span>';
      const reasoning = e.reasoning.length ? e.reasoning.map(r => `• ${r}`).join('\n') : '';
      const ti = e.threat_intel;
      const tiCell = (ti && (ti.in_the_wild || ti.threat_actors?.length || ti.ransomware_groups?.length))
        ? `<span class="ti-badge" title="${[
              ti.in_the_wild ? 'Exploited in the wild' : '',
              ti.threat_actors?.length ? 'APT: '+ti.threat_actors.join(', ') : '',
              ti.ransomware_groups?.length ? 'Ransomware: '+ti.ransomware_groups.join(', ') : '',
            ].filter(Boolean).join(' · ')}">⚠ Threat Intel</span>`
        : '<span style="color:var(--muted)">—</span>';
      return `<tr title="${reasoning}">
        <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${e.cve_id}" target="_blank">${e.cve_id}</a></td>
        <td>${tierBadge}</td>
        <td style="font-size:0.79rem;color:var(--muted)">${e.vep_score.toFixed(1)}</td>
        <td>${epssCell(e.epss)}</td>
        <td>${kevHtml}</td>
        <td style="font-size:0.79rem;color:var(--muted)">${maturityLabel(e.exploit_maturity)}</td>
        <td>${patch}</td>
        <td>${tiCell}</td>
      </tr>`;
    }).join('');

    // Threat intel callout section
    const tiCves = sorted.filter(e => {
      const ti = e.threat_intel;
      return ti && (ti.in_the_wild || ti.threat_actors?.length || ti.ransomware_groups?.length);
    });
    const tiSectionHtml = tiCves.length ? `
      <div style="margin-top:24px;padding:16px 20px;background:rgba(255,69,58,0.05);border:1px solid rgba(255,69,58,0.18);border-radius:var(--radius-sm)">
        <div style="font-size:0.83rem;font-weight:700;color:var(--red);margin-bottom:12px;">
          ⚠ THREAT INTELLIGENCE — Active Exploitation Signals
        </div>
        ${tiCves.map(e => {
          const ti = e.threat_intel;
          const pills = [
            ti.in_the_wild ? `<span style="background:rgba(255,69,58,0.18);color:#ff453a;padding:2px 8px;border-radius:4px;font-size:0.73rem">In the wild</span>` : '',
            ...(ti.threat_actors||[]).map(a => `<span style="background:rgba(191,90,242,0.15);color:#bf5af2;padding:2px 8px;border-radius:4px;font-size:0.73rem">APT: ${a}</span>`),
            ...(ti.ransomware_groups||[]).map(g => `<span style="background:rgba(255,159,10,0.18);color:#ff9f0a;padding:2px 8px;border-radius:4px;font-size:0.73rem">Ransomware: ${g}</span>`),
          ].filter(Boolean).join(' ');
          const notes = (ti.exploitation_notes||[]).map(n => `<li style="color:var(--muted);font-size:0.81rem;padding:3px 0">${n}</li>`).join('');
          return `<div style="margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid rgba(255,69,58,0.12)">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap">
              <a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${e.cve_id}" target="_blank">${e.cve_id}</a>
              ${pills}
            </div>
            ${notes ? `<ul style="list-style:none;padding-left:12px">${notes}</ul>` : ''}
          </div>`;
        }).join('')}
      </div>` : '';

    const epssDateStr = s2.epss_score_date ? (() => {
      const d = new Date(s2.epss_score_date);
      const ageDays = Math.floor((Date.now() - d.getTime()) / 86400000);
      const stale = ageDays >= 2;
      return `<span style="color:${stale ? 'var(--orange)' : 'var(--muted)'}" title="EPSS feed date">EPSS data: ${s2.epss_score_date}${stale ? ` (${ageDays}d old)` : ''}</span>`;
    })() : '';

    el.innerHTML = `
      <p style="font-size:0.8rem;color:var(--muted);margin-bottom:2px;">
        Sources: ${s2.sources_queried.map(sourceLabel).join(', ') || '—'}
      </p>
      ${epssDateStr ? `<p style="font-size:0.77rem;margin-bottom:4px;">${epssDateStr}</p>` : ''}
      <p style="font-size:0.77rem;color:var(--muted);margin-bottom:12px;">Hover a row to see VEP reasoning.</p>
      <div style="overflow-x:auto;">
        <table class="vael-table">
          <thead><tr>
            <th>CVE ID</th><th>VEP Tier</th><th>Score</th>
            <th>EPSS</th><th>KEV</th><th>Maturity</th><th>Patch</th><th>Threat Intel</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${tiSectionHtml}`;
  }

  // ── Stage 3 ───────────────────────────────────────────────────────────
  function qualityBadge(q) {
    const labels = { WEAPONIZED:'💣 Weaponized', FUNCTIONAL:'⚡ Functional',
                     CONCEPTUAL:'📄 Conceptual', FAKE:'🗑 Fake', UNKNOWN:'❓ Unknown' };
    return `<span class="badge-quality quality-${q}">${labels[q] ?? q}</span>`;
  }

  const INTL_ENGINES = {
    'Gitee':  { flag: '🇨🇳', label: 'Gitee (China)' },
    'Seebug': { flag: '🇨🇳', label: 'Seebug (China)' },
    'CNVD':   { flag: '🇨🇳', label: 'CNVD (China)' },
    'Naver':  { flag: '🇰🇷', label: 'Naver (Korea)' },
    'Yandex': { flag: '🇷🇺', label: 'Yandex (Russia)' },
    'Baidu':  { flag: '🇨🇳', label: 'Baidu (China)' },
  };

  function renderStage3(s3) {
    const el = document.getElementById('tab-stage3');
    if (!s3) {
      el.innerHTML = '<p style="color:var(--muted)">PoC data not available (Stage 3 skipped or no network).</p>';
      return;
    }
    const allPocs = s3.bundles.flatMap(b => b.pocs);
    if (!allPocs.length) {
      el.innerHTML = '<p style="color:var(--muted)">No public PoCs found across all CVEs.</p>';
      return;
    }

    const intlPocs = allPocs.filter(p => p.raw_meta && p.raw_meta.discovered_via);
    const stdPocs  = allPocs.filter(p => !p.raw_meta || !p.raw_meta.discovered_via);

    let intlHtml = '';
    if (intlPocs.length) {
      const byEngine = {};
      for (const poc of intlPocs) {
        const via = poc.raw_meta.discovered_via;
        if (!byEngine[via]) byEngine[via] = [];
        byEngine[via].push(poc);
      }
      const engineBlocks = Object.entries(byEngine).map(([engine, pocs]) => {
        const meta = INTL_ENGINES[engine] || { flag: '🌐', label: engine };
        const rows = pocs.map(poc => {
          const shortUrl = poc.url.replace(/^https?:\/\/(www\.)?/, '').slice(0, 70);
          return `<tr>
            <td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${poc.cve_id}" target="_blank">${poc.cve_id}</a></td>
            <td>${qualityBadge(poc.quality)}</td>
            <td style="font-size:0.81rem"><a href="${poc.url}" target="_blank" rel="noopener" style="color:var(--accent)">${(poc.title || shortUrl).slice(0,80)}</a></td>
            <td style="font-size:0.79rem;color:var(--muted)">${sourceLabel(poc.source)}</td>
          </tr>`;
        }).join('');
        return `<div style="margin-bottom:20px;">
          <div style="font-weight:600;font-size:0.88rem;margin-bottom:8px;">
            ${meta.flag} ${meta.label}
            <span style="font-weight:400;color:var(--muted);font-size:0.8rem;margin-left:8px">${pocs.length} result${pocs.length!==1?'s':''}</span>
          </div>
          <div style="overflow-x:auto;">
            <table class="vael-table">
              <thead><tr><th>CVE</th><th>Quality</th><th>URL / Title</th><th>Source</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>`;
      }).join('');

      intlHtml = `
        <div style="background:var(--surface2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:16px 20px;margin-bottom:24px;">
          <div style="font-size:0.86rem;font-weight:700;color:var(--accent-hi);margin-bottom:14px;">
            🌐 INTERNATIONAL SEARCH ENGINE RESULTS
            <span style="font-weight:400;color:var(--muted);font-size:0.79rem;margin-left:8px">${intlPocs.length} found across ${Object.keys(byEngine).length} engines</span>
          </div>
          ${engineBlocks}
        </div>`;
    }

    const qualRank = { WEAPONIZED:4, FUNCTIONAL:3, CONCEPTUAL:2, UNKNOWN:1, FAKE:0 };
    const sorted = [...stdPocs].sort((a, b) => (qualRank[b.quality]??0) - (qualRank[a.quality]??0));

    const cards = sorted.map(poc => {
      const stars  = poc.stars != null ? `⭐ ${poc.stars.toLocaleString()}` : '';
      const forks  = poc.forks != null ? `🍴 ${poc.forks.toLocaleString()}` : '';
      const lang   = poc.language ? `<code style="font-size:0.76rem">${poc.language}</code>` : '';
      const compat = COMPAT_LABELS[poc.version_compatibility] ?? poc.version_compatibility;
      const compatColor = poc.version_compatibility === 'CONFIRMED'    ? 'var(--green)'
                        : poc.version_compatibility === 'LIKELY'       ? 'var(--yellow)'
                        : poc.version_compatibility === 'INCOMPATIBLE' ? 'var(--red)' : 'var(--muted)';
      const nucleiCat = poc.source === 'NUCLEI' && poc.raw_meta?.category
        ? `<code style="font-size:0.73rem;background:rgba(0,113,227,0.12);color:var(--accent-hi);padding:1px 6px;border-radius:3px">${poc.raw_meta.category}</code>`
        : '';
      return `<div class="poc-card">
        <div class="poc-card-header">
          ${qualityBadge(poc.quality)}
          <a class="poc-card-title" href="${poc.url}" target="_blank" rel="noopener">${poc.title || poc.url}</a>
        </div>
        <div class="poc-card-meta">
          <span><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${poc.cve_id}" target="_blank">${poc.cve_id}</a></span>
          <span>${sourceLabel(poc.source)}${nucleiCat ? ' '+nucleiCat : ''}</span>
          ${stars ? `<span>${stars}</span>` : ''}
          ${forks ? `<span>${forks}</span>` : ''}
          ${lang  ? `<span>${lang}</span>`  : ''}
          <span style="color:${compatColor}">${compat}</span>
          ${poc.published ? `<span style="color:var(--muted)">${poc.published}</span>` : ''}
        </div>
        ${poc.description ? `<div style="margin-top:8px;font-size:0.81rem;color:var(--muted)">${poc.description.slice(0,180)}</div>` : ''}
      </div>`;
    }).join('');

    el.innerHTML = `
      <p style="font-size:0.8rem;color:var(--muted);margin-bottom:16px;">
        ${s3.total_pocs} exploit${s3.total_pocs!==1?'s':''} found
        · <span style="color:var(--red)">${s3.weaponized_count} weaponized</span>
        · ${s3.cves_with_compatible_pocs} CVEs have version-compatible PoCs
        · Sources: ${s3.sources_queried.map(sourceLabel).join(', ')}
      </p>
      ${intlHtml}
      ${sorted.length ? `<div class="section-label" style="margin-bottom:12px;">Standard Sources</div>` : ''}
      ${cards}`;
  }

  // ── AI Verdict tab ────────────────────────────────────────────────────
  function renderVerdictTab(v) {
    const el  = document.getElementById('tab-verdict');
    const pct = Math.round(v.confidence * 100);
    const evidenceItems = v.key_evidence.map(e => `<li>${e}</li>`).join('');
    const paras = v.reasoning_summary.split(/\n\n+/)
      .map(p => `<p style="margin-bottom:14px">${p.trim()}</p>`).join('');
    const vColor = ({ 'PATCH NOW': 'var(--red)', HIGH: 'var(--orange)', MONITOR: 'var(--yellow)', DEFER: 'var(--green)' })[v.label] || 'var(--accent)';

    el.innerHTML = `
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;margin-bottom:24px;">
        <div>
          <div class="section-label" style="margin-bottom:6px">Verdict</div>
          <div style="font-size:1.75rem;font-weight:700;letter-spacing:-0.5px;color:${vColor}">${v.label}</div>
        </div>
        <div>
          <div class="section-label" style="margin-bottom:6px">Confidence</div>
          <div style="font-size:1.75rem;font-weight:700;letter-spacing:-0.5px">${pct}%</div>
          <div style="font-size:0.77rem;color:var(--muted)">${v.used_ai ? 'Gemini AI' : 'Deterministic rules'}</div>
        </div>
        <div>
          <div class="section-label" style="margin-bottom:6px">Method</div>
          <div style="font-size:0.95rem;font-weight:600;color:var(--muted)">${v.used_ai ? '🤖 AI-assisted' : '📐 Rule-based'}</div>
        </div>
      </div>
      <div class="section-label" style="margin-bottom:8px">Recommendation</div>
      <div style="padding:14px 16px;background:var(--surface2);border-left:3px solid ${vColor};border-radius:var(--radius-sm);margin-bottom:24px;font-weight:500;line-height:1.6">${v.recommendation}</div>
      <div class="section-label" style="margin-bottom:10px">Analysis</div>
      <div style="margin-bottom:24px;line-height:1.8;font-size:0.9rem">${paras}</div>
      <div class="section-label" style="margin-bottom:10px">Key Evidence</div>
      <ul class="evidence-list">${evidenceItems}</ul>`;
  }
