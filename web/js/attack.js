  // ── Attack Path (Stage 5) ─────────────────────────────────────────────

  let _attackData = null;
  let _attackSelectedTactic = null;

  function _maybeAutoRunAttack() {
    const sw  = (document.getElementById('swInput')  || {}).value?.trim();
    const ver = (document.getElementById('verInput') || {}).value?.trim();
    if (!sw || !ver) {
      document.getElementById('attackOutput').innerHTML =
        `<p class="attack-empty">${t('attackNoSoftware')}</p>`;
      return;
    }
    // Auto-run only once per software+version pair
    const key = `${sw}|${ver}`;
    if (_attackData && _attackData._key === key) return;
    runAttackPath();
  }

  async function runAttackPath() {
    const sw  = (document.getElementById('swInput')  || {}).value?.trim();
    const ver = (document.getElementById('verInput') || {}).value?.trim();
    if (!sw || !ver) {
      document.getElementById('attackOutput').innerHTML =
        `<p class="attack-empty">${t('attackNoSoftware')}</p>`;
      return;
    }

    const btn = document.getElementById('attackRunBtn');
    if (btn) { btn.disabled = true; btn.querySelector('span').textContent = t('attackRunning'); }
    document.getElementById('attackOutput').innerHTML =
      `<p class="attack-empty">${t('attackRunning')}</p>`;

    const offline = document.getElementById('optOffline')?.checked || false;
    try {
      const resp = await fetch('/analyze/attack-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software: sw, version: ver, offline }),
      });
      if (!resp.ok) throw new Error(`HTTP ${resp.status}: ${(await resp.json()).detail || resp.statusText}`);
      const data = await resp.json();
      data._key = `${sw}|${ver}`;
      _attackData = data;
      _attackSelectedTactic = null;
      _renderAttackPath(data);
    } catch (e) {
      document.getElementById('attackOutput').innerHTML =
        `<p style="color:var(--red);font-size:0.88rem;">Error: ${e.message}</p>`;
    } finally {
      if (btn) { btn.disabled = false; btn.querySelector('span').textContent = t('btnMapAttack'); }
    }
  }

  function _attackRiskClass(score) {
    if (score >= 6) return 'at-risk-high';
    if (score >= 3) return 'at-risk-med';
    if (score >= 0.1) return 'at-risk-low';
    return 'at-risk-none';
  }

  function _renderAttackPath(data) {
    const out = document.getElementById('attackOutput');
    if (!data.total_tactics) {
      out.innerHTML = `<p class="attack-empty">${t('attackEmpty')}</p>`;
      return;
    }

    // ── Summary row ──────────────────────────────────────────────────────
    const highestLabel = data.highest_risk_tactic || '—';
    const summaryHtml = `
      <div class="attack-summary-row">
        <div class="attack-summary-item">
          <span class="num" style="color:var(--accent-hi)">${data.total_tactics}</span>
          <span class="lbl">${t('attackStatTactics')}</span>
        </div>
        <div class="attack-summary-item">
          <span class="num" style="color:var(--orange)">${data.total_techniques}</span>
          <span class="lbl">${t('attackStatTechniques')}</span>
        </div>
        <div class="attack-summary-item">
          <span class="num" style="color:var(--red);font-size:1rem;">${highestLabel}</span>
          <span class="lbl">${t('attackStatHighestRisk')}</span>
        </div>
      </div>`;

    // ── Kill-chain flow ───────────────────────────────────────────────────
    const allTacticIds = [
      'TA0043','TA0001','TA0002','TA0003','TA0004','TA0005',
      'TA0006','TA0007','TA0008','TA0009','TA0010','TA0011','TA0040'
    ];
    const nodeMap = {};
    (data.tactic_nodes || []).forEach(n => { nodeMap[n.tactic_id] = n; });
    const activePath = new Set(data.kill_chain_path || []);

    const chainBoxes = allTacticIds.map((tid, idx) => {
      const node = nodeMap[tid];
      const active = activePath.has(tid);
      const riskClass = active ? _attackRiskClass(node?.risk_score || 0) : 'at-risk-none';
      const count = active ? (node?.cve_ids?.length || 0) : '·';
      const name = node?.tactic_name || _TACTIC_NAMES[tid] || tid;
      const shortName = name.replace('Privilege Escalation','Priv. Esc.')
                            .replace('Defense Evasion','Def. Evasion')
                            .replace('Command and Control','C2')
                            .replace('Resource Development','Res. Dev.')
                            .replace('Lateral Movement','Lateral Mv.');
      const arrow = idx < allTacticIds.length - 1
        ? `<span class="attack-arrow">›</span>` : '';
      return `
        <div class="attack-tactic ${riskClass}" onclick="_selectTactic('${tid}')" id="atac-${tid}">
          <div class="tac-count">${count}</div>
          <div class="tac-name">${shortName}</div>
        </div>${arrow}`;
    }).join('');

    const hint = `<p style="font-size:0.78rem;color:var(--muted);margin:8px 0 0;">${t('attackClickTactic')}</p>`;
    out.innerHTML = summaryHtml +
      `<div class="attack-chain">${chainBoxes}</div>` + hint +
      `<div id="attackDetailPanel"></div>`;
  }

  const _TACTIC_NAMES = {
    'TA0043':'Reconnaissance','TA0042':'Resource Development',
    'TA0001':'Initial Access','TA0002':'Execution',
    'TA0003':'Persistence','TA0004':'Privilege Escalation',
    'TA0005':'Defense Evasion','TA0006':'Credential Access',
    'TA0007':'Discovery','TA0008':'Lateral Movement',
    'TA0009':'Collection','TA0010':'Exfiltration',
    'TA0011':'Command and Control','TA0040':'Impact',
  };

  function _selectTactic(tid) {
    if (!_attackData) return;
    const nodeMap = {};
    (_attackData.tactic_nodes || []).forEach(n => { nodeMap[n.tactic_id] = n; });
    const node = nodeMap[tid];
    if (!node) return;

    // Toggle selection
    if (_attackSelectedTactic === tid) {
      _attackSelectedTactic = null;
      document.querySelectorAll('.attack-tactic').forEach(el => el.classList.remove('selected'));
      document.getElementById('attackDetailPanel').innerHTML = '';
      return;
    }
    _attackSelectedTactic = tid;
    document.querySelectorAll('.attack-tactic').forEach(el => el.classList.remove('selected'));
    const box = document.getElementById(`atac-${tid}`);
    if (box) box.classList.add('selected');

    const techRows = (node.techniques || [])
      .sort((a, b) => (b.cve_ids?.length || 0) - (a.cve_ids?.length || 0))
      .map(tech => {
        const cveBadges = (tech.cve_ids || []).slice(0, 5).map(id =>
          `<span class="technique-cve-badge">${id}</span>`).join('');
        const more = tech.cve_ids?.length > 5
          ? `<span style="font-size:0.65rem;color:var(--muted)">+${tech.cve_ids.length - 5} more</span>` : '';
        const sources = [...(tech.cwe_sources || []).map(c => `CWE-${c}`),
                         ...(tech.cvss_sources || [])].join(', ');
        return `
          <div class="technique-row">
            <div style="min-width:64px">
              <div class="technique-id">${tech.technique_id}</div>
            </div>
            <div style="flex:1">
              <div style="font-weight:600;font-size:0.83rem;">${tech.technique_name}</div>
              <div class="technique-meta">${cveBadges}${more}</div>
              ${sources ? `<div class="technique-meta" style="margin-top:3px;">via ${sources}</div>` : ''}
            </div>
          </div>`;
      }).join('');

    const riskPct = Math.min(100, Math.round((node.risk_score || 0) * 10));
    document.getElementById('attackDetailPanel').innerHTML = `
      <div class="attack-detail-panel">
        <h4>${node.tactic_name}
          <span style="font-size:0.75rem;font-weight:400;color:var(--muted);margin-left:8px;">${tid}</span>
          <span style="font-size:0.75rem;font-weight:400;float:right;color:var(--muted);">
            Risk score: <strong style="color:var(--text)">${(node.risk_score||0).toFixed(1)}/10</strong>
            &nbsp;·&nbsp; ${node.cve_ids?.length || 0} CVE(s) &nbsp;·&nbsp; ${node.techniques?.length || 0} technique(s)
          </span>
        </h4>
        <div style="height:4px;background:var(--surface3);border-radius:2px;margin-bottom:16px;overflow:hidden;">
          <div style="height:100%;width:${riskPct}%;background:var(--red);border-radius:2px;transition:width 0.5s;"></div>
        </div>
        ${techRows || '<p style="color:var(--muted);font-size:0.83rem;">No technique details available.</p>'}
      </div>`;
  }
