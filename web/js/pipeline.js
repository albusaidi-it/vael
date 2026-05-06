  // ── Demo loader ───────────────────────────────────────────────────────
  async function loadDemo(scenarioId) {
    clearResults();
    setStatus(`<span class="spinner"></span> Loading demo scenario…`, 'info');
    try {
      const resp = await fetch(`${API}/demo/${scenarioId}`);
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setStatus(`<b>Demo error:</b> ${err.detail}`, 'error');
        return;
      }
      const data = await resp.json();
      document.getElementById('software').value = data.stage1.software;
      document.getElementById('version').value  = data.stage1.version;
      renderResults(data);
      setStatus(
        `⚡ <b>Demo data</b> — ${data.stage1.software} ${data.stage1.version} · `
        + `${data.stage1.total_cves} CVEs · fixture data (instant, no network)`,
        'ok'
      );
    } catch {
      setStatus(`<b>Connection error:</b> API not reachable at <code>${API}</code>`, 'error');
    }
  }

  // ── Live analysis (SSE streaming) ─────────────────────────────────────
  function runAnalysis(e) {
    e.preventDefault();
    if (_activeSource) { _activeSource.close(); _activeSource = null; }
    clearResults();

    const software      = document.getElementById('software').value.trim();
    const version       = document.getElementById('version').value.trim();
    const offline       = document.getElementById('offline').checked;
    const deterministic = document.getElementById('deterministic').checked;
    const skipGithub    = document.getElementById('skipGithub').checked;

    const btn          = document.getElementById('submitBtn');
    const loadingText  = document.getElementById('loadingText');
    const loadingStage = document.getElementById('loadingStage');
    btn.disabled = true;
    loadingText.classList.remove('hidden');
    loadingStage.textContent = t('loadingStage1');

    let s1data = null, s2data = null, s3data = null;

    const params = new URLSearchParams({
      software, version,
      offline:       offline       ? 'true' : 'false',
      deterministic: deterministic ? 'true' : 'false',
      skip_github:   skipGithub    ? 'true' : 'false',
      top_n: '10',
    });

    const src = new EventSource(`${API}/analyze/stream?${params}`);
    _activeSource = src;

    function done() {
      src.close();
      _activeSource = null;
      btn.disabled = false;
      loadingText.classList.add('hidden');
    }

    src.addEventListener('stage1', ev => {
      s1data = JSON.parse(ev.data);
      showRateLimitWarnings(s1data.rate_limit_warnings);
      document.getElementById('results').classList.remove('hidden');
      renderStage1(s1data);
      renderStats(s1data, { enrichments:[], kev_count:0, t0_patch_now_count:0, t1_high_count:0, t2_monitor_count:0, sources_queried:[] }, null);
      switchTab('stage1');
      loadingStage.textContent = t('loadingStage2');
    });

    src.addEventListener('stage2', ev => {
      s2data = JSON.parse(ev.data);
      showRateLimitWarnings(s2data.rate_limit_warnings);
      renderStage2(s2data, s1data);
      renderStats(s1data, s2data, null);
      loadingStage.textContent = t('loadingStage3');
    });

    src.addEventListener('stage3', ev => {
      s3data = JSON.parse(ev.data);
      showRateLimitWarnings(s3data.rate_limit_warnings);
      renderStage3(s3data);
      renderStats(s1data, s2data, s3data);
      loadingStage.textContent = t('loadingVerdict');
    });

    src.addEventListener('verdict', ev => {
      const v = JSON.parse(ev.data);
      renderVerdictBanner(v);
      renderVerdictTab(v);
    });

    src.addEventListener('done', () => {
      _currentSoftware = s1data?.software || null;
      _currentVersion  = s1data?.version  || null;
      done();
      setStatus(
        `🔍 <b>Live analysis</b> — ${s1data?.software} ${s1data?.version} · `
        + `${s1data?.total_cves ?? 0} CVEs · `
        + `${s2data?.kev_count ?? 0} in KEV · `
        + `${s3data?.total_pocs ?? 0} PoCs`,
        'ok'
      );
    });

    src.addEventListener('error', ev => {
      done();
      let msg = 'Pipeline error';
      try { msg = JSON.parse(ev.data).message; } catch (_) {}
      setStatus(`<b>Error:</b> ${msg}`, 'error');
    });

    src.onerror = () => {
      if (src.readyState === EventSource.CLOSED) return;
      done();
      setStatus(
        `<b>Connection error:</b> Could not reach VAEL API at <code>${API}</code>. `
        + `Start it with: <code>uvicorn api.main:app --reload</code>`,
        'error'
      );
    };
  }

  // ── Render pipeline (demo full-data path) ─────────────────────────────
  function renderResults(data) {
    const { stage1, stage2, stage3, verdict } = data;
    showRateLimitWarnings([
      ...(stage1?.rate_limit_warnings  || []),
      ...(stage2?.rate_limit_warnings  || []),
      ...((stage3 && stage3.rate_limit_warnings) || []),
    ]);
    _currentSoftware = stage1?.software || null;
    _currentVersion  = stage1?.version  || null;
    document.getElementById('results').classList.remove('hidden');
    renderVerdictBanner(verdict);
    renderStats(stage1, stage2, stage3);
    renderStage1(stage1);
    renderStage2(stage2, stage1);
    renderStage3(stage3);
    renderVerdictTab(verdict);
    switchTab('stage1');
  }
