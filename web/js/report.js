  // ── Report Export ─────────────────────────────────────────────────────
  async function downloadReport(fmt) {
    const sw  = _currentSoftware || document.getElementById('software').value.trim();
    const ver = _currentVersion  || document.getElementById('version').value.trim();
    if (!sw || !ver) {
      setStatus('Run an analysis first before downloading the report.', 'error');
      return;
    }
    const offline       = document.getElementById('offline').checked;
    const deterministic = document.getElementById('deterministic').checked;
    const skipGithub    = document.getElementById('skipGithub').checked;

    try {
      const resp = await fetch(`${API}/analyze/report?fmt=${fmt}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ software: sw, version: ver, offline, deterministic, skip_github: skipGithub }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        setStatus(`Report error: ${err.detail || resp.statusText}`, 'error');
        return;
      }
      const blob     = await resp.blob();
      const swSafe   = sw.replace(/[/:\\]/g, '_');
      const verSafe  = ver.replace(/[/:\\]/g, '_');
      const filename = `vael_report_${swSafe}_${verSafe}.${fmt}`;
      const url      = URL.createObjectURL(blob);
      const a        = document.createElement('a');
      a.href = url; a.download = filename; a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setStatus(`Download failed: ${e.message}`, 'error');
    }
  }
