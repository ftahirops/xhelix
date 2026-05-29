// charts.js — lightweight SVG chart helpers for the egress dashboard.
// No external dependencies. All functions return SVG element strings
// (caller is responsible for putting them in the DOM via innerHTML).
// User input is NOT embedded into these helpers; only numeric series
// pass through, so we don't need to HTML-escape inside.
//
// Class colour palette is shared with egress.css.

(function (global) {
  const CLASS_COLORS = {
    cloud_provider: '#60a5fa',
    cloudflare:     '#f97316',
    aws:            '#facc15',
    gcp:            '#34d399',
    azure:          '#818cf8',
    cdn:            '#2dd4bf',
    private:        '#6b7283',
    metadata:       '#a78bfa',
    intel_bad:      '#f87171',
    dev_registry:   '#4ade80',
    os_update:      '#4ade80',
    fleet_baseline: '#a4abc0',
    unknown:        '#3a4256',
  };

  function colorFor(cls) {
    return CLASS_COLORS[cls] || '#ee8033';
  }

  // ── Sparkline ─────────────────────────────────────────
  // values: number[]; returns SVG string.
  function sparkline(values, opts) {
    opts = opts || {};
    const w = opts.width || 100;
    const h = opts.height || 24;
    const color = opts.color || '#ee8033';
    if (!values || values.length < 2) {
      return `<svg class="spark" width="${w}" height="${h}"></svg>`;
    }
    const max = Math.max.apply(null, values);
    const min = Math.min.apply(null, values);
    const range = (max - min) || 1;
    const step = w / (values.length - 1);
    let d = '';
    values.forEach((v, i) => {
      const x = (i * step).toFixed(2);
      const y = (h - ((v - min) / range) * (h - 2) - 1).toFixed(2);
      d += (i === 0 ? 'M' : 'L') + x + ' ' + y + ' ';
    });
    const area = d + `L ${w} ${h} L 0 ${h} Z`;
    return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <path class="area" d="${area}" fill="${color}" fill-opacity=".18"/>
      <path d="${d}" fill="none" stroke="${color}" stroke-width="1.4"/>
    </svg>`;
  }

  // ── Line chart ────────────────────────────────────────
  // series: [{name, color, points: [{x:number,y:number}]}]; returns SVG.
  function lineChart(series, opts) {
    opts = opts || {};
    const w = opts.width || 800;
    const h = opts.height || 220;
    const pad = { l: 48, r: 12, t: 10, b: 24 };
    if (!series || !series.length) return _emptyChart(w, h);
    let xMin = Infinity, xMax = -Infinity, yMax = 0;
    series.forEach(s => s.points.forEach(p => {
      if (p.x < xMin) xMin = p.x;
      if (p.x > xMax) xMax = p.x;
      if (p.y > yMax) yMax = p.y;
    }));
    if (!isFinite(xMin) || xMin === xMax) return _emptyChart(w, h);
    yMax = yMax || 1;
    const xs = x => pad.l + ((x - xMin) / (xMax - xMin)) * (w - pad.l - pad.r);
    const ys = y => h - pad.b - (y / yMax) * (h - pad.t - pad.b);

    let svg = `<svg class="chart-svg" width="100%" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`;
    svg += _gridY(w, h, pad, yMax, 4);
    svg += _axisX(w, h, pad, xMin, xMax, 6);
    series.forEach(s => {
      let d = '';
      s.points.forEach((p, i) => {
        d += (i === 0 ? 'M' : 'L') + xs(p.x).toFixed(1) + ' ' + ys(p.y).toFixed(1) + ' ';
      });
      svg += `<path d="${d}" fill="none" stroke="${s.color || '#ee8033'}" stroke-width="1.6"/>`;
    });
    svg += '</svg>';
    return svg;
  }

  // ── Stacked area chart ────────────────────────────────
  // buckets: [{x:number, parts:{className: value}}]; classes: string[]; returns SVG.
  function stackedArea(buckets, classes, opts) {
    opts = opts || {};
    const w = opts.width || 1100;
    const h = opts.height || 240;
    const pad = { l: 56, r: 12, t: 10, b: 28 };
    if (!buckets || !buckets.length) return _emptyChart(w, h);

    const xMin = buckets[0].x;
    const xMax = buckets[buckets.length - 1].x;
    const totals = buckets.map(b => classes.reduce((s, c) => s + (b.parts[c] || 0), 0));
    const yMax = Math.max.apply(null, totals) || 1;
    const xs = x => pad.l + ((x - xMin) / Math.max(1, xMax - xMin)) * (w - pad.l - pad.r);
    const ys = y => h - pad.b - (y / yMax) * (h - pad.t - pad.b);

    let svg = `<svg class="chart-svg" width="100%" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`;
    svg += _gridY(w, h, pad, yMax, 4);
    svg += _axisX(w, h, pad, xMin, xMax, 6);

    // Build stacked paths from bottom to top.
    const baseline = buckets.map(() => 0);
    classes.forEach(cls => {
      let dTop = '';
      let dBot = '';
      buckets.forEach((b, i) => {
        const v = b.parts[cls] || 0;
        const yBot = ys(baseline[i]);
        baseline[i] += v;
        const yTop = ys(baseline[i]);
        const x = xs(b.x);
        dTop += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + yTop.toFixed(1) + ' ';
        dBot = 'L' + x.toFixed(1) + ' ' + yBot.toFixed(1) + ' ' + dBot;
      });
      const path = dTop + dBot + 'Z';
      const col = colorFor(cls);
      svg += `<path d="${path}" fill="${col}" fill-opacity=".55" stroke="${col}" stroke-width=".6"/>`;
    });
    svg += '</svg>';
    return svg;
  }

  function _emptyChart(w, h) {
    return `<svg class="chart-svg" width="100%" height="${h}" viewBox="0 0 ${w} ${h}">
      <text x="${w/2}" y="${h/2}" text-anchor="middle" fill="#6b7283" font-size="12" font-family="ui-monospace,monospace">no data</text>
    </svg>`;
  }

  function _gridY(w, h, pad, yMax, ticks) {
    let s = '';
    for (let i = 0; i <= ticks; i++) {
      const y = pad.t + (i / ticks) * (h - pad.t - pad.b);
      const v = yMax * (1 - i / ticks);
      s += `<line x1="${pad.l}" x2="${w - pad.r}" y1="${y}" y2="${y}" stroke="#232938" stroke-width=".5"/>`;
      s += `<text x="${pad.l - 6}" y="${y + 3}" text-anchor="end" fill="#6b7283" font-size="10" font-family="ui-monospace,monospace">${_fmtBytes(v)}</text>`;
    }
    return s;
  }

  function _axisX(w, h, pad, xMin, xMax, ticks) {
    let s = '';
    for (let i = 0; i <= ticks; i++) {
      const x = pad.l + (i / ticks) * (w - pad.l - pad.r);
      const t = xMin + (i / ticks) * (xMax - xMin);
      const d = new Date(t * 1000);
      const label = d.getHours().toString().padStart(2, '0') + ':00';
      s += `<line x1="${x}" x2="${x}" y1="${h - pad.b}" y2="${h - pad.b + 3}" stroke="#3a4256" stroke-width=".5"/>`;
      s += `<text x="${x}" y="${h - pad.b + 16}" text-anchor="middle" fill="#6b7283" font-size="10" font-family="ui-monospace,monospace">${label}</text>`;
    }
    return s;
  }

  function _fmtBytes(n) {
    if (n < 1024) return n.toFixed(0) + 'B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + 'K';
    if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + 'M';
    return (n / 1024 / 1024 / 1024).toFixed(2) + 'G';
  }

  // ── World grid (fallback choropleth) ─────────────────
  // countries: [{country, bytes_out, ...}]; returns HTML string.
  // We pick the top N (default 50) and lay them out in a CSS grid.
  function worldGrid(countries, opts) {
    opts = opts || {};
    const limit = opts.limit || 50;
    const top = countries.slice(0, limit);
    if (!top.length) return '<div class="placeholder">no traffic in selected range</div>';
    const max = top[0].bytes_out || 1;
    let html = '<div class="world-grid">';
    top.forEach(c => {
      const ratio = (c.bytes_out || 0) / max;
      let lvl = 0;
      if (ratio > .6) lvl = 4;
      else if (ratio > .3) lvl = 3;
      else if (ratio > .1) lvl = 2;
      else if (ratio > 0)  lvl = 1;
      html += `<div class="world-cell lvl-${lvl}" data-country="${c.country}" title="${c.country} · ${_fmtBytes(c.bytes_out)}">
        <div class="cc">${c.country}</div>
        <div class="val">${_fmtBytes(c.bytes_out)}</div>
      </div>`;
    });
    html += '</div>';
    return html;
  }

  global.Charts = {
    sparkline, lineChart, stackedArea, worldGrid,
    colorFor, fmtBytes: _fmtBytes,
  };
})(window);
