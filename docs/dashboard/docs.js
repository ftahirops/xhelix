// xhelix documentation — shared sidebar nav, search, active state, TOC
// All DOM manipulation uses safe APIs (createElement + textContent) — no innerHTML
// with dynamic content.

// ─────────────────────────────────────────────────────────────────────────
// 1. SIDEBAR NAVIGATION (single source of truth — same on every page)
// ─────────────────────────────────────────────────────────────────────────
const NAV = [
  {
    section: 'Getting Started',
    pages: [
      { href: 'index.html', title: 'Introduction' },
      { href: 'mission.html', title: 'Mission & Scope' },
      { href: 'not-xhelix.html', title: 'What xhelix is NOT' },
    ],
  },
  {
    section: 'Architecture',
    pages: [
      { href: 'three-plane.html', title: 'Three-Plane Overview' },
      { href: 'diagrams.html', title: 'Architecture Diagrams' },
      { href: 'detection-stack.html', title: 'Detection Stack' },
      { href: 'data-flow.html', title: 'Data Flow & Storage' },
      { href: 'protect-our-own.html', title: 'Protect-Our-Own Backstop' },
    ],
  },
  {
    section: 'Engines & Capabilities',
    pages: [
      { href: 'engines.html', title: 'Engine Catalog' },
      { href: 'source-lineage.html', title: 'Source Lineage' },
      { href: 'brp.html', title: 'Behavioral Reference Profiles' },
      { href: 'verification.html', title: 'Verification Engine' },
      { href: 'multi-chain.html', title: 'Multi-Chain Composition' },
      { href: 'containment.html', title: 'Containment Ladder' },
      { href: 'forensic-chain.html', title: 'Forensic Chain' },
    ],
  },
  {
    section: 'Telemetry',
    pages: [
      { href: 'telemetry.html', title: 'Class A / B / C' },
      { href: 'inventory.html', title: 'App Inventory Fingerprinting' },
      { href: 'lifecycle.html', title: 'Data Lifecycle & Retention' },
    ],
  },
  {
    section: 'Operations',
    pages: [
      { href: 'progress.html', title: 'Build Progress' },
      { href: 'tasks.html', title: 'Task List' },
    ],
  },
  {
    section: 'Testing & Maturity',
    pages: [
      { href: 'testing.html', title: 'Test Results' },
      { href: 'maturity.html', title: 'Maturity Grades' },
      { href: 'fp-trajectory.html', title: 'FP Trajectory' },
    ],
  },
  {
    section: 'Comparison',
    pages: [
      { href: 'comparison.html', title: 'Level 1 — Summary' },
      { href: 'comparison-deep.html', title: 'Level 2 — Deep Features' },
      { href: 'comparison-rates.html', title: 'Level 3 — Detection Rates' },
    ],
  },
  {
    section: 'Reference',
    pages: [
      { href: 'risks.html', title: 'Risk Register' },
      { href: 'glossary.html', title: 'Glossary' },
      { href: 'honest-limits.html', title: 'Honest Non-Promises' },
    ],
  },
];

const FLAT_PAGES = NAV.flatMap(sec => sec.pages.map(p => ({ ...p, section: sec.section })));

// Small DOM helpers — keep all dynamic content out of innerHTML.
function el(tag, attrs, text) {
  const e = document.createElement(tag);
  if (attrs) for (const k of Object.keys(attrs)) e.setAttribute(k, attrs[k]);
  if (text != null) e.textContent = text;
  return e;
}

// ─────────────────────────────────────────────────────────────────────────
// 2. RENDER SIDEBAR
// ─────────────────────────────────────────────────────────────────────────
function renderSidebar() {
  const root = document.querySelector('.sidebar');
  if (!root) return;
  const currentPage = location.pathname.split('/').pop() || 'index.html';
  root.replaceChildren();
  for (const sec of NAV) {
    root.appendChild(el('h5', null, sec.section));
    for (const p of sec.pages) {
      const a = el('a', { href: p.href }, p.title);
      if (p.href === currentPage) a.classList.add('active');
      root.appendChild(a);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────
// 3. BUILD "ON THIS PAGE" TOC FROM CONTENT HEADINGS
// ─────────────────────────────────────────────────────────────────────────
function renderTOC() {
  const tocEl = document.querySelector('.toc');
  if (!tocEl) return;
  const content = document.querySelector('.content');
  if (!content) return;
  const headings = content.querySelectorAll('h2, h3, h4');
  if (headings.length === 0) {
    tocEl.style.display = 'none';
    return;
  }
  tocEl.replaceChildren();
  tocEl.appendChild(el('h5', null, 'On this page'));
  headings.forEach((h, i) => {
    if (!h.id) {
      const slug = (h.textContent || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40);
      h.id = 'h-' + i + '-' + slug;
    }
    const a = el('a', { href: '#' + h.id }, h.textContent);
    a.classList.add(h.tagName.toLowerCase());
    tocEl.appendChild(a);
  });
  // Scroll-spy.
  const tocLinks = tocEl.querySelectorAll('a');
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        const link = tocEl.querySelector('a[href="#' + entry.target.id + '"]');
        if (!link) return;
        if (entry.isIntersecting) {
          tocLinks.forEach((l) => l.classList.remove('active'));
          link.classList.add('active');
        }
      });
    },
    { rootMargin: '-80px 0px -70% 0px' }
  );
  headings.forEach((h) => observer.observe(h));
}

// ─────────────────────────────────────────────────────────────────────────
// 4. PREV / NEXT NAVIGATION
// ─────────────────────────────────────────────────────────────────────────
function renderPrevNext() {
  const root = document.querySelector('.prevnext');
  if (!root) return;
  const currentPage = location.pathname.split('/').pop() || 'index.html';
  const idx = FLAT_PAGES.findIndex(p => p.href === currentPage);
  if (idx < 0) return;
  const prev = idx > 0 ? FLAT_PAGES[idx - 1] : null;
  const next = idx < FLAT_PAGES.length - 1 ? FLAT_PAGES[idx + 1] : null;
  root.replaceChildren();
  function buildLink(p, dir) {
    const wrap = el('div');
    if (!p) return wrap;
    const a = el('a', { href: p.href });
    a.classList.add('pn');
    if (dir === 'next') a.classList.add('next');
    a.appendChild(el('div', { class: 'label' }, dir === 'next' ? 'Next →' : '← Previous'));
    a.appendChild(el('div', { class: 'title' }, p.title));
    wrap.appendChild(a);
    return wrap;
  }
  root.appendChild(buildLink(prev, 'prev'));
  root.appendChild(buildLink(next, 'next'));
}

// ─────────────────────────────────────────────────────────────────────────
// 5. SEARCH (client-side over hardcoded NAV — no user-supplied HTML)
// ─────────────────────────────────────────────────────────────────────────
function initSearch() {
  const input = document.querySelector('.search input');
  const results = document.querySelector('.search-results');
  if (!input || !results) return;

  function render(query) {
    const q = query.toLowerCase().trim();
    results.replaceChildren();
    if (!q) {
      results.classList.remove('open');
      return;
    }
    const matches = FLAT_PAGES.filter(p =>
      p.title.toLowerCase().includes(q) || p.section.toLowerCase().includes(q)
    ).slice(0, 12);
    if (matches.length === 0) {
      const empty = el('div', null, 'No matches');
      empty.classList.add('sr-empty');
      results.appendChild(empty);
    } else {
      for (const m of matches) {
        const a = el('a', { href: m.href });
        const page = el('div', null, m.title);
        page.classList.add('sr-page');
        const sec = el('div', null, m.section);
        sec.classList.add('sr-section');
        a.appendChild(page);
        a.appendChild(sec);
        results.appendChild(a);
      }
    }
    results.classList.add('open');
  }

  input.addEventListener('input', e => render(e.target.value));
  input.addEventListener('focus', e => { if (e.target.value) render(e.target.value); });
  document.addEventListener('click', e => {
    if (!e.target.closest('.search')) results.classList.remove('open');
  });
}

// ─────────────────────────────────────────────────────────────────────────
// 6. MOBILE SIDEBAR TOGGLE
// ─────────────────────────────────────────────────────────────────────────
function initMobileNav() {
  const burger = document.querySelector('.burger');
  const sidebar = document.querySelector('.sidebar');
  if (!burger || !sidebar) return;
  burger.addEventListener('click', () => sidebar.classList.toggle('open'));
}

// ─────────────────────────────────────────────────────────────────────────
// INIT
// ─────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderSidebar();
  renderTOC();
  renderPrevNext();
  initSearch();
  initMobileNav();
});
