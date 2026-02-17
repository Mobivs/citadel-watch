// Tab Content Loader — replaces iframe-based tab loading
// Fetches sub-page HTML, extracts content + styles, injects inline,
// then dynamically imports and initializes the page's JS module.
//
// Architecture:
//   - Only one non-intelligence tab's content is in the DOM at a time
//   - This avoids ID collisions between pages that share element IDs
//   - Content HTML is cached after first fetch
//   - Styles are injected into <head> once (deduplicated)
//   - CDN scripts (Chart.js, D3.js) are loaded on demand
//   - Page JS modules are imported once, then init/destroy called on tab switch

// ── CDN dependencies per tab ────────────────────────────────────────

const CDN_DEPS = {
    charts:          ['https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js'],
    timeline:        ['https://cdn.jsdelivr.net/npm/d3@7.9.0/dist/d3.min.js'],
    'risk-metrics':  ['https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js'],
    assets:          [],
    'remote-shield': [],
    'panic-room':    [],
    vault:           [],
    backup:          [],
    performance:     [],
};

const MODULE_PATHS = {
    charts:          './charts.js',
    timeline:        './timeline.js',
    'risk-metrics':  './risk-metrics.js',
    assets:          './assets.js',
    'remote-shield': './remote-shield.js',
    'panic-room':    './panic-room.js',
    vault:           './vault.js',
    backup:          './backups.js',
    performance:     './performance.js',
};

const PAGE_SOURCES = {
    charts:          'charts.html',
    timeline:        'timeline.html',
    'risk-metrics':  'risk-metrics.html',
    assets:          'assets.html',
    'remote-shield': 'remote-shield.html',
    'panic-room':    'panic-room.html',
    vault:           'vault.html',
    backup:          'backup.html',
    performance:     'performance.html',
};


// ── State ────────────────────────────────────────────────────────────

const _htmlCache = {};      // tabId → extracted HTML string
const _modules = {};         // tabId → imported module
const _loadedScripts = new Set();  // CDN URLs already loaded
let _activeTabId = null;


// ── CDN script loader ────────────────────────────────────────────────

function loadScript(url) {
    if (_loadedScripts.has(url)) return Promise.resolve();

    // Check if already in DOM (e.g. Chart.js loaded by another tab)
    const existing = document.querySelector(`script[src="${url}"]`);
    if (existing) {
        _loadedScripts.add(url);
        return Promise.resolve();
    }

    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = url;
        script.onload = () => {
            _loadedScripts.add(url);
            resolve();
        };
        script.onerror = () => reject(new Error(`Failed to load: ${url}`));
        document.head.appendChild(script);
    });
}


// ── HTML fetcher & parser ────────────────────────────────────────────

async function fetchAndParse(tabId) {
    if (_htmlCache[tabId]) return _htmlCache[tabId];

    const src = PAGE_SOURCES[tabId];
    if (!src) return null;

    const resp = await fetch(src);
    if (!resp.ok) {
        console.error(`[tab-loader] Failed to fetch ${src}: ${resp.status}`);
        return null;
    }

    const html = await resp.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Extract styles from <head>
    const styles = Array.from(doc.querySelectorAll('head style'))
        .map(s => s.textContent)
        .join('\n');

    // Extract body content minus header, footer, scripts
    const body = doc.body.cloneNode(true);
    body.querySelectorAll('header, footer, script').forEach(el => el.remove());
    const content = body.innerHTML.trim();

    // Cache
    _htmlCache[tabId] = content;

    // Inject styles once
    injectStyles(tabId, styles);

    return content;
}


// ── Style injector ───────────────────────────────────────────────────

function injectStyles(tabId, css) {
    if (!css) return;
    const id = `tab-styles-${tabId}`;
    if (document.getElementById(id)) return;

    const style = document.createElement('style');
    style.id = id;
    style.textContent = css;
    document.head.appendChild(style);
}


// ── Tab activation ───────────────────────────────────────────────────

async function activate(tabId) {
    if (tabId === 'intelligence') return; // intelligence is always inline

    // Destroy previous active tab's module
    if (_activeTabId && _activeTabId !== 'intelligence') {
        deactivate(_activeTabId);
    }

    _activeTabId = tabId;

    const panel = document.getElementById('tab-panel-dynamic');
    if (!panel) {
        console.error('[tab-loader] Dynamic panel not found: tab-panel-dynamic');
        return;
    }

    // 1. Fetch & inject content
    const content = await fetchAndParse(tabId);
    if (!content) {
        panel.innerHTML = '<div class="text-center text-gray-500 py-12">Failed to load content</div>';
        return;
    }
    panel.innerHTML = content;

    // 2. Load CDN dependencies
    const deps = CDN_DEPS[tabId] || [];
    try {
        await Promise.all(deps.map(loadScript));
    } catch (err) {
        console.error(`[tab-loader] CDN load error for ${tabId}:`, err);
    }

    // 3. Import / re-init page module
    const modulePath = MODULE_PATHS[tabId];
    if (!modulePath) return;

    try {
        if (!_modules[tabId]) {
            _modules[tabId] = await import(modulePath);
        }
        // Always call init (first load + re-activation)
        if (typeof _modules[tabId].init === 'function') {
            await _modules[tabId].init();
        }
    } catch (err) {
        console.error(`[tab-loader] Module error for ${tabId}:`, err);
    }
}


// ── Tab deactivation ─────────────────────────────────────────────────

function deactivate(tabId) {
    if (tabId === 'intelligence') return;

    // Call module's destroy to clean up intervals, charts, subscriptions
    const mod = _modules[tabId];
    if (mod && typeof mod.destroy === 'function') {
        try {
            mod.destroy();
        } catch (err) {
            console.error(`[tab-loader] Destroy error for ${tabId}:`, err);
        }
    }

    // Clear panel content to remove DOM elements (prevents ID collisions)
    const panel = document.getElementById('tab-panel-dynamic');
    if (panel) {
        panel.innerHTML = '';
    }
}


// ── Exports ──────────────────────────────────────────────────────────

export { activate, deactivate };
