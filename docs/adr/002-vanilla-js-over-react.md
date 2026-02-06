# ADR 002: Use Vanilla JavaScript + Web Components Instead of React

**Status**: Accepted
**Date**: 2026-02-02
**PRD Impact**: Technical Architecture - Technology Stack (Frontend)
**Deciders**: John Vickrey (User/Product Owner), Claude (Technical Advisor)

---

## Context

The initial PRD (v0.2.2) specified React 18+ with TypeScript for the frontend UI. During Phase 1 implementation, we reconsidered this choice based on:

1. **Application Type**: Citadel Archer is a **desktop application** wrapped in pywebview, not a web application
2. **Security Focus**: As a security product, minimizing dependencies reduces attack surface
3. **UI Complexity**: Phase 1 UI is relatively simple (status dashboard, process list, event log)
4. **User Trust**: Users need to audit and trust the code protecting their systems

**The Question**: Is React the right choice for a security-focused desktop application, or would vanilla JavaScript be more appropriate?

## Decision

**Replace React with Vanilla JavaScript + Web Components** for the frontend UI.

**Frontend Stack:**
- Vanilla JavaScript (ES6+ modules)
- Web Components (for reusable UI elements)
- Shadow DOM (for style isolation)
- Tailwind CSS (for styling)
- Native browser APIs (WebSocket, Fetch)
- Optional: TypeScript (for type safety without React overhead)

## Rationale

### Why NOT React?

#### 1. **Dependency Bloat (Security Risk)**
React applications typically have 1000+ npm packages:
```
node_modules/: ~200MB, 1000+ dependencies
Examples: react, react-dom, babel, webpack, eslint, etc.
Supply chain risk: HIGH (eslint-scope, event-stream incidents)
```

For a **security application**, each dependency is a potential attack vector. We must audit or trust every package.

#### 2. **Build Complexity**
React requires:
- Babel (JSX transpilation)
- Webpack/Vite (bundling)
- Development server
- Hot module replacement
- Complex configuration

This adds failure points and makes deployment more complex.

#### 3. **Desktop App Context**
React's benefits fade in a desktop app:
- ❌ No SSR needed (it's local)
- ❌ No code splitting needed (all files local)
- ❌ No SEO needed (not a website)
- ❌ No React ecosystem features apply (Next.js, Remix, etc.)

#### 4. **Update Churn**
React ecosystem moves fast:
- React 16 → 17 → 18 (breaking changes)
- Class components → Hooks (paradigm shift)
- Now: React Server Components (major shift)

For a **security product**, we want stability and predictability, not chasing framework updates.

### Why Vanilla JS + Web Components?

#### 1. **Minimal Attack Surface**
```
Dependencies: 0 runtime (maybe PostCSS for Tailwind)
Build output: ~50KB + Tailwind CSS
Supply chain risk: MINIMAL
```

Users can audit the entire codebase without sifting through `node_modules`.

#### 2. **Simplicity & Auditability**
- Pure HTML/CSS/JavaScript (no JSX transpilation)
- Direct DOM manipulation (no virtual DOM)
- Standard browser APIs (everyone understands them)
- Users can inspect and verify the code

For a **proprietary security product**, this builds trust.

#### 3. **Performance**
- Faster cold start (no framework initialization)
- Smaller bundle size (~50KB vs ~500KB)
- No virtual DOM overhead
- Direct browser rendering

#### 4. **Still Modern**
- ES6 modules (clean imports/exports)
- Web Components (reusable UI: `<guardian-status>`, `<threat-card>`)
- Shadow DOM (style isolation)
- Native APIs (WebSocket, Fetch, observers)
- Tailwind CSS (rapid styling)

#### 5. **Appropriate for Our UI**
Phase 1 UI is not complex:
- Status dashboard (Guardian active/inactive, threat level)
- Process list (scrollable table)
- Event log viewer (scrollable list)
- Settings form (security level, monitored paths)

This doesn't require React's component model or state management.

### Alternative Considered: Lit (5KB Framework)

**Lit** is a tiny Web Components framework (5KB):
- Reactive updates
- Declarative templates
- TypeScript support
- Still Web Components (Shadow DOM)

**Decision**: Start with pure Vanilla JS. If we need reactivity helpers, add Lit later (easy migration).

## Consequences

### Positive
- ✅ **Smaller attack surface** (near-zero dependencies)
- ✅ **Simpler deployment** (no complex build pipeline)
- ✅ **Faster cold start** (no framework initialization)
- ✅ **More auditable** (users can inspect all code)
- ✅ **Stable** (ES6/Web Components are stable standards)
- ✅ **Appropriate** (matches UI complexity)

### Negative
- ⚠️ **Manual state management** (no Redux/Zustand)
  - **Mitigation**: Simple reactive patterns sufficient for our use case
- ⚠️ **No React DevTools** (debugging)
  - **Mitigation**: Browser DevTools + console.log + structured logging
- ⚠️ **More boilerplate** (for complex UIs)
  - **Mitigation**: Our UI is simple; Web Components reduce boilerplate

### Neutral
- If Phase 2+ UI becomes complex, we can reassess (add Lit or even React island)
- Tailwind CSS still works perfectly
- FastAPI backend unchanged

## PRD Alignment

- ⚠️ **Deviation**: Original PRD v0.2.2 specified React 18+ with TypeScript
- ✅ **Update**: PRD v0.2.3 now reflects Vanilla JS + Web Components
- ✅ **Reason**: Security-first architecture, appropriate for desktop app, simpler is better

**PRD Update Required?** ✅ Yes - **COMPLETED**
- Updated PRD to v0.2.3
- Added changelog entry explaining change
- Updated Technical Architecture → Technology Stack

## Implementation Notes

**Frontend Structure:**
```
frontend/
├── index.html          # Main HTML
├── css/
│   └── styles.css      # Tailwind + custom styles
├── js/
│   ├── main.js         # Entry point
│   ├── api.js          # FastAPI client (WebSocket + REST)
│   ├── components/     # Web Components
│   │   ├── guardian-status.js
│   │   ├── threat-card.js
│   │   ├── process-list.js
│   │   └── event-log.js
│   └── utils/          # Helpers
│       ├── state.js    # Simple reactive state
│       └── dom.js      # DOM utilities
└── assets/             # Images, icons
```

**Web Component Example:**
```javascript
class GuardianStatus extends HTMLElement {
  connectedCallback() {
    this.attachShadow({ mode: 'open' });
    this.render();
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>/* Scoped styles */</style>
      <div class="status-card">
        <h2>Guardian Status</h2>
        <p class="status-active">🟢 Active</p>
      </div>
    `;
  }
}
customElements.define('guardian-status', GuardianStatus);
```

**State Management:**
```javascript
// Simple reactive state (no framework needed)
const state = {
  guardianActive: false,
  securityLevel: 'guardian',
  processes: [],
  listeners: new Set()
};

function subscribe(listener) {
  state.listeners.add(listener);
}

function setState(updates) {
  Object.assign(state, updates);
  state.listeners.forEach(fn => fn(state));
}
```

**Tailwind Integration:**
- Use Tailwind CLI (no npm needed) OR
- PostCSS for build step (minimal) OR
- CDN for MVP (fastest start)

## References

- PRD v0.2.2: Section "Technical Architecture, Technology Stack"
- PRD v0.2.3: Updated "Technical Architecture, Technology Stack"
- User Quote: "i'm concerned is react the best choise... would something more simplistic an fundamental like vanilla JS be better?"
- Security Principle: "Proprietary code (protect algorithms from attackers)" - fewer deps = more auditable
- Philosophy: "Simpler is often better for security applications"

---

## Revision History

| Date | Change | Reason |
|------|--------|--------|
| 2026-02-02 | Initial ADR | Document decision to use Vanilla JS over React for security and simplicity |
