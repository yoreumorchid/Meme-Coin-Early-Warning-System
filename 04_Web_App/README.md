# Meme-Coin Early Warning System — Web Frontend

A presentation-ready frontend for the agentic on-chain forensics system.
Pure HTML / CSS / JS — no build step required.

## Run

Just open `index.html` in a browser. Or serve locally:

```powershell
cd 04_Web_App
python -m http.server 8000
# then visit http://localhost:8000
```

## Features

- **Address Scanner** — paste an Ethereum / BSC contract address.
- **Animated Agent Pipeline** — visualizes the 5 stages: MCP fetch → NetworkX graph → AST scan → CatBoost inference → weighted synthesis.
- **Risk Dashboard** — gauge score, ML probability bar, AST findings, NetworkX graph metrics, transaction sample, and a plain-language agent verdict.
- **Deterministic mock** — same address always returns the same report (good for demos).

## Wiring up the real backend

In [app.js](app.js) inside `handleSubmit()`, replace:

```js
const report = runAgentMock(address, chain);
```

with a real call:

```js
const report = await fetch('/api/audit', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address, chain })
}).then(r => r.json());
```

The backend should return JSON matching the schema documented at the top of [app.js](app.js).

## Files

- [index.html](index.html) — markup & layout
- [styles.css](styles.css) — dark forensics theme
- [app.js](app.js) — agent pipeline animation, mock inference, render
