# Meme-Coin Early Warning System

---
OCC2 Group18
- Wang Yingqi (23050522)
- Lim Qian Hui (22091617)
- Queh Qian Yu (22112617)
- Wee Dun Ying (23005029)
---
Github Repo Link: https://github.com/yoreumorchid/Meme-Coin-Early-Warning-System.git

## 1. What the system does

Given an Ethereum ERC-20 contract address, the system returns a 0–100 risk
score along with a written verdict. The pipeline has four stages:

1. Pull the token's ERC-20 transfer history from the Etherscan v2 API.
2. Build a directed transfer graph with NetworkX and compute five
   features: `max_centrality`, `avg_clustering`, `unique_wallets`,
   `value_volatility`, `tx_count`.
3. Feed those features into a CatBoost classifier trained on ~380 confirmed
   rug-pull tokens, producing a fraud probability.
4. Fetch the verified Solidity source (if available) and scan it for
   high-risk patterns — mint backdoors, owner-only blacklists, trading
   pause switches, hidden fee setters — to get an AST risk score in
   [0, 1].

The final score is

```
risk = clamp(ml_prob * 75 + ast_score * 100, 0, 100)
```

with cut-offs HIGH ≥ 70, MEDIUM ≥ 40, otherwise LOW.

A FastAPI backend (`04_Web_App/backend.py`) calls the four tools in fixed
order. A separate DeepSeek-orchestrated agent
(`03_Agents_and_Tools/agent_logic.ipynb`) does the same job by letting an
LLM plan the tool calls — kept around for the bonus task but not used by
the web UI.

---

## 2. Repository layout

```
01_Data_Pipeline/       Raw fraud CSVs + graph feature extraction notebooks
02_Model_Training/      CatBoost training, evaluation, exported model files
03_Agents_and_Tools/    The four MCP-style tools and the LLM agent notebook
04_Web_App/             FastAPI backend + static frontend (the demo target)
requirements.txt        Python dependencies
```

Model artifacts live in `02_Model_Training/exported_models/`:
`rugpull_detector.cbm`, `scaler.joblib`, `recall_threshold.joblib`. Feature
order is fixed:
`[max_centrality, avg_clustering, unique_wallets, value_volatility, tx_count]`.

---

## 3. Running it

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Create `.env` in the repo root:

```
ETHERSCAN_API_KEY=your_etherscan_v2_key
DEEPSEEK_API_KEY=your_deepseek_key    # only needed for the agent notebook
```

Then start the web app:

```powershell
uvicorn backend:app --app-dir 04_Web_App --port 8000 --reload
```

Open `http://localhost:8000`, paste a contract address, hit *Run Forensic
Audit*. The report shows the gauge, AST findings, graph features, a
sample of the underlying transactions, and a plain-text verdict. Export
buttons produce a print-styled PDF or the raw JSON.

If the address has no on-chain transfers or Etherscan errors out, the UI
shows the actual HTTP error in a red banner — there is no mock fallback
in production mode.

---

## 4. Out-of-sample validation

To check that the model does something useful on addresses it has never
seen, we ran `04_Web_App/prescreen_candidates.py`. The script downloads
the Forta Network *malicious_smart_contracts.csv* blacklist (publicly
maintained, not used in training), drops anything that appears in our
training filenames, and audits a random sample through the full pipeline.

The following nine addresses come from that blacklist (https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/malicious_smart_contracts.csv), are confirmed by
Forta as phishing token contracts, and were correctly flagged HIGH by our
pipeline:

| Address | Forta tag | tx count |
|---|---|---:|
| `0x49c5cd3b1ad9718db6e275b1b3d81c459cb59a6a` | Fake_Phishing3852 | 17 |
| `0x29cc635a3968beec56c6a3f5da1c033a18ee1571` | Fake_Phishing2799 | 37 |
| `0x6618dd109ee9dc93026ab36ab6ab7b4fbde0411b` | Fake_Phishing4502 | 19 |
| `0xca03cc32bb8063261aa6ff488b89da5b0f8a487e` | Fake_Phishing4240 | 25 |
| `0xcf1e4c2899ed260dcc68da9bbd986d8ea1c740d9` | Fake_Phishing4219 | 20 |
| `0x476f96132384e5ac79a929970505d045b4a7eaf9` | UniswapV4.com (UNI-V4) | 200 |
| `0x2bb34304c3ee09f485d3adf09dc4ce686b3d7e11` | LINE Metaverse (LINE) | 94 |
| `0x688b56c0740658f9ed2244b56a23f93f409a6a96` | fees.wtf (FEESWTF) | 15 |
| `0x1e891e6c7ea7a7c32d4b9643b90b8a9fa313c77f` | Sudoswap Governance Token | 595 |

These cases span pure fake-phishing tokens and brand-impersonation tokens
(a fake UniswapV4, a fake LINE Metaverse coin, a fake fees.wtf, a fake
Sudoswap governance token). Convenient for a live demo because none of
them are in the training set, and the model still produces high ML
probabilities purely from the transfer-graph shape.

For comparison, the following established meme coins should land in LOW
or MEDIUM:

| Address | Token |
|---|---|
| `0x6982508145454Ce325dDbE47a25d4ec3d2311933` | PEPE |
| `0x95aD61b0a150d79219dCF64E1E6Cc01f0B64C4cE` | SHIB |
| `0xcf0C122c6b73ff809C693DB761e7BaeBe62b6a2E` | FLOKI |
| `0xaaeE1A9723aaDB7afA2810263653A34bA2C21C7a` | MOG |

These will usually score high on the AST side — they really do ship
`mint`, `owner`, and `pause` functions — but the ML side keeps the
composite in the safe zone.

---

## 5. What it catches well, what it does not

**Where it works.** Small-cap meme coins with the classic pump-then-dump
shape: a small number of wallets concentrating supply, sudden value
volatility, and source code containing owner-only mint or blacklist
functions. The model was trained on roughly this distribution and behaves
as expected on the validation addresses above.

**Where it struggles:**

- *Presale / ICO exit scams.* There is almost no on-chain trading history
  to learn from, so the graph features come out empty.
- *Quiet abandoned tokens.* A sparse graph reads as "small but normal"
  rather than "rug."
- *Established large-caps* (USDC, UNI, WETH, …). Transaction counts in
  the millions are far outside what the model has ever seen, and the
  output should be ignored.
- *Anything off-chain.* CEX collapses, fake teams, social-engineering
  rugs — the system only reads the blockchain.
- *Novel patterns* introduced after the training data was collected.

The LOW RISK verdict text in the UI now includes this caveat so users
don't read a low score as an endorsement.

---

## 6. Known limitations

A few things worth being honest about:

- **Ethereum mainnet only.** Chain ID is hardcoded to `1` throughout.
  BSC, Polygon, Arbitrum, Base, Solana etc. are not supported.
- **AST false positives.** Mint and pause functions are common in
  legitimate meme contracts. The composite weighting prioritises the ML
  signal to compensate, but users will sometimes see scary-looking AST
  findings on safe tokens.
- **Unverified contracts.** When the source isn't published on Etherscan
  the AST tool falls back to `ast_score = 0` and a single "Unverified"
  finding. The ML side still runs.
- **Rate limits.** Free-tier Etherscan caps at roughly 5 req/s. During a
  busy demo this can surface as a 502 from the backend.
- **Small training set.** ~380 tokens is not a lot. Performance on rug
  patterns very different from those in the training set is uncertain.
- **Not financial advice.** A LOW score is not an endorsement and a HIGH
  score is not a legal conclusion. Always verify independently.

---

## 7. Files worth looking at

- [04_Web_App/backend.py](04_Web_App/backend.py) — FastAPI service, the canonical orchestration
- [04_Web_App/index.html](04_Web_App/index.html), [app.js](04_Web_App/app.js), [styles.css](04_Web_App/styles.css) — the frontend
- [04_Web_App/prescreen_candidates.py](04_Web_App/prescreen_candidates.py) — the Forta-based OOS validator
- [03_Agents_and_Tools/tools/](03_Agents_and_Tools/tools/) — the four tools
- [03_Agents_and_Tools/agent_logic.ipynb](03_Agents_and_Tools/agent_logic.ipynb) — the LLM-orchestrated variant
- [02_Model_Training/3_fraud_detection_modeling.ipynb](02_Model_Training/3_fraud_detection_modeling.ipynb) — model training
- [01_Data_Pipeline/2_processing_and_graph.ipynb](01_Data_Pipeline/2_processing_and_graph.ipynb) — feature engineering
