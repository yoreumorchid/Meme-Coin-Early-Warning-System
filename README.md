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

## 4. Components in detail

This section walks through the actual notebooks and Python modules so the
report reflects what is in the repo, not just the high-level picture.

### 4.1 Data pipeline (`01_Data_Pipeline/`)

**`1_data_ingestion.ipynb`** — pulls the two label sources. Fraud labels
come from a public rugpull dataset on GitHub; safe labels come from the
Uniswap verified-token list (fetched via IPFS). For each labelled
contract it calls the Etherscan v2 `account.tokentx` endpoint and writes
the raw transfers to one CSV per token under `01_Data_Pipeline/raw_data/`
with filenames like `fraud_eth_0x….csv` / `safe_eth_0x….csv`. The label
and the chain are encoded in the filename.

**`2_processing_and_graph.ipynb`** — turns each raw transaction CSV into
a single feature row. Transfers are loaded into a directed NetworkX
graph (nodes = wallets, edges = transfers weighted by transferred value)
and five features are computed per token:

| Feature | Meaning |
|---|---|
| `max_centrality` | Largest degree centrality — flags a wallet that touches almost everything (a master / deployer wallet) |
| `avg_clustering` | Average clustering coefficient on the undirected projection — picks up wash-trading triangles |
| `unique_wallets` | Number of distinct wallets in the graph |
| `value_volatility` | Standard deviation of transfer values |
| `tx_count` | Total number of transfers |

All rows are concatenated with the binary `label` column (0 = safe,
1 = fraud) and written to `01_Data_Pipeline/processed_features.csv`.
That file is the only input to the model-training notebook.

### 4.2 Model training (`02_Model_Training/`)

**`3_fraud_detection_modeling.ipynb`** — loads `processed_features.csv`,
fits a `StandardScaler` on the five features, then does a stratified
80/20 train/test split. The classifier is **CatBoost** with
`iterations=300`, `depth=6`, `learning_rate=0.05`, `loss=Logloss`,
`eval_metric=Recall`. We deliberately optimise for recall because the
cost of missing a rug is higher than the cost of flagging a borderline
contract. After fitting we report ROC-AUC plus the standard
precision / recall / F1 breakdown on the test set, and pick a decision
threshold that protects recall on the validation fold.

Three artifacts are exported into `02_Model_Training/exported_models/`:

- `rugpull_detector.cbm` — the trained CatBoost model
- `scaler.joblib` — the fitted StandardScaler (so inference scales
  exactly the same way as training)
- `recall_threshold.joblib` — the chosen decision threshold

These three files are the only thing the production pipeline needs at
inference time.

### 4.3 Tools (`03_Agents_and_Tools/tools/`)

Each tool is a plain Python module exposing one function, written in the
MCP-tool style (single dict-in, dict-out, no hidden state). They are the
building blocks reused by both the FastAPI backend and the LLM agent.

- **`fetch_tool.fetch_transactions(address, chain_id)`** — thin wrapper
  around Etherscan v2's `account.tokentx` endpoint. Returns up to 1000
  ERC-20 transfer rows.
- **`graph_tool.extract_graph_features(transactions)`** — implements
  the same NetworkX pipeline as the training notebook, so live inference
  and training share the exact same feature definitions.
- **`predict_tool.predict_fraud_probability(features)`** — loads the
  three exported artifacts, scales the input dict, and returns a fraud
  probability in the 0–100 range plus a status.
- **`ast_tool.analyze_contract_code(address)`** — fetches the verified
  Solidity source through Etherscan v2. It first tries `solidity_parser`
  to walk a real AST, and falls back to regex patterns when parsing
  fails or when the source contains constructs the parser can't handle.
  The patterns it scores are:
  - public / external mint functions (`_mint`, `mintTo`, etc.) — weight 0.20–0.35
  - `onlyOwner` functions whose names contain drain / withdraw / blacklist / pause keywords — 0.15–0.25
  - mapping-based blacklists
  - trading-pause / trading-enable switches

  Findings are deduplicated, weights are summed and capped at 1.0, and a
  short plain-English explanation is attached to each finding.

### 4.4 Bonus integration notebook

**`03_Agents_and_Tools/4_bonus_ast_and_integration.ipynb`** is the
playground that ties the AST scanner to the trained CatBoost model end
to end, without the LLM in the loop. It uses an earlier 70/30 weighting
(`ml_prob × 0.70 + ast_score × 100 × 0.30`); the production backend
uses the 75/100 formula in Section 1 instead. The notebook is kept for
the assignment's bonus task and as a place to sanity-check changes to
either component in isolation.

### 4.5 LLM agent (`03_Agents_and_Tools/agent_logic.ipynb`)

The agent uses the **DeepSeek** chat completions API in OpenAI-compatible
function-calling mode. The four tools above are registered as JSON
schemas; the model decides on its own which tool to call next and in
what order. A typical run looks like this:

1. The user prompt is a contract address plus the instruction to audit
   it.
2. The model emits a `tool_call` for `fetch_transactions`. We execute
   it locally and feed the result back as a `tool` message.
3. The model then calls `extract_graph_features`, then
   `predict_fraud_probability`, then `analyze_contract_code` — though
   the order is its choice, not hard-coded.
4. Once it has enough information, it emits a final assistant message
   containing a JSON object with the component scores (ML %, AST %), a
   composite risk, and a HIGH / MEDIUM / LOW verdict.

The notebook also contains a small test suite that runs the agent
against a handful of known fraud and known-safe addresses (SHIB, PEPE,
FLOKI, plus several confirmed rugs) so we can sanity-check both the
agent's planning behaviour and the underlying model's predictions in one
go. The agent is intentionally **not** in the web app's request path —
the web app uses a fixed, deterministic call order so audits are
reproducible and don't depend on LLM availability.

### 4.6 Web application (`04_Web_App/`)

`backend.py` is a small FastAPI service. It exposes one endpoint that
takes a contract address, calls the four tools in fixed order, applies
the `risk = clamp(ml_prob × 75 + ast_score × 100, 0, 100)` formula,
and returns one JSON document containing the score, the AST findings,
the graph features, a sample of transactions, and a verdict string.

The frontend (`index.html` + `app.js` + `styles.css`) is a single static
page. It shows the animated five-step pipeline while the request is in
flight, then renders the gauge, panels, and verdict. *Export PDF*
triggers a print-styled stylesheet; *Export JSON* dumps the raw
response.

`prescreen_candidates.py` is the out-of-sample harness described in the
next section.

---

## 5. Out-of-sample validation

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

## 6. What it catches well, what it does not

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

## 7. Known limitations

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

## 8. Files worth looking at

- [04_Web_App/backend.py](04_Web_App/backend.py) — FastAPI service, the canonical orchestration
- [04_Web_App/index.html](04_Web_App/index.html), [app.js](04_Web_App/app.js), [styles.css](04_Web_App/styles.css) — the frontend
- [04_Web_App/prescreen_candidates.py](04_Web_App/prescreen_candidates.py) — the Forta-based OOS validator
- [03_Agents_and_Tools/tools/](03_Agents_and_Tools/tools/) — the four tools
- [03_Agents_and_Tools/agent_logic.ipynb](03_Agents_and_Tools/agent_logic.ipynb) — the LLM-orchestrated variant
- [02_Model_Training/3_fraud_detection_modeling.ipynb](02_Model_Training/3_fraud_detection_modeling.ipynb) — model training
- [01_Data_Pipeline/2_processing_and_graph.ipynb](01_Data_Pipeline/2_processing_and_graph.ipynb) — feature engineering
