"""
Meme-Coin Early Warning System — Backend API
--------------------------------------------
Wraps the 4 agent tools (fetch / graph / AST / predict) into a single
HTTP endpoint that the frontend calls. Also serves the static frontend
(index.html, app.js, styles.css) from the same port so there is no
CORS friction.

Run from the workspace root:
    uvicorn 04_Web_App.backend:app --reload --port 8000

…or from inside this folder:
    cd 04_Web_App
    uvicorn backend:app --reload --port 8000

Then open http://localhost:8000/
"""

from __future__ import annotations

import sys
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Make `tools` importable: workspace root + 03_Agents_and_Tools
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "03_Agents_and_Tools"))

from tools.fetch_tool import fetch_transactions          # noqa: E402
from tools.graph_tool import extract_graph_features      # noqa: E402
from tools.ast_tool import analyze_contract_code         # noqa: E402
from tools.predict_tool import predict_fraud_probability # noqa: E402

# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger("ews")

app = FastAPI(
    title="Meme-Coin Early Warning System",
    description="Agentic on-chain forensics — rug-pull risk scoring API",
    version="1.0.0",
)

# CORS is permissive in dev; tighten in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Chain id mapping used by Etherscan v2 API
CHAIN_IDS = {"eth": "1", "bsc": "56"}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class AuditRequest(BaseModel):
    address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    chain: str = Field(default="eth")


# ---------------------------------------------------------------------------
# Helpers — adapt tool outputs to the schema the frontend already expects.
# Frontend schema (see 04_Web_App/app.js header):
#   { address, chain, timestamp,
#     riskScore: 0-100, mlProbability: 0-1,
#     ast: [{severity, pattern, detail}],
#     graph: {label: value},
#     transactions: [{hash, from, to, value, time}],
#     verdict: str }
# ---------------------------------------------------------------------------
def _severity_for(score: float) -> str:
    if score >= 0.25:
        return "high"
    if score >= 0.15:
        return "med"
    return "low"


def _ast_to_frontend(ast_result: dict) -> list[dict]:
    """Convert ast_tool's findings into the {severity, pattern, detail} list."""
    findings = ast_result.get("findings", [])
    out = []
    for f in findings:
        target = f.get("function") or f.get("variable") or ""
        out.append({
            "severity": _severity_for(f.get("risk_score", 0.0)),
            "pattern": f["issue"] + (f" — {target}" if target else ""),
            "detail": _detail_for(f["issue"]),
        })
    # surface any plain explanations that don't have a corresponding finding
    if not out:
        for msg in ast_result.get("explanations", []):
            out.append({"severity": "low", "pattern": "Static analysis note", "detail": msg})
    # sort high → low
    rank = {"high": 3, "med": 2, "low": 1}
    out.sort(key=lambda x: rank.get(x["severity"], 0), reverse=True)
    return out


def _detail_for(issue: str) -> str:
    return {
        "Public Mint Function":      "Externally callable mint can inflate total supply.",
        "Dangerous Owner Privilege": "Owner can perform drain / liquidity-removal actions.",
        "Blacklist Mechanism":       "Owner can prevent specific wallets from selling.",
        "Trading Control Function":  "Owner can pause or disable trading at will.",
        "Unverified Contract":       "Contract source is not verified on Etherscan.",
    }.get(issue, "Suspicious pattern detected by static analysis.")


def _txs_to_frontend(raw_txs: list[dict], limit: int = 6) -> list[dict]:
    out = []
    now = time.time()
    for t in raw_txs[-limit:][::-1]:
        try:
            ts = int(t.get("timeStamp", 0))
            mins = max(1, int((now - ts) // 60))
            time_str = f"{mins} min ago" if mins < 90 else f"{mins // 60} h ago"
        except Exception:
            time_str = "—"
        try:
            decimals = int(t.get("tokenDecimal", 18))
            value = float(t.get("value", 0)) / (10 ** decimals)
        except Exception:
            value = 0.0
        out.append({
            "hash": t.get("hash", ""),
            "from": t.get("from", ""),
            "to":   t.get("to", ""),
            "value": f"{value:.4f}",
            "time": time_str,
        })
    return out


def _graph_to_frontend(g: dict) -> dict:
    """Pretty-label the graph features for the UI table."""
    if "error" in g:
        return {"Status": g["error"]}
    return {
        "Unique wallets":       g["unique_wallets"],
        "Transactions":         g["tx_count"],
        "Max degree centrality": round(g["max_centrality"], 4),
        "Avg clustering coef.":  round(g["avg_clustering"], 4),
        "Value volatility":      round(g["value_volatility"], 4),
    }


def _weighted_score(ml_prob_0_1: float, ast_score_0_1: float) -> int:
    """ML probability is dominant (75%), AST findings add up to 25 points."""
    return max(0, min(100, round(ml_prob_0_1 * 75 + ast_score_0_1 * 25 * 4)))


def _verdict(score: int, ml_prob: float, ast: list[dict]) -> str:
    high = sum(1 for f in ast if f["severity"] == "high")
    if score >= 70:
        return (f"HIGH RISK — Strong rug-pull signature. CatBoost reports "
                f"{ml_prob*100:.1f}% fraud probability and the AST scan flagged "
                f"{high} critical pattern(s). Recommend liquidity providers withdraw "
                f"and avoid new deposits.")
    if score >= 40:
        return (f"MEDIUM RISK — Mixed signals. Model probability "
                f"{ml_prob*100:.1f}%, contract carries owner-privileged operations. "
                f"Treat with caution and monitor on-chain activity.")
    return (f"LOW RISK — No strong fraud signature detected. Model probability "
            f"{ml_prob*100:.1f}% and no critical AST pattern triggered. Not financial "
            f"advice — continued monitoring is still recommended.")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/api/audit")
def audit(req: AuditRequest):
    log.info("Audit request: %s on %s", req.address, req.chain)
    chain_id = CHAIN_IDS.get(req.chain.lower(), "1")

    # 1) Fetch on-chain transactions
    fetched = fetch_transactions(req.address, chain_id=chain_id)
    if not fetched.get("success"):
        raise HTTPException(
            status_code=502,
            detail=f"Etherscan fetch failed: {fetched.get('error', 'unknown')}",
        )
    raw_txs = fetched["transactions"]

    # 2) Graph features
    graph_feat = extract_graph_features(raw_txs)
    if "error" in graph_feat:
        raise HTTPException(status_code=422, detail=graph_feat["error"])

    # 3) AST static analysis
    ast_result = analyze_contract_code(req.address)

    # 4) ML inference
    pred = predict_fraud_probability(graph_feat)
    if pred.get("status") != "success":
        log.warning("Predict tool error: %s", pred.get("error"))
    ml_prob = float(pred.get("ml_probability", 50.0)) / 100.0  # tool returns 0-100

    # 5) Weighted synthesis
    ast_score = float(ast_result.get("ast_risk_score", 0.0))   # 0-1
    risk_score = _weighted_score(ml_prob, ast_score)
    ast_frontend = _ast_to_frontend(ast_result)

    response = {
        "address":   req.address,
        "chain":     req.chain.lower(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "riskScore":     risk_score,
        "mlProbability": ml_prob,
        "ast":           ast_frontend,
        "graph":         _graph_to_frontend(graph_feat),
        "transactions":  _txs_to_frontend(raw_txs),
        "verdict":       _verdict(risk_score, ml_prob, ast_frontend),
    }
    log.info("Audit complete: score=%d  ml=%.3f  ast=%.2f  findings=%d",
             risk_score, ml_prob, ast_score, len(ast_frontend))
    return response


# ---------------------------------------------------------------------------
# Static frontend — must be mounted LAST so /api/* routes win.
# ---------------------------------------------------------------------------
app.mount("/", StaticFiles(directory=str(HERE), html=True), name="frontend")
