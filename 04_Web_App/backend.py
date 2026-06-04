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
import re
import json
import time
import logging
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Make agent_runner + tools importable from 03_Agents_and_Tools
# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "03_Agents_and_Tools"))

from agent_runner import run_agent, chat_about_report     # noqa: E402

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
CHAIN_IDS = {"eth": "1"}


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------
class AuditRequest(BaseModel):
    address: str = Field(..., pattern=r"^0x[0-9a-fA-F]{40}$")
    chain: str = Field(default="eth")


class ChatMessage(BaseModel):
    role: str = Field(..., pattern=r"^(user|assistant)$")
    content: str


class ChatRequest(BaseModel):
    question: str
    report: dict
    history: list[ChatMessage] = Field(default_factory=list)


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
    if not g:
        return {"Status": "Graph features unavailable (agent did not call extract_graph_features)"}
    if "error" in g:
        return {"Status": g["error"]}
    def _r(v):
        try:
            return round(float(v), 4)
        except (TypeError, ValueError):
            return v
    return {
        "Unique wallets":        g.get("unique_wallets", "—"),
        "Transactions":          g.get("tx_count", "—"),
        "Max degree centrality": _r(g.get("max_centrality", 0)),
        "Avg clustering coef.":  _r(g.get("avg_clustering", 0)),
        "Value volatility":      _r(g.get("value_volatility", 0)),
    }


def _weighted_score(ml_prob_0_1: float, ast_score_0_1: float) -> int:
    """ML probability is dominant (up to 75 pts), AST findings add up to 25 pts.

    Capping AST at 25 prevents established tokens with legitimate owner
    primitives (USDT, USDC, …) from being scored HIGH purely on static
    findings. A real rug needs BOTH a suspicious transfer graph and risky
    contract code to reach the HIGH band.
    """
    return max(0, min(100, round(ml_prob_0_1 * 75 + ast_score_0_1 * 25)))


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
            f"{ml_prob*100:.1f}% and no critical AST pattern triggered. "
            f"CAVEAT: this model is trained on secondary-market meme-coin rug pulls "
            f"(pump-then-dump patterns). It may MISS other failure modes such as "
            f"ICO/presale exit scams, low-activity dead tokens, or novel attack "
            f"vectors with sparse on-chain footprints. Not financial advice — "
            f"always DYOR and continue on-chain monitoring.")


# ---------------------------------------------------------------------------
# Agent-output parsing helpers
# ---------------------------------------------------------------------------
def _extract_json(text: str) -> dict:
    """Pull the first JSON object out of the LLM's final message.

    The agent is instructed to emit a JSON report but may wrap it in a
    ```json ... ``` fence or include surrounding prose. We try (a) the
    fenced block, then (b) the first balanced {...} we can find.
    """
    if not text:
        return {}

    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass

    # naive but works for the agent's report shape
    start = text.find("{")
    if start == -1:
        return {}
    depth = 0
    for i, ch in enumerate(text[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return {}
    return {}


def _coerce_pct(val) -> int | None:
    """Accept '84%', '84', 84, 84.0 -> 84 (clamped 0-100). Else None."""
    if val is None:
        return None
    try:
        if isinstance(val, str):
            val = val.strip().rstrip("%")
        f = float(val)
    except (TypeError, ValueError):
        return None
    return max(0, min(100, round(f)))


def _verdict_from_agent(
    risk_level: str,
    explanation: str,
    score: int,
    ml_prob: float,
    ast: list[dict],
) -> str:
    """Prefer the agent's natural-language explanation; fall back to template."""
    if explanation:
        prefix = risk_level if risk_level else _level_from_score(score)
        return f"{prefix} — {explanation}"
    return _verdict(score, ml_prob, ast)


def _level_from_score(score: int) -> str:
    if score >= 70:
        return "HIGH RISK"
    if score >= 50:
        return "MEDIUM RISK"
    return "LOW RISK"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "version": app.version}


@app.post("/api/audit")
def audit(req: AuditRequest):
    log.info("Audit request (agent): %s on %s", req.address, req.chain)
    chain_id = CHAIN_IDS.get(req.chain.lower(), "1")

    # ── Run the DeepSeek function-calling agent ──────────────────────────
    try:
        agent_out = run_agent(req.address, chain_id=chain_id, verbose=False)
    except EnvironmentError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        log.exception("Agent crashed")
        raise HTTPException(status_code=502, detail=f"Agent failure: {e}")

    tool_results = agent_out.get("tool_results", {}) or {}
    final_text   = agent_out.get("final_response", "") or ""

    # ── Surface upstream tool errors as clear HTTP responses ─────────────
    fetched = tool_results.get("fetch_transactions", {})
    if fetched and not fetched.get("success", True):
        err = (fetched.get("error") or "").lower()
        if "no transactions" in err or "no records" in err:
            raise HTTPException(
                status_code=404,
                detail=(
                    "No ERC-20 transactions found for this address on Ethereum "
                    "mainnet. The address may not be an ERC-20 token contract, "
                    "or it may not exist on this chain."
                ),
            )
        raise HTTPException(
            status_code=502,
            detail=f"Etherscan fetch failed: {fetched.get('error', 'unknown')}",
        )

    raw_txs    = fetched.get("transactions", []) if fetched else []
    graph_feat = tool_results.get("extract_graph_features", {}) or {}
    pred       = tool_results.get("predict_fraud_probability", {}) or {}
    ast_result = tool_results.get("analyze_contract_code", {}) or {}

    # ── Parse the agent's JSON report (it may be wrapped in ```json ... ```) ──
    parsed = _extract_json(final_text)

    # Risk score: prefer agent's final_risk_score, else recompute from components
    ml_prob   = float(pred.get("ml_probability", 50.0)) / 100.0   # 0-1
    ast_score = float(ast_result.get("ast_risk_score", 0.0))      # 0-1

    risk_score = _coerce_pct(parsed.get("final_risk_score"))
    if risk_score is None:
        risk_score = max(0, min(100, round(ml_prob * 75 + ast_score * 25)))

    ast_frontend = _ast_to_frontend(ast_result)
    risk_level   = (parsed.get("risk_level") or "").upper()
    explanation  = parsed.get("explanation") or ""

    verdict = _verdict_from_agent(risk_level, explanation, risk_score, ml_prob, ast_frontend)

    response = {
        "address":   req.address,
        "chain":     req.chain.lower(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "riskScore":     risk_score,
        "mlProbability": ml_prob,
        "ast":           ast_frontend,
        "graph":         _graph_to_frontend(graph_feat),
        "transactions":  _txs_to_frontend(raw_txs),
        "verdict":       verdict,
        "agent": {
            "risk_level":  risk_level or None,
            "explanation": explanation or None,
            "raw":         final_text,
        },
    }
    log.info("Audit complete (agent): score=%d  ml=%.3f  ast=%.2f  level=%s",
             risk_score, ml_prob, ast_score, risk_level or "n/a")
    return response


@app.post("/api/chat")
def chat(req: ChatRequest):
    """Follow-up Q&A about a given audit report (uses DeepSeek)."""
    try:
        history = [m.model_dump() for m in req.history]
        answer = chat_about_report(
            question=req.question,
            report=req.report,
            history=history,
        )
    except EnvironmentError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        log.exception("Chat failure")
        raise HTTPException(status_code=502, detail=f"Chat failure: {e}")
    return {"answer": answer}


# ---------------------------------------------------------------------------
# Static frontend — must be mounted LAST so /api/* routes win.
# ---------------------------------------------------------------------------
app.mount("/", StaticFiles(directory=str(HERE), html=True), name="frontend")
