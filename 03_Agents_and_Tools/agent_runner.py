"""
Agent runner — extracted from agent_logic.ipynb so the FastAPI backend
can invoke the DeepSeek function-calling agent without duplicating logic.

Exposes:
    run_agent(address, chain_id="1", verbose=False) -> dict
        {
            "final_response": "<LLM final assistant message (JSON string)>",
            "tool_results":   { "<tool_name>": <raw tool output>, ... }
        }
"""

from __future__ import annotations

import os
import sys
import json
import time
import logging
from pathlib import Path

from openai import OpenAI, RateLimitError
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from tools.fetch_tool import fetch_transactions          # noqa: E402
from tools.graph_tool import extract_graph_features      # noqa: E402
from tools.predict_tool import predict_fraud_probability # noqa: E402
from tools.ast_tool import analyze_contract_code         # noqa: E402

log = logging.getLogger("ews.agent")

# ---------------------------------------------------------------------------
# DeepSeek client (lazy — only built on first call so import never fails)
# ---------------------------------------------------------------------------
load_dotenv()
MODEL = "deepseek-chat"
_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not api_key:
            raise EnvironmentError(
                "DEEPSEEK_API_KEY not set. Add it to the .env file in the workspace root."
            )
        _client = OpenAI(base_url="https://api.deepseek.com", api_key=api_key)
    return _client


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
TOOL_FUNCTIONS = {
    "fetch_transactions":        fetch_transactions,
    "extract_graph_features":    extract_graph_features,
    "predict_fraud_probability": predict_fraud_probability,
    "analyze_contract_code":     analyze_contract_code,
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_transactions",
            "description": (
                "Fetch ERC-20 token transfer records for a contract address "
                "from the Etherscan blockchain API."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address":  {"type": "string", "description": "The ERC-20 contract address"},
                    "chain_id": {"type": "string", "description": "'1' = Ethereum, '56' = BSC", "default": "1"},
                },
                "required": ["address"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_graph_features",
            "description": (
                "Convert a raw transaction list into NetworkX graph metrics "
                "(max_centrality, avg_clustering, unique_wallets, value_volatility, tx_count)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "transactions": {
                        "type": "array",
                        "description": "List of transaction dicts from fetch_transactions",
                    }
                },
                "required": ["transactions"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "predict_fraud_probability",
            "description": (
                "Load the pre-trained CatBoost model and calculate a fraud probability "
                "(0-100%) from the five graph features."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "features": {
                        "type": "object",
                        "description": "Dict with the five graph features",
                        "properties": {
                            "max_centrality":   {"type": "number"},
                            "avg_clustering":   {"type": "number"},
                            "unique_wallets":   {"type": "number"},
                            "value_volatility": {"type": "number"},
                            "tx_count":         {"type": "number"},
                        },
                    }
                },
                "required": ["features"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_contract_code",
            "description": (
                "Fetch the Solidity source code from Etherscan and scan it for "
                "vulnerability patterns: hidden mints, owner backdoors, blacklists, "
                "trading-pause functions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "The contract address"},
                },
                "required": ["address"],
            },
        },
    },
]


SYSTEM_PROMPT = """You are a blockchain forensics agent that detects meme coin rug pulls.

Workflow - call all four tools in order, then produce a final report:
1. fetch_transactions(address)          -> get on-chain records
2. extract_graph_features(transactions) -> compute graph metrics
3. predict_fraud_probability(features)  -> get ML fraud score (0-100%)
4. analyze_contract_code(address)       -> get AST risk score (0.0-1.0) + findings

After all tools complete, output a structured JSON report:
{
  "contract_address": "...",
  "ml_score": "<value>%",
  "ast_score": "<value>%",
  "final_risk_score": "<value>%",
  "risk_level": "HIGH RISK | MEDIUM RISK | LOW RISK",
  "ast_findings": [...],
  "explanation": "..."
}

Formula: final_score = (ml_score * 0.70) + (ast_score * 100 * 0.30)

Risk levels (balanced Recall-Precision):
  >= 70 -> HIGH RISK  |  >= 50 -> MEDIUM RISK  |  < 50 -> LOW RISK

Escalation rules - apply in order:
1. HIGH RISK if final_score >= 70 AND ml_score >= 65 (both signals must be elevated)
2. HIGH RISK if ml_score >= 80 regardless of AST (strong ML signal alone is sufficient)
3. MEDIUM RISK if final_score >= 50
4. LOW RISK otherwise
Do NOT assign HIGH RISK based on AST patterns alone when ml_score < 50% - many
legitimate tokens share ownership/mint/pause patterns with rug pulls.
"""


def run_agent(address: str, chain_id: str = "1", verbose: bool = False) -> dict:
    """Run the DeepSeek function-calling agent on a contract address."""
    client = _get_client()

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",
         "content": f"Analyze this contract for rug pull risk: {address} (chain_id={chain_id})"},
    ]

    tool_results: dict = {}

    for iteration in range(12):  # safety cap
        for attempt in range(3):
            try:
                response = client.chat.completions.create(
                    model=MODEL,
                    messages=messages,
                    tools=TOOLS,
                    tool_choice="auto",
                )
                break
            except RateLimitError as e:
                if attempt == 2:
                    raise
                wait = 35
                try:
                    wait = e.response.json()["error"]["metadata"]["retry_after_seconds"] + 5
                except Exception:
                    pass
                log.warning("Rate limit hit, sleeping %.0fs before retry %d/3", wait, attempt + 2)
                time.sleep(wait)

        choice = response.choices[0]
        msg    = choice.message

        if verbose:
            log.info("[Round %d] finish_reason=%s", iteration + 1, choice.finish_reason)

        # No tool calls -> agent is done, return its final message
        if not msg.tool_calls:
            return {"final_response": msg.content or "", "tool_results": tool_results}

        messages.append(msg)

        for tc in msg.tool_calls:
            fn_name = tc.function.name
            try:
                fn_args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                fn_args = {}

            if verbose:
                log.info("  -> %s(%s)", fn_name, list(fn_args.keys()))

            # Always re-use the FULL stored tx list for graph extraction
            if fn_name == "extract_graph_features" and "fetch_transactions" in tool_results:
                full_txns = tool_results["fetch_transactions"].get("transactions", [])
                result = TOOL_FUNCTIONS["extract_graph_features"](transactions=full_txns)
            else:
                try:
                    result = TOOL_FUNCTIONS[fn_name](**fn_args)
                except Exception as e:
                    result = {"success": False, "error": f"{type(e).__name__}: {e}"}

            tool_results[fn_name] = result

            # Truncate large fetch results before feeding back to the LLM
            result_str = json.dumps(result, default=str)
            if len(result_str) > 4000 and fn_name == "fetch_transactions":
                result_str = json.dumps({
                    "success": result.get("success"),
                    "count":   result.get("count"),
                    "transactions": result.get("transactions", [])[:5],
                    "note": f"Truncated - showing 5 of {result.get('count')} transactions",
                })

            messages.append({
                "role":         "tool",
                "tool_call_id": tc.id,
                "content":      result_str,
            })

    return {"final_response": "Max iterations reached.", "tool_results": tool_results}


# ---------------------------------------------------------------------------
# Follow-up chat — answer questions about an existing audit report.
# Plain chat, no tool calls. The report JSON is injected as context.
# ---------------------------------------------------------------------------
CHAT_SYSTEM_PROMPT = """You are a blockchain forensics analyst answering follow-up questions
about a rug-pull audit report that was just produced for a specific ERC-20 contract.

The full audit report JSON is provided in the next system message. Ground every answer in
those numbers — risk score, ML probability, AST findings, graph features, recent transactions.
If the user asks about something not in the report, say so plainly instead of guessing.

Keep answers concise (2-5 sentences). Use plain English suitable for a non-technical liquidity
provider, but include the specific numbers when relevant (e.g. "max centrality of 0.94 means
one wallet touched ~94% of transfers"). Never give financial advice — frame conclusions as
risk signals, not buy/sell recommendations.
"""


def chat_about_report(question: str, report: dict, history: list[dict] | None = None) -> str:
    """Single-turn (with history) chat about an audit report. No tool calls."""
    client = _get_client()
    history = history or []

    messages = [
        {"role": "system", "content": CHAT_SYSTEM_PROMPT},
        {"role": "system", "content": "AUDIT REPORT JSON:\n" + json.dumps(report, default=str)},
    ]
    for m in history[-8:]:  # cap context
        role = m.get("role")
        content = m.get("content", "")
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": question})

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=0.3,
    )
    return response.choices[0].message.content or ""
