import json
import os
import re
import requests
from pathlib import Path
from dotenv import load_dotenv

# Load .env from workspace root (two levels above this file)
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def analyze_contract_code(address: str) -> dict:
    """Tool 4 (AST): Fetch Solidity source code and scan for rug pull vulnerability patterns."""
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    url = (
        f"https://api.etherscan.io/v2/api"
        f"?chainid=1&module=contract&action=getsourcecode"
        f"&address={address}&apikey={api_key}"
    )
    try:
        r = requests.get(url, timeout=15)
        data = r.json()
    except Exception as e:
        return {
            "ast_risk_score": 0.30,
            "findings": [],
            "explanations": [f"API call failed: {e}"],
        }

    if data.get("status") != "1" or not data.get("result"):
        return {
            "ast_risk_score": 0.30,
            "findings": [],
            "explanations": ["Contract not found on Etherscan."],
        }

    raw_source = data["result"][0].get("SourceCode", "")
    if not raw_source:
        return {
            "ast_risk_score": 0.30,
            "findings": [{"issue": "Unverified Contract", "risk_score": 0.30}],
            "explanations": ["Source code is not publicly verified — strong rug pull indicator."],
        }

    # Handle multi-file JSON source format
    source_code = raw_source
    if raw_source.startswith("{{"):
        try:
            source_dict = json.loads(raw_source[1:-1])
            source_code = "".join(
                f.get("content", "") for f in source_dict.get("sources", {}).values()
            )
        except Exception:
            pass

    findings = []

    # Public/External mint functions only.
    # Internal/private mint is the standard ERC-20 _mint pattern and is NOT suspicious.
    # Only flag functions that are externally callable without restriction.
    for m in re.finditer(
        r"function\s+(_?mint\w*)\s*\([^)]*\)([^{]{0,120})\{",
        source_code, re.IGNORECASE
    ):
        fn, modifiers = m.group(1), m.group(2).lower()
        if "internal" in modifiers or "private" in modifiers:
            continue  # standard ERC-20 _mint — not suspicious
        score = 0.35 if "onlyowner" not in modifiers else 0.20
        findings.append({"issue": "Public Mint Function", "function": fn, "risk_score": score})

    # Dangerous onlyOwner functions — only flag drain/liquidity actions, not routine setters
    drain_kw = ["withdraw", "drain", "removeliquidity", "recovertoken"]
    moderate_kw = ["blacklist", "pause", "disable", "lock"]
    for fn in re.findall(r"function\s+(\w+)\s*\([^)]*\)[^{]*onlyOwner", source_code, re.IGNORECASE):
        fn_lower = fn.lower()
        if any(kw in fn_lower for kw in drain_kw):
            findings.append({"issue": "Dangerous Owner Privilege", "function": fn, "risk_score": 0.25})
        elif any(kw in fn_lower for kw in moderate_kw):
            findings.append({"issue": "Dangerous Owner Privilege", "function": fn, "risk_score": 0.15})

    # Blacklist state variables
    for var in re.findall(r"mapping\s*\([^)]+\)\s+(?:public\s+)?(\w+)", source_code, re.IGNORECASE):
        if any(kw in var.lower() for kw in ["blacklist", "blocked", "banned"]):
            findings.append({"issue": "Blacklist Mechanism", "variable": var, "risk_score": 0.15})

    # Trading control functions
    for fn in re.findall(
        r"function\s+(pause\w*|disableTrading\w*|stopTrading\w*)\s*\(",
        source_code,
        re.IGNORECASE,
    ):
        findings.append({"issue": "Trading Control Function", "function": fn, "risk_score": 0.15})

    # Deduplicate
    seen, unique_findings = set(), []
    for f in findings:
        key = (f["issue"], f.get("function", f.get("variable", "")))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    ast_risk = min(sum(f["risk_score"] for f in unique_findings), 1.0) if unique_findings else 0.0

    explanations = list(
        {
            "Minting capability detected." if "Mint" in f["issue"]
            else "Owner has dangerous administrative privileges." if "Owner" in f["issue"]
            else "Blacklist or wallet restriction mechanism detected." if "Blacklist" in f["issue"]
            else "Trading control or pause function detected."
            for f in unique_findings
        }
    )

    return {
        "ast_risk_score": round(ast_risk, 2),
        "findings": unique_findings,
        "explanations": explanations,
    }
