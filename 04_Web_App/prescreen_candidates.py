"""
Pre-screening script for live demo.
Fetches Forta Network's labelled-datasets malicious_smart_contracts.csv,
filters to confirmed scam TOKEN CONTRACTS (notes == 'phish-hack'),
samples some, and runs them through the full audit pipeline.
"""
import sys
import csv
import io
import time
import random
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "03_Agents_and_Tools" / "tools"))

from fetch_tool import fetch_transactions
from graph_tool import extract_graph_features
from predict_tool import predict_fraud_probability
from ast_tool import analyze_contract_code

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BLACKLIST_URL = (
    "https://raw.githubusercontent.com/forta-network/labelled-datasets/"
    "main/labels/1/malicious_smart_contracts.csv"
)
SAMPLE_SIZE   = 25
RANDOM_SEED   = None   # set to int for reproducibility

# ---------------------------------------------------------------------------
# Skip anything in our training set
# ---------------------------------------------------------------------------
RAW_DIR = ROOT / "01_Data_Pipeline" / "raw_data"
TRAINING_SET = set()
if RAW_DIR.exists():
    for f in RAW_DIR.glob("*.csv"):
        for p in f.stem.split("_"):
            if p.startswith("0x") and len(p) == 42:
                TRAINING_SET.add(p.lower())
print(f"Loaded {len(TRAINING_SET)} training-set addresses (will skip)\n")

# ---------------------------------------------------------------------------
# Download + filter Forta blacklist to scam TOKEN CONTRACTS only
# ---------------------------------------------------------------------------
print("Downloading Forta Network malicious_smart_contracts.csv ...")
with urllib.request.urlopen(BLACKLIST_URL, timeout=60) as resp:
    text = resp.read().decode("utf-8", errors="replace")

reader = csv.DictReader(io.StringIO(text))
all_rows = list(reader)
print(f"  -> {len(all_rows)} total labelled malicious contracts")

# Forta CSV is mis-aligned: the "phish-hack" / "exploit" / "heist" label
# actually lands in the LAST column (contract_creator_etherscan_label),
# while the documented `notes` column is usually empty. Check both.
def _label(row):
    for k in ("notes", "contract_creator_etherscan_label"):
        v = (row.get(k) or "").strip().lower()
        if v:
            return v
    return ""

# Keep only fake-token / phishing contracts (these are ERC-20-like contracts
# masquerading as real tokens). Skip exploiter wallets ('exploit', 'heist').
token_rows = [
    r for r in all_rows
    if _label(r) == "phish-hack"
    and r.get("contract_address", "").lower() not in TRAINING_SET
]
print(f"  -> {len(token_rows)} fake-token contracts (label=phish-hack)\n")

if RANDOM_SEED is not None:
    random.seed(RANDOM_SEED)
random.shuffle(token_rows)
CANDIDATES = token_rows[:SAMPLE_SIZE]
print(f"Sampling {len(CANDIDATES)} candidates to audit\n")


def audit(address: str) -> dict:
    fetched = fetch_transactions(address, chain_id="1")
    if not fetched.get("success"):
        return {"status": "fetch_failed", "error": fetched.get("error")}
    txs = fetched.get("transactions", [])
    if not txs:
        return {"status": "no_transactions"}
    graph = extract_graph_features(txs)
    if "error" in graph:
        return {"status": "graph_failed", "error": graph["error"]}
    pred = predict_fraud_probability(graph)
    ast = analyze_contract_code(address)
    ml = float(pred.get("ml_probability", 0)) / 100.0
    ast_score = float(ast.get("ast_risk_score", 0))
    risk = max(0, min(100, round(ml * 75 + ast_score * 100)))
    return {
        "status":   "ok",
        "ml_pct":   round(ml * 100, 1),
        "ast_pct":  round(ast_score * 100, 1),
        "risk":     risk,
        "level":    "HIGH" if risk >= 70 else "MEDIUM" if risk >= 40 else "LOW",
        "tx_count": graph.get("tx_count"),
        "wallets":  graph.get("unique_wallets"),
    }


def main():
    print(f"{'Address':<44} {'Tag':<28} {'Status':<14} {'ML':>7} {'AST':>7} {'Risk':>5} {'Level':<6} {'#tx':>6}")
    print("-" * 130)
    keepers = []
    for row in CANDIDATES:
        addr = row["contract_address"]
        tag  = (row.get("contract_tag") or "").strip()[:26]
        try:
            r = audit(addr)
        except Exception as e:
            print(f"{addr:<44} {tag:<28} ERROR        {e}")
            time.sleep(1.2)
            continue
        if r["status"] != "ok":
            print(f"{addr:<44} {tag:<28} {r['status']:<14}")
            time.sleep(1.2)
            continue
        print(
            f"{addr:<44} {tag:<28} {r['status']:<14} "
            f"{r['ml_pct']:>6.1f}% {r['ast_pct']:>6.1f}% {r['risk']:>5}  "
            f"{r['level']:<6} {r['tx_count']:>6}"
        )
        if r["level"] == "HIGH":
            keepers.append((addr, tag, r))
        time.sleep(1.2)

    print("\n" + "=" * 80)
    print(f"DEMO-READY HIGH RISK CANDIDATES ({len(keepers)})")
    print("=" * 80)
    for addr, tag, r in keepers:
        print(f"  {addr}  [{tag}]  risk={r['risk']}  ml={r['ml_pct']}%  tx={r['tx_count']}")
    if not keepers:
        print("  None this round. Re-run for a fresh random sample.")


if __name__ == "__main__":
    main()