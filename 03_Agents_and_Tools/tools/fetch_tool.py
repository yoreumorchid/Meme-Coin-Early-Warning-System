import os
import requests
from pathlib import Path
from dotenv import load_dotenv

# Load .env from workspace root (two levels above this file)
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def fetch_transactions(address: str, chain_id: str = "1") -> dict:
    """Tool 1 (MCP-style): Fetch ERC-20 token transfer records from Etherscan."""
    api_key = os.environ.get("ETHERSCAN_API_KEY", "")
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": chain_id,
        "module": "account",
        "action": "tokentx",
        "contractaddress": address,
        "page": 1,
        "offset": 1000,
        "sort": "asc",
        "apikey": api_key,
    }
    try:
        r = requests.get(url, params=params, timeout=15)
        data = r.json()
        if data.get("status") == "1" and data.get("result"):
            return {
                "success": True,
                "transactions": data["result"],
                "count": len(data["result"]),
            }
        return {
            "success": False,
            "transactions": [],
            "count": 0,
            "error": data.get("message", "No data returned"),
        }
    except Exception as e:
        return {"success": False, "transactions": [], "count": 0, "error": str(e)}
