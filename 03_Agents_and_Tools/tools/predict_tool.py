import numpy as np
import joblib
from catboost import CatBoostClassifier
from pathlib import Path

# Workspace root is two levels above this file (tools/ -> 03_Agents_and_Tools/ -> root)
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

FEATURE_ORDER = [
    "max_centrality",
    "avg_clustering",
    "unique_wallets",
    "value_volatility",
    "tx_count",
]


def predict_fraud_probability(features: dict) -> dict:
    """Tool 3 (pre-trained model): Load CatBoost model and calculate fraud probability."""
    try:
        scaler = joblib.load(WORKSPACE_ROOT / "02_Model_Training" / "exported_models" / "scaler.joblib")
        model = CatBoostClassifier()
        model.load_model(str(WORKSPACE_ROOT / "02_Model_Training" / "exported_models" / "rugpull_detector.cbm"))

        X = np.array([[features[f] for f in FEATURE_ORDER]])
        X_scaled = scaler.transform(X)

        prob = float(model.predict_proba(X_scaled)[:, 1][0]) * 100
        return {
            "ml_probability": round(prob, 2),
            "status": "success",
        }
    except Exception as e:
        return {"ml_probability": 50.0, "status": "error", "error": str(e)}
