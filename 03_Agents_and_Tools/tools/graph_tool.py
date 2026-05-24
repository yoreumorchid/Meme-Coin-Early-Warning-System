import pandas as pd
import networkx as nx


def extract_graph_features(transactions: list) -> dict:
    """Tool 2 (NetworkX): Convert raw transaction list into graph-theory features for ML."""
    if not transactions:
        return {"error": "No transactions provided"}

    df = pd.DataFrame(transactions)
    df["value"] = df["value"].astype(float)

    G = nx.from_pandas_edgelist(
        df, "from", "to", edge_attr="value", create_using=nx.DiGraph()
    )

    centrality = nx.degree_centrality(G)
    max_cent = max(centrality.values()) if centrality else 0
    cluster = nx.average_clustering(G.to_undirected())

    return {
        "max_centrality": max_cent,
        "avg_clustering": cluster,
        "unique_wallets": G.number_of_nodes(),
        "value_volatility": float(df["value"].std()) if len(df) > 1 else 0.0,
        "tx_count": len(df),
    }
