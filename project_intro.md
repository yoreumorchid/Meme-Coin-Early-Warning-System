# Meme-Coin Early Warning System: Agentic On-Chain Forensics 

# Background 

Decentralized Finance (DeFi) is rife with asymmetric information and malicious actors. Rug pulls involve artificially inflating liquidity before developers abruptly withdraw funds. 

# Overview

A forensic data science study applying machine learning to immutable blockchain ledgers. An **auditing agent** will actively identify statistical footprints of malicious smart contracts before liquidity is drained. 

# Objective 

Construct a highly sensitive binary classifier trained on on-chain heuristics. The student must deploy an agent that utilizes MCP to autonomously poll blockchain endpoints and **optimize for Recall in fraud detection**. 

# Dataset 

Programmatic extraction of transaction hashes and wallet distributions via the Etherscan or BscScan RPC APIs. 

# Main Components

Pandas for massive tabular data wrangling, NetworkX to track wallet funding graphs, and Gradient Boosting algorithms. 

# Deliverables

A web utility providing an audited Risk Score for any inputted smart contract address. A whitepaper detailing the Area Under the Receiver Operating Characteristic Curve (ROC-AUC). 

# Bonus/Extra Components

Integrate an Abstract Syntax Tree (AST) parser to statically analyze uncompiled Solidity code. The auditing agent must autonomously flag known vulnerability patterns or hidden mint functions.

\-\> The auditing agent must be able to:  
1\. utilizes MCP to autonomously poll blockchain endpoints and optimize for Recall in fraud detection  
2\.  autonomously flag known vulnerability patterns or hidden mint functions

Input: Smart contract address  
Output: A audited risk score and a whitepaper detailing the Area Under the Receiver Operating Characteristic Curve (ROC-AUC)