# Task Distribution

Deepnote for collaboration  
Free open-source hosted LLMs? Have a look here: [**https://openrouter.ai/openrouter/free**](https://openrouter.ai/openrouter/free) 

| Name | Student ID | Role |
| :---- | :---- | :---- |
| WANG YINGQI | 23050522 | Construct a fund flow network and calculate graph theory features (such as node degree and centrality) to transform complex transfer paths into numerical features that can be read by the model. |
| LIM QIAN HUI | 22091617 | *(2ppl, pic of task 4 needs to help do this)* Responsible for building highly sensitive binary classification models; using Gradient Boosting algorithms (CatBoost/Gboost) to focus on optimizing Recall; calculating ROC-AUC curves. |
| QUEH QIAN YU | 22112617 | Use the Etherscan/BscScan RPC API to extract transaction hashes and wallet distribution; responsible for Pandas data cleaning and Ground Truth labeling (fraud vs. legitimate). |
| WEE DUN YING | 23005029 | Responsible for writing the AST Parser to scan for vulnerability patterns in the Solidity source code; and finally integrating the AST analysis results with the model predictions from Task 3\. |

# Submission

Mini **Markdown** Report (to Submit)  
Live Demo (presentation)

# Logic

In the contemporary Decentralized Finance (DeFi) landscape, systemic asymmetry and malicious actors pose a profound threat to market stability. This project addresses the critical issue of "rug pulls"—schemes where developers engineer artificial liquidity before abruptly draining pools—by establishing a Meme-Coin Early Warning System. From the perspective of a blockchain architect, this system mitigates the systemic risk faced by liquidity providers by shifting the forensic paradigm from post-mortem analysis to proactive threat detection. By identifying the "statistical footprints" of fraud within immutable ledgers, we provide a definitive solution to the information gap that currently leaves investors vulnerable.  
Traditional smart contract auditing is often insufficient as it relies on static execution-based testing that may fail to account for the dynamic, historical behaviors of the deployer. Our "Agentic On-Chain Forensics" approach offers a competitive advantage by specifically addressing the inherent data imbalance of fraud detection—where fraudulent events are rare but catastrophic. By integrating autonomous agent orchestration with a pre-trained forensic model, the system identifies malicious patterns in real-time, offering a level of security that manual reviews cannot achieve.

| Phase | Objective |
| :---- | :---- |
| Data training | Train a model on historical fraud patterns and network metrics |
| Agent automation | Establish a modular orchestration center to autonomously poll APIs and coordinate security tools |
| Web interface | Deliver a front-end utility for user input and the presentation of unified, weighted risk assessments |

## Model Training

Recall optimization: The architectural rationale is clear, the cost of a False Negative (missing a rug pull) far outweighs the cost of a False Positive (a false alarm). We must ensure that the maximum number of fraudulent contracts are flagged to prevent financial catastrophe. 

Our approach utilizes a "Gradient Boosting" methodology (CatBoost/GBoost) to learn the complex statistical relationships between the graph-theory features and known fraud events. Once trained, this model is stored on a server as a "pre-trained static model file," waiting to be called by the Agent. To validate the system’s ability to distinguish between normal and fraudulent contracts, we mandate the generation of a technical whitepaper detailing the Area Under the Receiver Operating Characteristic Curve (ROC-AUC). This ensures our forensic expert model meets the highest standards of scientific rigor before being integrated into the autonomous workflow. 

## Agent Workflow

1. **Address Submission:** A user submits a smart contract address via the web interface.  
2. **Autonomous Polling:** The Agent calls RPC APIs to fetch real-time transaction records and source code.  
3. **Feature Transformation:** The Agent utilizes NetworkX to convert raw data into network graph metrics.  
4. **Static Analysis:** The Agent executes the AST parser to flag vulnerability patterns and control flow anomalies.  
5. **Inference:** The processed features are fed into the pre-trained CatBoost model to calculate a fraud probability.  
6. **Weighted Synthesis:** The Agent combines the ML probability (e.g., 92%) and the AST findings into a single, unified "Risk Score by Weight System" report.

According to the development process, you need to prepare the following four tools for the Agent:

- Data Fetching Function (based on MCP): Input an address and automatically retrieve the original transaction records from the blockchain.  
- Feature Transformation Function (based on NetworkX): Convert the retrieved raw records into mathematical features such as degree centrality that the model can understand.  
- Prediction Function (based on a trained model): Allow the Agent to read the static model file you trained in the first step and calculate the fraud probability based on the features.  
- Code Analysis Function (based on AST): Automatically scan the contract source code to find hidden malicious logic such as "minting".

