
#  Security AI Analyzer

**Security AI Analyzer** is an MVP that demonstrates how AI agents can analyze cybersecurity incidents and generate actionable insights. The current focus is on the **core analysis pipeline**, which can later be extended to trigger additional workflows for mitigation, escalation, or automated response.

---

##  Project Structure
```
security-ai-analyzer/
├── server/        # FastAPI backend to host and serve the pipeline
├── client/        # Frontend UI to input incidents and view results
├── Agent/         # Core agent logic
│   └── tools/     # Modular analysis tools
├── data/          # Raw and processed incident data
├── common/        # Shared schemas
└── utilities/     # Shared utilities
```
---

##  High-Level Architecture

The system is built using a modular agent pipeline, structured as a graph-based reasoning workflow. This pipeline mimics human reasoning by parsing the raw input, analyzing it using domain knowledge + LLMs, and generating a clear report.

###  Orchestration Layer

The core class is `SecurityAnalysisPipeline`. It uses a `StateGraph` to orchestrate each subtask:

1. **Parsing:** Normalize and structure the raw JSON incident.
2. **Analysis:** Use LLM to evaluate threats and context.
3. **Reporting:** Summarize results into a clear, actionable format.

```text
[ Raw Incident Input ]
           │
           ▼
 ┌────────────────────────┐
 │  SecurityParseInput    │  → Parses and normalizes incident context
 └────────────────────────┘
           │
           ▼
 ┌────────────────────────┐
 │   SecurityAnalysis     │  → Uses LLM to assess and analyze the structured input
 └────────────────────────┘
           │
           ▼
 ┌────────────────────────┐
 │    SecurityReport      │  → Summarizes results into a readable report
 └────────────────────────┘
           │
           ▼
[ Final Output (Summary / Actionable Report) ]
```

---

##  Tools

The agent pipeline uses the following tools in a sequential, dependency-aware manner:

### `ParseIncidentContextTool`

**Use this tool FIRST.**

- **Input:** A raw incident in JSON format  
- **Output:** A structured context object describing the incident (assets, attack vector, scope)  
- **Purpose:** Prepares the input for all other downstream analysis tools.

---

### `IntrusionSetInstructionTool`

**Use this tool AFTER parsing the incident.**

- **Input:** Structured context of the incident  
- **Output:** A list of relevant intrusion set instructions  
- **Purpose:** Associates the context with known APT playbooks and operational goals.

---

### `CVEKnowledgeTool`

**Use this tool AFTER parsing the incident.**

- **Input:** Structured context of the incident  
- **Output:** A list of known CVEs (Common Vulnerabilities and Exposures)  
- **Purpose:** Identifies relevant vulnerabilities based on known weaknesses in the environment.

---

### `AttackPatternTool`

**Use this tool AFTER parsing the incident.**

- **Input:** Structured context of the incident  
- **Output:** A list of relevant MITRE ATT&CK patterns (TTPs)  
- **Purpose:** Links observed behaviors to standard adversarial tactics, techniques, and procedures.

---

##  Installation

To set up the environment, download dependencies, and create required folders, run:

```bash
./setup.sh
```

---

###  Environment Management with Pixi

This project uses [Pixi](https://pixi.sh) for isolated Python environments and task management.  
Install Pixi if you haven't:

```bash
curl -sSf https://install.pixi.sh | bash
```

---

##  CLI Commands

###  Parse & Normalize Incidents

Convert raw incidents into structured JSON objects under the `data/processed` directory:

```bash
pixi run parse
```

Uses internal schemas defined in the `common` module.

---

###  Create Embedding Dataset

Instead of using a vector DB like Chroma, we use `.pkl` files with metadata for simplicity.

```bash
pixi run ce
```

This command computes embeddings from processed incidents and stores them for fast retrieval.

---

### ✅ Run Tests

Runs lightweight tests (mocking the LLM) to verify each tool is functioning correctly.

```bash
pixi run test
```

---

##  Run the Application

To launch both the backend server and frontend client, run:

```bash
pixi run up
```

Then access the client interface at:

[http://127.0.0.1:7860/](http://127.0.0.1:7860/)

---

