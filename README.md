# 🛡️ IMDA Agentic Governance
### Agentic ETL Architect — Secure RAG Pipeline for Singapore SME Context

[![IMDA 2026](https://img.shields.io/badge/IMDA-2026%20AI%20Governance-blue)](https://aiverifyfoundation.sg)
[![PDPA](https://img.shields.io/badge/PDPA-Singapore%20Compliant-green)](https://www.pdpc.gov.sg)
[![BigQuery](https://img.shields.io/badge/Google%20BigQuery-asia--southeast1-orange)](https://cloud.google.com/bigquery)
[![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-purple)](https://ai.google.dev)
[![Status](https://img.shields.io/badge/Status-Work%20In%20Progress-yellow)](https://github.com/aiknowlah/imda-agentic-governance)

---

## ⚠️ Important Notice to All Readers

> ### This repository is a deliberate, staged publication.
>
> This is **not** an abandoned or incomplete project.
>
> It has been intentionally published at this stage as a **live build journal** —
> a transparent record of a governance-first AI development approach.
>
> The gaps identified in this project (documented fully in
> [`docs/AIVerify_Gap_Analysis.docx`](docs/AIVerify_Gap_Analysis.docx))
> were **discovered through a structured self-assessment** against the official
> **IMDA AI Verify Testing Framework (2025 Edition)** covering all 11 governance principles.
>
> Identifying and documenting gaps honestly — before claiming compliance —
> is itself a governance best practice. This is precisely what the AI Verify
> framework expects organisations to do.
>
> **The next release (`v1.0-compliant`) will close every identified gap with:**
> - Formal governance documents (System Card, Materiality Assessment, Incident Response Plan)
> - A Python test suite generating technical compliance evidence
> - Project Moonshot red-team results
> - A completed AI Verify Governance Report
>
> *Readers are encouraged to review the Gap Analysis document to understand
> exactly what has been built, what remains, and why.*

---

## 📌 Build Progress

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Data Governance & Ingestion (BigQuery + Gemini Embeddings) | ✅ Complete |
| Phase 2 | Agentic RBAC Retrieval (LangGraph Pipeline) | ✅ Complete |
| Phase 3 | Ethics & Governance Layer (HITL + Audit Logs) | ✅ Complete |
| Phase 4 | AI Verify Evidence Package & Formal Governance Report | 🔜 In Progress |

---

## 🎯 What This Project Does

This project builds an **Agentic ETL Architect** — a secure, role-based, AI-powered
data retrieval system that demonstrates responsible AI governance in practice.

A user queries employee data using natural language. The system:
1. **Validates** their role against a strict RBAC policy
2. **Embeds** their query using Google Gemini (`gemini-embedding-001`)
3. **Retrieves** the top 5 most semantically relevant records from BigQuery
4. **Enforces** field-level access control — stripping any data the role cannot see
5. **Pauses** for human approval if sensitive fields (NRIC, ethnicity, medical info) are detected
6. **Logs** every decision permanently to a tamper-evident BigQuery audit table

---

## 🏗️ System Architecture

```
User Query + Role
       │
       ▼
┌─────────────────────┐
│  validate_role      │  ◄── Safety Gate: unknown roles denied immediately
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  embed_query        │  ◄── Gemini gemini-embedding-001 (3072 dimensions)
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  retrieve           │  ◄── Cosine similarity search → TOP_K=5 records
└────────┬────────────┘       (BigQuery: secure-rag-sg.secure_rag)
         │
         ▼
┌─────────────────────┐
│  enforce_rbac       │  ◄── Strip fields not permitted for role
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  human_review       │  ◄── HITL Gate: pauses if sensitive fields detected
└────────┬────────────┘       Human must approve or reject
         │
         ▼
┌─────────────────────┐
│  output             │  ◄── Display results + write to audit_log (BigQuery)
└─────────────────────┘
```

---

## 🔐 Role-Based Access Control (RBAC)

| Role | Permitted Fields |
|------|-----------------|
| `General_Staff` | name, employment |
| `HR_Admin` | name, employment, nric, ethnicity |
| `Finance_Lead` | name, employment, financial_info |
| `Medical_Lead` | name, employment, medical_info |

**Sensitive fields** (trigger HITL gate): `nric`, `ethnicity`, `medical_info`, `financial_info`, `criminal_record`

---

## ☁️ Google Cloud Infrastructure

| Component | Detail |
|-----------|--------|
| GCP Project | `secure-rag-sg` |
| Region | `asia-southeast1` (Singapore — PDPA data residency) |
| BigQuery Dataset | `secure_rag` |
| Tables | `employee_data`, `employee_embeddings`, `audit_log` |
| AI Model | `gemini-2.5-flash` (generation) + `gemini-embedding-001` (embeddings) |

---

## 🧱 Tech Stack

```
Python 3.11+
├── google-genai          # Gemini API (embeddings + generation)
├── google-cloud-bigquery # BigQuery client
├── langgraph             # Agentic pipeline (StateGraph)
├── langchain             # AI agent framework
├── pandas                # Data ingestion
├── numpy                 # Cosine similarity
└── python-dotenv         # Secrets management
```

---

## 📁 Repository Structure

```
imda-agentic-governance/
├── README.md                          # This file
├── requirements.txt                   # Pinned Python dependencies
├── .gitignore                         # Protects .env and secrets
│
├── src/
│   └── ingestion/
│       ├── processor.py               # Phase 1: Data ingestion + Gemini embeddings
│       └── main.py                    # Phase 2 & 3: Agent pipeline (RBAC + HITL)
│
├── data/
│   └── raw/
│       └── f_data.xlsx                # Source employee data (100 records)
│
├── docs/
│   ├── Session_Progress_Report_8Mar2026.docx   # Full build log — Phases 1–3
│   └── AIVerify_Gap_Analysis.docx              # AI Verify 11-principle gap map
│
└── tests/                             # 🔜 Phase 4: Python test suite (coming)
    └── .gitkeep
```

---

## 🇸🇬 IMDA 2026 AI Governance Alignment

This project is designed against the
[IMDA 2026 Model AI Governance Framework for Agentic AI](https://aiverifyfoundation.sg)
and the [AI Verify Testing Framework (2025 Edition)](https://aiverifyfoundation.sg).

| IMDA Requirement | Implementation |
|-----------------|----------------|
| Bounded Autonomy | LangGraph StateGraph — agent cannot act outside defined nodes |
| Least-Privilege Data Access | RBAC strips all fields not explicitly permitted per role |
| Meaningful Human Control | HITL gate pauses pipeline; human must approve sensitive data release |
| Transparency & Auditability | Every query logged to BigQuery `audit_log` with full decision trail |
| Data Residency (PDPA) | All data stored in `asia-southeast1` Singapore region |

---

## 📋 AI Verify Gap Analysis

A full gap analysis against all 11 AI Verify principles has been completed.
See [`docs/AIVerify_Gap_Analysis.docx`](docs/AIVerify_Gap_Analysis.docx) for the detailed report.

**Current readiness summary:**

| Principle | Readiness |
|-----------|-----------|
| 1. Transparency | Medium |
| 2. Explainability | High |
| 3. Reproducibility | Low |
| 4. Safety | Low |
| 5. Security | Low |
| 6. Robustness | Low |
| 7. Fairness | Low |
| 8. Data Governance | **High** |
| 9. Accountability | Low |
| 10. Human Agency & Oversight | **High** |
| 11. Inclusive Growth | Low |

The `v1.0-compliant` release will address all gaps identified.

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.11+
- Google Cloud account with BigQuery and Vertex AI APIs enabled
- Google AI Studio API key ([get one here](https://aistudio.google.com))
- `gcloud` CLI installed and authenticated

### Installation

```bash
# Clone the repository
git clone https://github.com/aiknowlah/imda-agentic-governance.git
cd imda-agentic-governance

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Create .env file (never commit this)
echo GOOGLE_API_KEY=your_key_here > .env
```

### Running the Pipeline

```bash
# Step 1: Ingest data into BigQuery
python src/ingestion/processor.py

# Step 2: Run the agentic pipeline
python src/ingestion/main.py
```

---

## 📄 Documentation

| Document | Description |
|----------|-------------|
| [Session Progress Report](docs/Session_Progress_Report_8Mar2026.docx) | Detailed build log of all work completed in Phases 1–3 |
| [AI Verify Gap Analysis](docs/AIVerify_Gap_Analysis.docx) | Full 11-principle gap map with prioritised action plan |

---

## 🗺️ Roadmap to `v1.0-compliant`

- [ ] System Card / Model Card
- [ ] Materiality Assessment
- [ ] Incident Response Plan
- [ ] Acceptable Use Policy
- [ ] Python test suite (7 test scripts)
- [ ] Project Moonshot red-team results
- [ ] Formal AI Verify Governance Report

---

## 👤 Author

**aiknowlah**
Agentic ETL Architect | Data Governance | AI Ethics
Singapore 🇸🇬

Built as part of a professional development roadmap aligned to the
**IMDA 2026 Model AI Governance Framework** and **WSQ ICT Skills Framework**
(Data Governance and AI System Design tracks).

---

## 📜 Licence

This project is for educational and portfolio purposes.
All employee data used is synthetic and does not represent real individuals.

---

*"Governance is not a gate at the end of the pipeline. It is every node in the graph."*
