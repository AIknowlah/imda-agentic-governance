# 🛡️ IMDA Agentic Governance
### Agentic ETL Architect — Secure RAG Pipeline for Singapore SME Context

[![IMDA 2026](https://img.shields.io/badge/IMDA-2026%20AI%20Governance-blue)](https://aiverifyfoundation.sg)
[![PDPA](https://img.shields.io/badge/PDPA-Singapore%20Compliant-green)](https://www.pdpc.gov.sg)
[![BigQuery](https://img.shields.io/badge/Google%20BigQuery-asia--southeast1-orange)](https://cloud.google.com/bigquery)
[![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-purple)](https://ai.google.dev)
[![Status](https://img.shields.io/badge/Status-v1.0%20Complete-brightgreen)](https://github.com/aiknowlah/imda-agentic-governance)

---

## ⚠️ Important Notice to All Readers

> ### This repository is a deliberate, staged publication.
>
> This is **not** an abandoned or incomplete project.
>
> It has been intentionally published at this stage as a **live build journal** —
> a transparent record of a governance-first AI development approach.
>
> **Where this project currently stands:**
> A working agentic pipeline (Phases 1–3) has been built and is functional.
> However, a structured self-assessment has identified gaps at **two levels**:
>
> **Code-level gaps — resolved in v1.0 ✅:**
> - SQL injection risk — fixed with parameterised BigQuery queries
> - No error handling — all Gemini and BigQuery calls now wrapped in try/except
> - Audit log missing session IDs — UUID request_id now generated per query
> - HITL no timeout — auto-reject after 5 minutes now implemented
> - Output not labelled — [AI-GENERATED] label now on all results
>
> **Remaining code-level gap (being addressed in v1.1):**
> - HITL approval is single-person and unverified — supervisor PIN registry coming in v1.1
>
> **Governance documentation gaps** (being addressed in v1.2–v1.5):
> - No System Card, Materiality Assessment, or Incident Response Plan
> - No formal bias assessment on retrieval outputs
> - No Python test suite generating reproducibility evidence
> - No Project Moonshot red-team results
> - No completed AI Verify Governance Report
>
> Identifying and documenting gaps honestly — before claiming compliance —
> is itself a governance best practice. This is precisely what the AI Verify
> framework expects organisations to do.
>
> *Readers are encouraged to review the Gap Analysis document and the version
> roadmap below to understand exactly what has been built, what remains, and why.*

---

## 📌 Build Progress

| Phase | Description | Status | Notes |
|-------|-------------|--------|-------|
| Phase 1 | Data Governance & Ingestion (BigQuery + Gemini Embeddings) | ✅ Complete | Stable |
| Phase 2 | Agentic RBAC Retrieval (LangGraph Pipeline) | ✅ Complete | SQL injection fixed in v1.0 |
| Phase 3 | Ethics & Governance Layer (HITL + Audit Logs) | 🔧 Partial | HITL hardened in v1.0 — supervisor PIN verification coming in v1.1 |
| Phase 4 | AI Verify Evidence Package & Formal Governance Report | 🔜 Not Started | Begins after v1.2 |

---

## 🗺️ Version Roadmap

This project follows a deliberate, incremental release strategy.
Each version is a genuine GitHub release — not a feature dump.
The commit history is itself a governance audit trail.

| Version | Focus | Key Changes | Status |
|---------|-------|-------------|--------|
| **v0.9** | Functional prototype | Core pipeline working — RBAC, HITL (basic), BigQuery audit log | ✅ Complete |
| **v1.0** | Harden foundations | SQL injection fix, API error handling, HITL timeout, UUID audit entries, `[AI-GENERATED]` output label, similarity score + RBAC rule in output, low similarity score warning, `.env.example` | ✅ Complete |
| **v1.1** | Proper HITL | Supervisor PIN registry, two-person approval, scoped authority, auto-reject on timeout, enhanced audit log | 🔧 In Progress |
| **v1.2** | Input hardening | Prompt injection detection, rate limiting per role, query sanitisation, blocked attempt logging | 🔜 Planned |
| **v1.3** | Test suite | `test_reproducibility.py`, `test_rbac_compliance.py`, `test_robustness.py`, `test_hitl_trigger.py`, `test_audit_log.py`, `test_adversarial.py`, `monitor_anomalies.py` | 🔜 Planned |
| **v1.4** | Governance documents | System Card, Materiality Assessment, Acceptable Use Policy, Incident Response Plan, Bias Assessment | 🔜 Planned |
| **v1.5** | AI Verify submission | Completed Governance Report, Project Moonshot results, evidence package, compliance README | 🔜 Planned |

> **Design principle:** Each version hardens what exists before adding new capability.
> Governance theatre — where documentation outpaces the actual system — is explicitly avoided.

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
└────────┬────────────┘       [v1.1: supervisor PIN + two-person rule]
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

> **Note on `criminal_record`:** This field is stored in BigQuery but intentionally excluded
> from all role permission sets. No role currently has access to it. This is a deliberate
> design decision — formal access policy for this field will be documented in the
> System Card (v1.4).

---

## ☁️ Google Cloud Infrastructure

| Component | Detail |
|-----------|--------|
| GCP Project | `secure-rag-sg` |
| Region | `asia-southeast1` (Singapore — PDPA data residency) |
| BigQuery Dataset | `secure_rag` |
| Tables | `employee_data`, `employee_embeddings`, `audit_log` |
| AI Model | `gemini-2.5-flash` (generation) + `gemini-embedding-001` (embeddings, 3072 dimensions) |

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
├── .env.example                       # Environment variable template [v1.0]
├── .gitignore                         # Protects .env and secrets
│
├── src/
│   └── ingestion/
│       ├── processor.py               # Phase 1: Data ingestion + Gemini embeddings
│       └── main.py                    # Phase 2 & 3: Agent pipeline (RBAC + HITL)
│
├── data/
│   └── raw/
│       └── f_data.xlsx                # Synthetic employee data (100 records, AI-generated)
│
├── docs/
│   ├── Session_Progress_Report_8Mar2026.docx   # Full build log — Phases 1–3
│   └── AIVerify_Gap_Analysis.docx              # AI Verify 11-principle gap map
│
└── tests/                             # 🔜 v1.3: Python test suite
    └── .gitkeep
```

---

## 🇸🇬 IMDA 2026 AI Governance Alignment

This project is designed against the
[IMDA 2026 Model AI Governance Framework for Agentic AI](https://aiverifyfoundation.sg)
and the [AI Verify Testing Framework (2025 Edition)](https://aiverifyfoundation.sg).

| IMDA Requirement | Implementation | Maturity |
|-----------------|----------------|---------|
| Bounded Autonomy | LangGraph StateGraph — agent cannot act outside defined nodes | ✅ Implemented |
| Least-Privilege Data Access | RBAC strips all fields not explicitly permitted per role | ✅ Implemented |
| Meaningful Human Control | HITL gate pauses pipeline; human must approve sensitive data release | 🔧 Basic — supervisor verification in v1.1 |
| Transparency & Auditability | Every query logged to BigQuery `audit_log` — UUID request_id, RBAC rule, similarity score all captured | ✅ Implemented |
| Data Residency (PDPA) | All data stored in `asia-southeast1` Singapore region | ✅ Implemented |

---

## 📋 AI Verify Gap Analysis

A full gap analysis against all 11 AI Verify principles has been completed.
See [`docs/AIVerify_Gap_Analysis.docx`](docs/AIVerify_Gap_Analysis.docx) for the detailed report.

**Current readiness summary:**

| Principle | Readiness | Target Version |
|-----------|-----------|---------------|
| 1. Transparency | Medium | v1.4 |
| 2. Explainability | High | — |
| 3. Reproducibility | Low | v1.3 |
| 4. Safety | Low | v1.2 |
| 5. Security | **Medium** | v1.2 |
| 6. Robustness | **Medium** | v1.2 |
| 7. Fairness | Low | v1.4 |
| 8. Data Governance | **Medium** | v1.4 |
| 9. Accountability | **Medium** | v1.1 |
| 10. Human Agency & Oversight | **Medium** | v1.1 |
| 11. Inclusive Growth | Low | v1.4 |

---

## 🤔 Model Selection Rationale

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Embedding model | `gemini-embedding-001` | Google's latest embedding model — 3072 dimensions, strongest semantic retrieval performance available via AI Studio |
| Generation model | `gemini-2.5-flash` | Best balance of capability and cost for a prototype; fast inference suitable for interactive pipeline |
| Database | Google BigQuery | Enterprise-grade, cloud-native, Singapore-hosted, queryable audit logs — appropriate for PDPA-aligned production system |
| Cloud provider | Google Cloud (`asia-southeast1`) | PDPA data residency requirement — personal data of Singapore residents must remain in Singapore |
| API access | Google AI Studio | Vertex AI requires billing enabled; AI Studio provides free Gemini API access suitable for prototyping without credit card |
| Vector search | Python cosine similarity | BigQuery standard tier lacks native vector search; Python cosine similarity is sufficient and transparent for 100-record datasets |
| Pipeline framework | LangGraph StateGraph | Enforces bounded autonomy — agent cannot act outside defined nodes, satisfying IMDA 2026 agentic AI governance requirement |

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

# Create .env file from template (never commit this)
cp .env.example .env
# Then edit .env and add your GOOGLE_API_KEY
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
| [AI Verify Gap Analysis — v0.9 Baseline](docs/AIVerify_Gap_Analysis_v0.9.docx) | Full 11-principle gap map with prioritised action plan |

---

## 📋 Changelog

| Version | Date | Status | What Changed |
|---------|------|--------|-------------|
| v0.9 | 8 Mar 2026 | ✅ Complete | Core pipeline complete — RBAC, basic HITL, BigQuery audit log, AI Verify gap analysis published |
| v1.0 | 12 Mar 2026 | ✅ Complete | SQL injection fix, API error handling, HITL timeout, UUID audit entries, `[AI-GENERATED]` output label, similarity score + RBAC rule printed in output, low similarity warning (score < 0.3), `.env.example`, access_* fields removed |
| v1.1 | In Progress | 🔧 | Supervisor PIN registry, two-person HITL approval, auto-reject on timeout, enhanced audit log with reviewer identity |
| v1.2 | Planned | 🔜 | Prompt injection detection, rate limiting per role, query sanitisation |
| v1.3 | Planned | 🔜 | Python test suite — `test_reproducibility.py`, `test_rbac_compliance.py`, `test_robustness.py`, `test_hitl_trigger.py`, `test_audit_log.py`, `test_adversarial.py`, `monitor_anomalies.py` |
| v1.4 | Planned | 🔜 | System Card, Materiality Assessment, Acceptable Use Policy, Incident Response Plan, Bias Assessment |
| v1.5 | Planned | 🔜 | AI Verify Governance Report, Project Moonshot red-team results, full evidence package |

---

## 👤 Author

**AIknowlah**
Agentic ETL Architect | Data Governance | AI Ethics | Singapore 🇸🇬

Built as part of a professional development roadmap aligned to the
**IMDA 2026 Model AI Governance Framework** and **WSQ ICT Skills Framework**
(Data Governance and AI System Design tracks).

---

## 📬 Contact & Collaboration

Interested in this project, AI governance consulting, or collaboration opportunities?

- 💼 LinkedIn: [linkedin.com/in/aiknowlah](https://www.linkedin.com/in/aiknowlah/)
- 🐙 GitHub: [@AIknowlah](https://github.com/AIknowlah)
- 💬 Open a [GitHub Discussion](https://github.com/AIknowlah/imda-agentic-governance/discussions)

---

## 📜 Licence

This project is for educational and portfolio purposes.

### ⚠️ Data Disclaimer

The file `data/raw/f_data.xlsx` contains **100% fictitious employee records**.
This data was **synthetically generated using the Gemini AI app** specifically
for this project and does not represent, reference, or resemble any real individual,
organisation, or entity.

It was created solely to demonstrate the system's RBAC, HITL, and audit logging
capabilities in a safe, privacy-preserving way — fully aligned with PDPA principles
of data minimisation and purpose limitation.

No real personal data was used at any stage of this project.

---

*"Governance is not a gate at the end of the pipeline. It is every node in the graph."*
