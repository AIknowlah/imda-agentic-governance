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
> [`docs/AIVerify_Gap_Analysis_v1_1.docx`](docs/AIVerify_Gap_Analysis_v1_1.docx))
> were **discovered through a structured self-assessment** against the official
> **IMDA AI Verify Testing Framework (2025 Edition)** covering all 11 governance principles.
>
> Identifying and documenting gaps honestly — before claiming compliance —
> is itself a governance best practice. This is precisely what the AI Verify
> framework expects organisations to do.
>
> **The next release (`v1.2`) will continue closing identified gaps with:**
> - Input hardening (prompt injection detection, rate limiting, query sanitisation)
> - Formal governance documents (System Card, Materiality Assessment, Incident Response Plan)
> - A Python test suite generating technical compliance evidence
> - Project Moonshot red-team results
> - A completed AI Verify Governance Report
>
> *Readers are encouraged to review the Gap Analysis document to understand
> exactly what has been built, what remains, and why.*

---

## 📌 Build Progress

| Phase | Description | Status | Notes |
|-------|-------------|--------|-------|
| Phase 1 | Data Governance & Ingestion (BigQuery + Gemini Embeddings) | ✅ Complete | Stable |
| Phase 2 | Agentic RBAC Retrieval (LangGraph Pipeline) | ✅ Complete | SQL injection fixed in v1.0 |
| Phase 3 | Ethics & Governance Layer (HITL + Audit Logs) | ✅ Complete | Two-person HITL gate, supervisor PIN, lockout, Gmail escalation completed in v1.1 |
| Phase 4 | AI Verify Evidence Package & Formal Governance Report | 🔜 Not Started | Begins after v1.2 |

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
6. **Verifies** the approver's identity via supervisor PIN (two-person rule)
7. **Locks** the supervisor account after 3 failed PIN attempts and escalates to manager via Gmail
8. **Logs** every decision permanently to a tamper-evident BigQuery audit table

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
│  human_review       │  ◄── HITL Gate v1.1: two-person rule, supervisor PIN,
└────────┬────────────┘       3-strike lockout, Gmail escalation to manager
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
| Tables | `employee_data`, `employee_embeddings`, `audit_log`, `supervisors`, `managers` |
| AI Model | `gemini-2.5-flash` (generation) + `gemini-embedding-001` (embeddings) |

---

## 🧱 Tech Stack

```
Python 3.11+
├── google-genai              # Gemini API (embeddings + generation)
├── google-cloud-bigquery     # BigQuery client
├── langgraph                 # Agentic pipeline (StateGraph)
├── pandas                    # Data ingestion
├── numpy                     # Cosine similarity
├── google-auth-oauthlib      # Gmail OAuth 2.0 authentication
├── google-auth-httplib2      # Gmail HTTP transport
├── google-api-python-client  # Gmail API — escalation emails
└── python-dotenv             # Secrets management
```

---

## 📁 Repository Structure

```
imda-agentic-governance/
├── README.md                              # This file
├── requirements.txt                       # Pinned Python dependencies
├── .gitignore                             # Protects .env and secrets
│
├── src/
│   ├── ingestion/
│   │   ├── processor.py                   # Phase 1: Data ingestion + Gemini embeddings
│   │   ├── main.py                        # Phase 2 & 3: Agent pipeline (RBAC + HITL)
│   │   └── setup_supervisors.py           # v1.1: Creates supervisor/manager tables
│   └── hitl/
│       └── hitl_gate.py                   # v1.1: Two-person HITL governance module
│
├── data/
│   └── raw/
│       └── f_data.xlsx                    # Synthetic employee data (100 records)
│
├── docs/
│   ├── AIVerify_Gap_Analysis_v1_1.docx    # AI Verify gap map — current (v1.1)
│   ├── AIVerify_Gap_Analysis_v0_9.docx    # AI Verify gap map — baseline (v0.9)
│   └── evidence/
│       ├── v0.9/                          # HITL data exposure flaw documented
│       ├── v1.0/                          # Output labels, UUID, RBAC rule verified
│       └── v1.1/                          # Summary-only HITL preview verified
│
└── tests/                                 # 🔜 Phase 4: Python test suite (coming)
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
| Meaningful Human Control | Two-person HITL gate — supervisor PIN, lockout, Gmail escalation |
| Transparency & Auditability | Every query logged to BigQuery `audit_log` with full decision trail |
| Data Residency (PDPA) | All data stored in `asia-southeast1` Singapore region |

---

## 📋 AI Verify Gap Analysis

A full gap analysis against all 11 AI Verify principles has been completed.
See [`docs/AIVerify_Gap_Analysis_v1_1.docx`](docs/AIVerify_Gap_Analysis_v1_1.docx) for the current report.
The original baseline assessment is preserved at [`docs/AIVerify_Gap_Analysis_v0_9.docx`](docs/AIVerify_Gap_Analysis_v0_9.docx).

**Current readiness summary:**

| Principle | v1.0 | v1.1 | Target |
|-----------|------|------|--------|
| 1. Transparency | Medium | Medium | v1.4 |
| 2. Explainability | High | High | — |
| 3. Reproducibility | Low | Low | v1.3 |
| 4. Safety | Low | Low | v1.2 |
| 5. Security | Medium | Medium | v1.2 |
| 6. Robustness | Medium | Medium | v1.2 |
| 7. Fairness | Low | Low | v1.4 |
| 8. Data Governance | Medium | Medium | v1.4 |
| 9. Accountability | Medium | **High ↑** | v1.1 ✅ |
| 10. Human Agency & Oversight | Medium | **High ↑** | v1.1 ✅ |
| 11. Inclusive Growth | Low | Low | v1.4 |

---

## 🔍 Evidence Trail

This project maintains a versioned evidence trail documenting both flaws identified
and fixes verified at each release. Evidence is captured before and after remediation
— demonstrating that compliance is earned through process, not claimed through assertion.

| Version | Folder | Status | Contents |
|---------|--------|--------|----------|
| v0.9 | `docs/evidence/v0.9/` | ✅ Complete | HITL data exposure flaw documented |
| v1.0 | `docs/evidence/v1.0/` | ✅ Complete | Output labels, UUID request ID, RBAC rule verified |
| v1.1 | `docs/evidence/v1.1/` | ✅ Complete | Supervisor PIN, two-person approval, summary-only preview verified |
| v1.2 | `docs/evidence/v1.2/` | 🔜 Planned | Prompt injection blocked, rate limiting active |
| v1.3 | `docs/evidence/v1.3/` | 🔜 Planned | Test suite passing — all 7 scripts |
| v1.4 | `docs/evidence/v1.4/` | 🔜 Planned | Governance documents completed |
| v1.5 | `docs/evidence/v1.5/` | 🔜 Planned | AI Verify Governance Report — final submission |

---

## ⚙️ Setup Instructions

### Prerequisites
- Python 3.11+
- Google Cloud account with BigQuery and Vertex AI APIs enabled
- Google AI Studio API key ([get one here](https://aistudio.google.com))
- `gcloud` CLI installed and authenticated
- Gmail API enabled in GCP project with OAuth 2.0 credentials (`credentials.json`)

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
# Required variables:
# GOOGLE_API_KEY=your_gemini_api_key
# MANAGER_EMAIL=your_gmail@gmail.com
# ESCALATION_FROM=your_gmail@gmail.com
```

### Running the Pipeline

```bash
# Step 1: Ingest data into BigQuery
python src/ingestion/processor.py

# Step 2: Set up supervisor and manager tables
python src/ingestion/setup_supervisors.py

# Step 3: Run the agentic pipeline
python src/ingestion/main.py
```

---

## 📄 Documentation

| Document | Description |
|----------|-------------|
| [AI Verify Gap Analysis v1.1](docs/AIVerify_Gap_Analysis_v1_1.docx) | Full 11-principle gap map — 8 gaps closed at v1.1 |
| [AI Verify Gap Analysis v0.9](docs/AIVerify_Gap_Analysis_v0_9.docx) | Original baseline assessment |

---

## 🗺️ Roadmap

- [x] v0.9 — Functional prototype
- [x] v1.0 — Foundation hardening (SQL injection, error handling, UUID audit, HITL timeout)
- [x] v1.1 — Two-person HITL gate (supervisor PIN, lockout, Gmail escalation)
- [ ] v1.2 — Input hardening (prompt injection detection, rate limiting)
- [ ] v1.3 — Python test suite (7 test scripts)
- [ ] v1.4 — Governance documents (System Card, Materiality Assessment, Incident Response Plan)
- [ ] v1.5 — AI Verify submission (Governance Report, Project Moonshot red-team results)

## 📋 Changelog

| Version | Date | What Changed |
|---|---|---|
| v0.9 | 8 Mar 2026 | Functional prototype — core pipeline, RBAC, basic HITL, BigQuery audit log |
| v1.0 | 12 Mar 2026 | Foundation hardening — SQL injection fix, error handling, UUID audit, HITL timeout, output labels |
| v1.1 | 27 Mar 2026 | Two-person HITL gate — supervisor PIN verification, three-strike lockout, Gmail escalation to manager |

---

## 👤 Author

**AIknowlah**
Agentic ETL Architect | Data Governance | AI Ethics | Singapore 🇸🇬

Built as part of a self-directed learning journey into agentic AI systems and responsible
data engineering, aligned to the **IMDA 2026 Model AI Governance Framework**.

---

## 📬 Contact & Collaboration

Interested in this project or collaboration opportunities?

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

This synthetic data was used during development to avoid handling real personal data
entirely — this reflects a **privacy-by-design approach** and safe testing practice.

No real personal data was used at any stage of this project.

---

*"Governance is not a gate at the end of the pipeline. It is every node in the graph."*
