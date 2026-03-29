# 🛡️ IMDA Agentic Governance
### Agentic ETL Architect — Secure RAG Pipeline for Singapore SME Context

[![IMDA 2026](https://img.shields.io/badge/IMDA-2026%20AI%20Governance-blue)](https://aiverifyfoundation.sg)
[![PDPA](https://img.shields.io/badge/PDPA-Singapore%20Compliant-green)](https://www.pdpc.gov.sg)
[![BigQuery](https://img.shields.io/badge/Google%20BigQuery-asia--southeast1-orange)](https://cloud.google.com/bigquery)
[![Gemini](https://img.shields.io/badge/Gemini-2.5%20Flash-purple)](https://ai.google.dev)
[![Status](https://img.shields.io/badge/Status-Complete-brightgreen)](https://github.com/aiknowlah/imda-agentic-governance)

---

## ⚠️ Important Notice to All Readers

> ### This repository is a complete, versioned governance project.
>
> Built as a **live build journal** — a transparent record of a governance-first
> AI development approach from v0.9 through v1.5.
>
> All 11 AI Verify principles have been assessed. 9 of 11 are at High readiness.
> All gaps are documented honestly in
> [`docs/AIVerify_Gap_Analysis_v1_3.docx`](docs/AIVerify_Gap_Analysis_v1_3.docx)
>
> The full governance submission package is available in [`docs/`](docs/).

---

## 📌 Build Progress

| Phase | Description | Status | Notes |
|-------|-------------|--------|-------|
| Phase 1 | Data Governance & Ingestion (BigQuery + Gemini Embeddings) | ✅ Complete | Stable |
| Phase 2 | Agentic RBAC Retrieval (LangGraph Pipeline) | ✅ Complete | SQL injection fixed in v1.0 |
| Phase 3 | Ethics & Governance Layer (HITL + Audit Logs) | ✅ Complete | Two-person HITL gate, supervisor PIN, lockout, Gmail escalation |
| Phase 4 | AI Verify Evidence Package & Formal Governance Report | ✅ Complete | 134 tests passing, governance documents published, v1.5 report complete |

---

## 🎯 What This Project Does

This project builds an **Agentic ETL Architect** — a secure, role-based, AI-powered
data retrieval system that demonstrates responsible AI governance in practice.

A user queries employee data using natural language. The system:
1. **Validates** their role against a strict RBAC policy
2. **Hardens** the query — sanitisation, injection detection, rate limiting
3. **Embeds** their query using Google Gemini (`gemini-embedding-001`)
4. **Retrieves** the top 5 most semantically relevant records from BigQuery
5. **Enforces** field-level access control — stripping any data the role cannot see
6. **Pauses** for human approval if sensitive fields (NRIC, ethnicity, medical info) are detected
7. **Verifies** the approver's identity via supervisor PIN (two-person rule)
8. **Locks** the supervisor account after 3 failed PIN attempts and escalates to manager via Gmail
9. **Logs** every decision permanently to a tamper-evident BigQuery audit table

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
│  input_guard        │  ◄── Sanitisation + 23-pattern injection detection + rate limiting
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
| Tables | `employee_data`, `employee_embeddings`, `audit_log`, `supervisors`, `managers`, `rate_limit_log` |
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
├── README.md
├── requirements.txt                       # Pinned Python dependencies
├── .gitignore                             # Protects .env and secrets
│
├── src/
│   ├── ingestion/
│   │   ├── processor.py                   # Phase 1: Data ingestion + Gemini embeddings
│   │   ├── main.py                        # v1.2: Agent pipeline (RBAC + HITL + Input Hardening)
│   │   └── setup_supervisors.py           # v1.1: Creates supervisor/manager tables
│   ├── hitl/
│   │   └── hitl_gate.py                   # v1.1: Two-person HITL governance module
│   └── security/
│       └── input_guard.py                 # v1.2: Injection detection, sanitisation, rate limiting
│
├── data/
│   └── raw/
│       └── f_data.xlsx                    # Synthetic employee data (100 records)
│
├── docs/
│   ├── AIVerify_Governance_Report_v1_5.docx   # Final governance report
│   ├── AIVerify_Gap_Analysis_v1_3.docx        # Current gap analysis (v1.3)
│   ├── AIVerify_Gap_Analysis_v1_1.docx        # Gap analysis (v1.1)
│   ├── AIVerify_Gap_Analysis_v0_9.docx        # Baseline gap analysis (v0.9)
│   ├── System_Card_v1_4.docx
│   ├── Materiality_Assessment_v1_4.docx
│   ├── Incident_Response_Plan_v1_4.docx
│   └── evidence/
│       ├── v0.9/                          # HITL data exposure flaw documented
│       ├── v1.0/                          # Output labels, UUID, RBAC rule verified
│       └── v1.1/                          # Summary-only HITL preview verified
│
└── tests/
    ├── test_sanitisation.py               # P6 Robustness — 18 tests
    ├── test_injection.py                  # P4 Safety, P5 Security — 33 tests
    ├── test_rate_limit.py                 # P5 Security — 5 tests
    ├── test_similarity.py                 # P2 Explainability — 10 tests
    ├── test_rbac.py                       # P8 Data Governance, P10 — 34 tests
    ├── test_audit_log.py                  # P9 Accountability — 22 tests
    └── test_hitl.py                       # P10 Human Agency — 12 tests
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
| Input Hardening | 23-pattern injection detector, sanitisation, rate limiting (10/hour/role) |
| Meaningful Human Control | Two-person HITL gate — supervisor PIN, lockout, Gmail escalation |
| Transparency & Auditability | Every query logged to BigQuery `audit_log` with full decision trail |
| Data Residency (PDPA) | All data stored in `asia-southeast1` Singapore region |

---

## 📋 AI Verify Gap Analysis

A full gap analysis against all 11 AI Verify principles has been completed.
See [`docs/AIVerify_Gap_Analysis_v1_3.docx`](docs/AIVerify_Gap_Analysis_v1_3.docx) for the current report.

**Current readiness summary — v1.3:**

| Principle | Readiness | Evidence |
|-----------|-----------|----------|
| 1. Transparency | Medium | System Card, README, Gap Analysis, Materiality Assessment, IRP published |
| 2. Explainability | **High** | test_similarity.py 10/10 ✅ |
| 3. Reproducibility | **High** | 134 tests passing, pinned requirements.txt ✅ |
| 4. Safety | **High** | test_injection.py 33/33 ✅ |
| 5. Security | **High** | test_rate_limit.py 5/5, SHA-256 PIN, parameterised SQL ✅ |
| 6. Robustness | **High** | test_sanitisation.py 18/18 ✅ |
| 7. Fairness | Medium | Fairness statement in System Card |
| 8. Data Governance | **High** | test_rbac.py 34/34, PDPA compliant ✅ |
| 9. Accountability | **High** | test_audit_log.py 22/22 ✅ |
| 10. Human Agency & Oversight | **High** | test_hitl.py 12/12 ✅ |
| 11. Inclusive Growth | Medium | Inclusive growth statement in System Card |

---

## 🧪 Test Suite

134 automated tests across 7 scripts — all passing.

```bash
python tests/test_sanitisation.py   # 18/18
python tests/test_injection.py      # 33/33
python tests/test_rate_limit.py     # 5/5
python tests/test_similarity.py     # 10/10
python tests/test_rbac.py           # 34/34
python tests/test_audit_log.py      # 22/22
python tests/test_hitl.py           # 12/12
```

---

## 🔍 Evidence Trail

| Version | Status | Contents |
|---------|--------|----------|
| v0.9 | ✅ Complete | HITL data exposure flaw documented |
| v1.0 | ✅ Complete | Output labels, UUID request ID, RBAC rule verified |
| v1.1 | ✅ Complete | Supervisor PIN, two-person approval, summary-only preview verified |
| v1.2 | ✅ Complete | Injection detection working, rate limiting active |
| v1.3 | ✅ Complete | 134 tests passing — all 7 scripts |
| v1.4 | ✅ Complete | Governance documents published |
| v1.5 | ✅ Complete | AI Verify Governance Report — final submission package |

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
| [AI Verify Governance Report v1.5](docs/AIVerify_Governance_Report_v1_5.docx) | Final governance submission package — all 11 principles assessed |
| [System Card v1.4](docs/System_Card_v1_4.docx) | Full system description, controls, limitations, test evidence |
| [Materiality Assessment v1.4](docs/Materiality_Assessment_v1_4.docx) | 10-risk register with likelihood, impact, controls, residual risk |
| [Incident Response Plan v1.4](docs/Incident_Response_Plan_v1_4.docx) | Response procedures, escalation, recovery gate |
| [AI Verify Gap Analysis v1.3](docs/AIVerify_Gap_Analysis_v1_3.docx) | Current gap analysis — 9 of 11 principles at High |
| [AI Verify Gap Analysis v1.1](docs/AIVerify_Gap_Analysis_v1_1.docx) | Gap analysis after v1.1 |
| [AI Verify Gap Analysis v0.9](docs/AIVerify_Gap_Analysis_v0_9.docx) | Original baseline assessment |

---

## 🗺️ Roadmap

- [x] v0.9 — Functional prototype
- [x] v1.0 — Foundation hardening (SQL injection, error handling, UUID audit, HITL timeout)
- [x] v1.1 — Two-person HITL gate (supervisor PIN, lockout, Gmail escalation)
- [x] v1.2 — Input hardening (prompt injection detection, rate limiting)
- [x] v1.3 — Python test suite (7 test scripts, 134 tests)
- [x] v1.4 — Governance documents (System Card, Materiality Assessment, Incident Response Plan)
- [x] v1.5 — AI Verify Governance Report (final submission package)

---

## 📋 Changelog

| Version | Date | What Changed |
|---|---|---|
| v0.9 | 8 Mar 2026 | Functional prototype — core pipeline, RBAC, basic HITL, BigQuery audit log |
| v1.0 | 12 Mar 2026 | Foundation hardening — SQL injection fix, error handling, UUID audit, HITL timeout, output labels |
| v1.1 | 27 Mar 2026 | Two-person HITL gate — supervisor PIN verification, three-strike lockout, Gmail escalation to manager |
| v1.2 | 29 Mar 2026 | Input hardening — prompt injection detection (23 patterns), query sanitisation, rate limiting per role |
| v1.3 | 29 Mar 2026 | Python test suite — 7 scripts, 134 tests, 0 failures, 8 principles evidenced |
| v1.4 | 29 Mar 2026 | Governance documents — System Card, Materiality Assessment, Incident Response Plan, Gap Analysis v1.3 |
| v1.5 | 29 Mar 2026 | AI Verify Governance Report — final submission package, Moonshot applicability assessed |

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
