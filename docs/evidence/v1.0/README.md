# 📁 Evidence — v1.0 Fixes Verified

This folder contains visual evidence of fixes delivered in **v1.0 (12 March 2026)**
— the foundation hardening release.

v1.0 applied 10 code-level fixes to harden the pipeline against real security,
robustness, and accountability gaps identified at v0.9.

---

## 📸 Screenshots in This Folder

---

### 1. `v1.0_output_labels_uuid_rbac.png`

| Field | Detail |
|-------|--------|
| **Version captured** | v1.0 |
| **Date verified** | 28 March 2026 |
| **Fix type** | Output transparency and traceability |
| **AI Verify principles** | Principle 1 (Transparency), Principle 3 (Reproducibility), Principle 9 (Accountability) |
| **Severity** | ✅ Resolved |

**What this screenshot shows:**

Three v1.0 fixes verified in a single pipeline run using the `General_Staff` role:

**Fix 5 — [AI-GENERATED] Label (Principle 1: Transparency)**

Every pipeline output now carries the `[AI-GENERATED]` label. Users are never
in doubt about the nature of what they are seeing. This is a non-negotiable
transparency requirement under AI Verify Principle 1.

**Fix 3 — UUID Request ID (Principle 9: Accountability)**

Every pipeline run now generates a unique UUID (`request_id`) that flows through
every node, appears in the output, and is stored in the BigQuery audit log.
This allows any query to be looked up, traced, and audited by its unique ID —
like a receipt number for every data access event.

**Fix 6 — RBAC Rule in Output (Principles 1 & 2: Transparency & Explainability)**

The output now prints exactly which RBAC rule was applied — the role name and
the permitted fields list. Users can see exactly why they received the results
they did. This is also stored in the audit log under `rbac_rule_applied`.

**Additional evidence visible in screenshot:**

- `[HITL] No sensitive fields detected. Proceeding automatically.` — confirms
  the HITL gate correctly does NOT trigger for `General_Staff` since no sensitive
  fields are in their permitted field set. This is the correct behaviour.
- `[RBAC] Role 'General_Staff' — permitted fields: ['name', 'employment']` —
  confirms field-level access control is enforced at retrieval time.
- Only `name`, `employment`, and `similarity_score` are returned — NRIC,
  ethnicity, medical and financial data are completely absent from output.

---

## 📋 Full v1.0 Fix Summary

All 10 fixes were applied to `src/ingestion/main.py` and `src/ingestion/processor.py`.

| Fix | Description | AI Verify Principle |
|-----|-------------|---------------------|
| Fix 1 | SQL injection prevention — parameterised BigQuery queries | P5 Security |
| Fix 2 | Error handling — all API calls wrapped in try/except | P6 Robustness |
| Fix 3 | UUID request_id — unique traceable ID per pipeline run | P9 Accountability |
| Fix 4 | HITL timeout — auto-reject after 5 minutes, never auto-approve | P10 Human Agency |
| Fix 5 | [AI-GENERATED] label on all pipeline output | P1 Transparency |
| Fix 6 | RBAC rule and similarity score in output and audit log | P1 Transparency, P2 Explainability |
| Fix 7 | Low similarity score warning if top result scores below 0.3 | P4 Safety |
| Fix 8 | Embedding dimension comment corrected (768 → 3072) | P3 Reproducibility |
| Fix 9 | access_* fields removed from BigQuery schema — unused by RBAC | Code Quality |
| Fix 10 | .env.example created with placeholder credentials | P3 Reproducibility |

---

*Evidence captured as part of the Agentic ETL Architect governance roadmap.*
*IMDA AI Verify Testing Framework (2025 Edition) | PDPA Singapore*
