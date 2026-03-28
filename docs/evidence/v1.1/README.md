# 📁 Evidence — v1.1 Fixes Verified

This folder contains visual evidence of fixes delivered in **v1.1 (27 March 2026)**
— the two-person HITL governance release.

v1.1 replaced the v0.9/v1.0 single-person CLI HITL gate with a proper two-person
governance mechanism. This directly resolves the flaw documented in `evidence/v0.9/`.

---

## 📸 Screenshots in This Folder

---

### 1. `v1.1_HITL_fix_summary_only_preview.png`

| Field | Detail |
|-------|--------|
| **Version captured** | v1.1 |
| **Date verified** | 27 March 2026 |
| **Fix type** | Two-person HITL gate — summary-only preview |
| **AI Verify principles** | Principle 9 (Accountability), Principle 10 (Human Agency & Oversight) |
| **Resolves flaw in** | v0.9 |
| **Severity** | ✅ Resolved |

**What this screenshot shows:**

The v1.1 HITL gate displaying the **summary-only preview** — field names are
shown but no actual sensitive values are visible. This directly fixes the v0.9
flaw where full NRIC numbers and ethnicity values were exposed at the gate
before any approval decision was made.

**Evidence visible in screenshot:**

- `DATA SUMMARY (field names only — values hidden)` — confirms values are hidden ✅
- `Record 1: fields present → ['name', 'employment', 'nric', 'ethnicity']` — field names only, no values ✅
- `A supervisor must authenticate to approve this release.` — PIN required ✅
- `The requester cannot approve their own query (Two-Person Rule).` — two-person rule enforced ✅
- `Enter Supervisor ID (e.g. SUP001):` — pipeline paused, awaiting supervisor identity ✅

**Contrast with v0.9 flaw:**

| | v0.9 (flaw) | v1.1 (fix) |
|---|---|---|
| Data shown at gate | Full values (NRIC, ethnicity visible) | Field names only — no values |
| Approver identity | Anyone on the machine | Verified supervisor with PIN |
| Two-person rule | Not enforced | System enforced |
| Account lockout | Not implemented | 3 strikes → locked |
| Manager escalation | Not implemented | Gmail alert on lockout |

---

## 📋 Full v1.1 Fix Summary

All five governance rules were built, tested, and verified on 27 March 2026.

| Rule | Description | AI Verify Principle | Status |
|------|-------------|---------------------|--------|
| Rule 1 | Two-Person Rule — requester cannot approve own query | P10 Human Agency | ✅ Verified |
| Rule 2 | Supervisor PIN verification — SHA-256 hashed in BigQuery | P9 Accountability | ✅ Verified |
| Rule 3 | Three-strike lockout — account locked after 3 wrong PINs | P5 Security | ✅ Verified |
| Rule 4 | Gmail escalation — automatic email to manager on lockout | P9 Accountability | ✅ Verified |
| Rule 5 | Full audit trail — every action logged with request_id | P9 Accountability | ✅ Verified |

**New files added in v1.1:**

| File | Purpose |
|------|---------|
| `src/ingestion/setup_supervisors.py` | Creates supervisors and managers tables in BigQuery |
| `src/hitl/hitl_gate.py` | All HITL v1.1 logic as a standalone module |
| `src/ingestion/main.py` (updated) | node_human_review() now calls hitl_gate.py |

**New BigQuery tables added in v1.1:**

| Table | Purpose |
|-------|---------|
| `supervisors` | Stores supervisor IDs, hashed PINs, approved roles, lockout status |
| `managers` | Stores manager email for escalation alerts |

---

*Evidence captured as part of the Agentic ETL Architect governance roadmap.*
*IMDA AI Verify Testing Framework (2025 Edition) | PDPA Singapore*
