# 📁 Evidence — Governance Flaw Documentation & Fix Verification

This folder contains visual evidence of flaws identified and fixes verified
across each version of the Agentic ETL Architect project.

Evidence is captured through structured self-assessment against the
**IMDA AI Verify Testing Framework (2025 Edition)**.

Identifying and evidencing flaws **before** fixing them is a core governance
practice. It demonstrates that compliance is earned through process, not claimed
through assertion.

---

## 🗂️ Evidence Index — All Versions

| Version | Folder | Status | Contents |
|---------|--------|--------|----------|
| v0.9 | `evidence/v0.9/` | ✅ Complete | HITL data exposure flaw documented |
| v1.0 | `evidence/v1.0/` | 🔜 Planned | SQL injection fix, error handling, UUID audit log |
| v1.1 | `evidence/v1.1/` | ✅ Complete | Supervisor PIN working, two-person approval, summary-only preview verified |
| v1.2 | `evidence/v1.2/` | 🔜 Planned | Prompt injection blocked, rate limiting active |
| v1.3 | `evidence/v1.3/` | 🔜 Planned | Test suite passing — all 7 scripts |
| v1.4 | `evidence/v1.4/` | 🔜 Planned | Governance documents completed |
| v1.5 | `evidence/v1.5/` | 🔜 Planned | AI Verify Governance Report — final submission |

---

## 📸 v0.9 Evidence

### `v0.9_HITL_flaw_data_visible_before_approval.png`

| Field | Detail |
|-------|--------|
| **Version captured** | v0.9 |
| **Date identified** | March 2026 |
| **Flaw type** | Logic flaw — premature data exposure |
| **AI Verify principle** | Principle 10 — Human Agency & Oversight |
| **Severity** | 🔴 High |
| **Resolved in** | v1.1 |

**What this screenshot shows:**

The HITL (Human-in-the-Loop) gate displays the **full sensitive field values**
to the reviewer — including NRIC, ethnicity, and medical information — **before**
the reviewer has approved or rejected the request.

**Why this is a flaw:**

The purpose of the HITL gate is to require a human decision before sensitive
data is released. Showing the data before approval defeats this purpose entirely.
A reviewer — or anyone observing the screen — can read all sensitive values
without ever clicking approve. The gate provides the appearance of control
without the substance of it.

This is an example of **governance theatre** — a control that looks correct
in design but fails in implementation.

**What the correct behaviour should be:**

The reviewer should see only a **summary** at the gate:
- Who is requesting
- What query was submitted
- Which sensitive field categories are involved (e.g. "NRIC, ethnicity")
- How many records are pending

Full field values should only be released **after** the reviewer approves,
and only to the original requester — not displayed at the gate itself.

**Remediation delivered in v1.1:**

| Step | Version | Status | Description |
|------|---------|--------|-------------|
| Summary-only preview at gate | v1.1 | ✅ Done | Reviewer sees field names only — values hidden |
| Supervisor PIN verification | v1.1 | ✅ Done | SHA-256 hashed PIN verified against BigQuery |
| Two-person approval rule | v1.1 | ✅ Done | Requester cannot approve their own query |
| Three-strike lockout | v1.1 | ✅ Done | Account locked after 3 wrong PINs |
| Gmail escalation to manager | v1.1 | ✅ Done | Automatic email sent on lockout |
| Reviewer identity in audit log | v1.1 | ✅ Done | Supervisor ID recorded in BigQuery audit_log |

---

## 📸 v1.1 Evidence

### `v1.1_HITL_fix_summary_only_preview.png`

| Field | Detail |
|-------|--------|
| **Version captured** | v1.1 |
| **Date verified** | 27 March 2026 |
| **Fix type** | Summary-only preview at HITL gate |
| **AI Verify principle** | Principle 10 — Human Agency & Oversight |
| **Severity** | ✅ Resolved |
| **Replaces flaw in** | v0.9 |

**What this screenshot shows:**

The v1.1 HITL gate displays **field names only** — no actual values are shown
at the review screen. The reviewer sees which sensitive field categories are
involved and how many records are pending, but cannot read any sensitive data
until after approval.

**Evidence of fix:**

- Sensitive field values (NRIC, ethnicity) are hidden at the gate
- Supervisor must enter their ID and PIN before any decision is made
- Two-person rule prevents the requester from approving their own query
- Results are only released to the original requester after approval

> 📌 **Note:** Add screenshot `v1.1_HITL_fix_summary_only_preview.png` to this
> folder showing the v1.1 HITL gate with summary-only preview working.
> Capture a terminal screenshot showing field names displayed without values
> at the HITL gate prompt.

---

## 📐 How Evidence is Captured at Each Version

For every version, evidence follows this structure:

1. **Before screenshot** — the flaw or gap as it existed
2. **Companion note** — what the flaw is, why it matters, which AI Verify
   principle it maps to, and which version resolves it
3. **After screenshot** — the fix working correctly (added in the resolution version)
4. **Test output** — where applicable, Python test results confirming the fix

This structure ensures that by v1.5, the full AI Verify evidence package contains
a complete, auditable record of the governance journey — not just the end state.

---

*Evidence captured as part of the Agentic ETL Architect governance roadmap.*
*IMDA AI Verify Testing Framework (2025 Edition) | PDPA Singapore*
