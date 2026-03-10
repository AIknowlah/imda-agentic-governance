# 📁 Evidence — v0.9 Known Flaws

This folder contains visual evidence of flaws and gaps identified at **v0.9**
through structured self-assessment against the IMDA AI Verify Testing Framework
(2025 Edition).

These screenshots were captured **before remediation** — deliberately preserving
the evidence of what was found, when it was found, and how it was documented.

Identifying and evidencing flaws before fixing them is a core governance
practice. It demonstrates that compliance is earned through process, not claimed
through assertion.

---

## 📸 Screenshots in This Folder

---

### 1. `v0.9_HITL_flaw_data_visible_before_approval.png`

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

**Remediation planned:**

| Step | Version | Description |
|------|---------|-------------|
| Summary-only preview at gate | v1.1 | Reviewer sees categories, not values |
| Supervisor PIN verification | v1.1 | Reviewer identity verified before decision |
| Two-person approval rule | v1.1 | Requester and approver must be different people |
| Auto-reject on timeout | v1.1 | No indefinite pipeline freeze |
| Reviewer identity in audit log | v1.1 | Who approved is permanently recorded |

---

## 🗂️ Evidence Index — All Versions

As the project progresses, each version folder will contain its own evidence
of both **flaws identified** and **fixes verified**.

| Version | Folder | Contents |
|---------|--------|----------|
| v0.9 | `evidence/v0.9/` | ✅ HITL data exposure flaw |
| v1.0 | `evidence/v1.0/` | 🔜 SQL injection fix, error handling, UUID audit log |
| v1.1 | `evidence/v1.1/` | 🔜 Supervisor PIN working, two-person approval, timeout |
| v1.2 | `evidence/v1.2/` | 🔜 Prompt injection blocked, rate limiting active |
| v1.3 | `evidence/v1.3/` | 🔜 Test suite passing — all 7 scripts |
| v1.4 | `evidence/v1.4/` | 🔜 Governance documents completed |
| v1.5 | `evidence/v1.5/` | 🔜 AI Verify Governance Report — final submission |

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
