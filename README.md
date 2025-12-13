# AdChainAudit
Audit the ad supply chain — starting with ads.txt
# AdChainAudit

Audit the ad supply chain — starting with ads.txt.

AdChainAudit is a buyer-focused, security-style auditor for programmatic supply paths.  
Today it lint-checks ads.txt for red flags that actually matter to media buyers. Tomorrow it maps and validates the full chain (sellers.json, schain, hop counts, reselling risk, and “cleanest path” recommendations).

---

## Why this matters

Programmatic supply chains are still too easy to game, too hard to verify, and too expensive to keep messy.

- **Counterfeit / misrepresented inventory is still a thing.** ads.txt exists specifically to increase transparency and make it harder for bad actors to profit from selling counterfeit inventory by letting publishers publicly declare who is authorized to sell.  
  (If you can’t trust the seller declaration layer, everything above it becomes guesswork.)

- **Supply chain opacity is measurable.** The ISBA/PwC supply chain study found that publishers received about **half of advertiser spend**, and **15% (“unknown delta”)** could not be attributed. Even “premium” programmatic paths can hide leakage.  

- **Waste/fraud is still massive.** Juniper Research estimated **22% ($84B) of online ad spend** was lost to ad fraud in 2023 (projected to grow materially over the following years).

- **Even when efficiency improves, verification remains mandatory.** Benchmarks still show large portions of spend not translating cleanly into “working” outcomes, and the industry is actively pushing transparency improvements — which only works if the underlying supply signals are clean.

Bottom line: **SPO is not just about cheaper CPMs. It’s about provable paths.** AdChainAudit is built to make those paths auditable.

---

## What it does today (MVP)

Given an ads.txt file (upload or paste), AdChainAudit produces:
- A simple scorecard (risk score)
- Buyer-facing red flags with line-level evidence
- Exportable JSON report

### Red flag examples
- Malformed lines (wrong number of fields)
- Invalid relationship values (must be DIRECT or RESELLER)
- Missing certification authority ID (transparency gap)
- Relationship ambiguity (same seller appears as DIRECT and RESELLER)

---

## Roadmap (where this goes)

### Phase 1 — Ads.txt hardening (now)
- ✅ Parse + validate ads.txt
- ✅ Risk scoring + buyer report export
- ⬜ Domain mode (`example.com` → fetch `/ads.txt`)
- ⬜ Diff + monitoring (detect changes, alert on new risk)

### Phase 2 — Seller verification
- ⬜ sellers.json fetch + validation (confirm seller exists, type, domain ownership)
- ⬜ OWNERDOMAIN / MANAGERDOMAIN interpretation (where present)
- ⬜ Evidence locker (store raw files + timestamps for audit trails)

### Phase 3 — Full supply chain
- ⬜ schain parsing + graph building (hops, intermediaries, resellers)
- ⬜ SPO scoring (shortest/cleanest path, reseller risk, “unknown hop” penalties)
- ⬜ Buyer controls (allowlists, preferred sellers, block risky patterns)
- ⬜ Report packs (PDF buyer report + procurement-friendly appendix)

### Phase 4 — Operator mode
- ⬜ CLI (`adchainaudit scan <domain|file>`)
- ⬜ GitHub Action (run audits in CI for publisher ops / adops)
- ⬜ Dashboard + scheduled scans

---

## Quickstart (local)

### 1) Install
```bash
python -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
