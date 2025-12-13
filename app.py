from __future__ import annotations

import streamlit as st

from analyzer import parse_ads_txt, analyze, to_report_json


st.set_page_config(page_title="AdChainAudit", layout="wide")

st.title("🛡️ AdChainAudit")
st.caption("Audit the ad supply chain — starting with ads.txt. Upload a file or paste contents to generate a buyer-focused red-flag summary.")

with st.sidebar:
    st.header("⚙️ Options")
    show_meta = st.toggle("Show meta/variable lines (if present)", value=False)
    max_examples = st.slider("Examples per issue", 5, 25, 12, step=1)

tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

content = None

with tab_upload:
    uploaded = st.file_uploader("Upload your ads.txt file", type=["txt"])
    if uploaded is not None:
        content = uploaded.getvalue().decode("utf-8", errors="ignore")

with tab_paste:
    pasted = st.text_area("Paste ads.txt contents here", height=260, placeholder="Paste ads.txt lines...")
    if pasted.strip():
        content = pasted

if not content:
    st.info("Upload an ads.txt file or paste its contents to begin.")
    st.stop()

records = parse_ads_txt(content)
summary, issues = analyze(records)

# --- Top KPI row ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Entries parsed", summary["totals"]["entries"])
c2.metric("DIRECT", summary["relationships"].get("DIRECT", 0))
c3.metric("RESELLER", summary["relationships"].get("RESELLER", 0))
c4.metric("Risk score (0–100)", summary["risk_score_0_100"])

# --- High-level summary ---
st.subheader("🧾 Summary")
st.write(
    f"- **Relationship ambiguity pairs:** {summary['relationship_ambiguity_pairs']}\n"
    f"- **Entries missing CAID (field #4):** {summary['missing_caid_entries']}\n"
)

# --- Issues ---
st.subheader("🚩 Potential red flags")
if not issues:
    st.success("No red flags detected with the current rule set.")
else:
    # Sort by severity importance
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues_sorted = sorted(issues, key=lambda x: order.get(x["severity"], 99))

    for issue in issues_sorted:
        sev = issue["severity"]
        title = issue["title"]
        detail = issue["detail"]
        examples = issue.get("examples", [])[:max_examples]

        expanded = sev in ("CRITICAL", "HIGH")
        with st.expander(f"{sev} — {title}", expanded=expanded):
            st.write(detail)

            if examples:
                st.markdown("**Examples (line-level evidence):**")
                # Print original raw line for readability
                lines = []
                for e in examples:
                    line_no = e.get("line_no")
                    raw = e.get("raw", "").rstrip("\n")
                    lines.append(f"L{line_no}: {raw}")
                st.code("\n".join(lines))

# --- Optional meta lines display ---
if show_meta and summary["totals"]["meta_lines"] > 0:
    st.subheader("🧩 Meta / variable lines")
    meta = [r for r in records if r.record_type == "meta"]
    for m in meta[:200]:
        st.write(f"- `L{m.line_no}` **{m.meta_key}** = `{m.meta_value}`")

# --- Downloads ---
st.subheader("⬇️ Export")
report_json = to_report_json(summary, issues)
st.download_button(
    label="Download JSON report",
    data=report_json,
    file_name="adchainaudit_report.json",
    mime="application/json",
)

st.caption("🧠 Tip: Keep reports as evidence snapshots when ads.txt changes over time.")
