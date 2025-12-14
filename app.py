# app.py
from __future__ import annotations

from pathlib import Path
from typing import Optional

import streamlit as st

from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes

APP_TITLE = "AdChainAudit"

SAMPLE_PATH = Path("samples/thestar_ads_20251214.txt")
SAMPLE_LABEL = "thestar.com.my/ads.txt (snapshot: 14 Dec 2025)"
SAMPLE_SOURCE_NOTE = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)

GITHUB_REPO_URL = "https://github.com/maazkhan86/AdChainAudit"
APP_URL = "https://adchainaudit.streamlit.app/"


@st.cache_data(show_spinner=False)
def load_sample_text() -> str:
    if SAMPLE_PATH.exists():
        return SAMPLE_PATH.read_text(encoding="utf-8", errors="replace")
    # Fallback: keep the app usable even if the file is missing.
    return (
        "# Sample file missing.\n"
        "# Please add: samples/thestar_ads_20251214.txt\n"
        "# Then paste the snapshot content into that file.\n"
    )


def set_ads_text(text: str, label: Optional[str] = None) -> None:
    st.session_state["ads_text"] = text
    if label is not None:
        st.session_state["source_label"] = label


def get_ads_text() -> str:
    return st.session_state.get("ads_text", "")


def get_source_label() -> str:
    return st.session_state.get("source_label", "Uploaded/Pasted ads.txt")


def main() -> None:
    st.set_page_config(
        page_title=APP_TITLE,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    # Header
    st.markdown(f"# 🛡️ {APP_TITLE}")
    st.caption(
        "Audit the ad supply chain starting with ads.txt. "
        "Upload or paste an ads.txt file to generate a buyer-focused red-flag summary."
    )

    # Compact utility row (keeps vertical space low)
    c1, c2, c3, c4 = st.columns([1.15, 1.25, 1.25, 2.35])
    with c1:
        if st.button("⚡ Try sample ads.txt", use_container_width=True):
            set_ads_text(load_sample_text(), SAMPLE_LABEL)
            st.rerun()

    with c2:
        st.link_button("🌐 Open web app", APP_URL, use_container_width=True)

    with c3:
        st.link_button("👩‍💻 GitHub (technical)", GITHUB_REPO_URL, use_container_width=True)

    with c4:
        st.info("✅ Open-source (MIT). Marketers can use the app. Technical folks can contribute via GitHub.", icon="ℹ️")

    # How-to (compact)
    with st.expander("📌 How to get a site’s ads.txt (quick)", expanded=False):
        st.markdown(
            """
**Fastest method**
1. In your browser, open: `https://example.com/ads.txt`
2. If it 404s, try: `https://www.example.com/ads.txt`
3. Copy all text (Ctrl+A → Ctrl+C) and paste it into the app, or save it as `ads.txt` and upload.

**Tip**
- Some publishers redirect you. That’s fine. Just copy the final page contents.
"""
        )

    # Input area
    tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

    uploaded_text: Optional[str] = None

    with tab_upload:
        uploaded = st.file_uploader("Upload an ads.txt file", type=["txt"], label_visibility="visible")
        if uploaded is not None:
            uploaded_text = uploaded.getvalue().decode("utf-8", errors="replace")
            set_ads_text(uploaded_text, getattr(uploaded, "name", "Uploaded ads.txt"))

    with tab_paste:
        ads_text = st.text_area(
            "Paste ads.txt contents here",
            value=get_ads_text(),
            height=220,
            placeholder="Paste the full contents of ads.txt here…",
        )
        set_ads_text(ads_text, get_source_label())

    # Attribution for sample usage
    if get_source_label() == SAMPLE_LABEL:
        st.caption(SAMPLE_SOURCE_NOTE)

    # Analyze
    st.divider()
    run = st.button("🔎 Run audit", type="primary", use_container_width=False)

    if run:
        text = get_ads_text().strip()
        if not text:
            st.warning("Please upload or paste an ads.txt first (or click “Try sample ads.txt”).")
            st.stop()

        with st.spinner("Analyzing…"):
            report = analyze_ads_txt(text=text, source_label=get_source_label())

        # Summary (compact)
        top = st.columns([1.1, 1.1, 1.1, 1.7])
        top[0].metric("Risk score", report["summary"]["risk_score"])
        top[1].metric("Risk level", report["summary"]["risk_level"])
        top[2].metric("Findings", report["summary"]["finding_count"])
        top[3].metric("Entries", report["summary"]["entry_count"])

        st.subheader("Buyer-relevant red flags")
        findings = report.get("findings", [])
        if not findings:
            st.success("No red flags detected by the current rule set.")
        else:
            for f in findings[:50]:
                sev = f.get("severity", "LOW")
                title = f.get("title", "Finding")
                why = f.get("why_buyer_cares", "")
                evidence = f.get("evidence", {})
                line_no = evidence.get("line_no")
                line = evidence.get("line", "")

                badge = {
                    "CRITICAL": "🟥",
                    "HIGH": "🟧",
                    "MEDIUM": "🟨",
                    "LOW": "🟦",
                }.get(sev, "🟦")

                with st.expander(f"{badge} [{sev}] {title}", expanded=False):
                    if why:
                        st.write(why)
                    if line_no is not None:
                        st.code(f"Line {line_no}: {line}".strip())
                    rec = f.get("recommendation", "")
                    if rec:
                        st.markdown(f"**What to do:** {rec}")

            if len(findings) > 50:
                st.caption(f"Showing first 50 findings out of {len(findings)}.")

        st.subheader("Exports")
        dl = st.columns([1, 1, 1, 1])
        dl[0].download_button(
            "⬇️ JSON",
            data=report_to_json_bytes(report),
            file_name="adchainaudit_report.json",
            mime="application/json",
            use_container_width=True,
        )
        dl[1].download_button(
            "⬇️ TXT",
            data=report_to_txt_bytes(report),
            file_name="adchainaudit_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
        dl[2].download_button(
            "⬇️ CSV",
            data=report_to_csv_bytes(report),
            file_name="adchainaudit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )
        dl[3].download_button(
            "⬇️ Sample ads.txt",
            data=load_sample_text().encode("utf-8", errors="replace"),
            file_name="sample_thestar_ads_20251214.txt",
            mime="text/plain",
            use_container_width=True,
        )

    # Footer
    st.caption("Built in public. Feedback, feature ideas, and collaborators welcome 🤝")


if __name__ == "__main__":
    main()
