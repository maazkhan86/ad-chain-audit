# app.py
from __future__ import annotations

import json
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from analyzer import (
    analyze_ads_txt,
    report_to_csv_bytes,
    report_to_json_bytes,
    report_to_txt_bytes,
)

# Phase 2 (sellers.json) is optional — app still works if module import fails
PHASE2_AVAILABLE = True
PHASE2_IMPORT_ERROR = ""
try:
    from phase2_sellers_json import run_sellers_json_verification
except Exception as e:
    PHASE2_AVAILABLE = False
    PHASE2_IMPORT_ERROR = str(e)


APP_TITLE = "AdChainAudit"
APP_TAGLINE = "Audit the programmatic ad supply chain — starting with ads.txt"


DEMO_LABEL = "thestar.com.my/ads.txt (captured 14 Dec 2025)"
DEMO_NOTE = "ads.txt changes over time — treat this as demo input only."


def _pill_success(text: str):
    st.markdown(
        f"""
        <div style="
            display:inline-block;
            padding:6px 10px;
            border-radius:999px;
            background:#e8f7ee;
            border:1px solid #bfe7cd;
            color:#146c2e;
            font-weight:700;
            font-size:13px;">
            {text}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _pill_warn(text: str):
    st.markdown(
        f"""
        <div style="
            display:inline-block;
            padding:6px 10px;
            border-radius:999px;
            background:#fff4e5;
            border:1px solid #ffd8a8;
            color:#8a4b00;
            font-weight:700;
            font-size:13px;">
            {text}
        </div>
        """,
        unsafe_allow_html=True,
    )


def _pill_error(text: str):
    st.markdown(
        f"""
        <div style="
            display:inline-block;
            padding:6px 10px;
            border-radius:999px;
            background:#fdeaea;
            border:1px solid #f5bcbc;
            color:#8a1f1f;
            font-weight:700;
            font-size:13px;">
            {text}
        </div>
        """,
        unsafe_allow_html=True,
    )


def fetch_ads_txt(url_or_domain: str, timeout_s: int = 8) -> Tuple[bool, str, str]:
    """
    Hardcoded behavior:
      - try HTTPS first
      - if fails, try HTTP
    Returns: (ok, final_url, text_or_error)
    """
    raw = (url_or_domain or "").strip()
    if not raw:
        return False, "", "Please enter a domain or URL."

    if raw.startswith("http://") or raw.startswith("https://"):
        candidates = [raw]
    else:
        d = raw.replace("http://", "").replace("https://", "").strip("/")
        candidates = [f"https://{d}/ads.txt", f"http://{d}/ads.txt"]

    headers = {
        "User-Agent": "AdChainAudit/1.0 (+https://adchainaudit.streamlit.app/)"
    }

    last_err = ""
    for u in candidates:
        try:
            r = requests.get(u, headers=headers, timeout=timeout_s)
            if r.status_code != 200:
                last_err = f"HTTP {r.status_code}"
                continue
            text = r.text or ""
            if not text.strip():
                last_err = "Empty response"
                continue
            return True, u, text
        except Exception as e:
            last_err = str(e)

    return False, candidates[-1] if candidates else "", f"Fetch failed: {last_err}"


def report_to_pdf_bytes(main_report: Dict[str, Any], sellers_report: Optional[Dict[str, Any]] = None) -> bytes:
    """
    Simple, clean PDF summary for sharing.
    """
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    w, h = letter

    y = h - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "AdChainAudit report")
    y -= 18

    meta = main_report.get("meta", {})
    sm = main_report.get("summary", {})

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Source: {meta.get('source_label','ads.txt')}")
    y -= 14
    c.drawString(50, y, f"Generated: {meta.get('generated_at','')}")
    y -= 18

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Risk score: {sm.get('risk_score')} ({sm.get('risk_level')})")
    y -= 16

    c.setFont("Helvetica", 10)
    c.drawString(50, y, f"Entries: {sm.get('entry_count')} | Findings: {sm.get('finding_count')}")
    y -= 14
    c.drawString(50, y, f"DIRECT: {sm.get('direct_count')} | RESELLER: {sm.get('reseller_count')}")
    y -= 18

    highlights = sm.get("highlights") or []
    if highlights:
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, "Highlights")
        y -= 14
        c.setFont("Helvetica", 10)
        for hline in highlights[:6]:
            c.drawString(60, y, f"• {hline}")
            y -= 12
        y -= 6

    # Sellers.json summary (if provided)
    if sellers_report:
        ssum = sellers_report.get("summary", {})
        c.setFont("Helvetica-Bold", 11)
        c.drawString(50, y, "Seller verification (sellers.json)")
        y -= 14
        c.setFont("Helvetica", 10)
        c.drawString(50, y, f"Domains checked: {ssum.get('domains_checked')} | Reachable: {ssum.get('reachable')} | Unreachable: {ssum.get('unreachable')}")
        y -= 12
        c.drawString(50, y, f"Avg match rate: {ssum.get('avg_match_rate')}")
        y -= 18

    c.showPage()
    c.save()
    return buf.getvalue()


def summarize_sellers_report(sellers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turn the huge sellers.json output into something normal users can read.
    """
    summary = sellers.get("summary", {}) or {}
    stats: List[Dict[str, Any]] = sellers.get("domain_stats", []) or []

    unreachable = [s for s in stats if not s.get("json_ok")]
    reachable = [s for s in stats if s.get("json_ok")]

    zero_match = [s for s in reachable if float(s.get("match_rate") or 0) == 0.0 and int(s.get("seller_ids_in_ads_txt") or 0) > 0]
    low_match = [s for s in reachable if 0.0 < float(s.get("match_rate") or 0) < 0.30]
    high_match = [s for s in reachable if float(s.get("match_rate") or 0) >= 0.80]

    # Agency-like examples (best-effort)
    agency_hits = []
    for s in reachable:
        for ex in (s.get("agency_like_examples") or []):
            agency_hits.append((s.get("domain"), ex))
    agency_hits = agency_hits[:10]

    # Sort tables
    reachable_sorted = sorted(reachable, key=lambda x: float(x.get("match_rate") or 0), reverse=True)

    return {
        "summary": summary,
        "reachable_sorted": reachable_sorted,
        "unreachable": unreachable,
        "zero_match": zero_match,
        "low_match": low_match,
        "high_match": high_match,
        "agency_hits": agency_hits,
    }


def main():
    st.set_page_config(page_title=APP_TITLE, layout="wide")

    # --- Header (tight spacing)
    left, right = st.columns([0.72, 0.28], vertical_alignment="center")
    with left:
        st.markdown(f"## {APP_TITLE}")
        st.caption(APP_TAGLINE)
    with right:
        st.markdown(
            """
            <div style="text-align:right; font-size:14px;">
              <a href="https://adchainaudit.streamlit.app/" target="_blank">Live App</a> ·
              <a href="https://github.com/maazkhan86/AdChainAudit" target="_blank">GitHub</a>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # --- Session state
    if "ads_txt_text" not in st.session_state:
        st.session_state.ads_txt_text = ""
    if "source_label" not in st.session_state:
        st.session_state.source_label = "ads.txt"
    if "fetch_status" not in st.session_state:
        st.session_state.fetch_status = ""  # "", "fetched", "demo", "uploaded", "pasted"

    # --- Input area (tabs keep it compact)
    tabs = st.tabs(["Paste", "Upload", "Fetch (URL)", "Demo"])

    with tabs[0]:
        txt = st.text_area(
            "Paste ads.txt content",
            value=st.session_state.ads_txt_text,
            height=200,
            placeholder="Paste the full ads.txt content here…",
        )
        c1, c2 = st.columns([0.2, 0.8])
        with c1:
            if st.button("Use pasted text", type="primary"):
                st.session_state.ads_txt_text = txt or ""
                st.session_state.source_label = "Pasted ads.txt"
                st.session_state.fetch_status = "pasted"
        with c2:
            st.caption("Tip: Open a publisher ads.txt via `https://example.com/ads.txt`, copy all, paste here.")

    with tabs[1]:
        up = st.file_uploader("Upload ads.txt file", type=["txt"])
        if up is not None:
            st.session_state.ads_txt_text = up.read().decode("utf-8", errors="replace")
            st.session_state.source_label = f"Uploaded: {up.name}"
            st.session_state.fetch_status = "uploaded"
            _pill_success("Uploaded ✅ File loaded")

    with tabs[2]:
        url_in = st.text_input("Publisher domain or full URL", placeholder="thestar.com.my  OR  https://thestar.com.my/ads.txt")
        if st.button("Fetch ads.txt", type="primary"):
            ok, final_url, payload = fetch_ads_txt(url_in)
            if ok:
                st.session_state.ads_txt_text = payload
                st.session_state.source_label = f"Fetched: {final_url}"
                st.session_state.fetch_status = "fetched"
                _pill_success("Fetched ✅ No manual upload needed")
            else:
                st.session_state.fetch_status = ""
                _pill_error("Fetch blocked or failed — please upload or paste ads.txt manually.")
                st.caption(payload)

    with tabs[3]:
        st.markdown(f"**Demo input:** {DEMO_LABEL}")
        st.caption(DEMO_NOTE)
        if st.button("Load demo ads.txt", type="primary"):
            # Keep demo lightweight; use a tiny placeholder if you don't want to store the full file in repo.
            # You can replace DEMO_TEXT with your real snapshot later.
            DEMO_TEXT = """rubiconproject.com, 16186, DIRECT, 0bfd66d529a55807
google.com, pub-8292728281684217, DIRECT, f08c47fec0942fa0
appnexus.com, 6849, RESELLER
"""
            st.session_state.ads_txt_text = DEMO_TEXT
            st.session_state.source_label = f"Demo: {DEMO_LABEL}"
            st.session_state.fetch_status = "demo"
            _pill_warn("Demo loaded 🧪")

    st.divider()

    # --- Show status line (very visible)
    if st.session_state.fetch_status == "fetched":
        _pill_success("Fetched ✅ You can run audit now")
    elif st.session_state.fetch_status == "uploaded":
        _pill_success("Uploaded ✅ You can run audit now")
    elif st.session_state.fetch_status == "pasted":
        _pill_success("Pasted ✅ You can run audit now")
    elif st.session_state.fetch_status == "demo":
        _pill_warn("Demo input 🧪 You can run audit now")

    # Preview (collapsed)
    with st.expander("Preview ads.txt input", expanded=False):
        if st.session_state.ads_txt_text.strip():
            st.code(st.session_state.ads_txt_text[:20000])
        else:
            st.info("No ads.txt loaded yet. Use Paste / Upload / Fetch / Demo above.")

    st.divider()

    # --- Run audit
    run_left, run_right = st.columns([0.65, 0.35], vertical_alignment="center")
    with run_left:
        st.markdown("### Run audit")
        st.caption("This tool flags buyer-relevant signals. It does not guarantee fraud or quality — it helps you ask better questions.")
    with run_right:
        verify_sellers = st.toggle(
            "Also verify sellers.json (recommended)",
            value=True,
            help="Checks seller IDs found in ads.txt against each ad system's sellers.json when reachable.",
        )

    if not st.session_state.ads_txt_text.strip():
        st.stop()

    if st.button("Analyze now", type="primary"):
        main_report = analyze_ads_txt(
            st.session_state.ads_txt_text,
            source_label=st.session_state.source_label,
            include_optional_checks=True,  # hardcoded
        )

        sellers_report = None
        if verify_sellers:
            if PHASE2_AVAILABLE:
                sellers_report = run_sellers_json_verification(st.session_state.ads_txt_text)
            else:
                st.warning("Phase 2 module not available. App will run ads.txt checks only.")
                st.caption(f"Import error: {PHASE2_IMPORT_ERROR}")

        # --- Top summary
        sm = main_report.get("summary", {})
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk score", sm.get("risk_score"))
        c2.metric("Risk level", sm.get("risk_level"))
        c3.metric("Entries", sm.get("entry_count"))
        c4.metric("Findings", sm.get("finding_count"))

        highlights = sm.get("highlights") or []
        if highlights:
            st.markdown("#### Summary (what a buyer should notice)")
            for h in highlights[:8]:
                st.write(f"• {h}")

        with st.expander("How scoring works", expanded=False):
            st.markdown(
                """
- Score starts at **100** (clean).
- Each rule adds a penalty with **diminishing returns** (repeat issues still matter, but less each time).
- **Optional signals** (like missing CAID) have **minimal impact**.
- Interpret as:
  - **80–100** → LOW risk (cleaner ads.txt)
  - **55–79** → MEDIUM risk (some questions to ask)
  - **0–54** → HIGH risk (multiple transparency/structure issues)
                """.strip()
            )

        st.divider()

        # --- Findings view (normal users)
        findings: List[Dict[str, Any]] = main_report.get("findings", []) or []
        if findings:
            st.markdown("### Findings")
            sev = st.selectbox("Filter by severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], index=0)
            show = findings if sev == "ALL" else [f for f in findings if f.get("severity") == sev]

            # Compact table view
            rows = []
            for f in show:
                ev = f.get("evidence", {}) or {}
                rows.append(
                    {
                        "Severity": f.get("severity"),
                        "Rule": f.get("rule_id"),
                        "Title": f.get("title"),
                        "Line": ev.get("line_no"),
                        "Evidence": (ev.get("line") or "")[:160],
                    }
                )
            st.dataframe(rows, use_container_width=True, hide_index=True)

            with st.expander("Details (Why buyer cares + what to do)", expanded=False):
                for i, f in enumerate(show[:60], start=1):
                    ev = f.get("evidence", {}) or {}
                    st.markdown(f"**{i}. [{f.get('severity')}] {f.get('title')}**")
                    st.caption(f"Rule: {f.get('rule_id')}")
                    st.write(f"**Why buyer cares:** {f.get('why_buyer_cares')}")
                    st.write(f"**What to do:** {f.get('recommendation')}")
                    if ev.get("line_no") is not None:
                        st.code(f"Line {ev.get('line_no')}: {ev.get('line','')}")
                    elif ev.get("line"):
                        st.code(ev.get("line"))
                    st.write("")

        # --- Sellers.json summary (clean)
        if sellers_report:
            st.divider()
            st.markdown("### Seller verification (sellers.json)")

            summarized = summarize_sellers_report(sellers_report)
            ssum = summarized["summary"]

            a, b, c = st.columns(3)
            a.metric("Domains checked", ssum.get("domains_checked"))
            b.metric("Reachable", ssum.get("reachable"))
            c.metric("Avg match rate", ssum.get("avg_match_rate"))

            # Key callouts
            if summarized["unreachable"]:
                _pill_error(f"Unreachable sellers.json: {len(summarized['unreachable'])} domain(s)")
                st.write("These ad systems did not return valid sellers.json, so verification is limited for them.")
                st.write("• " + "\n• ".join([u.get("domain") for u in summarized["unreachable"][:10]]))
            else:
                _pill_success("All sellers.json endpoints reachable ✅")

            if summarized["zero_match"]:
                _pill_warn(f"0% match (reachable): {len(summarized['zero_match'])} domain(s)")
                st.write("Reachable sellers.json but **none** of the seller IDs matched — this usually deserves a follow-up.")
                st.write("• " + "\n• ".join([z.get("domain") for z in summarized["zero_match"][:10]]))

            if summarized["low_match"]:
                _pill_warn(f"Low match rate (<30%): {len(summarized['low_match'])} domain(s)")
                st.write("Low match rate can mean stale configs, mismatched seller IDs, or unclear selling relationships.")
                st.write("• " + "\n• ".join([l.get("domain") for l in summarized["low_match"][:10]]))

            # Agency / trading desk best-effort signals
            if summarized["agency_hits"]:
                with st.expander("Possible agency / trading desk names detected (best-effort)", expanded=False):
                    st.caption("This is heuristic keyword matching, not a definitive classification.")
                    for dom, ex in summarized["agency_hits"]:
                        st.write(f"• **{dom}** → {ex}")

            # Table (compact + sortable)
            st.markdown("#### Per-domain summary")
            table_rows = []
            for s in summarized["reachable_sorted"]:
                mix = s.get("seller_type_mix") or {}
                mix_str = ", ".join([f"{k}:{v}" for k, v in list(mix.items())[:4]]) if mix else ""
                table_rows.append(
                    {
                        "Domain": s.get("domain"),
                        "HTTP": s.get("status"),
                        "Match rate": s.get("match_rate"),
                        "Seller IDs in ads.txt": s.get("seller_ids_in_ads_txt"),
                        "Matched": s.get("seller_ids_matched"),
                        "Seller type mix": mix_str,
                    }
                )
            if table_rows:
                st.dataframe(table_rows, use_container_width=True, hide_index=True)

            with st.expander("What to ask next (copy/paste)", expanded=False):
                st.markdown(
                    """
**If sellers.json is unreachable**
- “Do you publish a valid sellers.json endpoint? If yes, what is the URL?”
- “Can you confirm you follow IAB sellers.json spec and keep it current?”

**If match rate is 0% or very low**
- “Can you confirm the seller account IDs in ads.txt are correct and current?”
- “Which path do you recommend for our buy (DIRECT where possible)?”

**If INTERMEDIARY / BOTH dominates**
- “Why is this hop needed? Is a more direct route available?”
- “Can you provide a preferred supply path for our deal IDs / inventory?”
                    """.strip()
                )

            # Keep raw available, but not dumped in main UI
            with st.expander("Technical details (raw JSON)", expanded=False):
                st.json(sellers_report)

        # --- Downloads
        st.divider()
        st.markdown("### Export report")
        colA, colB, colC, colD = st.columns(4)

        json_bytes = report_to_json_bytes(main_report)
        txt_bytes = report_to_txt_bytes(main_report)
        csv_bytes = report_to_csv_bytes(main_report)
        pdf_bytes = report_to_pdf_bytes(main_report, sellers_report)

        with colA:
            st.download_button("Download JSON", data=json_bytes, file_name="adchainaudit_report.json", mime="application/json")
        with colB:
            st.download_button("Download TXT", data=txt_bytes, file_name="adchainaudit_report.txt", mime="text/plain")
        with colC:
            st.download_button("Download CSV", data=csv_bytes, file_name="adchainaudit_report.csv", mime="text/csv")
        with colD:
            st.download_button("Download PDF", data=pdf_bytes, file_name="adchainaudit_report.pdf", mime="application/pdf")


if __name__ == "__main__":
    main()
