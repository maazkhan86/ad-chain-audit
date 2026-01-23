# app.py
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import streamlit as st

from analyzer import (
    analyze_ads_txt,
    report_to_csv_bytes,
    report_to_json_bytes,
    report_to_txt_bytes,
)
from phase2_sellers_json import run_sellers_json_verification

# Evidence pack (Phase 2)
try:
    from evidence_locker import zip_run_dir
except Exception:
    zip_run_dir = None  # if you haven't added evidence_locker.py yet


# ----------------------------
# Helpers
# ----------------------------
APP_UA = "AdChainAudit (+https://github.com/maazkhan86/AdChainAudit)"
FETCH_TIMEOUT_S = 8


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_domain_or_url(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    # If user typed a URL, keep it
    if s.startswith("http://") or s.startswith("https://"):
        return s
    # else treat as domain
    s = re.sub(r"^www\.", "", s.strip(), flags=re.IGNORECASE)
    s = s.strip().strip("/")
    return s


def _candidate_ads_urls(domain_or_url: str) -> List[str]:
    s = _normalize_domain_or_url(domain_or_url)
    if not s:
        return []
    if s.startswith("http://") or s.startswith("https://"):
        # If they gave a URL, try it, then try /ads.txt if it looks like a domain root
        u = s
        parsed = urlparse(u)
        base = f"{parsed.scheme}://{parsed.netloc}"
        urls = [u]
        if not u.rstrip("/").endswith("/ads.txt"):
            urls.append(f"{base}/ads.txt")
        # Hardcoded HTTP fallback if HTTPS url was provided
        if parsed.scheme == "https":
            urls.append(u.replace("https://", "http://", 1))
            urls.append(f"http://{parsed.netloc}/ads.txt")
        return list(dict.fromkeys(urls))

    # Domain mode: hardcode https then http fallback
    d = s
    urls = [
        f"https://{d}/ads.txt",
        f"https://www.{d}/ads.txt",
        f"http://{d}/ads.txt",
        f"http://www.{d}/ads.txt",
    ]
    return list(dict.fromkeys(urls))


def fetch_ads_txt(domain_or_url: str) -> Tuple[Optional[str], str, str]:
    """
    Returns (text or None, used_url, debug_message)
    """
    urls = _candidate_ads_urls(domain_or_url)
    if not urls:
        return None, "", "No domain/URL provided."

    last_err = None
    for url in urls:
        try:
            r = requests.get(
                url,
                timeout=FETCH_TIMEOUT_S,
                headers={"User-Agent": APP_UA, "Accept": "text/plain,*/*"},
                allow_redirects=True,
            )
            if r.status_code == 200 and (r.text or "").strip():
                return r.text, url, f"Fetched OK ({r.status_code})."
            last_err = f"{url} → HTTP {r.status_code}"
        except Exception as e:
            last_err = f"{url} → {e}"
    return None, "", f"Fetch failed. Last error: {last_err}"


def load_demo_ads_txt() -> Tuple[str, str]:
    """
    Tries to load a demo sample from repo. Falls back to a small embedded snippet.
    """
    candidates = [
        "samples/thestar_ads_2025-12-14.txt",
        "samples/thestar_ads_2025_12_14.txt",
        "samples/thestar_ads.txt",
        "samples/demo_ads.txt",
        "samples/ads.txt",
        "samples/ads_sample.txt",
    ]
    for p in candidates:
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read(), p
        except Exception:
            pass

    # Fallback tiny snippet (better than nothing)
    fallback = """# Demo ads.txt (sample snippet)
google.com, pub-0000000000000000, DIRECT, f08c47fec0942fa0
rubiconproject.com, 12345, DIRECT, 0bfd66d529a55807
openx.com, 123456789, RESELLER, 6a698e2ec38604c6
"""
    return fallback, "embedded_demo_snippet"


def _severity_rank(sev: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get((sev or "").upper(), 9)


def summarize_phase2_for_humans(seller_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turns the Phase-2 JSON into a clean summary for UI:
      - headline metrics
      - top problematic domains (unreachable / low match)
      - a compact findings summary
    """
    summary = seller_report.get("summary", {}) or {}
    domain_stats = seller_report.get("domain_stats", []) or []
    findings = seller_report.get("findings", []) or []

    # Unreachable domains
    unreachable = [d for d in domain_stats if not d.get("json_ok")]
    unreachable_sorted = sorted(unreachable, key=lambda x: str(x.get("error") or ""))[:10]

    # Low match domains (only among reachable)
    reachable = [d for d in domain_stats if d.get("json_ok")]
    low_match = sorted(reachable, key=lambda x: float(x.get("match_rate") or 0.0))[:10]

    # High match domains (nice to show)
    high_match = sorted(reachable, key=lambda x: float(x.get("match_rate") or 0.0), reverse=True)[:10]

    # Findings summary counts
    by_rule: Dict[str, int] = {}
    by_sev: Dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id", "UNKNOWN")
        sev = (f.get("severity") or "LOW").upper()
        by_rule[rid] = by_rule.get(rid, 0) + 1
        by_sev[sev] = by_sev.get(sev, 0) + 1

    top_rules = sorted(by_rule.items(), key=lambda kv: kv[1], reverse=True)[:6]

    return {
        "headline": {
            "domains_checked": summary.get("domains_checked"),
            "reachable": summary.get("reachable"),
            "unreachable": summary.get("unreachable"),
            "avg_match_rate": summary.get("avg_match_rate"),
            "total_seller_ids_checked": summary.get("total_seller_ids_checked"),
            "total_seller_ids_matched": summary.get("total_seller_ids_matched"),
        },
        "unreachable": unreachable_sorted,
        "low_match": low_match,
        "high_match": high_match,
        "by_severity": by_sev,
        "top_rules": top_rules,
    }


def phase1_report_to_pdf_bytes(report: Dict[str, Any]) -> bytes:
    """
    Simple, readable PDF export for non-technical users.
    Requires: reportlab in requirements.txt
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    meta = report.get("meta", {}) or {}
    sm = report.get("summary", {}) or {}
    findings = report.get("findings", []) or []

    x = 2.0 * cm
    y = h - 2.0 * cm
    line = 14

    def draw(text: str, size: int = 11, bold: bool = False):
        nonlocal y
        font = "Helvetica-Bold" if bold else "Helvetica"
        c.setFont(font, size)
        for part in (text or "").split("\n"):
            if y < 2.0 * cm:
                c.showPage()
                y = h - 2.0 * cm
                c.setFont(font, size)
            c.drawString(x, y, part[:140])
            y -= line

    draw("AdChainAudit Report", size=16, bold=True)
    draw(f"Source: {meta.get('source_label', 'ads.txt')}")
    draw(f"Generated: {meta.get('generated_at', '')}")
    draw("")

    draw(f"Risk score: {sm.get('risk_score')} ({sm.get('risk_level')})", bold=True)
    draw(f"Entries: {sm.get('entry_count')} | Findings: {sm.get('finding_count')}")
    draw(f"DIRECT: {sm.get('direct_count')} | RESELLER: {sm.get('reseller_count')}")
    draw("")

    rc = sm.get("rule_counts", {}) or {}
    if rc:
        draw("Findings by rule:", bold=True)
        for k, v in sorted(rc.items(), key=lambda kv: kv[1], reverse=True):
            draw(f"• {k}: {v}")
        draw("")

    draw("Findings (buyer-relevant):", bold=True)
    for i, f in enumerate(findings[:80], start=1):
        sev = f.get("severity", "")
        title = f.get("title", "")
        why = f.get("why_buyer_cares", "")
        rec = f.get("recommendation", "")
        ev = f.get("evidence", {}) or {}
        ev_line = ev.get("line", "")
        ev_no = ev.get("line_no")

        draw(f"{i}. [{sev}] {title}", bold=True)
        if why:
            draw(f"Why it matters: {why}")
        if ev_no is not None:
            draw(f"Evidence (Line {ev_no}): {ev_line}")
        if rec:
            draw(f"What to do: {rec}")
        draw("")

    c.save()
    return buf.getvalue()


# ----------------------------
# UI
# ----------------------------
st.set_page_config(page_title="AdChainAudit", layout="wide")

st.title("AdChainAudit")
st.caption("Sanity-check a publisher’s ads.txt and verify seller accounts via sellers.json. Built for media and marketing teams.")


# Session state
if "ads_txt_text" not in st.session_state:
    st.session_state.ads_txt_text = ""
if "source_label" not in st.session_state:
    st.session_state.source_label = "ads.txt"
if "input_mode" not in st.session_state:
    st.session_state.input_mode = "none"  # fetched / uploaded / pasted / demo
if "fetched_url" not in st.session_state:
    st.session_state.fetched_url = ""


# ---- Input row (clean, less vertical)
colA, colB, colC = st.columns([1.1, 1.1, 1.0], gap="small")

with colA:
    st.subheader("1) Get ads.txt")
    domain_or_url = st.text_input(
        "Publisher domain or URL",
        placeholder="example.com   or   https://example.com/ads.txt",
        label_visibility="collapsed",
    )
    fetch_clicked = st.button("Fetch ads.txt", use_container_width=True)

    if fetch_clicked:
        txt, used_url, msg = fetch_ads_txt(domain_or_url)
        if txt:
            st.session_state.ads_txt_text = txt
            st.session_state.source_label = used_url or "ads.txt"
            st.session_state.input_mode = "fetched"
            st.session_state.fetched_url = used_url
            st.success("Fetched ✅ You don’t need to upload manually.")
        else:
            st.error("Could not fetch ads.txt. Please upload or paste it instead.")
            st.caption(msg)

with colB:
    st.subheader("2) Upload (optional)")
    up = st.file_uploader("Upload ads.txt", type=["txt"], label_visibility="collapsed")
    if up is not None:
        try:
            txt = up.read().decode("utf-8", errors="replace")
        except Exception:
            txt = str(up.read())
        st.session_state.ads_txt_text = txt
        st.session_state.source_label = up.name or "uploaded_ads.txt"
        st.session_state.input_mode = "uploaded"
        st.session_state.fetched_url = ""
        st.success("Uploaded ✅")

    demo_clicked = st.button("Load demo sample", use_container_width=True)
    if demo_clicked:
        demo_text, demo_path = load_demo_ads_txt()
        st.session_state.ads_txt_text = demo_text
        st.session_state.source_label = demo_path
        st.session_state.input_mode = "demo"
        st.session_state.fetched_url = ""
        st.error("Demo input loaded (for testing).")
        st.error("Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). ads.txt changes over time; treat this as a demo input.")

with colC:
    st.subheader("3) Paste (optional)")
    with st.expander("Paste ads.txt text here"):
        pasted = st.text_area(
            "Paste ads.txt",
            value="",
            height=220,
            placeholder="Paste the full ads.txt content here…",
            label_visibility="collapsed",
        )
        if st.button("Use pasted text", use_container_width=True):
            if (pasted or "").strip():
                st.session_state.ads_txt_text = pasted
                st.session_state.source_label = "pasted_ads.txt"
                st.session_state.input_mode = "pasted"
                st.session_state.fetched_url = ""
                st.success("Pasted ✅")
            else:
                st.warning("Nothing pasted.")


# Current input status (compact)
mode = st.session_state.input_mode
src = st.session_state.source_label
if mode != "none" and (st.session_state.ads_txt_text or "").strip():
    badge = {
        "fetched": "Fetched ✅",
        "uploaded": "Uploaded ✅",
        "pasted": "Pasted ✅",
        "demo": "Demo ✅",
    }.get(mode, "Ready ✅")
    st.info(f"{badge}  |  Input source: {src}")
else:
    st.warning("Add an ads.txt input (fetch, upload, or paste) to run the audit.")


st.divider()

# Controls (keep simple)
left, right = st.columns([1.2, 1.0], gap="small")
with left:
    run_phase2 = st.checkbox("Also verify seller accounts (sellers.json)", value=True)

with right:
    run_btn = st.button("Run audit", type="primary", use_container_width=True)


# ----------------------------
# Run analysis
# ----------------------------
if run_btn:
    text = (st.session_state.ads_txt_text or "").strip()
    if not text:
        st.error("No ads.txt content found. Please fetch, upload, or paste first.")
        st.stop()

    # Phase 1 (hardcode: no optional checks)
    report = analyze_ads_txt(
        text=text,
        source_label=st.session_state.source_label or "ads.txt",
        include_optional_checks=False,
    )

    sm = report.get("summary", {}) or {}
    risk_score = sm.get("risk_score", 0)
    risk_level = sm.get("risk_level", "UNKNOWN")
    findings = report.get("findings", []) or []

    # Headline
    topA, topB, topC, topD = st.columns(4)
    topA.metric("Risk score", int(risk_score))
    topB.metric("Risk level", str(risk_level))
    topC.metric("ads.txt entries", int(sm.get("entry_count", 0)))
    topD.metric("Red flags found", int(sm.get("finding_count", 0)))

    # Plain-English summary
    if findings:
        st.write(
            "Summary: This ads.txt has potential supply-path red flags that may introduce extra hops, reselling, or ambiguity. "
            "Use the findings below as a checklist for what to ask your agency, SSP, or publisher."
        )
    else:
        st.success("Summary: No obvious formatting or relationship red flags detected based on current rules.")

    # Findings (clean)
    if findings:
        # Sort by severity
        findings_sorted = sorted(findings, key=lambda f: _severity_rank(f.get("severity")))
        rows = []
        for f in findings_sorted:
            ev = f.get("evidence", {}) or {}
            rows.append(
                {
                    "Severity": f.get("severity"),
                    "Rule": f.get("rule_id"),
                    "Finding": f.get("title"),
                    "Line #": ev.get("line_no"),
                    "Evidence": (ev.get("line") or "")[:180],
                    "Why buyer cares": f.get("why_buyer_cares"),
                    "What to do": f.get("recommendation"),
                }
            )
        with st.expander("View findings"):
            st.dataframe(rows, use_container_width=True, hide_index=True)

    # Downloads (Phase 1)
    st.subheader("Download report")
    d1, d2, d3, d4 = st.columns(4)
    with d1:
        st.download_button(
            "TXT",
            data=report_to_txt_bytes(report),
            file_name="adchainaudit_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "CSV",
            data=report_to_csv_bytes(report),
            file_name="adchainaudit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with d3:
        st.download_button(
            "JSON",
            data=report_to_json_bytes(report),
            file_name="adchainaudit_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with d4:
        try:
            pdf_bytes = phase1_report_to_pdf_bytes(report)
            st.download_button(
                "PDF",
                data=pdf_bytes,
                file_name="adchainaudit_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as e:
            st.caption(f"PDF export unavailable: {e}")

    # ----------------------------
    # Phase 2 (Seller verification + Evidence locker)
    # ----------------------------
    if run_phase2:
        st.divider()
        st.subheader("Seller verification (sellers.json)")

        with st.spinner("Fetching sellers.json and verifying seller accounts…"):
            seller_report = run_sellers_json_verification(
                ads_txt_text=text,
                source_label=st.session_state.source_label or "ads.txt",
                evidence_locker_enabled=True,   # hardcoded ON
                evidence_base_dir="evidence",
            )

        s2 = summarize_phase2_for_humans(seller_report)
        h = s2["headline"]

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Domains checked", int(h.get("domains_checked") or 0))
        m2.metric("Reachable", int(h.get("reachable") or 0))
        m3.metric("Unreachable", int(h.get("unreachable") or 0))
        m4.metric("Avg match rate", float(h.get("avg_match_rate") or 0.0))
        m5.metric("Seller IDs matched", f"{int(h.get('total_seller_ids_matched') or 0)}/{int(h.get('total_seller_ids_checked') or 0)}")

        st.write(
            "What this means: For each ad system listed in ads.txt, AdChainAudit tries to retrieve its sellers.json and checks "
            "whether the seller IDs in ads.txt appear there. Low match rates or unreachable sellers.json are not always ‘fraud’, "
            "but they are useful signals to ask better questions about authorization and extra hops."
        )

        # Compact “what to look at”
        sev_counts = s2["by_severity"] or {}
        if sev_counts:
            st.caption(
                "Signals found: "
                + ", ".join([f"{k}: {sev_counts.get(k, 0)}" for k in ["HIGH", "MEDIUM", "LOW"] if k in sev_counts])
            )

        # Show top issues cleanly
        colX, colY = st.columns(2, gap="small")

        with colX:
            if s2["unreachable"]:
                st.warning("Unreachable / invalid sellers.json (top):")
                rows = []
                for d in s2["unreachable"]:
                    rows.append(
                        {
                            "Domain": d.get("domain"),
                            "Status": d.get("status"),
                            "Reason": (d.get("error") or "")[:160],
                        }
                    )
                st.dataframe(rows, use_container_width=True, hide_index=True)
            else:
                st.success("All checked sellers.json were reachable and valid JSON.")

        with colY:
            if s2["low_match"]:
                st.info("Lowest match rates (reachable sellers.json):")
                rows = []
                for d in s2["low_match"]:
                    rows.append(
                        {
                            "Domain": d.get("domain"),
                            "Match rate": d.get("match_rate"),
                            "IDs in ads.txt": d.get("seller_ids_in_ads_txt"),
                            "IDs matched": d.get("seller_ids_matched"),
                        }
                    )
                st.dataframe(rows, use_container_width=True, hide_index=True)
            else:
                st.success("No low-match domains detected among reachable sellers.json.")

        with st.expander("Show highest match rates (sanity check)"):
            rows = []
            for d in s2["high_match"]:
                rows.append(
                    {
                        "Domain": d.get("domain"),
                        "Match rate": d.get("match_rate"),
                        "IDs in ads.txt": d.get("seller_ids_in_ads_txt"),
                        "IDs matched": d.get("seller_ids_matched"),
                    }
                )
            st.dataframe(rows, use_container_width=True, hide_index=True)

        with st.expander("Findings summary (top rules)"):
            top_rules = s2["top_rules"] or []
            if top_rules:
                st.write(
                    "\n".join([f"• **{rid}**: {cnt}" for rid, cnt in top_rules])
                )
            else:
                st.write("No findings summary available.")

        # Evidence pack download
        ev = (seller_report.get("evidence") or {})
        run_dir = ev.get("run_dir")
        run_id = ev.get("run_id")

        if run_id and run_dir and zip_run_dir:
            st.success(f"Evidence saved: {run_id}")
            try:
                zip_name, zip_bytes = zip_run_dir(run_dir)
                st.download_button(
                    "Download evidence pack (ZIP)",
                    data=zip_bytes,
                    file_name=zip_name,
                    mime="application/zip",
                    use_container_width=False,
                )
                st.caption("Includes input ads.txt, fetched sellers.json bodies, manifest, and Phase 2 report JSON.")
            except Exception as e:
                st.warning(f"Evidence pack was saved, but ZIP creation failed: {e}")
        elif ev.get("enabled") is False:
            st.caption("Evidence locker is disabled.")
        else:
            st.caption("Evidence locker not available (did you add evidence_locker.py?).")

        # Optional: raw details (kept behind expanders so UI stays clean)
        with st.expander("Show detailed domain table"):
            st.dataframe(seller_report.get("domain_stats", []), use_container_width=True, hide_index=True)

        with st.expander("Show raw Phase 2 JSON (for debugging)"):
            st.json(seller_report)
