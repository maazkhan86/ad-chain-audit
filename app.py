# app.py
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import List, Optional, Tuple

import streamlit as st
import requests

from analyzer import (
    analyze_ads_txt,
    report_to_csv_bytes,
    report_to_json_bytes,
    report_to_txt_bytes,
)
from phase2_sellers_json import run_sellers_json_verification

# --- Links ---
APP_TITLE = "AdChainAudit"
REPO_URL = "https://github.com/maazkhan86/AdChainAudit"
WEB_APP_URL = "https://adchainaudit.streamlit.app/"

# --- Sample ---
SAMPLE_PATH_CANDIDATES = [
    "samples/thestar_ads.txt",
    "samples/sample_ads.txt",
    "ads.txt",  # fallback if you kept it at repo root
]
SAMPLE_BANNER_TEXT = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)

# --- Hardcoded behavior (no UI toggles) ---
TRY_HTTP_IF_HTTPS_FAILS = True
CAPTURE_FETCH_DEBUG_ALWAYS = True
INCLUDE_OPTIONAL_SIGNALS_ALWAYS = True
VERIFY_SELLER_ACCOUNTS_ALWAYS = True

# --- Report display caps ---
MAX_FINDINGS_SHOWN = 75


@dataclass
class FetchAttempt:
    url: str
    ok: bool
    status: Optional[int]
    content_type: Optional[str]
    size_bytes: Optional[int]
    error: Optional[str]


def _now_utc_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def normalize_domain(raw: str) -> str:
    raw = (raw or "").strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    raw = raw.strip().strip("/")
    raw = raw.replace("www.", "", 1) if raw.lower().startswith("www.") else raw
    return raw


def build_ads_txt_urls(domain: str) -> List[str]:
    https_urls = [f"https://{domain}/ads.txt", f"https://www.{domain}/ads.txt"]
    if not TRY_HTTP_IF_HTTPS_FAILS:
        return https_urls
    http_urls = [f"http://{domain}/ads.txt", f"http://www.{domain}/ads.txt"]
    return https_urls + http_urls


def looks_like_html(text: str) -> bool:
    head = (text or "").lstrip()[:300].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


def fetch_url(url: str, timeout_s: int = 12) -> Tuple[Optional[str], FetchAttempt]:
    headers = {
        "User-Agent": "AdChainAudit/1.0 (+https://github.com/maazkhan86/AdChainAudit)",
        "Accept": "text/plain, text/*;q=0.9, */*;q=0.1",
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True)
        ct = r.headers.get("content-type")
        attempt = FetchAttempt(
            url=url,
            ok=(r.status_code == 200),
            status=r.status_code,
            content_type=ct,
            size_bytes=len(r.content) if r.content is not None else None,
            error=None if r.status_code == 200 else f"Non-200 status ({r.status_code})",
        )
        if r.status_code != 200:
            return None, attempt

        text = r.text or ""
        if looks_like_html(text):
            return None, FetchAttempt(
                url=url,
                ok=False,
                status=r.status_code,
                content_type=ct,
                size_bytes=len(r.content) if r.content is not None else None,
                error="Looks like HTML (possible block page / WAF)",
            )

        return text, attempt

    except requests.RequestException as e:
        return None, FetchAttempt(
            url=url,
            ok=False,
            status=None,
            content_type=None,
            size_bytes=None,
            error=str(e),
        )


def fetch_ads_txt_for_domain(domain: str) -> Tuple[Optional[str], Optional[str], List[FetchAttempt]]:
    attempts: List[FetchAttempt] = []
    for url in build_ads_txt_urls(domain):
        text, attempt = fetch_url(url)
        attempts.append(attempt)
        if text:
            return text, url, attempts
    return None, None, attempts


def load_sample_text() -> Optional[str]:
    for p in SAMPLE_PATH_CANDIDATES:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            continue
    return None


def init_state() -> None:
    st.session_state.setdefault("ads_txt_text", "")
    st.session_state.setdefault("input_source", "None")
    st.session_state.setdefault("fetched_url", None)
    st.session_state.setdefault("fetched_at", None)
    st.session_state.setdefault("fetch_attempts", [])
    st.session_state.setdefault("last_fetch_domain", "")
    st.session_state.setdefault("last_fetch_ok", False)
    st.session_state.setdefault("sample_loaded", False)


def set_ads_input(text: str, source: str, fetched_url: Optional[str] = None, sample_loaded: bool = False) -> None:
    st.session_state["ads_txt_text"] = text or ""
    st.session_state["input_source"] = source
    st.session_state["fetched_url"] = fetched_url
    st.session_state["fetched_at"] = _now_utc_label() if fetched_url else None
    st.session_state["sample_loaded"] = sample_loaded


def get_effective_text(uploaded_file) -> str:
    if uploaded_file is not None:
        try:
            return uploaded_file.getvalue().decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return st.session_state.get("ads_txt_text", "") or ""


def render_visible_sample_banner() -> None:
    if st.session_state.get("sample_loaded"):
        st.markdown(
            f"""
            <div style="
                background:#ffe5e5;
                border:1px solid #ff4d4f;
                color:#7a1f1f;
                padding:10px 12px;
                border-radius:10px;
                margin-top:8px;
                margin-bottom:8px;
                font-weight:600;
            ">
                ✅ Sample loaded. {SAMPLE_BANNER_TEXT}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_fetch_success_banner() -> None:
    if st.session_state.get("last_fetch_ok") and st.session_state.get("fetched_url"):
        url = st.session_state.get("fetched_url")
        when = st.session_state.get("fetched_at")
        st.success(f"Fetched ✅ ads.txt loaded from: {url} • {when}")


def report_to_pdf_bytes(report: dict) -> bytes:
    # Simple PDF export with ReportLab
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    x = 48
    y = height - 56
    line_h = 14

    def draw_line(text: str, bold: bool = False):
        nonlocal y
        if y < 56:
            c.showPage()
            y = height - 56
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 11 if bold else 10)
        c.drawString(x, y, text[:140])
        y -= line_h

    # Header
    draw_line("AdChainAudit report", bold=True)
    draw_line(f"Source: {report.get('source_label')}", bold=False)
    draw_line(f"Generated: {report.get('generated_at')}", bold=False)
    draw_line("", bold=False)

    # Summary
    draw_line("Summary", bold=True)
    draw_line(f"Risk score: {report.get('risk_score')} ({report.get('risk_level')})")
    draw_line(f"Entries: {report.get('entries')} • Findings: {report.get('findings_count')}")
    dc = report.get("direct_count")
    rc = report.get("reseller_count")
    if dc is not None and rc is not None:
        draw_line(f"DIRECT: {dc} • RESELLER: {rc}")
    one = report.get("one_liner")
    if one:
        draw_line(one)
    draw_line("", bold=False)

    # Findings
    draw_line("Buyer-relevant red flags (top)", bold=True)
    findings = report.get("findings", []) if isinstance(report, dict) else []
    for i, f in enumerate(findings[:MAX_FINDINGS_SHOWN], start=1):
        sev = (f.get("severity") or "UNKNOWN").upper()
        title = f.get("title") or "Finding"
        draw_line(f"{i}. [{sev}] {title}", bold=True)

        why = f.get("why_buyer_cares") or ""
        if why:
            draw_line(f"Why: {why}")

        rec = f.get("recommendation") or ""
        if rec:
            draw_line(f"Do: {rec}")

        ev = f.get("evidence") or {}
        ln = ev.get("line_no")
        line = ev.get("line")
        if ln is not None and line:
            draw_line(f"Evidence (L{ln}): {str(line)[:120]}")

        draw_line("", bold=False)

    if len(findings) > MAX_FINDINGS_SHOWN:
        draw_line(f"(Showing first {MAX_FINDINGS_SHOWN} of {len(findings)} findings.)")

    c.save()
    return buf.getvalue()


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_state()

    # Header
    left, right = st.columns([0.78, 0.22])
    with left:
        st.title(APP_TITLE)
        st.caption(
            "Audit the ad supply chain starting with ads.txt. Upload, paste, or fetch a site’s ads.txt to generate a buyer-focused red-flag summary."
        )
    with right:
        st.link_button("🧰 GitHub (technical)", REPO_URL, use_container_width=True)

    # Top actions (keep clean)
    a1, a2 = st.columns([0.52, 0.48])
    with a1:
        if st.button("⚡ Try sample ads.txt", use_container_width=True):
            sample = load_sample_text()
            if not sample:
                st.error("Sample file not found. Add one under `samples/` (e.g., `samples/thestar_ads.txt`).")
            else:
                set_ads_input(
                    sample,
                    source="Sample",
                    fetched_url=None,
                    sample_loaded=True,
                )
                st.session_state["last_fetch_ok"] = True
                st.toast("Sample loaded ✅", icon="✅")

    with a2:
        # (User asked to remove the “Open web app” button previously; so we don’t show it.)
        st.markdown("")

    render_visible_sample_banner()

    st.divider()

    # Fetch section (compact)
    st.subheader("Get ads.txt")
    f1, f2 = st.columns([0.72, 0.28])
    with f1:
        domain = st.text_input(
            "Website domain",
            value=st.session_state.get("last_fetch_domain", ""),
            placeholder="example.com",
        )
    with f2:
        st.markdown(" ")
        if st.button("🌐 linker Fetch ads.txt".replace("linker ", ""), use_container_width=True):
            nd = normalize_domain(domain)
            st.session_state["last_fetch_domain"] = nd
            st.session_state["last_fetch_ok"] = False
            st.session_state["sample_loaded"] = False

            if not nd:
                st.warning("Please enter a domain (e.g., example.com).")
            else:
                with st.spinner(f"Fetching ads.txt for {nd} (HTTPS → HTTP fallback)…"):
                    text, url, attempts = fetch_ads_txt_for_domain(nd)

                if CAPTURE_FETCH_DEBUG_ALWAYS:
                    st.session_state["fetch_attempts"] = attempts

                if text and url:
                    set_ads_input(text, source=f"Fetched ({nd})", fetched_url=url, sample_loaded=False)
                    st.session_state["last_fetch_ok"] = True
                    st.toast("Fetched ✅", icon="✅")
                else:
                    st.error("Couldn’t fetch ads.txt (possibly blocked). Please upload or paste it below.")
                    # Auto-show debug on failure (still hardcoded)
                    with st.expander("Fetch attempts (debug)", expanded=False):
                        for a in st.session_state.get("fetch_attempts", []):
                            st.write(
                                f"- {a.url} | ok={a.ok} | status={a.status} | ct={a.content_type} | err={a.error}"
                            )

    render_fetch_success_banner()

    st.markdown("")

    # Manual option (always works)
    with st.expander("Manual option (always works)", expanded=False):
        st.write("Quick ways to get ads.txt:")
        st.markdown(
            "- Open `https://<site>/ads.txt` (try with and without `www`).\n"
            "- Copy the full text and paste it in the **Paste ads.txt** tab.\n"
            "- Or download it as a `.txt` file and upload it."
        )

    st.divider()

    # Inputs
    tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

    uploaded = None
    with tab_upload:
        uploaded = st.file_uploader("Upload an ads.txt file", type=["txt"])
        if uploaded is not None:
            st.session_state["sample_loaded"] = False
            st.toast("File selected ✅", icon="✅")

    with tab_paste:
        st.session_state["ads_txt_text"] = st.text_area(
            "Paste ads.txt contents",
            value=st.session_state.get("ads_txt_text", ""),
            height=220,
            placeholder="Paste the full ads.txt text here…",
        )

    st.caption("Defaults enabled: optional signals ✅ • sellers.json verification ✅ • auto HTTPS→HTTP fallback ✅")

    st.divider()

    # Scoring explainer (requested)
    with st.expander("How the score works (simple)", expanded=False):
        st.markdown(
            "- **Risk score** is **0–100**. Higher means “cleaner / lower-risk signals” based on current rules.\n"
            "- Score uses **severity weights** with **diminishing returns** (repeated issues matter, but not linearly).\n"
            "- **Risk level** is derived from score: **LOW ≥ 80**, **MEDIUM 55–79**, **HIGH < 55**.\n"
            "- This is a **buyer-focused sanity check**, not a full guarantee."
        )

    # Run audit
    if st.button("🔎 Run audit", type="primary"):
        text = get_effective_text(uploaded)
        if not text.strip():
            st.warning("Please fetch, upload, or paste an ads.txt first.")
            st.stop()

        source_label = st.session_state.get("input_source") or "ads.txt"
        if st.session_state.get("fetched_url"):
            source_label = f"{source_label} • {st.session_state.get('fetched_url')}"

        with st.spinner("Analyzing ads.txt…"):
            report = analyze_ads_txt(
                text=text,
                source_label=source_label,
                include_optional_checks=INCLUDE_OPTIONAL_SIGNALS_ALWAYS,
            )

        # Phase 2: sellers.json verification (hardcoded ON)
        sellers_section = None
        if VERIFY_SELLER_ACCOUNTS_ALWAYS:
            with st.spinner("Verifying seller accounts via sellers.json (this can take a bit)…"):
                try:
                    sellers_section = run_sellers_json_verification(text)
                except TypeError:
                    sellers_section = run_sellers_json_verification(ads_txt_text=text)
                except Exception as e:
                    sellers_section = {"ok": False, "error": str(e)}

        if isinstance(report, dict) and sellers_section is not None:
            report["sellers_json_verification"] = sellers_section

        # --- Use top-level keys from revised analyzer.py ---
        findings = report.get("findings", []) if isinstance(report, dict) else []

        risk_score = report.get("risk_score")
        risk_level = report.get("risk_level")
        entries = report.get("entries")
        findings_count = report.get("findings_count", len(findings))
        one_liner = report.get("one_liner")
        sev_counts = report.get("severity_counts", {})

        # Metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk score", str(risk_score) if risk_score is not None else "—")
        m2.metric("Risk level", str(risk_level) if risk_level else "—")
        m3.metric("Findings", str(findings_count))
        m4.metric("Entries", str(entries) if entries is not None else "—")

        # Summary
        st.subheader("Summary")
        if one_liner:
            st.write(one_liner)
        else:
            parts = []
            for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                v = sev_counts.get(k, 0) if isinstance(sev_counts, dict) else 0
                if v:
                    parts.append(f"{k}: {v}")
            breakdown = ", ".join(parts) if parts else "No flags"
            st.write(f"Found **{findings_count}** buyer-relevant flags. Breakdown: {breakdown}")

        # Findings
        st.subheader("Buyer-relevant red flags")
        if not findings:
            st.write("Nothing to show yet.")
        else:
            for i, f in enumerate(findings[:MAX_FINDINGS_SHOWN], start=1):
                title = f.get("title") or "Finding"
                sev = (f.get("severity") or "UNKNOWN").upper()
                why = f.get("why_buyer_cares") or ""
                rec = f.get("recommendation") or ""
                ev = f.get("evidence") or {}
                line_no = ev.get("line_no")
                line = ev.get("line")

                with st.expander(f"[{sev}] {title}", expanded=(i <= 6)):
                    if why:
                        st.write(why)
                    if rec:
                        st.write(f"**What to do:** {rec}")
                    if line_no is not None:
                        st.caption(f"Line: {line_no}")
                    if line:
                        st.code(str(line)[:2000])

            if len(findings) > MAX_FINDINGS_SHOWN:
                st.caption(f"Showing first {MAX_FINDINGS_SHOWN} of {len(findings)} findings.")

        # Sellers.json section
        if sellers_section is not None:
            st.subheader("Seller verification (sellers.json)")
            if isinstance(sellers_section, dict) and sellers_section.get("error"):
                st.warning(
                    "Sellers.json verification ran, but the fetch may be blocked for some domains. "
                    "The ads.txt audit still works."
                )
                st.caption(f"Error: {sellers_section.get('error')}")
            st.json(sellers_section)

        # Export
        st.subheader("Export report")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.download_button(
                "⬇️ JSON",
                data=report_to_json_bytes(report),
                file_name="adchainaudit_report.json",
                mime="application/json",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                "⬇️ TXT",
                data=report_to_txt_bytes(report),
                file_name="adchainaudit_report.txt",
                mime="text/plain",
                use_container_width=True,
            )
        with c3:
            st.download_button(
                "⬇️ CSV",
                data=report_to_csv_bytes(report),
                file_name="adchainaudit_findings.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c4:
            st.download_button(
                "⬇️ PDF",
                data=report_to_pdf_bytes(report),
                file_name="adchainaudit_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )

    st.caption("Built in public. Feedback, feature ideas, and collaborators welcome 🤝")


if __name__ == "__main__":
    main()
