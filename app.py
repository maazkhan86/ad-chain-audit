# app.py
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import streamlit as st

# Your existing modules (keep these file names the same in your repo)
from analyzer import analyze_ads_txt
from phase2_sellers_json import run_sellers_json_verification

# ---- Config ----
APP_TITLE = "AdChainAudit"
REPO_URL = "https://github.com/maazkhan86/AdChainAudit"
WEB_APP_URL = "https://adchainaudit.streamlit.app/"

# If you keep a sample file in your repo, put it under samples/sample_ads.txt
# Example: samples/thestar_ads.txt
SAMPLE_PATH_CANDIDATES = [
    "samples/thestar_ads.txt",
    "samples/sample_ads.txt",
    "ads.txt",  # fallback if you keep it in root
]

# Fetch behavior (hardcoded ON)
TRY_HTTP_IF_HTTPS_FAILS = True
CAPTURE_FETCH_DEBUG_ALWAYS = True
INCLUDE_OPTIONAL_SIGNALS_ALWAYS = True
VERIFY_SELLER_ACCOUNTS_ALWAYS = True

# ---- Optional dependency: requests ----
# Add `requests>=2.31` in requirements.txt if not already.
import requests


@dataclass
class FetchAttempt:
    url: str
    ok: bool
    status: Optional[int]
    content_type: Optional[str]
    size_bytes: Optional[int]
    error: Optional[str]


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def normalize_domain(raw: str) -> str:
    raw = (raw or "").strip()
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)
    raw = raw.strip().strip("/")
    raw = raw.replace("www.", "", 1) if raw.lower().startswith("www.") else raw
    return raw


def build_ads_txt_urls(domain: str) -> List[str]:
    # Try both apex and www
    https_urls = [
        f"https://{domain}/ads.txt",
        f"https://www.{domain}/ads.txt",
    ]
    if not TRY_HTTP_IF_HTTPS_FAILS:
        return https_urls

    http_urls = [
        f"http://{domain}/ads.txt",
        f"http://www.{domain}/ads.txt",
    ]
    return https_urls + http_urls


def looks_like_html(text: str) -> bool:
    head = (text or "").lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<body" in head


def fetch_url(url: str, timeout_s: int = 12) -> Tuple[Optional[str], FetchAttempt]:
    headers = {
        "User-Agent": "AdChainAudit/1.0 (+https://github.com/maazkhan86/AdChainAudit)",
        "Accept": "text/plain, text/*;q=0.9, */*;q=0.1",
    }
    try:
        r = requests.get(url, headers=headers, timeout=timeout_s, allow_redirects=True)
        ct = r.headers.get("content-type")
        text = r.text if r.status_code == 200 else None

        attempt = FetchAttempt(
            url=url,
            ok=(r.status_code == 200),
            status=r.status_code,
            content_type=ct,
            size_bytes=len(r.content) if r.content is not None else None,
            error=None if r.status_code == 200 else f"Non-200 status ({r.status_code})",
        )

        # Some sites return 200 but serve HTML block pages
        if text and looks_like_html(text):
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


def set_ads_input(text: str, source: str, fetched_url: Optional[str] = None) -> None:
    st.session_state["ads_txt_text"] = text or ""
    st.session_state["input_source"] = source
    st.session_state["fetched_url"] = fetched_url
    st.session_state["fetched_at"] = _now_utc_iso() if source.startswith("Fetched") else None


def get_effective_text(uploaded_file) -> str:
    # Prefer uploaded file if present; else use textarea / fetched content
    if uploaded_file is not None:
        try:
            return uploaded_file.getvalue().decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return st.session_state.get("ads_txt_text", "") or ""


def safe_get_findings(report: Dict) -> List[Dict]:
    if not isinstance(report, dict):
        return []
    for k in ["findings", "issues", "flags", "results"]:
        v = report.get(k)
        if isinstance(v, list):
            return v
    return []


def render_fetch_success_banner() -> None:
    if st.session_state.get("input_source", "").startswith("Fetched") and st.session_state.get("last_fetch_ok"):
        url = st.session_state.get("fetched_url")
        when = st.session_state.get("fetched_at")
        st.success(
            f"Fetched ✅ ads.txt loaded from: {url}  •  {when}\n\nYou can now click **Run audit** (no manual upload/paste needed)."
        )


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, layout="wide")
    init_state()

    # Header
    c1, c2 = st.columns([0.78, 0.22])
    with c1:
        st.title(APP_TITLE)
        st.caption("Audit the ad supply chain starting with ads.txt. Upload, paste, or fetch a site’s ads.txt to generate a buyer-focused red-flag summary.")

    with c2:
        st.markdown("")
        st.link_button("🧰 GitHub (technical)", REPO_URL, use_container_width=True)

    # Quick actions row
    qa1, qa2 = st.columns([0.5, 0.5])
    with qa1:
        if st.button("⚡ Try sample ads.txt", use_container_width=True):
            sample = load_sample_text()
            if not sample:
                st.error("Sample file not found in repo. Add one under `samples/` (e.g., `samples/sample_ads.txt`).")
            else:
                set_ads_input(
                    sample,
                    source="Sample (thestar.com.my/ads.txt captured 14 Dec 2025)",
                    fetched_url=None,
                )
                st.session_state["last_fetch_ok"] = True  # treat as “loaded”
                st.toast("Sample loaded ✅", icon="✅")

    with qa2:
        st.link_button("🌐 Open web app", WEB_APP_URL, use_container_width=True)

    st.divider()

    # Fetch section (clean + compact)
    with st.expander("Get ads.txt (optional)", expanded=True):
        left, right = st.columns([0.7, 0.3])

        with left:
            domain = st.text_input(
                "Website domain",
                value=st.session_state.get("last_fetch_domain", ""),
                placeholder="example.com",
                label_visibility="visible",
            )

        with right:
            st.markdown(" ")
            if st.button("🌐 Fetch ads.txt", use_container_width=True):
                nd = normalize_domain(domain)
                st.session_state["last_fetch_domain"] = nd
                st.session_state["last_fetch_ok"] = False

                if not nd:
                    st.warning("Please enter a domain (e.g., `example.com`).")
                else:
                    with st.spinner(f"Fetching ads.txt for {nd} ..."):
                        text, url, attempts = fetch_ads_txt_for_domain(nd)

                    if CAPTURE_FETCH_DEBUG_ALWAYS:
                        st.session_state["fetch_attempts"] = attempts

                    if text and url:
                        set_ads_input(text, source=f"Fetched ({nd})", fetched_url=url)
                        st.session_state["last_fetch_ok"] = True
                        st.toast("Fetched ✅", icon="✅")
                    else:
                        set_ads_input(st.session_state.get("ads_txt_text", ""), source="(unchanged)")
                        st.error("Couldn’t fetch ads.txt (possibly blocked). Please use Upload or Paste below.")

                        # Show debug automatically only on failure (still “hardcoded” in code)
                        if st.session_state.get("fetch_attempts"):
                            with st.expander("Fetch attempts (debug)", expanded=False):
                                for a in st.session_state["fetch_attempts"]:
                                    st.write(
                                        f"- {a.url} | ok={a.ok} | status={a.status} | ct={a.content_type} | err={a.error}"
                                    )

    # ✅ Very visible banner when fetched/loaded
    render_fetch_success_banner()

    st.divider()

    # Hardcoded ON (no checkboxes)
    st.caption("Defaults: optional signals ✅ • sellers.json verification ✅ • auto HTTPS→HTTP fallback ✅")

    # Input tabs
    tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

    uploaded = None
    with tab_upload:
        uploaded = st.file_uploader("Upload an ads.txt file", type=["txt"], label_visibility="visible")
        if uploaded is not None:
            set_ads_input("", source="Uploaded file", fetched_url=None)
            st.session_state["last_fetch_ok"] = True
            st.toast("File selected ✅", icon="✅")

    with tab_paste:
        st.session_state["ads_txt_text"] = st.text_area(
            "Paste ads.txt contents",
            value=st.session_state.get("ads_txt_text", ""),
            height=220,
            placeholder="Paste the full ads.txt text here…",
        )

    st.divider()

    # Run audit
    if st.button("🔎 Run audit", type="primary"):
        text = get_effective_text(uploaded)
        if not text.strip():
            st.warning("Please upload or paste an ads.txt (or fetch one).")
            st.stop()

        # Source label for report
        source_label = st.session_state.get("input_source", "Manual input")
        fetched_url = st.session_state.get("fetched_url")
        if fetched_url:
            source_label = f"{source_label} • {fetched_url}"

        # Phase 1 analysis (optional signals hardcoded ON)
        with st.spinner("Analyzing ads.txt…"):
            report = analyze_ads_txt(
                text=text,
                source_label=source_label,
                include_optional_checks=INCLUDE_OPTIONAL_SIGNALS_ALWAYS,
            )

        # Phase 2 sellers.json verification (hardcoded ON)
        sellers_section = None
        if VERIFY_SELLER_ACCOUNTS_ALWAYS:
            with st.spinner("Verifying seller accounts via sellers.json (this can take a bit)…"):
                try:
                    sellers_section = run_sellers_json_verification(text)
                except TypeError:
                    # In case your function signature differs
                    sellers_section = run_sellers_json_verification(ads_txt_text=text)
                except Exception as e:
                    sellers_section = {"error": str(e), "ok": False}

        # Merge seller verification into report (safe)
        if isinstance(report, dict) and sellers_section is not None:
            report["sellers_json_verification"] = sellers_section

        # ---- Render summary ----
        findings = safe_get_findings(report)
        total_entries = report.get("total_entries") or report.get("entries") or report.get("lines") or None
        risk_score = report.get("risk_score")
        risk_level = report.get("risk_level") or report.get("overall_risk") or "—"

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk score", str(risk_score) if risk_score is not None else "—")
        m2.metric("Risk level", str(risk_level))
        m3.metric("Findings", str(len(findings)))
        m4.metric("Entries", str(total_entries) if total_entries is not None else "—")

        # Short narrative summary (robust)
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or f.get("level") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        if findings:
            st.subheader("Summary")
            st.write(
                f"Found **{len(findings)}** buyer-relevant flags. Breakdown: "
                + ", ".join([f"**{k}**: {v}" for k, v in sorted(sev_counts.items(), key=lambda x: (-x[1], x[0]))])
            )
        else:
            st.info("No findings detected (based on current rule set).")

        st.subheader("Buyer-relevant red flags")
        if not findings:
            st.write("Nothing to show yet.")
        else:
            # Show first 50 expanded list (keep page readable)
            for i, f in enumerate(findings[:50], start=1):
                title = f.get("title") or f.get("name") or "Finding"
                sev = (f.get("severity") or f.get("level") or "UNKNOWN").upper()
                why = f.get("why") or f.get("buyer_impact") or f.get("message") or ""
                evidence = f.get("evidence") or ""
                line_no = f.get("line") or f.get("line_no")

                header = f"[{sev}] {title}"
                with st.expander(header, expanded=(i <= 5)):
                    if why:
                        st.write(why)
                    if line_no is not None:
                        st.caption(f"Line: {line_no}")
                    if evidence:
                        st.code(str(evidence)[:2000])

            if len(findings) > 50:
                st.caption(f"Showing first 50 of {len(findings)} findings.")

        # Show sellers.json section if present
        if sellers_section is not None:
            st.subheader("Seller verification (sellers.json)")
            if isinstance(sellers_section, dict) and sellers_section.get("error"):
                st.warning(f"Sellers.json verification ran but returned an error: {sellers_section.get('error')}")
                st.caption("This is common when domains block automated fetching. The ads.txt audit still works.")
            else:
                st.json(sellers_section)

        # Downloads
        st.subheader("Export")
        json_bytes = None
        try:
            import json

            json_bytes = json.dumps(report, indent=2).encode("utf-8")
        except Exception:
            json_bytes = str(report).encode("utf-8", errors="ignore")

        st.download_button(
            "⬇️ Download JSON report",
            data=json_bytes,
            file_name="adchainaudit_report.json",
            mime="application/json",
        )

    st.caption("Built in public. Feedback, feature ideas, and collaborators welcome 🤝")


if __name__ == "__main__":
    main()
