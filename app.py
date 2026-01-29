# app.py
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import streamlit as st

# Phase 1
from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes

# Phase 2 (optional import safety)
try:
    from phase2_sellers_json import run_sellers_json_verification  # type: ignore
except Exception:  # pragma: no cover
    run_sellers_json_verification = None  # type: ignore


APP_VERSION = "0.9"
EVIDENCE_DIR = Path("evidence")
SAMPLES_DIR = Path("samples")
DEMO_SAMPLE_PATH = SAMPLES_DIR / "ads.txt"

DEMO_SNAPSHOT_NOTE = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)

GITHUB_URL = "https://github.com/maazkhan86/AdChainAudit"


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_domain_or_url(s: str) -> str:
    return (s or "").strip()


def _looks_like_url(s: str) -> bool:
    return s.lower().startswith("http://") or s.lower().startswith("https://")


def _normalize_domain(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/", 1)[0]
    s = s.strip()
    s = re.sub(r"^www\.", "", s, flags=re.I)
    return s


def build_ads_txt_candidates(domain_or_url: str) -> Tuple[str, ...]:
    """
    Returns a list of URLs we will try (hardcoded logic):
      - If user provides a URL: try that, then http variant.
      - If user provides a domain: try https://domain/ads.txt, https://www.domain/ads.txt,
        then http variants.
    """
    s = _clean_domain_or_url(domain_or_url)
    if not s:
        return tuple()

    if _looks_like_url(s):
        url = s.rstrip("/")
        if not url.lower().endswith(".txt"):
            url = url + "/ads.txt"
        http_variant = re.sub(r"^https://", "http://", url, flags=re.I)
        return (url, http_variant) if http_variant != url else (url,)

    d = _normalize_domain(s)
    if not d:
        return tuple()

    https_main = f"https://{d}/ads.txt"
    https_www = f"https://www.{d}/ads.txt"
    http_main = f"http://{d}/ads.txt"
    http_www = f"http://www.{d}/ads.txt"

    urls = []
    for u in [https_main, https_www, http_main, http_www]:
        if u not in urls:
            urls.append(u)
    return tuple(urls)


def fetch_text(url: str, timeout_s: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Fetch a URL with a realistic User-Agent. Returns (text, debug_meta).
    """
    meta: Dict[str, Any] = {"url": url, "ok": False, "status": None, "error": None}

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/plain,text/*;q=0.9,*/*;q=0.8",
    }

    req = Request(url=url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", None)
            meta["status"] = status
            raw = resp.read()
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("latin-1", errors="replace")
            meta["ok"] = True if (status is None or int(status) < 400) else False
            return text, meta
    except HTTPError as e:
        meta["status"] = getattr(e, "code", None)
        meta["error"] = f"HTTPError: {e}"
    except URLError as e:
        meta["error"] = f"URLError: {e}"
    except Exception as e:
        meta["error"] = f"Error: {e}"

    return None, meta


def fetch_ads_txt(domain_or_url: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Tries a sequence of candidate URLs (hardcoded).
    Returns (text, debug) where debug includes attempts[].
    """
    candidates = build_ads_txt_candidates(domain_or_url)
    debug: Dict[str, Any] = {"attempts": [], "chosen": None}

    for u in candidates:
        text, meta = fetch_text(u)
        debug["attempts"].append(meta)
        if text and meta.get("ok"):
            debug["chosen"] = u
            return text, debug

    return None, debug


def safe_pct(x: Any, decimals: int = 0) -> str:
    try:
        return f"{float(x) * 100:.{decimals}f}%"
    except Exception:
        return "—"


def clamp_int(x: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(x)
        return max(lo, min(hi, v))
    except Exception:
        return default


def pretty_level(level: Any) -> str:
    s = str(level or "").upper().strip()
    return s if s in {"LOW", "MEDIUM", "HIGH"} else "—"


def evidence_write_run(
    *,
    ads_txt_text: str,
    source_label: str,
    audit_report: Dict[str, Any],
    sellers_report: Optional[Dict[str, Any]],
    fetch_debug: Optional[Dict[str, Any]],
) -> Optional[Path]:
    """
    Evidence pack (app-side):
    - Stores inputs + outputs with timestamp under ./evidence/<timestamp>_<source>/
    - Lets users download a “buyer pack ZIP”.
    """
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_source = re.sub(r"[^a-zA-Z0-9._-]+", "_", (source_label or "ads.txt").strip())[:60]
        run_dir = EVIDENCE_DIR / f"{ts}_{safe_source}"
        run_dir.mkdir(parents=True, exist_ok=True)

        (run_dir / "input_ads.txt").write_text(ads_txt_text, encoding="utf-8", errors="ignore")
        (run_dir / "audit_report.json").write_bytes(report_to_json_bytes(audit_report))
        (run_dir / "audit_report.txt").write_bytes(report_to_txt_bytes(audit_report))
        (run_dir / "audit_report.csv").write_bytes(report_to_csv_bytes(audit_report))

        meta = {"generated_at": now_iso(), "app_version": APP_VERSION, "source_label": source_label}
        if fetch_debug:
            meta["fetch_debug"] = fetch_debug
        (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        if sellers_report is not None:
            (run_dir / "sellers_verification.json").write_text(
                json.dumps(sellers_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return run_dir
    except Exception:
        return None


def zip_dir_bytes(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in folder.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(folder)))
    return buf.getvalue()


def call_sellers_verification(ads_txt_text: str) -> Optional[Dict[str, Any]]:
    """
    Calls phase2 function with signature-guessing (so you don’t have to keep editing app.py).
    """
    if run_sellers_json_verification is None:
        return None

    fn = run_sellers_json_verification

    for kwargs in [
        {},  # fn(text)
        {"ads_txt_text": ads_txt_text},
        {"text": ads_txt_text},
        {"ads_txt": ads_txt_text},
        {"max_domains": 25},
        {"ads_txt_text": ads_txt_text, "max_domains": 25},
        {"text": ads_txt_text, "max_domains": 25},
    ]:
        try:
            if kwargs:
                return fn(**kwargs)  # type: ignore[arg-type]
            return fn(ads_txt_text)  # type: ignore[misc]
        except TypeError:
            continue
        except Exception as e:
            return {
                "summary": {"error": str(e)},
                "domain_stats": [],
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "Seller verification failed",
                        "why_buyer_cares": "Seller verification could not be completed in this run.",
                        "recommendation": "Try again, or proceed with Phase 1 signals only.",
                        "evidence": {"error": str(e)},
                        "rule_id": "SELLERS_JSON_RUNTIME_ERROR",
                    }
                ],
            }

    return {
        "summary": {"error": "Could not call run_sellers_json_verification (signature mismatch)."},
        "domain_stats": [],
        "findings": [],
    }


def _short_reason(d: Dict[str, Any], max_len: int = 140) -> str:
    r = d.get("error") or ""
    r = str(r).strip()
    if not r:
        status = d.get("status")
        if status:
            r = f"HTTP {status}"
        else:
            r = "Blocked / unreachable"
    r = r.replace("\n", " ").strip()
    return (r[:max_len] + "…") if len(r) > max_len else r


def _summarize_sellers_findings_for_humans(sellers_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turns Phase 2 output into a short, readable summary.
    Returns:
      - headline
      - bullets
      - tables: worst_reachable, blocked
      - notable: top_missing, top_intermediary, top_unreachable
    """
    ssum = sellers_report.get("summary", {}) or {}
    domain_stats = sellers_report.get("domain_stats", []) or []

    domains_checked = clamp_int(ssum.get("domains_checked"), 0, 10**9, 0)
    reachable = clamp_int(ssum.get("reachable"), 0, 10**9, 0)
    unreachable = clamp_int(ssum.get("unreachable"), 0, 10**9, 0)

    total_ids = clamp_int(ssum.get("total_seller_ids_checked"), 0, 10**12, 0)
    matched_ids = clamp_int(ssum.get("total_seller_ids_matched"), 0, 10**12, 0)
    avg_match = ssum.get("avg_match_rate", None)

    not_matched = max(0, total_ids - matched_ids)

    # Buckets
    blocked: List[Dict[str, Any]] = []
    reachable_rows: List[Dict[str, Any]] = []
    for d in domain_stats:
        json_ok = bool(d.get("json_ok", False))
        status = d.get("status", None)
        err = d.get("error", None)
        if (not json_ok) or err or (isinstance(status, int) and status != 200):
            blocked.append(d)
        else:
            reachable_rows.append(d)

    reachable_sorted = sorted(reachable_rows, key=lambda x: (x.get("match_rate") or 0))
    worst10 = reachable_sorted[:10]

    # Notable issues from findings
    findings = sellers_report.get("findings", []) or []
    top_missing: List[Dict[str, Any]] = []
    top_inter: List[Dict[str, Any]] = []
    top_unreach: List[Dict[str, Any]] = []

    for f in findings:
        rid = str(f.get("rule_id", "")).strip()
        ev = f.get("evidence", {}) or {}
        dom = ev.get("domain") or ev.get("used_url") or ""
        if rid == "SELLER_ID_NOT_FOUND_IN_SELLERS_JSON":
            top_missing.append(
                {
                    "Domain": ev.get("domain"),
                    "Missing IDs": ev.get("missing_count"),
                    "Total IDs": ev.get("total_in_ads_txt"),
                    "Examples": ev.get("examples"),
                }
            )
        elif rid == "SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT":
            top_inter.append(
                {
                    "Domain": ev.get("domain"),
                    "Examples": ev.get("examples"),
                }
            )
        elif rid == "SELLERS_JSON_UNREACHABLE":
            top_unreach.append(
                {
                    "Domain": ev.get("domain"),
                    "Status": ev.get("status"),
                    "Reason": _short_reason(ev, 200),
                }
            )

    # Sort missing by missing_count desc
    def _mc(x: Dict[str, Any]) -> int:
        return clamp_int(x.get("Missing IDs"), 0, 10**9, 0)

    top_missing = sorted(top_missing, key=_mc, reverse=True)[:8]
    top_inter = top_inter[:6]
    top_unreach = top_unreach[:10]

    # Human headline
    coverage = safe_pct(avg_match, decimals=0) if avg_match is not None else "—"
    headline = f"Verified **{matched_ids:,}** of **{total_ids:,}** seller IDs ({coverage}) across **{domains_checked}** seller systems."

    bullets: List[str] = []
    if unreachable > 0:
        bullets.append(f"**{unreachable}** seller systems could not be verified (blocked/unreachable/not JSON).")
    if not_matched > 0:
        bullets.append(f"**{not_matched:,}** seller IDs from ads.txt did not appear in sellers.json (needs follow-up).")
    if reachable > 0 and (avg_match is not None) and float(avg_match) < 0.5:
        bullets.append("Overall match is **below 50%**. Treat this as a transparency check, not a final verdict.")
    if not bullets:
        bullets.append("Most sellers.json files were reachable and verification looks reasonably clean.")

    return {
        "metrics": {
            "domains_checked": domains_checked,
            "reachable": reachable,
            "unreachable": unreachable,
            "total_ids": total_ids,
            "matched_ids": matched_ids,
            "not_matched": not_matched,
            "avg_match": avg_match,
        },
        "headline": headline,
        "bullets": bullets,
        "worst10_reachable": worst10,
        "blocked": blocked,
        "top_missing": top_missing,
        "top_intermediaries": top_inter,
        "top_unreachable": top_unreach,
    }


# -----------------------------
# UI styling
# -----------------------------
st.set_page_config(page_title="AdChainAudit", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
/* App-like feel */
.block-container { padding-top: 1.1rem; padding-bottom: 2rem; max-width: 1180px; }
h1, h2, h3 { letter-spacing: -0.02em; }
small, .stCaption { opacity: 0.9; }

.card {
  border: 1px solid rgba(49, 51, 63, 0.12);
  border-radius: 16px;
  padding: 14px 14px;
  background: white;
  box-shadow: 0 1px 12px rgba(0,0,0,0.04);
}
.card-title { font-weight: 750; font-size: 0.95rem; margin-bottom: 8px; opacity: 0.95; }
.muted { opacity: 0.7; }

.pill {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 750;
  border: 1px solid rgba(49, 51, 63, 0.12);
  background: rgba(49, 51, 63, 0.03);
  margin-right: 6px;
  margin-bottom: 6px;
}
.pill-ok { background: rgba(0, 128, 0, 0.08); border-color: rgba(0, 128, 0, 0.20); }
.pill-warn { background: rgba(255, 165, 0, 0.10); border-color: rgba(255, 165, 0, 0.22); }
.pill-bad { background: rgba(255, 0, 0, 0.08); border-color: rgba(255, 0, 0, 0.18); }

.banner {
  border-radius: 14px;
  padding: 12px 14px;
  border: 1px solid rgba(49, 51, 63, 0.12);
  background: rgba(255, 0, 0, 0.06);
}

.banner-ok {
  background: rgba(0,128,0,0.06);
  border-color: rgba(0,128,0,0.18);
}

.stButton > button {
  border-radius: 12px !important;
  padding: 10px 14px !important;
  font-weight: 750 !important;
}

div[data-testid="stMetricValue"] { font-size: 34px; }
</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------
# State
# -----------------------------
if "ads_text" not in st.session_state:
    st.session_state.ads_text = None
if "ads_source_label" not in st.session_state:
    st.session_state.ads_source_label = None
if "fetch_debug" not in st.session_state:
    st.session_state.fetch_debug = None
if "demo_loaded" not in st.session_state:
    st.session_state.demo_loaded = False
if "audit_report" not in st.session_state:
    st.session_state.audit_report = None
if "sellers_report" not in st.session_state:
    st.session_state.sellers_report = None
if "evidence_path" not in st.session_state:
    st.session_state.evidence_path = None


# -----------------------------
# Header
# -----------------------------
top_l, top_r = st.columns([3, 1])
with top_l:
    st.title("AdChainAudit")
    st.caption(
        "Sanity-check a publisher’s ads.txt and verify seller accounts via sellers.json. "
        "Built for media and marketing teams."
    )
with top_r:
    st.link_button("GitHub (technical)", GITHUB_URL, use_container_width=True)

st.write("")

# -----------------------------
# Input area (App-like)
# -----------------------------
c1, c2, c3 = st.columns(3, gap="large")

with c1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">1) Fetch ads.txt</div>', unsafe_allow_html=True)
    domain_or_url = st.text_input(
        "Website domain or ads.txt URL",
        placeholder="example.com  or  https://example.com/ads.txt",
        label_visibility="collapsed",
    )
    fetch_btn = st.button("Fetch", use_container_width=True)
    st.markdown(
        '<div class="muted" style="margin-top:6px;">We try https first, then http. If blocked, upload or paste instead.</div>',
        unsafe_allow_html=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">2) Upload (optional)</div>', unsafe_allow_html=True)
    up = st.file_uploader("Upload ads.txt", type=["txt"], label_visibility="collapsed")
    demo_btn = st.button("Load demo sample", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">3) Paste (optional)</div>', unsafe_allow_html=True)
    pasted = st.text_area(
        "Paste ads.txt",
        height=120,
        placeholder="Paste ads.txt text here…",
        label_visibility="collapsed",
    )
    st.markdown("</div>", unsafe_allow_html=True)

# Actions: fetch / upload / demo / paste
if fetch_btn:
    if not domain_or_url.strip():
        st.warning("Enter a website domain or a full ads.txt URL first.")
    else:
        with st.spinner("Fetching ads.txt…"):
            text, dbg = fetch_ads_txt(domain_or_url.strip())
        st.session_state.fetch_debug = dbg
        if text:
            st.session_state.ads_text = text
            chosen = (dbg or {}).get("chosen") or domain_or_url.strip()
            st.session_state.ads_source_label = f"fetched:{chosen}"
            st.session_state.demo_loaded = False
            st.success("Fetched ads.txt successfully ✅")
        else:
            st.error("Couldn’t fetch ads.txt (blocked or not found). Use upload or paste instead.")
            with st.expander("Fetch details (for troubleshooting)"):
                st.json(dbg)

if up is not None:
    try:
        raw = up.getvalue()
        text = raw.decode("utf-8")
    except Exception:
        text = (up.getvalue() or b"").decode("latin-1", errors="replace")

    st.session_state.ads_text = text
    st.session_state.ads_source_label = f"uploaded:{up.name}"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

if demo_btn:
    if DEMO_SAMPLE_PATH.exists():
        demo_text = DEMO_SAMPLE_PATH.read_text(encoding="utf-8", errors="ignore")
        st.session_state.ads_text = demo_text
        st.session_state.ads_source_label = "demo:samples/ads.txt"
        st.session_state.demo_loaded = True
        st.session_state.fetch_debug = None
    else:
        st.error("Demo sample not found. Add it at ./samples/ads.txt in your repo and redeploy.")

if pasted and pasted.strip():
    st.session_state.ads_text = pasted.strip()
    st.session_state.ads_source_label = "pasted:textarea"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

# Visible “input loaded” indicators
st.write("")
ads_text = st.session_state.ads_text
src = st.session_state.ads_source_label

if st.session_state.demo_loaded:
    st.markdown(
        f'<div class="banner"><b>Demo sample loaded ✅</b><br/>{DEMO_SNAPSHOT_NOTE}</div>',
        unsafe_allow_html=True,
    )
elif ads_text:
    st.markdown(
        f'<div class="banner banner-ok"><b>Input ready ✅</b><br/><span class="muted">Source: {src}</span></div>',
        unsafe_allow_html=True,
    )
else:
    st.info("Add an ads.txt input (fetch, upload, or paste) to run the audit.")

st.write("")

run_col_l, run_col_r = st.columns([3, 2])
with run_col_r:
    run = st.button("Run audit", type="primary", use_container_width=True)

st.divider()

if run:
    if not ads_text:
        st.warning("Please add ads.txt input first (fetch, upload, or paste).")
    else:
        with st.spinner("Analyzing ads.txt…"):
            audit_report = analyze_ads_txt(
                text=ads_text,
                source_label=src or "ads.txt",
                include_optional_checks=True,  # hardcoded ON
            )

        with st.spinner("Verifying seller accounts (sellers.json)…"):
            sellers_report = call_sellers_verification(ads_text)

        st.session_state.audit_report = audit_report
        st.session_state.sellers_report = sellers_report

        ev_path = evidence_write_run(
            ads_txt_text=ads_text,
            source_label=src or "ads.txt",
            audit_report=audit_report,
            sellers_report=sellers_report,
            fetch_debug=st.session_state.fetch_debug,
        )
        st.session_state.evidence_path = ev_path


# -----------------------------
# Results: Phase 1
# -----------------------------
audit_report = st.session_state.audit_report
sellers_report = st.session_state.sellers_report

if audit_report:
    sm = audit_report.get("summary", {}) or {}
    risk_score = clamp_int(sm.get("risk_score"), 0, 100, default=0)
    risk_level = pretty_level(sm.get("risk_level"))
    findings_count = clamp_int(sm.get("finding_count"), 0, 10**9, default=0)
    entry_count = clamp_int(sm.get("entry_count"), 0, 10**9, default=0)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk score", risk_score)
    m2.metric("Risk level", risk_level)
    m3.metric("Findings", findings_count)
    m4.metric("Entries", entry_count)

    st.subheader("Summary")

    # Build severity breakdown from findings list
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in audit_report.get("findings", []) or []:
        sev = str(f.get("severity", "")).upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    st.write(
        f"Found **{findings_count}** buyer-relevant flags. "
        f"Breakdown: **CRITICAL:** {sev_counts['CRITICAL']}, **HIGH:** {sev_counts['HIGH']}, "
        f"**MEDIUM:** {sev_counts['MEDIUM']}, **LOW:** {sev_counts['LOW']}."
    )

    # Download buttons
    dl1, dl2, dl3, dl4 = st.columns([1, 1, 1, 2], gap="small")
    with dl1:
        st.download_button(
            "Download JSON",
            data=report_to_json_bytes(audit_report),
            file_name="adchainaudit_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with dl2:
        st.download_button(
            "Download TXT",
            data=report_to_txt_bytes(audit_report),
            file_name="adchainaudit_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with dl3:
        st.download_button(
            "Download CSV",
            data=report_to_csv_bytes(audit_report),
            file_name="adchainaudit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with dl4:
        ev_path = st.session_state.evidence_path
        if ev_path and Path(ev_path).exists():
            st.download_button(
                "Download buyer pack (ZIP)",
                data=zip_dir_bytes(Path(ev_path)),
                file_name=f"{Path(ev_path).name}.zip",
                mime="application/zip",
                use_container_width=True,
            )
        else:
            st.button("Download buyer pack (ZIP)", disabled=True, use_container_width=True)

    st.write("")
    st.subheader("Buyer-relevant red flags")

    findings = audit_report.get("findings", []) or []
    by_sev: Dict[str, list] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev not in by_sev:
            sev = "LOW"
        by_sev[sev].append(f)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        with st.expander(f"{sev} ({len(items)})", expanded=(sev in {"CRITICAL", "HIGH"})):
            max_show = 60
            for i, f in enumerate(items[:max_show], start=1):
                ev = f.get("evidence", {}) or {}
                title = f.get("title", "Finding")
                why = f.get("why_buyer_cares", "")
                rec = f.get("recommendation", "")
                line_no = ev.get("line_no", None)
                line = ev.get("line", "")

                st.markdown(f"**{i}. {title}**")
                if why:
                    st.markdown(f"- *Why buyer cares:* {why}")
                if rec:
                    st.markdown(f"- *What to do:* {rec}")
                if line:
                    if line_no is not None:
                        st.code(f"Line {line_no}: {line}", language="text")
                    else:
                        st.code(line, language="text")
                st.write("")

            if len(items) > max_show:
                st.info(f"Showing top {max_show} items. Download CSV for the full list.")

    st.divider()


# -----------------------------
# Results: Phase 2 (clean summary)
# -----------------------------
if sellers_report:
    st.subheader("Seller verification (sellers.json)")

    summary_obj = _summarize_sellers_findings_for_humans(sellers_report)
    met = summary_obj["metrics"]

    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Seller systems checked", met["domains_checked"])
    p2.metric("Reachable sellers.json", met["reachable"])
    p3.metric("Unreachable / blocked", met["unreachable"])
    p4.metric("Verified seller IDs", f"{met['matched_ids']:,}")

    st.markdown(f"**{summary_obj['headline']}**")
    st.caption(
        "This is a verification layer. A low match rate can mean stale ads.txt entries, non-standard endpoints, "
        "or unclear selling relationships. Use it to ask better questions."
    )

    # Pills
    st.markdown(
        f"""
<span class="pill pill-ok">Reachable: {met["reachable"]}</span>
<span class="pill pill-bad">Unreachable: {met["unreachable"]}</span>
<span class="pill pill-warn">Not verified: {met["not_matched"]:,}</span>
""",
        unsafe_allow_html=True,
    )

    # Buyer takeaway (simple)
    st.markdown("**What to do with this**")
    for b in summary_obj["bullets"]:
        st.markdown(f"- {b}")
    st.markdown(
        "- If you see **unreachable** sellers.json, treat it as a transparency gap.\n"
        "- If you see **large missing counts**, ask for the **preferred path** and whether **DIRECT** is available.\n"
        "- If intermediary sellers appear, it may add hops and fees. It is not always bad, but it is worth clarifying."
    )

    # Tables (kept short)
    worst10 = summary_obj["worst10_reachable"]
    if worst10:
        st.write("")
        st.markdown("**Worst match (reachable sellers.json)**")
        table = []
        for d in worst10:
            table.append(
                {
                    "Domain": d.get("domain"),
                    "IDs in ads.txt": d.get("seller_ids_in_ads_txt"),
                    "Verified": d.get("seller_ids_matched"),
                    "Match rate": f"{(d.get('match_rate') or 0):.2f}",
                }
            )
        st.dataframe(table, use_container_width=True, hide_index=True)

    blocked = summary_obj["blocked"]
    if blocked:
        st.write("")
        st.markdown("**Unreachable / blocked / not JSON (top)**")
        blk_table = []
        for d in blocked[:12]:
            blk_table.append(
                {
                    "Domain": d.get("domain"),
                    "Status": d.get("status"),
                    "Reason": _short_reason(d, 150),
                }
            )
        st.dataframe(blk_table, use_container_width=True, hide_index=True)

    # “Notable” findings (human friendly)
    st.write("")
    cols = st.columns(3, gap="large")

    with cols[0]:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Biggest missing ID gaps</div>', unsafe_allow_html=True)
        top_missing = summary_obj["top_missing"]
        if top_missing:
            for row in top_missing[:5]:
                dom = row.get("Domain") or "—"
                miss = row.get("Missing IDs") or 0
                tot = row.get("Total IDs") or 0
                st.markdown(f"**{dom}**  \nMissing **{miss}** of **{tot}**")
            st.caption("Tip: large gaps are good targets for follow-up on preferred path + DIRECT availability.")
        else:
            st.markdown('<span class="muted">No large missing-ID gaps detected.</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with cols[1]:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Intermediary sellers spotted (examples)</div>', unsafe_allow_html=True)
        top_inter = summary_obj["top_intermediaries"]
        if top_inter:
            for row in top_inter[:4]:
                dom = row.get("Domain") or "—"
                ex = (row.get("Examples") or "").strip()
                ex = (ex[:140] + "…") if len(ex) > 140 else ex
                st.markdown(f"**{dom}**  \n{ex if ex else 'Examples available in buyer pack ZIP.'}")
        else:
            st.markdown('<span class="muted">No intermediary examples captured in this run.</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with cols[2]:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Unreachable verification targets</div>', unsafe_allow_html=True)
        top_un = summary_obj["top_unreachable"]
        if top_un:
            for row in top_un[:5]:
                dom = row.get("Domain") or "—"
                status = row.get("Status")
                reason = row.get("Reason") or "Blocked / unreachable"
                reason = (reason[:120] + "…") if len(reason) > 120 else reason
                st.markdown(f"**{dom}**  \n{('HTTP ' + str(status)) if status else 'No status'} · {reason}")
        else:
            st.markdown('<span class="muted">No unreachable targets recorded.</span>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Advanced details (still available, but NOT a wall of JSON)
    with st.expander("Detailed seller-verification findings (advanced)"):
        sf = sellers_report.get("findings", []) or []
        max_show = 30

        def _format_evidence(rule_id: str, ev: Dict[str, Any]) -> str:
            dom = ev.get("domain") or "—"
            if rule_id == "SELLER_ID_NOT_FOUND_IN_SELLERS_JSON":
                miss = ev.get("missing_count")
                tot = ev.get("total_in_ads_txt")
                ex = ev.get("examples") or ""
                return f"{dom}: missing {miss}/{tot} seller IDs. Examples: {ex}"
            if rule_id == "SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT":
                ex = ev.get("examples") or ""
                return f"{dom}: intermediary examples → {ex}"
            if rule_id == "SELLERS_JSON_UNREACHABLE":
                stt = ev.get("status")
                err = ev.get("error") or ""
                url = ev.get("used_url") or ""
                bits = []
                if url:
                    bits.append(url)
                if stt:
                    bits.append(f"HTTP {stt}")
                if err:
                    bits.append(err)
                return f"{dom}: " + " | ".join(bits) if bits else f"{dom}: unreachable"
            # fallback
            return json.dumps(ev, ensure_ascii=False)[:300]

        for i, f in enumerate(sf[:max_show], start=1):
            rid = str(f.get("rule_id", "")).strip()
            sev = str(f.get("severity", "")).upper().strip()
            title = f.get("title", "") or "Finding"
            why = f.get("why_buyer_cares", "") or ""
            rec = f.get("recommendation", "") or ""
            ev = f.get("evidence", {}) or {}

            st.markdown(f"**{i}. [{sev}] {title}**")
            if why:
                st.markdown(f"- *Why buyer cares:* {why}")
            if rec:
                st.markdown(f"- *What to do:* {rec}")
            st.code(_format_evidence(rid, ev), language="text")
            st.write("")

        if len(sf) > max_show:
            st.info(f"Showing top {max_show} items. Download the buyer pack ZIP for full evidence.")
