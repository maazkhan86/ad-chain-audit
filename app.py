# app.py
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List
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

# Phase 3
try:
    from phase3_schain import analyze_schain, report_to_json_bytes as schain_report_to_json_bytes  # type: ignore
except Exception:  # pragma: no cover
    analyze_schain = None  # type: ignore
    schain_report_to_json_bytes = None  # type: ignore

# Portfolio
from portfolio_scanner import (
    run_portfolio_scan,
    portfolio_rows_to_csv_bytes,
    report_to_json_bytes as portfolio_report_to_json_bytes,
)


APP_VERSION = "1.0"
EVIDENCE_DIR = Path("evidence")
SAMPLES_DIR = Path("samples")

DEMO_ADS_PATH = SAMPLES_DIR / "ads.txt"
DEMO_SCHAIN_PATH = SAMPLES_DIR / "schain.json"

DEMO_SNAPSHOT_NOTE = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)
DEMO_SCHAIN_NOTE = (
    "Demo schain is a multi-hop example for learning. Real schain values usually come from bid requests / logs."
)


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
    s = s.strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/", 1)[0]
    return s.strip()


def build_ads_txt_candidates(domain_or_url: str) -> Tuple[str, ...]:
    s = _clean_domain_or_url(domain_or_url)
    if not s:
        return tuple()

    if _looks_like_url(s):
        url = s[:-1] if s.endswith("/") else s
        if not url.lower().endswith(".txt"):
            url = url + "/ads.txt"
        http_variant = re.sub(r"^https://", "http://", url, flags=re.I)
        return (url, http_variant) if http_variant != url else (url,)

    d = _normalize_domain(s)
    if not d:
        return tuple()

    https_main = f"https://{d}/ads.txt"
    https_www = f"https://www.{d}/ads.txt" if not d.lower().startswith("www.") else https_main
    http_main = f"http://{d}/ads.txt"
    http_www = f"http://www.{d}/ads.txt" if not d.lower().startswith("www.") else http_main

    urls = []
    for u in [https_main, https_www, http_main, http_www]:
        if u not in urls:
            urls.append(u)
    return tuple(urls)


def fetch_text(url: str, timeout_s: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
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
    candidates = build_ads_txt_candidates(domain_or_url)
    debug: Dict[str, Any] = {"attempts": [], "chosen": None}
    for u in candidates:
        text, meta = fetch_text(u)
        debug["attempts"].append(meta)
        if text and meta.get("ok"):
            debug["chosen"] = u
            return text, debug
    return None, debug


def safe_pct(x: Any) -> str:
    try:
        return f"{float(x) * 100:.0f}%"
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


def zip_dir_bytes(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in folder.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(folder)))
    return buf.getvalue()


def call_sellers_verification(ads_txt_text: str) -> Optional[Dict[str, Any]]:
    if run_sellers_json_verification is None:
        return None

    fn = run_sellers_json_verification
    for kwargs in [
        {"ads_txt_text": ads_txt_text, "max_domains": 25, "timeout_s": 6, "source_label": "ads.txt", "evidence_locker_enabled": False},
        {"ads_txt_text": ads_txt_text},
        {},
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
                        "evidence": {"line_no": None, "line": str(e)},
                        "rule_id": "SELLERS_JSON_RUNTIME_ERROR",
                    }
                ],
            }

    return {"summary": {"error": "Could not call run_sellers_json_verification."}, "domain_stats": [], "findings": []}


# -----------------------------
# Evidence locker
# -----------------------------
def evidence_write_single_run(
    *,
    ads_txt_text: str,
    source_label: str,
    audit_report: Dict[str, Any],
    sellers_report: Optional[Dict[str, Any]],
    fetch_debug: Optional[Dict[str, Any]],
    schain_json_text: Optional[str],
    schain_report: Optional[Dict[str, Any]],
) -> Optional[Path]:
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

        # Phase 3 evidence locker
        if schain_json_text:
            (run_dir / "input_schain.json").write_text(schain_json_text, encoding="utf-8", errors="ignore")
        if schain_report is not None:
            (run_dir / "schain_report.json").write_text(
                json.dumps(schain_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            controls = (schain_report or {}).get("controls", {}) or {}
            (run_dir / "schain_controls.json").write_text(
                json.dumps(controls, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return run_dir
    except Exception:
        return None


def evidence_write_portfolio_run(portfolio_report: Dict[str, Any]) -> Optional[Path]:
    """
    Stores:
      evidence/portfolio_<ts>/
        portfolio_report.json
        portfolio_results.csv
        domains/<domain>/input_ads.txt + audit_report.json + sellers_verification.json + fetch_debug.json
    """
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        root = EVIDENCE_DIR / f"{ts}_portfolio"
        root.mkdir(parents=True, exist_ok=True)

        (root / "portfolio_report.json").write_text(
            json.dumps(portfolio_report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        rows = (portfolio_report or {}).get("rows", []) or []
        (root / "portfolio_results.csv").write_bytes(portfolio_rows_to_csv_bytes(rows))

        domains_dir = root / "domains"
        domains_dir.mkdir(parents=True, exist_ok=True)

        artifacts = (portfolio_report or {}).get("artifacts", {}) or {}
        for dom, art in artifacts.items():
            safe_dom = re.sub(r"[^a-zA-Z0-9._-]+", "_", (dom or "domain").strip())[:120]
            ddir = domains_dir / safe_dom
            ddir.mkdir(parents=True, exist_ok=True)

            # fetch debug
            if art.get("fetch_debug") is not None:
                (ddir / "fetch_debug.json").write_text(
                    json.dumps(art["fetch_debug"], indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            # input ads
            if art.get("ads_txt_text"):
                (ddir / "input_ads.txt").write_text(art["ads_txt_text"], encoding="utf-8", errors="ignore")
            # audit report
            if art.get("audit_report") is not None:
                (ddir / "audit_report.json").write_text(
                    json.dumps(art["audit_report"], indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            # sellers report
            if art.get("sellers_report") is not None:
                (ddir / "sellers_verification.json").write_text(
                    json.dumps(art["sellers_report"], indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

        return root
    except Exception:
        return None


# -----------------------------
# UI styling
# -----------------------------
st.set_page_config(page_title="AdChainAudit", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
.block-container { padding-top: 1.1rem; padding-bottom: 2rem; max-width: 1200px; }
h1, h2, h3 { letter-spacing: -0.02em; }
small, .stCaption { opacity: 0.92; }

.card {
  border: 1px solid rgba(49, 51, 63, 0.12);
  border-radius: 16px;
  padding: 16px 16px;
  background: white;
  box-shadow: 0 1px 12px rgba(0,0,0,0.04);
}
.card-title { font-weight: 800; font-size: 0.95rem; margin-bottom: 10px; opacity: 0.95; }
.muted { opacity: 0.7; }

.pill {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 800;
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
  font-weight: 800 !important;
}

div[data-testid="stMetricValue"] { font-size: 34px; }
</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------
# State
# -----------------------------
def _init_state():
    defaults = {
        # single scan
        "ads_text": None,
        "ads_source_label": None,
        "fetch_debug": None,
        "demo_loaded": False,
        "audit_report": None,
        "sellers_report": None,
        "schain_text": None,
        "schain_source_label": None,
        "schain_demo_loaded": False,
        "schain_report": None,
        "evidence_path_single": None,
        # portfolio
        "portfolio_report": None,
        "evidence_path_portfolio": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


_init_state()


# -----------------------------
# Header
# -----------------------------
top_l, top_r = st.columns([3, 1])
with top_l:
    st.title("AdChainAudit")
    st.caption("Phase 1: ads.txt audit • Phase 2: sellers.json verification • Phase 3: schain hops (optional) • Portfolio scanning")
with top_r:
    st.link_button("GitHub (technical)", "https://github.com/maazkhan86/AdChainAudit", use_container_width=True)

st.write("")


# -----------------------------
# Tabs
# -----------------------------
tab1, tab2 = st.tabs(["Single scan", "Portfolio scan"])


# =============================
# Tab 1 — Single scan
# =============================
with tab1:
    st.subheader("Inputs")

    c1, c2, c3 = st.columns(3, gap="large")

    with c1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">1) Get ads.txt</div>', unsafe_allow_html=True)
        domain_or_url = st.text_input(
            "Website domain or ads.txt URL",
            placeholder="example.com  or  https://example.com/ads.txt",
            label_visibility="collapsed",
            key="single_domain",
        )
        fetch_btn = st.button("Fetch ads.txt", use_container_width=True, key="single_fetch")
        st.markdown('<div class="muted" style="margin-top:6px;">We try https first, then http. If blocked, upload or paste.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">2) Upload ads.txt (optional)</div>', unsafe_allow_html=True)
        up = st.file_uploader("Upload ads.txt", type=["txt"], label_visibility="collapsed", key="single_ads_upload")
        demo_btn = st.button("Load demo ads.txt", use_container_width=True, key="single_demo_ads")
        st.markdown("</div>", unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">3) Paste ads.txt (optional)</div>', unsafe_allow_html=True)
        pasted = st.text_area("Paste ads.txt", height=120, placeholder="Paste ads.txt text here…", label_visibility="collapsed", key="single_ads_paste")
        st.markdown("</div>", unsafe_allow_html=True)

    st.write("")
    c4, c5 = st.columns([2, 1], gap="large")
    with c4:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">4) Supply chain (schain) JSON (optional)</div>', unsafe_allow_html=True)
        schain_up = st.file_uploader("Upload schain.json", type=["json", "txt"], label_visibility="collapsed", key="single_schain_upload")
        schain_paste = st.text_area(
            "Paste schain JSON",
            height=120,
            placeholder='Paste schain object JSON like {"ver":"1.0","complete":1,"nodes":[...]}',
            label_visibility="collapsed",
            key="single_schain_paste",
        )
        st.markdown("</div>", unsafe_allow_html=True)

    with c5:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Demo</div>', unsafe_allow_html=True)
        schain_demo_btn = st.button("Load demo schain", use_container_width=True, key="single_demo_schain")
        st.markdown('<div class="muted">Use this if you don’t have schain yet.</div>', unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Apply actions (single)
    if fetch_btn:
        if not domain_or_url.strip():
            st.warning("Enter a website domain or full ads.txt URL.")
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
                st.error("Couldn’t fetch ads.txt (blocked or not found). Use upload/paste.")
                with st.expander("Fetch details"):
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
        if DEMO_ADS_PATH.exists():
            demo_text = DEMO_ADS_PATH.read_text(encoding="utf-8", errors="ignore")
            st.session_state.ads_text = demo_text
            st.session_state.ads_source_label = "demo:samples/ads.txt"
            st.session_state.demo_loaded = True
            st.session_state.fetch_debug = None
        else:
            st.error("Demo ads.txt not found at ./samples/ads.txt")

    if pasted and pasted.strip():
        st.session_state.ads_text = pasted.strip()
        st.session_state.ads_source_label = "pasted:textarea"
        st.session_state.demo_loaded = False
        st.session_state.fetch_debug = None

    # schain apply
    if schain_up is not None:
        try:
            raw = schain_up.getvalue()
            stext = raw.decode("utf-8")
        except Exception:
            stext = (schain_up.getvalue() or b"").decode("latin-1", errors="replace")
        st.session_state.schain_text = stext.strip()
        st.session_state.schain_source_label = f"uploaded:{schain_up.name}"
        st.session_state.schain_demo_loaded = False

    if schain_paste and schain_paste.strip():
        st.session_state.schain_text = schain_paste.strip()
        st.session_state.schain_source_label = "pasted:schain"
        st.session_state.schain_demo_loaded = False

    if schain_demo_btn:
        if DEMO_SCHAIN_PATH.exists():
            stext = DEMO_SCHAIN_PATH.read_text(encoding="utf-8", errors="ignore")
            st.session_state.schain_text = stext.strip()
            st.session_state.schain_source_label = "demo:samples/schain.json"
            st.session_state.schain_demo_loaded = True
        else:
            st.error("Demo schain not found at ./samples/schain.json")

    # Indicators
    st.write("")
    ads_text = st.session_state.ads_text
    src = st.session_state.ads_source_label
    if st.session_state.demo_loaded:
        st.markdown(f'<div class="banner"><b>Demo ads.txt loaded ✅</b><br/>{DEMO_SNAPSHOT_NOTE}</div>', unsafe_allow_html=True)
    elif ads_text:
        st.markdown(f'<div class="banner banner-ok"><b>ads.txt ready ✅</b><br/><span class="muted">Source: {src}</span></div>', unsafe_allow_html=True)
    else:
        st.info("Add ads.txt input to run Phase 1 + 2.")

    schain_text = st.session_state.schain_text
    schain_src = st.session_state.schain_source_label
    if st.session_state.schain_demo_loaded:
        st.markdown(f'<div class="banner"><b>Demo schain loaded ✅</b><br/>{DEMO_SCHAIN_NOTE}</div>', unsafe_allow_html=True)
    elif schain_text:
        st.markdown(f'<div class="banner banner-ok"><b>schain ready ✅</b><br/><span class="muted">Source: {schain_src}</span></div>', unsafe_allow_html=True)

    st.write("")
    run = st.button("Run audit", type="primary", use_container_width=True, key="single_run")
    st.divider()

    if run:
        if not ads_text:
            st.warning("Please provide ads.txt first.")
        else:
            with st.spinner("Analyzing ads.txt…"):
                audit_report = analyze_ads_txt(
                    text=ads_text,
                    source_label=src or "ads.txt",
                    include_optional_checks=True,
                )

            with st.spinner("Verifying seller accounts (sellers.json)…"):
                sellers_report = call_sellers_verification(ads_text)

            schain_report = None
            if schain_text and analyze_schain is not None:
                with st.spinner("Auditing supply chain hops (schain)…"):
                    schain_report = analyze_schain(
                        schain_json_text=schain_text,
                        source_label=schain_src or "schain",
                        ads_txt_text=ads_text,
                    )

            st.session_state.audit_report = audit_report
            st.session_state.sellers_report = sellers_report
            st.session_state.schain_report = schain_report

            ev_path = evidence_write_single_run(
                ads_txt_text=ads_text,
                source_label=src or "ads.txt",
                audit_report=audit_report,
                sellers_report=sellers_report,
                fetch_debug=st.session_state.fetch_debug,
                schain_json_text=schain_text,
                schain_report=schain_report,
            )
            st.session_state.evidence_path_single = ev_path

    # Results (single) – keep your existing layout compact
    audit_report = st.session_state.audit_report
    sellers_report = st.session_state.sellers_report
    schain_report = st.session_state.schain_report
    ev_path = st.session_state.evidence_path_single

    if audit_report:
        st.subheader("Phase 1 — ads.txt audit")
        sm = audit_report.get("summary", {}) or {}
        risk_score = clamp_int(sm.get("risk_score"), 0, 100, 0)
        risk_level = pretty_level(sm.get("risk_level"))
        findings_count = clamp_int(sm.get("finding_count"), 0, 10**9, 0)
        entry_count = clamp_int(sm.get("entry_count"), 0, 10**9, 0)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Risk score", risk_score)
        m2.metric("Risk level", risk_level)
        m3.metric("Findings", findings_count)
        m4.metric("Entries", entry_count)

        dl1, dl2, dl3, dl4 = st.columns([1, 1, 1, 2], gap="small")
        with dl1:
            st.download_button("Download JSON", data=report_to_json_bytes(audit_report),
                               file_name="adchainaudit_report.json", mime="application/json", use_container_width=True)
        with dl2:
            st.download_button("Download TXT", data=report_to_txt_bytes(audit_report),
                               file_name="adchainaudit_report.txt", mime="text/plain", use_container_width=True)
        with dl3:
            st.download_button("Download CSV", data=report_to_csv_bytes(audit_report),
                               file_name="adchainaudit_findings.csv", mime="text/csv", use_container_width=True)
        with dl4:
            if ev_path and Path(ev_path).exists():
                st.download_button("Download buyer pack (ZIP)", data=zip_dir_bytes(Path(ev_path)),
                                   file_name=f"{Path(ev_path).name}.zip", mime="application/zip", use_container_width=True)
            else:
                st.button("Download buyer pack (ZIP)", disabled=True, use_container_width=True)

        st.divider()

    if sellers_report:
        st.subheader("Phase 2 — sellers.json verification (summary)")
        ssum = sellers_report.get("summary", {}) or {}
        p1, p2, p3, p4 = st.columns(4)
        p1.metric("Systems checked", clamp_int(ssum.get("domains_checked"), 0, 10**9, 0))
        p2.metric("Reachable", clamp_int(ssum.get("reachable"), 0, 10**9, 0))
        p3.metric("Unreachable", clamp_int(ssum.get("unreachable"), 0, 10**9, 0))
        p4.metric("Avg match rate", safe_pct(ssum.get("avg_match_rate")))
        st.divider()

    if schain_report:
        st.subheader("Phase 3 — schain audit (summary)")
        ssum = schain_report.get("summary", {}) or {}
        a1, a2, a3, a4 = st.columns(4)
        a1.metric("SPO score", clamp_int(ssum.get("spo_score"), 0, 100, 0))
        a2.metric("SPO risk", pretty_level(ssum.get("spo_risk_level")))
        a3.metric("Hops", clamp_int(ssum.get("hop_count"), 0, 10**6, 0))
        a4.metric("Complete", "Yes" if clamp_int(ssum.get("complete"), 0, 1, 0) == 1 else "No")

        dot = schain_report.get("dot", "")
        if dot:
            st.graphviz_chart(dot, use_container_width=True)

        controls = schain_report.get("controls", {}) or {}
        with st.expander("Suggested buyer controls (JSON)"):
            st.json(controls)

        if schain_report_to_json_bytes is not None:
            st.download_button(
                "Download schain report (JSON)",
                data=schain_report_to_json_bytes(schain_report),
                file_name="adchainaudit_schain_report.json",
                mime="application/json",
                use_container_width=True,
            )


# =============================
# Tab 2 — Portfolio scan
# =============================
with tab2:
    st.subheader("Portfolio scan (Phase 1 + 2)")
    st.caption("Paste or upload a list of domains. The app will fetch ads.txt for each and produce a portfolio table + evidence ZIP.")

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">Domains</div>', unsafe_allow_html=True)

    portfolio_text = st.text_area(
        "Paste domains (one per line)",
        height=140,
        placeholder="example.com\npublisher2.com\npublisher3.com",
        label_visibility="collapsed",
        key="portfolio_text",
    )
    portfolio_up = st.file_uploader("Or upload a .txt/.csv with one domain per line", type=["txt", "csv"], label_visibility="collapsed", key="portfolio_upload")
    max_domains = st.slider("Max domains per run", min_value=5, max_value=50, value=25, step=5)

    st.markdown("</div>", unsafe_allow_html=True)

    def _parse_portfolio_inputs() -> List[str]:
        domains: List[str] = []
        if portfolio_up is not None:
            raw = portfolio_up.getvalue() or b""
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("latin-1", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                # allow CSV with domain in first column
                if "," in line:
                    line = line.split(",", 1)[0].strip()
                domains.append(line)

        if portfolio_text and portfolio_text.strip():
            for line in portfolio_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if "," in line:
                    line = line.split(",", 1)[0].strip()
                domains.append(line)

        # de-dupe preserve order
        seen = set()
        out: List[str] = []
        for d in domains:
            if d in seen:
                continue
            seen.add(d)
            out.append(d)
        return out

    domains_list = _parse_portfolio_inputs()
    st.write(f"Domains loaded: **{len(domains_list)}**")

    run_portfolio = st.button("Run portfolio scan", type="primary", use_container_width=True, key="portfolio_run")

    if run_portfolio:
        if not domains_list:
            st.warning("Add at least one domain.")
        else:
            progress = st.progress(0)
            status = st.empty()

            # We run the portfolio scan, but also show user progress using the artifacts count.
            # run_portfolio_scan itself is sequential; we update progress by estimating completion per domain.
            # For simplicity, run it once, then show results.
            status.write("Running portfolio scan…")
            report = run_portfolio_scan(
                domains=domains_list,
                analyze_ads_txt_fn=analyze_ads_txt,
                sellers_verify_fn=run_sellers_json_verification,
                timeout_s=8,
                include_optional_checks=True,
                include_phase2=True,
                max_domains=int(max_domains),
            )
            progress.progress(100)
            status.write("Done ✅")

            st.session_state.portfolio_report = report
            evp = evidence_write_portfolio_run(report)
            st.session_state.evidence_path_portfolio = evp

    portfolio_report = st.session_state.portfolio_report
    if portfolio_report:
        st.subheader("Portfolio results")
        summ = portfolio_report.get("summary", {}) or {}
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Scanned", summ.get("domains_scanned", 0))
        c2.metric("Fetched OK", summ.get("fetched_ok", 0))
        c3.metric("Fetch failed", summ.get("fetched_failed", 0))
        c4.metric("Avg risk", summ.get("avg_risk_score", "—"))

        rows = portfolio_report.get("rows", []) or []
        st.dataframe(rows, use_container_width=True, hide_index=True)

        d1, d2, d3 = st.columns([1, 1, 2])
        with d1:
            st.download_button(
                "Download CSV",
                data=portfolio_rows_to_csv_bytes(rows),
                file_name="portfolio_results.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with d2:
            st.download_button(
                "Download JSON",
                data=portfolio_report_to_json_bytes(portfolio_report),
                file_name="portfolio_results.json",
                mime="application/json",
                use_container_width=True,
            )
        with d3:
            evp = st.session_state.evidence_path_portfolio
            if evp and Path(evp).exists():
                st.download_button(
                    "Download portfolio buyer pack (ZIP)",
                    data=zip_dir_bytes(Path(evp)),
                    file_name=f"{Path(evp).name}.zip",
                    mime="application/zip",
                    use_container_width=True,
                )
            else:
                st.button("Download portfolio buyer pack (ZIP)", disabled=True, use_container_width=True)
