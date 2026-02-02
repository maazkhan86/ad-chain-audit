# phase2_sellers_json.py
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from evidence_locker import save_phase2_evidence

DEFAULT_TIMEOUT_S = 6
DEFAULT_MAX_DOMAINS = 25

USER_AGENT = "AdChainAudit/Phase2 (+https://github.com/maazkhan86/ad-chain-audit)"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _strip_inline_comment(line: str) -> str:
    s = line.strip()
    if not s:
        return ""
    if s.startswith("#"):
        return ""
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    return s


def _split_fields(line: str) -> List[str]:
    return [p.strip() for p in line.split(",")]


def _norm_domain(d: str) -> str:
    d = d.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.strip("/")
    return d


def _candidate_urls(domain: str) -> List[str]:
    d = _norm_domain(domain)
    urls = [
        f"https://{d}/sellers.json",
        f"https://www.{d}/sellers.json",
    ]

    # hardcoded HTTP fallback (no UI toggle)
    urls += [
        f"http://{d}/sellers.json",
        f"http://www.{d}/sellers.json",
    ]

    # a couple of practical special-cases seen in the wild
    if d in {"spotx.tv", "spotxchange.com"}:
        urls = [
            "https://cdn-source.spotxchange.com/media/cdn/cdn/iab/sellers.json",
            "https://spotxchange.com/sellers.json",
            "https://spotx.tv/sellers.json",
            "http://spotxchange.com/sellers.json",
            "http://spotx.tv/sellers.json",
        ] + urls

    return list(dict.fromkeys(urls))  # de-dupe preserving order


def _looks_like_json(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "json" in ct or ct.endswith("+json")


def _extract_ad_system_domains_and_seller_ids(ads_txt_text: str) -> Dict[str, Set[str]]:
    """
    Returns: {ad_system_domain -> set(seller_ids)}
    """
    out: Dict[str, Set[str]] = {}
    for raw in ads_txt_text.splitlines():
        cleaned = _strip_inline_comment(raw)
        if not cleaned:
            continue
        fields = _split_fields(cleaned)
        if len(fields) < 2:
            continue
        domain = _norm_domain(fields[0])
        seller_id = fields[1].strip()
        if not domain or not seller_id:
            continue
        out.setdefault(domain, set()).add(seller_id)
    return out


def _index_sellers_by_id(sellers_json_obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    IAB sellers.json usually has {"sellers": [ ... ]}.
    We index by seller_id for fast membership checks.
    """
    idx: Dict[str, Dict[str, Any]] = {}
    sellers = sellers_json_obj.get("sellers", [])
    if isinstance(sellers, list):
        for s in sellers:
            if not isinstance(s, dict):
                continue
            sid = str(s.get("seller_id", "")).strip()
            if sid:
                idx[sid] = s
    return idx


def _sample_intermediaries(idx: Dict[str, Dict[str, Any]], limit: int = 6) -> List[Tuple[str, str, str]]:
    """
    Returns [(seller_id, seller_type, name)] where seller_type is INTERMEDIARY or BOTH.
    """
    out: List[Tuple[str, str, str]] = []
    for sid, obj in idx.items():
        st = str(obj.get("seller_type", "")).upper()
        if st in {"INTERMEDIARY", "BOTH"}:
            name = str(obj.get("name", "")).strip()
            out.append((sid, st, name))
            if len(out) >= limit:
                break
    return out


@dataclass
class Finding:
    rule_id: str
    severity: str  # HIGH / MEDIUM
    title: str
    why_buyer_cares: str
    recommendation: str
    evidence: Dict[str, Any]


def _fetch_url(url: str, timeout_s: int) -> Tuple[Optional[int], str, bytes, Optional[str]]:
    """
    Returns (status, content_type, body_bytes, error)
    """
    try:
        r = requests.get(
            url,
            timeout=timeout_s,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json,text/plain,*/*"},
            allow_redirects=True,
        )
        status = r.status_code
        ct = r.headers.get("Content-Type", "") or ""
        body = r.content or b""
        if status != 200:
            return status, ct, body[:2000], f"Non-200 status ({status})"
        return status, ct, body, None
    except Exception as e:
        return None, "", b"", str(e)


def run_sellers_json_verification(
    ads_txt_text: str,
    *,
    max_domains: int = DEFAULT_MAX_DOMAINS,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    source_label: str = "ads.txt",
    evidence_locker_enabled: bool = True,
    evidence_base_dir: str = "evidence",
) -> Dict[str, Any]:
    """
    Phase 2:
      - derive ad-system domains from ads.txt
      - fetch sellers.json where possible
      - verify seller_ids found in ads.txt exist in sellers.json
      - optional evidence locker: saves artifacts + timestamps
    """
    domain_to_seller_ids = _extract_ad_system_domains_and_seller_ids(ads_txt_text)
    domains = list(domain_to_seller_ids.keys())[:max_domains]

    fetch_log: List[Dict[str, Any]] = []
    domain_stats: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    total_ids_checked = 0
    total_ids_matched = 0
    reachable = 0
    unreachable = 0

    for domain in domains:
        seller_ids = sorted(domain_to_seller_ids.get(domain, set()))
        total_ids_checked += len(seller_ids)

        best = None  # (status, ct, body, err, url)
        for url in _candidate_urls(domain):
            status, ct, body, err = _fetch_url(url, timeout_s=timeout_s)
            # record attempt
            if best is None:
                best = (status, ct, body, err, url)

            # success path
            if status == 200 and body:
                best = (status, ct, body, err, url)
                break

        status, ct, body, err, used_url = best

        json_ok = False
        parsed = None
        idx = {}

        if status == 200 and body and _looks_like_json(ct):
            try:
                parsed = json.loads(body.decode("utf-8", errors="replace"))
                if isinstance(parsed, dict):
                    json_ok = True
                    idx = _index_sellers_by_id(parsed)
            except Exception as e:
                err = f"JSON parse error: {e}"
        elif status == 200 and body and not _looks_like_json(ct):
            # 200 but HTML / non-json
            snippet = body[:240].decode("utf-8", errors="replace").replace("\n", " ").strip()
            err = f"Not JSON (ctype={ct}). Snippet: {snippet}"

        if json_ok:
            reachable += 1
        else:
            unreachable += 1

        matched = sum(1 for sid in seller_ids if sid in idx)
        total_ids_matched += matched
        match_rate = (matched / len(seller_ids)) if seller_ids else 0.0

        fetch_log.append({
            "domain": domain,
            "url": used_url,
            "status": status,
            "content_type": ct,
            "json_ok": json_ok,
            "error": err,
            "body_bytes": body if (body and (json_ok or status == 200)) else b"",  # store what we got
        })

        domain_stats.append({
            "domain": domain,
            "json_ok": json_ok,
            "status": status,
            "content_type": ct,
            "seller_ids_in_ads_txt": len(seller_ids),
            "seller_ids_matched": matched,
            "match_rate": round(match_rate, 3),
            "url": used_url,
            "error": err,
        })

        if json_ok and seller_ids:
            missing = [sid for sid in seller_ids if sid not in idx]
            if missing:
                examples = ", ".join(missing[:8])
                findings.append(Finding(
                    rule_id="SELLER_ID_NOT_FOUND_IN_SELLERS_JSON",
                    severity="HIGH",
                    title="Seller IDs in ads.txt not found in sellers.json",
                    why_buyer_cares=(
                        "When a seller account in ads.txt cannot be validated against sellers.json, "
                        "it raises questions about authorization accuracy, stale configs, or unclear selling relationships."
                    ),
                    recommendation="Ask the publisher/seller to confirm the correct seller account ID and preferred path (DIRECT where possible).",
                    evidence={
                        "domain": domain,
                        "missing_count": len(missing),
                        "total_in_ads_txt": len(seller_ids),
                        "examples": examples,
                        "used_url": used_url,
                    },
                ))

            inter = _sample_intermediaries(idx, limit=6)
            if inter:
                inter_str = ", ".join([f"{sid} ({st}) {name}".strip() for sid, st, name in inter])
                findings.append(Finding(
                    rule_id="SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT",
                    severity="MEDIUM",
                    title="Intermediary sellers detected (likely extra hops)",
                    why_buyer_cares=(
                        "Intermediary seller types can indicate additional hops and reselling, which may increase fees "
                        "and reduce transparency. It is not always bad, but it is worth asking why this path is needed."
                    ),
                    recommendation="Ask for the preferred path for your buy and whether a more direct route exists (DIRECT where possible).",
                    evidence={
                        "domain": domain,
                        "examples": inter_str,
                        "used_url": used_url,
                    },
                ))

        if not json_ok:
            findings.append(Finding(
                rule_id="SELLERS_JSON_UNREACHABLE",
                severity="MEDIUM",
                title="sellers.json not reachable or not valid JSON",
                why_buyer_cares="If sellers.json cannot be retrieved, seller verification is limited and supply-path transparency is weaker.",
                recommendation="Treat as a transparency gap. Ask the seller/exchange whether they publish sellers.json correctly.",
                evidence={
                    "domain": domain,
                    "used_url": used_url,
                    "status": status,
                    "content_type": ct,
                    "error": err,
                },
            ))

    avg_match_rate = (total_ids_matched / total_ids_checked) if total_ids_checked else 0.0

    report = {
        "meta": {
            "generated_at": _now_iso(),
            "source_label": source_label,
            "timeout_s": timeout_s,
            "max_domains": max_domains,
            "version": "0.2-phase2-evidence",
        },
        "summary": {
            "domains_checked": len(domains),
            "reachable": reachable,
            "unreachable": unreachable,
            "total_seller_ids_checked": total_ids_checked,
            "total_seller_ids_matched": total_ids_matched,
            "avg_match_rate": round(avg_match_rate, 3),
            "notes": "Match rate compares seller IDs in ads.txt to seller_id entries in each ad system's sellers.json.",
        },
        "domain_stats": domain_stats,
        "findings": [asdict(f) for f in findings],
    }

    # Evidence locker (writes to disk; app can zip + download)
    if evidence_locker_enabled:
        ev = save_phase2_evidence(
            base_dir=evidence_base_dir,
            source_label=source_label,
            ads_txt_text=ads_txt_text,
            sellers_fetch_log=fetch_log,
            phase2_report=report,
        )
        report["evidence"] = ev
    else:
        report["evidence"] = {"enabled": False}

    return report
