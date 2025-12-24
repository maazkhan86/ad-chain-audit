# phase2_sellers_json.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from functools import lru_cache
import time

from sellers_json_checks import fetch_sellers_json, index_sellers_by_id


@dataclass
class Evidence:
    line_no: Optional[int] = None
    line: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    title: str
    why_buyer_cares: str
    recommendation: str
    evidence: Evidence


def _strip_inline_comment(line: str) -> str:
    s = line.strip()
    if not s:
        return s
    if s.startswith("#"):
        return ""
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    return s


def _normalize_domain(d: str) -> str:
    d = d.strip().lower()
    d = d.replace("http://", "").replace("https://", "")
    d = d.split("/")[0]
    return d


def parse_ads_txt_entries(text: str) -> List[Tuple[int, str, str, str]]:
    """
    Return list of tuples:
      (line_no, raw_line, ad_system_domain, seller_id)

    Only uses first 2 fields; ignores malformed lines for Phase 2.
    """
    out: List[Tuple[int, str, str, str]] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        cleaned = _strip_inline_comment(raw)
        if not cleaned:
            continue
        parts = [p.strip() for p in cleaned.split(",")]
        if len(parts) < 2:
            continue
        domain = _normalize_domain(parts[0])
        seller_id = parts[1]
        out.append((i, cleaned, domain, seller_id))
    return out


@lru_cache(maxsize=128)
def _cached_fetch(domain: str):
    # Hardcode: try HTTPS first, then fallback inside sellers_json_checks if it does so.
    # If sellers_json_checks does not fallback, we still keep the UI messaging in app.py.
    return fetch_sellers_json(domain)


def _safe_upper(x: Optional[str]) -> str:
    return (x or "").strip().upper()


def _looks_agency_like(name: str) -> bool:
    """
    Best-effort heuristic. Not authoritative.
    """
    n = (name or "").lower()
    keywords = [
        "groupm", "mindshare", "wavemaker", "essence", "mec", "mediacom",
        "xaxis", "amnet", "dentsu", "carat", "iprospect",
        "publicis", "omnicom", "interpublic", "ipg", "wpp",
        "trading desk", "td", "programmatic",
    ]
    return any(k in n for k in keywords)


def run_sellers_json_verification(ads_txt: str) -> Dict:
    """
    Verifies seller IDs found in ads.txt against sellers.json for each ad system domain.

    Output:
      {
        "summary": {...},
        "domain_stats": [...],
        "findings": [...]
      }
    """
    entries = parse_ads_txt_entries(ads_txt)

    # domain -> set(seller_ids), plus example line
    domain_to_ids: Dict[str, set] = defaultdict(set)
    domain_to_example_line: Dict[str, str] = {}
    for line_no, line, domain, seller_id in entries:
        domain_to_ids[domain].add(seller_id)
        domain_to_example_line.setdefault(domain, f"Line {line_no}: {line}")

    domains = sorted(domain_to_ids.keys())
    domain_stats: List[Dict] = []
    findings: List[Finding] = []

    total_ids = 0
    total_matched = 0
    reachable = 0
    unreachable = 0

    sleep_between = 0.15  # be polite

    for domain in domains:
        seller_ids = sorted(domain_to_ids[domain])
        total_ids += len(seller_ids)

        res = _cached_fetch(domain)

        if not getattr(res, "ok", False):
            unreachable += 1
            domain_stats.append(
                {
                    "domain": domain,
                    "json_ok": False,
                    "status": getattr(res, "status", None),
                    "seller_ids_in_ads_txt": len(seller_ids),
                    "seller_ids_matched": 0,
                    "match_rate": 0.0,
                    "error": getattr(res, "error", "Fetch failed"),
                    "seller_type_mix": {},
                    "intermediary_examples": [],
                    "agency_like_examples": [],
                }
            )

            findings.append(
                Finding(
                    rule_id="SELLERS_JSON_UNREACHABLE",
                    severity="MEDIUM",
                    title="sellers.json not reachable or not valid JSON",
                    why_buyer_cares="If sellers.json cannot be retrieved, seller verification is limited and supply-path transparency is weaker.",
                    recommendation="Treat as a transparency gap. Ask the seller/exchange whether they publish sellers.json correctly.",
                    evidence=Evidence(
                        line_no=None,
                        line=f"{domain}/sellers.json → {getattr(res, 'error', 'unreachable')} | {domain_to_example_line.get(domain,'')}",
                    ),
                )
            )
            time.sleep(sleep_between)
            continue

        reachable += 1
        idx = index_sellers_by_id(res.data)

        matched = 0
        missing: List[str] = []
        seller_type_mix: Dict[str, int] = defaultdict(int)

        intermediary_examples: List[str] = []
        agency_like_examples: List[str] = []

        # matched entries details
        for sid in seller_ids:
            entry = idx.get(sid)
            if entry is None:
                missing.append(sid)
                continue

            matched += 1
            stype = _safe_upper(entry.get("seller_type") if isinstance(entry, dict) else None)
            seller_type_mix[stype or "UNKNOWN"] += 1

            name = ""
            if isinstance(entry, dict):
                name = entry.get("name") or ""

            # Collect a few intermediary examples
            if stype in {"INTERMEDIARY", "BOTH"} and len(intermediary_examples) < 6:
                intermediary_examples.append(f"{sid} ({stype}) {name}".strip())

            # Collect a few agency/trading-desk-like names (best-effort)
            if name and _looks_agency_like(name) and len(agency_like_examples) < 6:
                agency_like_examples.append(f"{sid} ({stype}) {name}".strip())

        match_rate = (matched / max(1, len(seller_ids)))
        total_matched += matched

        domain_stats.append(
            {
                "domain": domain,
                "json_ok": True,
                "status": getattr(res, "status", 200),
                "seller_ids_in_ads_txt": len(seller_ids),
                "seller_ids_matched": matched,
                "match_rate": round(match_rate, 3),
                "error": None,
                "seller_type_mix": dict(sorted(seller_type_mix.items(), key=lambda x: x[1], reverse=True)),
                "intermediary_examples": intermediary_examples,
                "agency_like_examples": agency_like_examples,
            }
        )

        # Finding: missing seller ids
        if missing:
            examples = ", ".join(missing[:8])
            findings.append(
                Finding(
                    rule_id="SELLER_ID_NOT_FOUND_IN_SELLERS_JSON",
                    severity="HIGH",
                    title="Seller IDs in ads.txt not found in sellers.json",
                    why_buyer_cares="When a seller account in ads.txt cannot be validated against sellers.json, it raises questions about authorization accuracy, stale configs, or unclear selling relationships.",
                    recommendation="Ask the publisher/seller to confirm the correct seller account ID and preferred path (DIRECT where possible).",
                    evidence=Evidence(
                        line_no=None,
                        line=f"{domain}: missing {len(missing)}/{len(seller_ids)} seller IDs. Examples: {examples}. | {domain_to_example_line.get(domain,'')}",
                    ),
                )
            )

        # Finding: intermediary sellers present
        if intermediary_examples:
            findings.append(
                Finding(
                    rule_id="SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT",
                    severity="MEDIUM",
                    title="Intermediary sellers detected (likely extra hops)",
                    why_buyer_cares="Intermediary seller types can indicate additional hops and reselling, which may increase fees and reduce transparency. It is not always bad, but it is worth asking why this path is needed.",
                    recommendation="Ask for the preferred path for your buy and whether a more direct route exists (DIRECT where possible).",
                    evidence=Evidence(
                        line_no=None,
                        line=f"{domain}: examples → " + " | ".join(intermediary_examples[:6]),
                    ),
                )
            )

        time.sleep(sleep_between)

    avg_match_rate = (total_matched / max(1, total_ids))
    summary = {
        "domains_checked": len(domains),
        "reachable": reachable,
        "unreachable": unreachable,
        "total_seller_ids_checked": total_ids,
        "total_seller_ids_matched": total_matched,
        "avg_match_rate": round(avg_match_rate, 3),
        "notes": "Match rate compares seller IDs in ads.txt to seller_id entries in each ad system's sellers.json.",
    }

    return {
        "summary": summary,
        "domain_stats": domain_stats,
        "findings": [asdict(f) for f in findings],
    }
