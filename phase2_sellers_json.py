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
        seller_id = parts[1].strip()
        if domain and seller_id:
            out.append((i, cleaned, domain, seller_id))
    return out


@lru_cache(maxsize=256)
def _cached_fetch(domain: str):
    # Cache per domain for the life of the Streamlit process.
    return fetch_sellers_json(domain)


def _safe_upper(x) -> str:
    if x is None:
        return ""
    return str(x).strip().upper()


def run_sellers_json_verification(
    ads_txt: str,
    *,
    max_domains: int = 25,
    sleep_between: float = 0.25,
    missing_sample_size: int = 8,
    intermediary_sample_size: int = 6,
    confidential_sample_size: int = 6,
) -> Dict:
    """
    Phase 2:
      - Extract unique ad_system domains
      - Fetch /sellers.json per domain (cached)
      - Check whether ads.txt seller IDs exist in sellers.json
      - NEW: detect INTERMEDIARY/BOTH sellers + confidential sellers
      - Return: summary + aggregated findings (dicts compatible with Phase 1 report)
    """
    entries = parse_ads_txt_entries(ads_txt)

    domain_to_ids: Dict[str, set] = defaultdict(set)
    domain_to_example_line: Dict[str, Tuple[int, str]] = {}

    for line_no, raw_line, domain, seller_id in entries:
        domain_to_ids[domain].add(seller_id)
        if domain not in domain_to_example_line:
            domain_to_example_line[domain] = (line_no, raw_line)

    domains = list(domain_to_ids.keys())[:max_domains]

    findings: List[Finding] = []

    reachable = 0
    unreachable = 0
    total_ids = 0
    total_matched = 0
    domain_stats = []

    for domain in domains:
        seller_ids = sorted(list(domain_to_ids[domain]))
        total_ids += len(seller_ids)

        res = _cached_fetch(domain)
        if not res.ok or not res.data:
            unreachable += 1
            ex_ln, ex_line = domain_to_example_line.get(domain, (None, ""))
            findings.append(
                Finding(
                    rule_id="SELLERS_JSON_UNREACHABLE",
                    severity="MEDIUM",
                    title="sellers.json not reachable or not valid JSON",
                    why_buyer_cares="If sellers.json cannot be retrieved, seller verification is limited and supply-path transparency is weaker.",
                    recommendation="Treat as a transparency gap. Ask the seller/exchange whether they publish sellers.json correctly.",
                    evidence=Evidence(
                        line_no=ex_ln,
                        line=f"{domain}/sellers.json → {res.error or 'unreachable'} | example ads.txt: {ex_line}",
                    ),
                )
            )
            domain_stats.append(
                {
                    "domain": domain,
                    "json_ok": False,
                    "status": res.status,
                    "seller_ids_in_ads_txt": len(seller_ids),
                    "seller_ids_matched": 0,
                    "match_rate": 0.0,
                    "error": res.error,
                }
            )
            time.sleep(sleep_between)
            continue

        reachable += 1
        idx = index_sellers_by_id(res.data)

        matched = 0
        missing: List[str] = []

        # NEW: collect intermediary + confidential sellers among matched IDs
        intermediary_hits: List[str] = []
        confidential_hits: List[str] = []

        for sid in seller_ids:
            rec = idx.get(str(sid))
            if rec is not None:
                matched += 1

                seller_type = _safe_upper(rec.get("seller_type"))
                # INTERMEDIARY or BOTH suggests extra hops / reselling
                if seller_type in {"INTERMEDIARY", "BOTH"} and len(intermediary_hits) < intermediary_sample_size:
                    name = rec.get("name") or ""
                    intermediary_hits.append(f"{sid} ({seller_type}) {name}".strip())

                is_conf = rec.get("is_confidential")
                if is_conf is True and len(confidential_hits) < confidential_sample_size:
                    name = rec.get("name") or ""
                    confidential_hits.append(f"{sid} (confidential) {name}".strip())
            else:
                if len(missing) < missing_sample_size:
                    missing.append(str(sid))

        total_matched += matched
        match_rate = (matched / len(seller_ids)) if seller_ids else 0.0

        # Aggregate missing seller IDs into a single finding per domain (keeps report readable)
        if matched < len(seller_ids):
            ex_ln, ex_line = domain_to_example_line.get(domain, (None, ""))
            missing_count = len(seller_ids) - matched
            sample_txt = ", ".join(missing) if missing else "—"
            findings.append(
                Finding(
                    rule_id="SELLER_ID_NOT_FOUND_IN_SELLERS_JSON",
                    severity="HIGH",
                    title="Seller IDs in ads.txt not found in sellers.json",
                    why_buyer_cares="When a seller account in ads.txt cannot be validated against sellers.json, it raises questions about authorization accuracy, stale configs, or unclear selling relationships.",
                    recommendation="Ask the publisher/seller to confirm the correct seller account ID and preferred path (DIRECT where possible).",
                    evidence=Evidence(
                        line_no=ex_ln,
                        line=(
                            f"{domain}: missing {missing_count}/{len(seller_ids)} seller IDs in sellers.json. "
                            f"Examples: {sample_txt}. | example ads.txt: {ex_line}"
                        ),
                    ),
                )
            )

        # NEW: Intermediary sellers signal
        if intermediary_hits:
            ex_ln, ex_line = domain_to_example_line.get(domain, (None, ""))
            findings.append(
                Finding(
                    rule_id="SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT",
                    severity="MEDIUM",
                    title="Intermediary sellers detected (likely extra hops)",
                    why_buyer_cares="Intermediary seller types can indicate additional hops and reselling, which may increase fees and reduce transparency. It is not always bad, but it is worth asking why this path is needed.",
                    recommendation="Ask for the preferred path for your buy and whether a more direct route exists (DIRECT where possible).",
                    evidence=Evidence(
                        line_no=ex_ln,
                        line=(
                            f"{domain}: example intermediary seller IDs from sellers.json → "
                            f"{', '.join(intermediary_hits)} | example ads.txt: {ex_line}"
                        ),
                    ),
                )
            )

        # NEW: Confidential sellers signal
        if confidential_hits:
            ex_ln, ex_line = domain_to_example_line.get(domain, (None, ""))
            findings.append(
                Finding(
                    rule_id="SELLERS_JSON_CONFIDENTIAL_SELLERS_PRESENT",
                    severity="LOW",
                    title="Confidential sellers detected (reduced transparency)",
                    why_buyer_cares="Confidential sellers can limit transparency and make verification harder. This is not automatically a red flag, but it reduces auditability.",
                    recommendation="If significant spend is routed through confidential sellers, ask the seller/publisher to clarify the relationship and preferred authorized path.",
                    evidence=Evidence(
                        line_no=ex_ln,
                        line=(
                            f"{domain}: example confidential sellers from sellers.json → "
                            f"{', '.join(confidential_hits)} | example ads.txt: {ex_line}"
                        ),
                    ),
                )
            )

        domain_stats.append(
            {
                "domain": domain,
                "json_ok": True,
                "status": res.status,
                "seller_ids_in_ads_txt": len(seller_ids),
                "seller_ids_matched": matched,
                "match_rate": round(match_rate, 3),
                "error": None,
            }
        )

        time.sleep(sleep_between)

    avg_match_rate = (total_matched / total_ids) if total_ids else 0.0

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
