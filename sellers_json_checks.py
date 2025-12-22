# sellers_json_checks.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import json
import gzip

import requests


@dataclass
class FetchResult:
    ok: bool
    url: str
    status: Optional[int]
    content_type: Optional[str]
    size_bytes: Optional[int]
    error: Optional[str]
    data: Optional[dict]


def _looks_like_json(content: bytes) -> bool:
    s = content.lstrip()
    return s.startswith(b"{") or s.startswith(b"[")


def fetch_sellers_json(
    domain: str,
    *,
    timeout: Tuple[int, int] = (5, 25),
    max_bytes: int = 10_000_000,
    user_agent: str = "AdChainAudit/0.2 (+https://github.com/maazkhan86/AdChainAudit)",
) -> FetchResult:
    domain = domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    url = f"https://{domain}/sellers.json"

    headers = {
        "User-Agent": user_agent,
        "Accept": "application/json,text/plain;q=0.9,*/*;q=0.8",
    }

    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
        status = r.status_code
        content_type = r.headers.get("Content-Type", "")

        content = b""
        for chunk in r.iter_content(chunk_size=64 * 1024):
            if not chunk:
                break
            content += chunk
            if len(content) > max_bytes:
                return FetchResult(
                    ok=False,
                    url=url,
                    status=status,
                    content_type=content_type,
                    size_bytes=len(content),
                    error=f"Response too large (> {max_bytes} bytes)",
                    data=None,
                )

        size_bytes = len(content)

        if content[:2] == b"\x1f\x8b":
            try:
                content = gzip.decompress(content)
            except Exception:
                pass

        if status != 200:
            return FetchResult(
                ok=False,
                url=url,
                status=status,
                content_type=content_type,
                size_bytes=size_bytes,
                error=f"Non-200 status ({status})",
                data=None,
            )

        if ("json" not in (content_type or "").lower()) and not _looks_like_json(content):
            snippet = content[:220].decode("utf-8", errors="replace").replace("\n", " ")
            return FetchResult(
                ok=False,
                url=url,
                status=status,
                content_type=content_type,
                size_bytes=size_bytes,
                error=f"Not JSON (ctype={content_type}). Snippet: {snippet}",
                data=None,
            )

        try:
            parsed = json.loads(content.decode("utf-8", errors="replace"))
        except Exception as e:
            return FetchResult(
                ok=False,
                url=url,
                status=status,
                content_type=content_type,
                size_bytes=size_bytes,
                error=f"JSON parse error: {e}",
                data=None,
            )

        if not isinstance(parsed, dict):
            return FetchResult(
                ok=False,
                url=url,
                status=status,
                content_type=content_type,
                size_bytes=size_bytes,
                error="Unexpected JSON structure (expected object at top-level)",
                data=None,
            )

        return FetchResult(
            ok=True,
            url=url,
            status=status,
            content_type=content_type,
            size_bytes=size_bytes,
            error=None,
            data=parsed,
        )

    except Exception as e:
        return FetchResult(
            ok=False,
            url=url,
            status=None,
            content_type=None,
            size_bytes=None,
            error=str(e),
            data=None,
        )


def index_sellers_by_id(sellers_json: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(sellers_json, dict):
        return {}

    sellers = sellers_json.get("sellers")
    if not isinstance(sellers, list):
        return {}

    idx: Dict[str, Dict[str, Any]] = {}
    for s in sellers:
        if not isinstance(s, dict):
            continue
        sid = s.get("seller_id")
        if sid is None:
            continue
        idx[str(sid)] = s

    return idx
