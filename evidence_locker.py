# evidence_locker.py
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _safe_name(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9._-]+", "_", s)
    return s[:180] if len(s) > 180 else s


@dataclass
class SavedArtifact:
    relpath: str
    bytes_len: int
    sha256: str
    note: str = ""


def ensure_base_dir(base_dir: str | Path = "evidence") -> Path:
    p = Path(base_dir)
    p.mkdir(parents=True, exist_ok=True)
    return p


def create_run_dir(base_dir: str | Path = "evidence", prefix: str = "run") -> Tuple[str, Path]:
    base = ensure_base_dir(base_dir)
    run_id = f"{prefix}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


def _write_bytes(path: Path, data: bytes) -> SavedArtifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return SavedArtifact(
        relpath=str(path.as_posix()),
        bytes_len=len(data),
        sha256=_sha256_bytes(data),
    )


def _write_text(path: Path, text: str, encoding: str = "utf-8") -> SavedArtifact:
    return _write_bytes(path, text.encode(encoding))


def save_phase2_evidence(
    *,
    base_dir: str | Path,
    source_label: str,
    ads_txt_text: str,
    sellers_fetch_log: Iterable[Dict[str, Any]],
    phase2_report: Dict[str, Any],
    max_body_bytes: int = 2_000_000,  # keep packs sane
) -> Dict[str, Any]:
    """
    Saves an evidence folder with:
      - inputs/ads.txt
      - sellers_json/<domain>.<ext>
      - reports/phase2_sellers_verification.json
      - manifest.json (hashes + fetch metadata)
    Returns a small dict you can attach to the UI (run_id, path, counts).
    """
    run_id, run_dir = create_run_dir(base_dir, prefix="phase2")

    artifacts: list[SavedArtifact] = []

    artifacts.append(_write_text(run_dir / "inputs" / "ads.txt", ads_txt_text))
    artifacts.append(_write_bytes(
        run_dir / "reports" / "phase2_sellers_verification.json",
        json.dumps(phase2_report, indent=2, ensure_ascii=False).encode("utf-8"),
    ))

    # Save each fetched body (or snippet) with reasonable limits
    saved_fetches: list[Dict[str, Any]] = []
    for row in sellers_fetch_log:
        domain = str(row.get("domain") or "unknown")
        url = str(row.get("url") or "")
        status = row.get("status")
        content_type = str(row.get("content_type") or "")
        ok_json = bool(row.get("json_ok", False))
        error = row.get("error")

        body: bytes = row.get("body_bytes") or b""
        note = ""
        if len(body) > max_body_bytes:
            body = body[:max_body_bytes]
            note = f"TRUNCATED to {max_body_bytes} bytes"

        ext = "json" if ok_json else "txt"
        fname = f"{_safe_name(domain)}.{ext}"
        saved = _write_bytes(run_dir / "sellers_json" / fname, body)
        if note:
            saved.note = note

        saved_fetches.append({
            "domain": domain,
            "url": url,
            "status": status,
            "content_type": content_type,
            "json_ok": ok_json,
            "error": error,
            "saved_as": f"sellers_json/{fname}",
            "sha256": saved.sha256,
            "bytes_len": saved.bytes_len,
            "note": saved.note,
        })
        artifacts.append(saved)

    manifest = {
        "run_id": run_id,
        "generated_at": _now_iso(),
        "source_label": source_label,
        "artifact_count": len(artifacts),
        "artifacts": [
            {
                "path": a.relpath.replace(str(run_dir.as_posix()) + "/", ""),
                "bytes_len": a.bytes_len,
                "sha256": a.sha256,
                "note": a.note,
            }
            for a in artifacts
        ],
        "fetch_log": saved_fetches,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "artifact_count": len(artifacts),
        "saved_fetches": len(saved_fetches),
        "generated_at": manifest["generated_at"],
    }


def zip_run_dir(run_dir: str | Path) -> Tuple[str, bytes]:
    """
    Returns (filename, zip_bytes) for a given run_dir.
    """
    run_path = Path(run_dir)
    if not run_path.exists() or not run_path.is_dir():
        raise FileNotFoundError(f"Run directory not found: {run_dir}")

    filename = f"{run_path.name}.zip"
    from io import BytesIO
    buf = BytesIO()

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in run_path.rglob("*"):
            if p.is_file():
                arcname = str(p.relative_to(run_path))
                z.write(p, arcname)

    return filename, buf.getvalue()
