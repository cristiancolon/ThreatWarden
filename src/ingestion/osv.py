import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

import httpx

from .base import (
    AffectedPackage,
    Ingestor,
    NormalizedVulnerability,
    RawVulnerability,
    Reference,
)

_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
_CVE_PREFIX = "CVE-"
_DEFAULT_ECOSYSTEMS = ("PyPI", "npm")


class OSVIngestor(Ingestor):
    def __init__(self, ecosystems: list[str] | None = None) -> None:
        self.ecosystems = ecosystems or list(_DEFAULT_ECOSYSTEMS)

    def source_name(self) -> str:
        return "osv"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        results: list[RawVulnerability] = []

        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            for ecosystem in self.ecosystems:
                url = f"{_GCS_BASE}/{ecosystem}/all.zip"
                response = await client.get(url)
                response.raise_for_status()

                with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                    for name in zf.namelist():
                        if not name.endswith(".json"):
                            continue

                        data = json.loads(zf.read(name))

                        if since:
                            modified_str = data.get("modified")
                            if modified_str:
                                modified = datetime.fromisoformat(modified_str)
                                if modified.tzinfo is None:
                                    modified = modified.replace(tzinfo=timezone.utc)
                                if modified < since:
                                    continue

                        aliases = data.get("aliases") or []
                        cve_ids = [a for a in aliases if a.startswith(_CVE_PREFIX)]
                        if not cve_ids and data.get("id", "").startswith(_CVE_PREFIX):
                            cve_ids = [data["id"]]
                        if not cve_ids:
                            continue

                        for cve_id in cve_ids:
                            results.append(
                                RawVulnerability(
                                    cve_id=cve_id,
                                    source=self.source_name(),
                                    raw_data=data,
                                ),
                            )

        return results

    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        aliases = raw.get("aliases") or []
        cve_id = next(
            (a for a in aliases if a.startswith(_CVE_PREFIX)),
            raw.get("id", ""),
        )

        cvss_vector = None
        cvss_version = None
        for sev in raw.get("severity") or []:
            vec = sev.get("score")
            if vec:
                cvss_vector = vec
                sev_type = sev.get("type", "")
                if sev_type == "CVSS_V3":
                    cvss_version = "3.1"
                elif sev_type == "CVSS_V4":
                    cvss_version = "4.0"
                break

        severity = None
        affected_packages: list[AffectedPackage] = []

        for affected in raw.get("affected") or []:
            pkg = affected.get("package") or {}
            ecosystem = pkg.get("ecosystem")
            name = pkg.get("name")
            if not ecosystem or not name:
                continue

            patched = None
            range_parts: list[str] = []

            for r in affected.get("ranges") or []:
                if r.get("type") != "ECOSYSTEM":
                    continue
                introduced = None
                for event in r.get("events") or []:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        patched = event["fixed"]
                if introduced is not None:
                    part = f">={introduced}" if introduced != "0" else "*"
                    if patched:
                        part += f", <{patched}"
                    range_parts.append(part)

            affected_packages.append(
                AffectedPackage(
                    ecosystem=ecosystem,
                    package_name=name,
                    vulnerable_versions=", ".join(range_parts) if range_parts else None,
                    patched_version=patched,
                ),
            )

            if not severity:
                eco_sev = (affected.get("ecosystem_specific") or {}).get("severity")
                db_sev = (affected.get("database_specific") or {}).get("severity")
                raw_sev = (eco_sev or db_sev or "").upper()
                if raw_sev and raw_sev != "UNKNOWN":
                    severity = raw_sev

        published_str = raw.get("published")
        modified_str = raw.get("modified")
        published_at = datetime.fromisoformat(published_str) if published_str else None
        modified_at = datetime.fromisoformat(modified_str) if modified_str else None

        references = [
            Reference(
                url=ref["url"],
                ref_type=(ref.get("type") or "").lower() or None,
            )
            for ref in raw.get("references") or []
            if ref.get("url")
        ]

        return NormalizedVulnerability(
            cve_id=cve_id,
            source=self.source_name(),
            description=raw.get("details") or raw.get("summary"),
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            severity=severity,
            published_at=published_at,
            modified_at=modified_at,
            affected_packages=affected_packages,
            references=references,
        )
