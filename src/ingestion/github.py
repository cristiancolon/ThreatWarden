from datetime import datetime, timezone
import logging
import os
import re
import asyncio
from typing import Any
import httpx
from .base import (
    Ingestor, RawVulnerability, NormalizedVulnerability,
    AffectedPackage, Reference, get_response_with_retry,
)

logger = logging.getLogger("threatwarden.github")


_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

def parse_next_url(link_header: str | None) -> str | None:
    """Extract the 'next' URL from a GitHub Link header."""
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header)
    return match.group(1) if match else None


class GithubIngestor(Ingestor):
    def __init__(self) -> None:
        self.base_url = "https://api.github.com/advisories"
        self.token = os.getenv("GITHUB_TOKEN")
        self.page_size = 100
        self.request_delay = 0.65
        self.date_format = "%Y-%m-%dT%H:%M:%SZ"

    def source_name(self) -> str:
        return "github"

    async def fetch_updates(self, since: datetime | None):
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params: dict[str, Any] | None = {
            "per_page": self.page_size,
            "type": "reviewed",
        }
        if since is not None:
            since_str = since.strftime(self.date_format)
            now_str = datetime.now(timezone.utc).strftime(self.date_format)
            params["modified"] = f"{since_str}..{now_str}"

        url: str | None = self.base_url
        seen_cve_ids: set[str] = set()
        consecutive_stale = 0
        page_count = 0
        _STALE_LIMIT = 50

        async with httpx.AsyncClient(timeout=60.0) as client:
            while url is not None:
                response = await get_response_with_retry(
                    client, url, headers=headers, params=params,
                )
                page = []
                new_on_page = 0
                for advisory in response.json():
                    cve_id = advisory.get("cve_id")
                    if cve_id:
                        page.append(RawVulnerability(cve_id, self.source_name(), advisory))
                        if cve_id not in seen_cve_ids:
                            seen_cve_ids.add(cve_id)
                            new_on_page += 1
                if page:
                    yield page

                page_count += 1

                if page and new_on_page == 0:
                    consecutive_stale += 1
                elif page:
                    consecutive_stale = 0

                if consecutive_stale >= _STALE_LIMIT:
                    logger.warning(
                        "stopping: %d consecutive pages with no new CVE IDs "
                        "(%d unique CVEs across %d pages)",
                        consecutive_stale, len(seen_cve_ids), page_count,
                    )
                    break

                if page_count % 100 == 0:
                    logger.info(
                        "page %d (%d unique CVEs so far)",
                        page_count, len(seen_cve_ids),
                    )

                url = parse_next_url(response.headers.get("Link"))
                params = None

                if url is not None:
                    await asyncio.sleep(self.request_delay)

    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        # cvss field was removed April 2025; use cvss_severities instead
        cvss_score = None
        cvss_vector = None
        cvss_version = None
        severities = raw.get("cvss_severities") or {}
        for key, version in (("cvss_v3", "3.1"), ("cvss_v4", "4.0")):
            entry = severities.get(key) or {}
            if entry.get("score") is not None:
                cvss_score = entry["score"]
                cvss_vector = entry.get("vector_string")
                cvss_version = version
                break

        raw_severity = (raw.get("severity") or "").upper()
        severity = raw_severity if raw_severity and raw_severity != "UNKNOWN" else None

        published_str = raw.get("published_at")
        modified_str = raw.get("updated_at")
        published_at = datetime.fromisoformat(published_str) if published_str else None
        modified_at = datetime.fromisoformat(modified_str) if modified_str else None

        affected_packages = [
            AffectedPackage(
                ecosystem=vuln["package"]["ecosystem"],
                package_name=vuln["package"]["name"],
                vulnerable_versions=vuln.get("vulnerable_version_range"),
                patched_version=vuln.get("first_patched_version"),
            )
            for vuln in raw.get("vulnerabilities") or []
            if vuln.get("package") and vuln["package"].get("name")
        ]

        # GitHub references are plain URL strings, not objects
        references = [
            Reference(url=url)
            for url in (raw.get("references") or [])
            if isinstance(url, str)
        ]

        # GitHub provides EPSS data directly (0-100 scale, normalize to 0-1)
        epss = raw.get("epss") or {}
        epss_pct = epss.get("percentage")
        epss_ptile = epss.get("percentile")
        epss_score = epss_pct / 100.0 if epss_pct is not None else None
        epss_percentile = epss_ptile / 100.0 if epss_ptile is not None else None

        return NormalizedVulnerability(
            cve_id=raw.get("cve_id", ""),
            source=self.source_name(),
            description=raw.get("description") or raw.get("summary"),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            severity=severity,
            published_at=published_at,
            modified_at=modified_at,
            affected_packages=affected_packages,
            references=references,
        )
