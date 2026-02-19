from datetime import date, datetime, timezone
import os
import asyncio
from typing import Any
import httpx
from .base import (
    Ingestor, RawVulnerability, NormalizedVulnerability,
    Reference, get_response_with_retry,
)

_NVD_TAG_MAP = {
    "Patch": "patch",
    "Exploit": "exploit",
    "Vendor Advisory": "advisory",
    "Third Party Advisory": "advisory",
    "US Government Resource": "advisory",
}


class NVDIngestor(Ingestor):
    def __init__(self) -> None:
        self.api_key = os.getenv("NVD_API_KEY")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.page_size = 2000
        self.request_delay = 0.65
        self.date_format = "%Y-%m-%dT%H:%M:%S.000"

    def source_name(self) -> str:
        return "nvd"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        params: dict[str, Any] = {"resultsPerPage": self.page_size}
        if since is not None:
            now = datetime.now(timezone.utc)
            params["lastModStartDate"] = since.strftime(self.date_format)
            params["lastModEndDate"] = now.strftime(self.date_format)
        results: list[RawVulnerability] = []
        start_idx = 0
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params["startIndex"] = start_idx
                response = await get_response_with_retry(
                    client, self.base_url, headers=headers, params=params,
                )
                data = response.json()
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "")
                    if cve_id:
                        results.append(RawVulnerability(cve_id, self.source_name(), cve))
                total = data.get("totalResults", 0)
                start_idx += len(data.get("vulnerabilities", []))
                if start_idx >= total:
                    break
                await asyncio.sleep(self.request_delay)
        return results

    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        descriptions = raw.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else None,
        )

        cvss_score = None
        cvss_vector = None
        cvss_version = None
        severity = None
        metrics = raw.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if not entries:
                continue
            metric = next(
                (e for e in entries if e.get("type") == "Primary"),
                entries[0],
            )
            data = metric.get("cvssData", {})
            cvss_score = data.get("baseScore")
            cvss_vector = data.get("vectorString")
            cvss_version = data.get("version")
            severity = data.get("baseSeverity") or metric.get("baseSeverity")
            break

        published_str = raw.get("published")
        modified_str = raw.get("lastModified")
        published_at = datetime.fromisoformat(published_str) if published_str else None
        modified_at = datetime.fromisoformat(modified_str) if modified_str else None

        cisa_due = raw.get("cisaActionDue")
        cisa_kev = cisa_due is not None
        cisa_kev_due_date = date.fromisoformat(cisa_due) if cisa_due else None

        references = [
            Reference(
                url=ref["url"],
                ref_type=next(
                    (_NVD_TAG_MAP[t] for t in ref.get("tags", []) if t in _NVD_TAG_MAP),
                    None,
                ),
            )
            for ref in raw.get("references", [])
            if ref.get("url")
        ]

        return NormalizedVulnerability(
            cve_id=raw.get("id", ""),
            source=self.source_name(),
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_version=cvss_version,
            severity=severity,
            cisa_kev=cisa_kev,
            cisa_kev_due_date=cisa_kev_due_date,
            published_at=published_at,
            modified_at=modified_at,
            references=references,
        )