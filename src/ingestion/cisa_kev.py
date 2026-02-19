from datetime import date, datetime, timezone
from typing import Any

import httpx

from .base import (
    Ingestor,
    NormalizedVulnerability,
    RawVulnerability,
    Reference,
    get_response_with_retry,
)

_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class CISAKEVIngestor(Ingestor):
    def source_name(self) -> str:
        return "cisa_kev"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            response = await get_response_with_retry(client, _KEV_URL, headers={})

        catalog = response.json()
        results: list[RawVulnerability] = []

        for entry in catalog.get("vulnerabilities", []):
            cve_id = entry.get("cveID")
            if not cve_id:
                continue

            if since:
                date_added = entry.get("dateAdded", "")
                if date_added:
                    try:
                        added = datetime.strptime(date_added, "%Y-%m-%d").replace(
                            tzinfo=timezone.utc,
                        )
                        if added < since:
                            continue
                    except ValueError:
                        pass

            results.append(
                RawVulnerability(
                    cve_id=cve_id,
                    source=self.source_name(),
                    raw_data=entry,
                )
            )

        return results

    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        cve_id = raw["cveID"]

        due_date: date | None = None
        if raw.get("dueDate"):
            try:
                due_date = date.fromisoformat(raw["dueDate"])
            except ValueError:
                pass

        published_at: datetime | None = None
        if raw.get("dateAdded"):
            try:
                published_at = datetime.strptime(
                    raw["dateAdded"], "%Y-%m-%d",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        references: list[Reference] = []
        notes = raw.get("notes", "")
        if notes and notes.startswith("http"):
            references.append(Reference(url=notes, ref_type="advisory"))

        return NormalizedVulnerability(
            cve_id=cve_id,
            source=self.source_name(),
            description=raw.get("shortDescription"),
            cisa_kev=True,
            cisa_kev_due_date=due_date,
            published_at=published_at,
            references=references,
        )
