import csv
import gzip
import io
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import httpx

from .base import (
    Ingestor,
    NormalizedVulnerability,
    RawVulnerability,
    get_response_with_retry,
)

_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EPSSIngestor(Ingestor):
    """Fetch the daily EPSS score snapshot (gzipped CSV) and upsert scores."""

    def source_name(self) -> str:
        return "epss"

    async def fetch_updates(self, since: datetime | None) -> AsyncIterator[list[RawVulnerability]]:
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            response = await get_response_with_retry(client, _EPSS_URL, headers={})

        text = gzip.decompress(response.content).decode("utf-8")

        lines = [ln for ln in text.splitlines() if not ln.startswith("#")]
        reader = csv.DictReader(lines)

        page: list[RawVulnerability] = []
        for row in reader:
            if row.get("cve"):
                page.append(
                    RawVulnerability(
                        cve_id=row["cve"],
                        source=self.source_name(),
                        raw_data=row,
                    )
                )
                if len(page) >= 5000:
                    yield page
                    page = []
        if page:
            yield page

    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        cve_id = raw["cve"]

        epss_score: float | None = None
        try:
            epss_score = float(raw["epss"])
        except (KeyError, ValueError, TypeError):
            pass

        epss_percentile: float | None = None
        try:
            epss_percentile = float(raw["percentile"])
        except (KeyError, ValueError, TypeError):
            pass

        return NormalizedVulnerability(
            cve_id=cve_id,
            source=self.source_name(),
            epss_score=epss_score,
            epss_percentile=epss_percentile,
        )
