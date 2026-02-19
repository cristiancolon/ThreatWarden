from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date, datetime
import asyncio
from typing import Any
from dotenv import load_dotenv
import httpx


load_dotenv()

@dataclass
class RawVulnerability:
    cve_id: str
    source: str
    raw_data: dict[str, Any]

@dataclass
class AffectedPackage:
    ecosystem: str
    package_name: str
    vulnerable_versions: str | None = None
    patched_version: str | None = None

@dataclass
class Exploit:
    source: str
    source_id: str | None = None
    url: str | None = None
    description: str | None = None
    discovered_at: datetime | None = None

@dataclass
class Reference:
    url: str
    ref_type: str | None = None

@dataclass
class NormalizedVulnerability:
    cve_id: str
    source: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_version: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    cisa_kev: bool = False
    cisa_kev_due_date: date | None = None
    severity: str | None = None
    published_at: datetime | None = None
    modified_at: datetime | None = None
    affected_packages: list[AffectedPackage] = field(default_factory=list)
    exploits: list[Exploit] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)


async def get_response_with_retry(
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
        max_retries: int = 5,
    ) -> httpx.Response:
        """Make an HTTP GET request with exponential backoff on 429 / 5xx responses."""
        delay = 1.0
        last_response = None
        for attempt in range(max_retries):
            response = await client.get(url, headers=headers, params=params or {})
            last_response = response
            if response.status_code in {429, 500, 502, 503, 504} and attempt < max_retries - 1:
                await asyncio.sleep(delay)
                delay *= 2
                continue
            response.raise_for_status()
            return response
        assert last_response is not None
        last_response.raise_for_status()
        return last_response

class Ingestor(ABC):
    @abstractmethod
    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        """
        Fetch new or updated vulnerability records since the given timestamp.
        If `since` is None, perform a full initial sync.
        Returns a list of normalized intermediate records.
        """
    @abstractmethod
    def source_name(self) -> str:
        """
        Return the name of this ingestor's source
        """
    @abstractmethod
    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        """
        Convert a single raw API response dict into a NormalizedVulnerability.
        """
    def normalize_updates(self, raw_updates: list[dict[str, Any]]) -> list[NormalizedVulnerability]:
        return [self._normalize(raw) for raw in raw_updates]

