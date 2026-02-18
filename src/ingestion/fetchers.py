from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
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

async def get_with_retry(
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any] | None = None,
        max_retries: int = 5,
    ) -> dict[str, Any]:
        """Convenience wrapper: same as get_response_with_retry but returns parsed JSON."""
        response = await get_response_with_retry(client, url, headers, params, max_retries)
        return response.json()

_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')

def parse_next_url(link_header: str | None) -> str | None:
    """Extract the 'next' URL from a GitHub Link header."""
    if not link_header:
        return None
    match = _LINK_NEXT_RE.search(link_header)
    return match.group(1) if match else None

class Fetcher(ABC):
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
        Return the name of this fetcher's source
        """

class NVDFetcher(Fetcher):
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
        params: dict[str, Any] = { "resultsPerPage" : self.page_size }
        if since is not None:
            now = datetime.now(timezone.utc)
            params["lastModStartDate"] = since.strftime(self.date_format)
            params["lastModEndDate"] = now.strftime(self.date_format)
        results: list[RawVulnerability] = []
        start_idx = 0
        async with httpx.AsyncClient(timeout=60.0) as client:
            while True:
                params["startIndex"] = start_idx
                data = await get_with_retry(client, self.base_url, headers=headers, params=params)
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



class GithubFetcher(Fetcher):
    def __init__(self) -> None:
        self.base_url = "https://api.github.com/advisories"
        self.token = os.getenv("SENTINEL_GITHUB_TOKEN")
        self.page_size = 100
        self.request_delay = 0.65
        self.date_format = "%Y-%m-%dT%H:%M:%SZ"

    def source_name(self) -> str:
        return "github"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params= {
            "per_page": self.page_size,
            "type": "reviewed",
        }
        if since is not None:
            since_str = since.strftime(self.date_format)
            params["modified"] = f"{since_str}..*"

        results = []
        url = self.base_url

        async with httpx.AsyncClient(timeout=60.0) as client:
            while url is not None:
                response = await get_response_with_retry(
                    client, url, headers=headers, params=params,
                )
                for advisory in response.json():
                    cve_id = advisory.get("cve_id")
                    if cve_id:
                        results.append(RawVulnerability(cve_id, self.source_name(), advisory))

                url = parse_next_url(response.headers.get("Link"))
                params = {}

                if url is not None:
                    await asyncio.sleep(self.request_delay)
        return results

class CISAKEVFetcher(Fetcher):
    def source_name(self) -> str:
        return "cisa_kev"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        pass

class EPSSFetcher(Fetcher):
    def source_name(self) -> str:
        return "epss"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        pass

class ExploitDBFetcher(Fetcher):
    def source_name(self) -> str:
        return "exploitdb"

    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        pass