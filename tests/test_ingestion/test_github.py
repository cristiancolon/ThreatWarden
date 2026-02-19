from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ingestion.github import GithubIngestor, parse_next_url

_REQ = httpx.Request("GET", "https://test.example.com")


# ── Sample data ───────────────────────────────────────────────────────────

_ADVISORY_FULL = {
    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
    "cve_id": "CVE-2025-5678",
    "summary": "Critical vulnerability in flask",
    "description": "A critical vulnerability was found in Flask allowing RCE.",
    "severity": "critical",
    "cvss_severities": {
        "cvss_v3": {
            "score": 9.8,
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }
    },
    "epss": {"percentage": 87.5, "percentile": 99.2},
    "published_at": "2025-01-15T10:00:00Z",
    "updated_at": "2025-01-20T12:00:00Z",
    "vulnerabilities": [
        {
            "package": {"ecosystem": "pip", "name": "flask"},
            "vulnerable_version_range": ">=2.0.0, <2.3.1",
            "first_patched_version": "2.3.1",
        }
    ],
    "references": [
        "https://nvd.nist.gov/vuln/detail/CVE-2025-5678",
        "https://github.com/pallets/flask/security/advisories/GHSA-xxxx",
    ],
}

_ADVISORY_MINIMAL = {
    "ghsa_id": "GHSA-yyyy-yyyy-yyyy",
    "cve_id": "CVE-2025-0001",
    "summary": "Minor issue",
    "severity": "low",
}


# ── parse_next_url ────────────────────────────────────────────────────────


def test_parse_next_url_extracts_url():
    header = (
        '<https://api.github.com/advisories?after=Y3Vyc29yOjEw>; rel="next", '
        '<https://api.github.com/advisories?before=Y3Vyc29yOjE>; rel="prev"'
    )
    assert parse_next_url(header) == "https://api.github.com/advisories?after=Y3Vyc29yOjEw"


def test_parse_next_url_returns_none_when_no_next():
    header = '<https://api.github.com/advisories?before=abc>; rel="prev"'
    assert parse_next_url(header) is None


def test_parse_next_url_returns_none_for_none_input():
    assert parse_next_url(None) is None


def test_parse_next_url_returns_none_for_empty_string():
    assert parse_next_url("") is None


# ── source_name ───────────────────────────────────────────────────────────


def test_source_name():
    assert GithubIngestor().source_name() == "github"


# ── fetch_updates ─────────────────────────────────────────────────────────


def _github_page(advisories: list[dict], link_header: str | None = None) -> httpx.Response:
    headers = {}
    if link_header:
        headers["Link"] = link_header
    return httpx.Response(200, json=advisories, headers=headers, request=_REQ)


async def test_fetch_full_sync():
    resp = _github_page([_ADVISORY_FULL, _ADVISORY_MINIMAL])

    with (
        patch("ingestion.github.get_response_with_retry", new_callable=AsyncMock, return_value=resp),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await GithubIngestor().fetch_updates(since=None)

    assert len(results) == 2
    assert results[0].cve_id == "CVE-2025-5678"
    assert all(r.source == "github" for r in results)


async def test_fetch_incremental_adds_modified_param():
    resp = _github_page([_ADVISORY_FULL])
    since = datetime(2025, 2, 1, 14, 30, 0, tzinfo=timezone.utc)

    with (
        patch("ingestion.github.get_response_with_retry", new_callable=AsyncMock, return_value=resp) as mock_get,
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        await GithubIngestor().fetch_updates(since=since)

    _, kwargs = mock_get.call_args
    params = kwargs["params"]
    assert "modified" in params
    assert params["modified"] == "2025-02-01T14:30:00Z..*"


async def test_fetch_pagination_follows_link_header():
    page1 = _github_page(
        [{"cve_id": "CVE-2025-0001", "ghsa_id": "A"}],
        link_header='<https://api.github.com/advisories?after=cur1>; rel="next"',
    )
    page2 = _github_page([{"cve_id": "CVE-2025-0002", "ghsa_id": "B"}])

    with (
        patch("ingestion.github.get_response_with_retry", new_callable=AsyncMock, side_effect=[page1, page2]),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await GithubIngestor().fetch_updates(since=None)

    assert len(results) == 2
    assert results[1].cve_id == "CVE-2025-0002"


async def test_fetch_skips_advisories_without_cve_id():
    resp = _github_page([
        {"cve_id": "CVE-2025-0001", "ghsa_id": "A"},
        {"ghsa_id": "B"},  # no cve_id
        {"cve_id": None, "ghsa_id": "C"},
    ])

    with (
        patch("ingestion.github.get_response_with_retry", new_callable=AsyncMock, return_value=resp),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await GithubIngestor().fetch_updates(since=None)

    assert len(results) == 1


# ── _normalize ────────────────────────────────────────────────────────────


def test_normalize_cvss_from_severities():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert result.cvss_score == 9.8
    assert result.cvss_version == "3.1"
    assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_normalize_cvss_falls_back_to_v4():
    advisory = {
        **_ADVISORY_MINIMAL,
        "cvss_severities": {
            "cvss_v4": {"score": 8.5, "vector_string": "CVSS:4.0/AV:N/..."},
        },
    }
    result = GithubIngestor()._normalize(advisory)

    assert result.cvss_score == 8.5
    assert result.cvss_version == "4.0"


def test_normalize_no_cvss():
    result = GithubIngestor()._normalize(_ADVISORY_MINIMAL)

    assert result.cvss_score is None
    assert result.cvss_vector is None


def test_normalize_affected_packages():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert len(result.affected_packages) == 1
    pkg = result.affected_packages[0]
    assert pkg.ecosystem == "pip"
    assert pkg.package_name == "flask"
    assert pkg.vulnerable_versions == ">=2.0.0, <2.3.1"
    assert pkg.patched_version == "2.3.1"


def test_normalize_epss_scaled_from_percentage():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert result.epss_score == pytest.approx(0.875)
    assert result.epss_percentile == pytest.approx(0.992)


def test_normalize_epss_none_when_missing():
    result = GithubIngestor()._normalize(_ADVISORY_MINIMAL)

    assert result.epss_score is None
    assert result.epss_percentile is None


def test_normalize_references_are_plain_urls():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    urls = [r.url for r in result.references]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2025-5678" in urls
    assert all(r.ref_type is None for r in result.references)


def test_normalize_severity_uppercased():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert result.severity == "CRITICAL"


def test_normalize_severity_unknown_treated_as_none():
    advisory = {**_ADVISORY_MINIMAL, "severity": "unknown"}
    result = GithubIngestor()._normalize(advisory)

    assert result.severity is None


def test_normalize_description_prefers_description_over_summary():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert "critical vulnerability" in result.description.lower()


def test_normalize_description_falls_back_to_summary():
    result = GithubIngestor()._normalize(_ADVISORY_MINIMAL)

    assert result.description == "Minor issue"


def test_normalize_parses_dates():
    result = GithubIngestor()._normalize(_ADVISORY_FULL)

    assert result.published_at is not None
    assert result.published_at.year == 2025
    assert result.modified_at is not None
