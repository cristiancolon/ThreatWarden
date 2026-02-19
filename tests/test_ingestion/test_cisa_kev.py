from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx

from ingestion.cisa_kev import CISAKEVIngestor

_REQ = httpx.Request("GET", "https://test.example.com")


async def _collect(gen):
    results = []
    async for page in gen:
        results.extend(page)
    return results


_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2025.01.10",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2025-1111",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE",
            "dateAdded": "2025-01-05",
            "shortDescription": "Remote code execution in Acme Widget.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2025-01-20",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
        {
            "cveID": "CVE-2025-2222",
            "vendorProject": "Beta",
            "product": "Service",
            "vulnerabilityName": "Beta Service SQLi",
            "dateAdded": "2025-02-01",
            "shortDescription": "SQL injection in Beta Service.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2025-02-15",
            "knownRansomwareCampaignUse": "Known",
            "notes": "https://beta.example.com/advisory",
        },
        {
            "cveID": "CVE-2025-3333",
            "vendorProject": "Gamma",
            "product": "Library",
            "vulnerabilityName": "Gamma Library XSS",
            "dateAdded": "2025-02-10",
            "shortDescription": "Cross-site scripting in Gamma Library.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2025-03-01",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
    ],
}


def _kev_response(catalog: dict | None = None) -> httpx.Response:
    return httpx.Response(200, json=catalog or _CATALOG, request=_REQ)


# ── source_name ───────────────────────────────────────────────────────────


def test_source_name():
    assert CISAKEVIngestor().source_name() == "cisa_kev"


# ── fetch_updates ─────────────────────────────────────────────────────────


async def test_fetch_returns_all_entries_when_no_since():
    resp = _kev_response()

    with patch("ingestion.cisa_kev.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await _collect(CISAKEVIngestor().fetch_updates(since=None))

    assert len(results) == 3
    cve_ids = {r.cve_id for r in results}
    assert cve_ids == {"CVE-2025-1111", "CVE-2025-2222", "CVE-2025-3333"}


async def test_fetch_filters_by_date_added():
    resp = _kev_response()
    since = datetime(2025, 1, 20, tzinfo=timezone.utc)

    with patch("ingestion.cisa_kev.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await _collect(CISAKEVIngestor().fetch_updates(since=since))

    cve_ids = {r.cve_id for r in results}
    assert "CVE-2025-1111" not in cve_ids  # dateAdded 2025-01-05, before cutoff
    assert "CVE-2025-2222" in cve_ids       # dateAdded 2025-02-01, after cutoff
    assert "CVE-2025-3333" in cve_ids       # dateAdded 2025-02-10, after cutoff


async def test_fetch_skips_entries_without_cve_id():
    catalog = {
        "vulnerabilities": [
            {"vendorProject": "NoID", "product": "Thing", "dateAdded": "2025-01-01"},
            {"cveID": "CVE-2025-9999", "dateAdded": "2025-01-01",
             "shortDescription": "Valid.", "dueDate": "2025-02-01"},
        ],
    }
    resp = _kev_response(catalog)

    with patch("ingestion.cisa_kev.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await _collect(CISAKEVIngestor().fetch_updates(since=None))

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-9999"


async def test_fetch_keeps_entry_with_unparseable_date_when_since_set():
    catalog = {
        "vulnerabilities": [
            {"cveID": "CVE-2025-0001", "dateAdded": "not-a-date",
             "shortDescription": "Bad date.", "dueDate": "2025-01-20"},
        ],
    }
    resp = _kev_response(catalog)
    since = datetime(2025, 6, 1, tzinfo=timezone.utc)

    with patch("ingestion.cisa_kev.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await _collect(CISAKEVIngestor().fetch_updates(since=since))

    assert len(results) == 1


async def test_fetch_returns_empty_for_empty_catalog():
    resp = _kev_response({"vulnerabilities": []})

    with patch("ingestion.cisa_kev.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await _collect(CISAKEVIngestor().fetch_updates(since=None))

    assert results == []


# ── _normalize ────────────────────────────────────────────────────────────


def test_normalize_sets_kev_flag():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][0])

    assert result.cisa_kev is True
    assert result.source == "cisa_kev"


def test_normalize_extracts_description():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][0])

    assert result.description == "Remote code execution in Acme Widget."


def test_normalize_parses_due_date():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][0])

    assert result.cisa_kev_due_date == date(2025, 1, 20)


def test_normalize_parses_date_added_as_published_at():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][0])

    assert result.published_at is not None
    assert result.published_at.year == 2025
    assert result.published_at.month == 1
    assert result.published_at.day == 5


def test_normalize_extracts_reference_from_notes_url():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][1])

    assert len(result.references) == 1
    assert result.references[0].url == "https://beta.example.com/advisory"
    assert result.references[0].ref_type == "advisory"


def test_normalize_skips_reference_when_notes_empty():
    result = CISAKEVIngestor()._normalize(_CATALOG["vulnerabilities"][0])

    assert result.references == []


def test_normalize_handles_missing_due_date():
    raw = {"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01"}
    result = CISAKEVIngestor()._normalize(raw)

    assert result.cisa_kev_due_date is None
    assert result.cisa_kev is True


def test_normalize_handles_invalid_due_date():
    raw = {"cveID": "CVE-2025-0001", "dueDate": "not-a-date", "dateAdded": "2025-01-01"}
    result = CISAKEVIngestor()._normalize(raw)

    assert result.cisa_kev_due_date is None
