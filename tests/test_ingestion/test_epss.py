import gzip
from unittest.mock import AsyncMock, patch

import httpx

from ingestion.epss import EPSSIngestor

_REQ = httpx.Request("GET", "https://test.example.com")

_CSV_LINES = [
    "#model_version:v2023.03.01,score_date:2025-01-20T00:00:00+0000",
    "cve,epss,percentile",
    "CVE-2025-1111,0.97565,0.99990",
    "CVE-2025-2222,0.00123,0.45678",
    "CVE-2025-3333,0.50000,0.75000",
]


def _epss_response(lines: list[str] | None = None) -> httpx.Response:
    text = "\n".join(lines if lines is not None else _CSV_LINES)
    compressed = gzip.compress(text.encode("utf-8"))
    return httpx.Response(200, content=compressed, request=_REQ)


# ── source_name ───────────────────────────────────────────────────────────


def test_source_name():
    assert EPSSIngestor().source_name() == "epss"


# ── fetch_updates ─────────────────────────────────────────────────────────


async def test_fetch_parses_all_csv_records():
    resp = _epss_response()

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=None)

    assert len(results) == 3
    cve_ids = {r.cve_id for r in results}
    assert cve_ids == {"CVE-2025-1111", "CVE-2025-2222", "CVE-2025-3333"}


async def test_fetch_skips_comment_lines():
    lines = [
        "#model_version:v2023.03.01,score_date:2025-01-20T00:00:00+0000",
        "# another comment",
        "cve,epss,percentile",
        "CVE-2025-1111,0.50000,0.75000",
    ]
    resp = _epss_response(lines)

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=None)

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-1111"


async def test_fetch_skips_rows_without_cve():
    lines = [
        "cve,epss,percentile",
        ",0.50000,0.75000",
        "CVE-2025-1111,0.50000,0.75000",
    ]
    resp = _epss_response(lines)

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=None)

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-1111"


async def test_fetch_preserves_raw_data():
    resp = _epss_response()

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=None)

    first = next(r for r in results if r.cve_id == "CVE-2025-1111")
    assert first.raw_data["epss"] == "0.97565"
    assert first.raw_data["percentile"] == "0.99990"


async def test_fetch_returns_empty_for_no_data_rows():
    lines = [
        "#comment",
        "cve,epss,percentile",
    ]
    resp = _epss_response(lines)

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=None)

    assert results == []


async def test_fetch_ignores_since_and_returns_full_snapshot():
    """EPSS is a daily snapshot — the since parameter doesn't filter results."""
    from datetime import datetime, timezone

    resp = _epss_response()
    since = datetime(2099, 1, 1, tzinfo=timezone.utc)

    with patch("ingestion.epss.get_response_with_retry", new_callable=AsyncMock, return_value=resp):
        results = await EPSSIngestor().fetch_updates(since=since)

    assert len(results) == 3


# ── _normalize ────────────────────────────────────────────────────────────


def test_normalize_extracts_scores():
    raw = {"cve": "CVE-2025-1111", "epss": "0.97565", "percentile": "0.99990"}
    result = EPSSIngestor()._normalize(raw)

    assert result.cve_id == "CVE-2025-1111"
    assert result.source == "epss"
    assert result.epss_score == 0.97565
    assert result.epss_percentile == 0.99990


def test_normalize_handles_missing_epss():
    raw = {"cve": "CVE-2025-1111", "percentile": "0.50000"}
    result = EPSSIngestor()._normalize(raw)

    assert result.epss_score is None
    assert result.epss_percentile == 0.50000


def test_normalize_handles_missing_percentile():
    raw = {"cve": "CVE-2025-1111", "epss": "0.12345"}
    result = EPSSIngestor()._normalize(raw)

    assert result.epss_score == 0.12345
    assert result.epss_percentile is None


def test_normalize_handles_invalid_score_values():
    raw = {"cve": "CVE-2025-1111", "epss": "N/A", "percentile": "bad"}
    result = EPSSIngestor()._normalize(raw)

    assert result.epss_score is None
    assert result.epss_percentile is None


def test_normalize_sets_no_other_fields():
    raw = {"cve": "CVE-2025-1111", "epss": "0.50000", "percentile": "0.75000"}
    result = EPSSIngestor()._normalize(raw)

    assert result.description is None
    assert result.cvss_score is None
    assert result.cisa_kev is False
    assert result.affected_packages == []
    assert result.exploits == []
    assert result.references == []
