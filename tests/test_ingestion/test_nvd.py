from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx

from ingestion.nvd import NVDIngestor

_REQ = httpx.Request("GET", "https://test.example.com")


async def _collect(gen):
    results = []
    async for page in gen:
        results.extend(page)
    return results


# ── Sample data ───────────────────────────────────────────────────────────

_CVE_FULL = {
    "id": "CVE-2025-1234",
    "descriptions": [
        {"lang": "en", "value": "Buffer overflow in example-lib allows RCE."},
        {"lang": "es", "value": "Desbordamiento de búfer..."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 9.8,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "version": "3.1",
                    "baseSeverity": "CRITICAL",
                },
            }
        ]
    },
    "published": "2025-01-15T10:00:00.000",
    "lastModified": "2025-01-20T12:00:00.000",
    "cisaActionDue": "2025-02-15",
    "cisaRequiredAction": "Apply mitigations per vendor instructions.",
    "references": [
        {"url": "https://example.com/patch", "tags": ["Patch"]},
        {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
        {"url": "https://example.com/exploit", "tags": ["Exploit"]},
        {"url": "https://example.com/other", "tags": ["Technical Description"]},
    ],
}

_CVE_MINIMAL = {
    "id": "CVE-2025-9999",
    "descriptions": [{"lang": "en", "value": "Minor issue."}],
    "metrics": {},
    "references": [],
}


# ── source_name ───────────────────────────────────────────────────────────


def test_source_name():
    assert NVDIngestor().source_name() == "nvd"


# ── fetch_updates ─────────────────────────────────────────────────────────


def _nvd_page(cve_ids: list[str], total: int) -> httpx.Response:
    vulns = [{"cve": {"id": cid}} for cid in cve_ids]
    return httpx.Response(
        200,
        json={"totalResults": total, "vulnerabilities": vulns},
        request=_REQ,
    )


async def test_fetch_full_sync_returns_all_cves():
    resp = _nvd_page(["CVE-2025-0001", "CVE-2025-0002"], total=2)

    with (
        patch("ingestion.nvd.get_response_with_retry", new_callable=AsyncMock, return_value=resp),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await _collect(NVDIngestor().fetch_updates(since=None))

    assert len(results) == 2
    assert results[0].cve_id == "CVE-2025-0001"
    assert results[1].cve_id == "CVE-2025-0002"
    assert all(r.source == "nvd" for r in results)


async def test_fetch_incremental_passes_date_params():
    resp = _nvd_page(["CVE-2025-0001"], total=1)
    since = datetime(2025, 2, 1, tzinfo=timezone.utc)

    with (
        patch("ingestion.nvd.get_response_with_retry", new_callable=AsyncMock, return_value=resp) as mock_get,
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        async for _ in NVDIngestor().fetch_updates(since=since):
            pass

    _, kwargs = mock_get.call_args
    params = kwargs["params"]
    assert "lastModStartDate" in params
    assert "lastModEndDate" in params
    assert params["lastModStartDate"].startswith("2025-02-01T")


async def test_fetch_paginates_multiple_pages():
    page1 = _nvd_page(["CVE-2025-0001", "CVE-2025-0002"], total=3)
    page2 = _nvd_page(["CVE-2025-0003"], total=3)

    with (
        patch("ingestion.nvd.get_response_with_retry", new_callable=AsyncMock, side_effect=[page1, page2]),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await _collect(NVDIngestor().fetch_updates(since=None))

    assert len(results) == 3
    assert results[2].cve_id == "CVE-2025-0003"


async def test_fetch_skips_entries_without_cve_id():
    vulns = [{"cve": {"id": "CVE-2025-0001"}}, {"cve": {"id": ""}}, {"cve": {}}]
    resp = httpx.Response(
        200,
        json={"totalResults": 3, "vulnerabilities": vulns},
        request=_REQ,
    )

    with (
        patch("ingestion.nvd.get_response_with_retry", new_callable=AsyncMock, return_value=resp),
        patch("asyncio.sleep", new_callable=AsyncMock),
    ):
        results = await _collect(NVDIngestor().fetch_updates(since=None))

    assert len(results) == 1


# ── _normalize ────────────────────────────────────────────────────────────

def test_normalize_extracts_english_description():
    result = NVDIngestor()._normalize(_CVE_FULL)

    assert result.description == "Buffer overflow in example-lib allows RCE."


def test_normalize_cvss_v31():
    result = NVDIngestor()._normalize(_CVE_FULL)

    assert result.cvss_score == 9.8
    assert result.cvss_version == "3.1"
    assert result.cvss_vector is not None
    assert result.cvss_vector.startswith("CVSS:3.1/")
    assert result.severity == "CRITICAL"


def test_normalize_prefers_v31_over_v2():
    raw = {
        **_CVE_MINIMAL,
        "metrics": {
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "version": "2.0"}, "baseSeverity": "MEDIUM"}],
            "cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 9.8, "version": "3.1", "baseSeverity": "CRITICAL"}}],
        },
    }
    result = NVDIngestor()._normalize(raw)

    assert result.cvss_score == 9.8
    assert result.cvss_version == "3.1"


def test_normalize_prefers_primary_metric():
    raw = {
        **_CVE_MINIMAL,
        "metrics": {
            "cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 5.0, "version": "3.1", "baseSeverity": "MEDIUM"}},
                {"type": "Primary", "cvssData": {"baseScore": 9.8, "version": "3.1", "baseSeverity": "CRITICAL"}},
            ],
        },
    }
    result = NVDIngestor()._normalize(raw)

    assert result.cvss_score == 9.8


def test_normalize_cisa_kev():
    result = NVDIngestor()._normalize(_CVE_FULL)

    assert result.cisa_kev is True
    assert result.cisa_kev_due_date is not None
    assert result.cisa_kev_due_date.isoformat() == "2025-02-15"


def test_normalize_no_cisa_kev():
    result = NVDIngestor()._normalize(_CVE_MINIMAL)

    assert result.cisa_kev is False
    assert result.cisa_kev_due_date is None


def test_normalize_reference_tag_mapping():
    result = NVDIngestor()._normalize(_CVE_FULL)

    ref_types = {r.ref_type for r in result.references}
    assert "patch" in ref_types
    assert "advisory" in ref_types
    assert "exploit" in ref_types
    assert None in ref_types  # the "Technical Description" tag doesn't map


def test_normalize_parses_dates():
    result = NVDIngestor()._normalize(_CVE_FULL)

    assert result.published_at is not None
    assert result.published_at.year == 2025
    assert result.published_at.month == 1
    assert result.modified_at is not None


def test_normalize_handles_missing_metrics():
    result = NVDIngestor()._normalize(_CVE_MINIMAL)

    assert result.cvss_score is None
    assert result.cvss_vector is None
    assert result.severity is None
    assert result.references == []
