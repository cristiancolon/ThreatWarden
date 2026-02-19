import io
import json
import zipfile
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx

from ingestion.osv import OSVIngestor

_REQ = httpx.Request("GET", "https://test.example.com")


# ── Helpers ───────────────────────────────────────────────────────────────


def _make_zip(records: list[dict]) -> bytes:
    """Build an in-memory zip containing one JSON file per record."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i, rec in enumerate(records):
            name = f"{rec.get('id', f'rec_{i}')}.json"
            zf.writestr(name, json.dumps(rec))
    return buf.getvalue()


def _mock_client_for(zip_bytes: bytes) -> AsyncMock:
    """Create a mock httpx.AsyncClient whose get() returns zip content."""
    resp = httpx.Response(200, content=zip_bytes, request=_REQ)
    client = AsyncMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


# ── Sample data ───────────────────────────────────────────────────────────

_OSV_RECORD = {
    "id": "PYSEC-2025-1",
    "aliases": ["CVE-2025-9999"],
    "summary": "Vulnerability in example-package",
    "details": "A detailed description of the vulnerability.",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    ],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-package"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.5.2"},
                    ],
                }
            ],
            "ecosystem_specific": {"severity": "HIGH"},
        }
    ],
    "references": [
        {"type": "ADVISORY", "url": "https://example.com/advisory"},
        {"type": "FIX", "url": "https://example.com/fix"},
    ],
    "published": "2025-01-15T10:00:00Z",
    "modified": "2025-01-20T12:00:00Z",
}

_OSV_NO_CVE = {
    "id": "GHSA-abcd-efgh-ijkl",
    "aliases": [],
    "summary": "No CVE assigned",
    "modified": "2025-01-20T12:00:00Z",
}


# ── source_name ───────────────────────────────────────────────────────────


def test_source_name():
    assert OSVIngestor().source_name() == "osv"


# ── fetch_updates ─────────────────────────────────────────────────────────


async def test_fetch_parses_zip_and_extracts_cves():
    zip_bytes = _make_zip([_OSV_RECORD])
    mock_client = _mock_client_for(zip_bytes)

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=None)

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-9999"
    assert results[0].source == "osv"


async def test_fetch_extracts_cve_from_aliases():
    record = {
        "id": "PYSEC-2025-2",
        "aliases": ["CVE-2025-1111", "CVE-2025-2222"],
        "modified": "2025-01-20T12:00:00Z",
    }
    zip_bytes = _make_zip([record])
    mock_client = _mock_client_for(zip_bytes)

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=None)

    cve_ids = {r.cve_id for r in results}
    assert cve_ids == {"CVE-2025-1111", "CVE-2025-2222"}


async def test_fetch_uses_id_as_cve_when_no_aliases():
    record = {
        "id": "CVE-2025-5555",
        "aliases": [],
        "modified": "2025-01-20T12:00:00Z",
    }
    zip_bytes = _make_zip([record])
    mock_client = _mock_client_for(zip_bytes)

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=None)

    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-5555"


async def test_fetch_skips_records_without_cve():
    zip_bytes = _make_zip([_OSV_NO_CVE])
    mock_client = _mock_client_for(zip_bytes)

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=None)

    assert results == []


async def test_fetch_filters_by_modified_date():
    old_record = {**_OSV_RECORD, "id": "OLD-1", "modified": "2024-06-01T00:00:00Z"}
    new_record = {**_OSV_RECORD, "id": "NEW-1", "modified": "2025-02-01T00:00:00Z"}
    zip_bytes = _make_zip([old_record, new_record])
    mock_client = _mock_client_for(zip_bytes)

    since = datetime(2025, 1, 1, tzinfo=timezone.utc)
    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=since)

    assert len(results) == 1


async def test_fetch_skips_non_json_files_in_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.md", "This is not JSON")
        zf.writestr("CVE-2025-0001.json", json.dumps({
            "id": "CVE-2025-0001", "aliases": ["CVE-2025-0001"],
            "modified": "2025-01-20T00:00:00Z",
        }))
    mock_client = _mock_client_for(buf.getvalue())

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        results = await OSVIngestor(ecosystems=["PyPI"]).fetch_updates(since=None)

    assert len(results) == 1


async def test_fetch_queries_each_configured_ecosystem():
    zip_bytes = _make_zip([])
    mock_client = _mock_client_for(zip_bytes)

    with patch("ingestion.osv.httpx.AsyncClient", return_value=mock_client):
        await OSVIngestor(ecosystems=["PyPI", "npm"]).fetch_updates(since=None)

    assert mock_client.get.call_count == 2
    urls = [call.args[0] for call in mock_client.get.call_args_list]
    assert any("PyPI" in u for u in urls)
    assert any("npm" in u for u in urls)


# ── _normalize ────────────────────────────────────────────────────────────


def test_normalize_affected_packages():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert len(result.affected_packages) == 1
    pkg = result.affected_packages[0]
    assert pkg.ecosystem == "PyPI"
    assert pkg.package_name == "example-package"
    assert pkg.patched_version == "1.5.2"


def test_normalize_version_range_format():
    result = OSVIngestor()._normalize(_OSV_RECORD)
    pkg = result.affected_packages[0]

    assert ">=1.0.0" in pkg.vulnerable_versions
    assert "<1.5.2" in pkg.vulnerable_versions


def test_normalize_introduced_zero_becomes_wildcard():
    record = {
        **_OSV_RECORD,
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "pkg"},
            "ranges": [{
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
            }],
        }],
    }
    result = OSVIngestor()._normalize(record)

    assert result.affected_packages[0].vulnerable_versions == "*, <2.0.0"


def test_normalize_cvss_vector():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert result.cvss_vector is not None
    assert result.cvss_vector.startswith("CVSS:3.1/")
    assert result.cvss_version == "3.1"


def test_normalize_severity_from_ecosystem_specific():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert result.severity == "HIGH"


def test_normalize_references():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert len(result.references) == 2
    urls = {r.url for r in result.references}
    assert "https://example.com/advisory" in urls
    assert "https://example.com/fix" in urls


def test_normalize_reference_types_lowercased():
    result = OSVIngestor()._normalize(_OSV_RECORD)
    ref_types = {r.ref_type for r in result.references}

    assert "advisory" in ref_types
    assert "fix" in ref_types


def test_normalize_description_prefers_details():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert result.description == "A detailed description of the vulnerability."


def test_normalize_description_falls_back_to_summary():
    record = {**_OSV_RECORD}
    del record["details"]
    result = OSVIngestor()._normalize(record)

    assert result.description == "Vulnerability in example-package"


def test_normalize_parses_dates():
    result = OSVIngestor()._normalize(_OSV_RECORD)

    assert result.published_at is not None
    assert result.published_at.year == 2025
    assert result.modified_at is not None
