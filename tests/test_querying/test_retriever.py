from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from querying.intent_parser import QueryIntent
from querying.retriever import (
    VulnRow,
    _parse_date_range,
    build_query,
    execute_query,
    needs_sql,
)


def _intent(**overrides) -> QueryIntent:
    defaults = dict(
        ecosystems=None,
        package_names=None,
        cve_ids=None,
        severity_filter=None,
        date_range=None,
        query_type="general_search",
        raw_search_query="test query",
    )
    defaults.update(overrides)
    return QueryIntent(**defaults)


# ── needs_sql ──────────────────────────────────────────────────────────────


class TestNeedsSql:
    def test_no_filters_returns_false(self):
        intent = _intent()
        assert needs_sql(intent) is False

    def test_cve_ids_returns_true(self):
        intent = _intent(cve_ids=["CVE-2025-1234"])
        assert needs_sql(intent) is True

    def test_package_names_returns_true(self):
        intent = _intent(package_names=["flask"])
        assert needs_sql(intent) is True

    def test_ecosystems_returns_true(self):
        intent = _intent(ecosystems=["pypi"])
        assert needs_sql(intent) is True

    def test_severity_returns_true(self):
        intent = _intent(severity_filter="HIGH")
        assert needs_sql(intent) is True

    def test_date_range_returns_true(self):
        intent = _intent(date_range="last 7 days")
        assert needs_sql(intent) is True

    def test_conversational_query_returns_false(self):
        """User asks 'what is a CVE?' — no structured filters."""
        intent = _intent(
            query_type="general_search",
            raw_search_query="what is a CVE?",
        )
        assert needs_sql(intent) is False


# ── build_query ────────────────────────────────────────────────────────────


class TestBuildQuery:
    def test_specific_cve_query(self):
        intent = _intent(cve_ids=["CVE-2025-1234", "CVE-2025-5678"])
        sql, params = build_query(intent)

        assert "v.cve_id IN ($1, $2)" in sql
        assert params == ["CVE-2025-1234", "CVE-2025-5678"]
        assert "affected_packages" not in sql

    def test_package_query_joins_affected_packages(self):
        intent = _intent(package_names=["flask"], ecosystems=["pypi"])
        sql, params = build_query(intent)

        assert "JOIN affected_packages ap" in sql
        assert "LOWER(ap.package_name) IN ($1)" in sql
        assert "LOWER(ap.ecosystem) IN ($2)" in sql
        assert params == ["flask", "pypi"]

    def test_severity_exact_match(self):
        intent = _intent(severity_filter="CRITICAL")
        sql, params = build_query(intent)

        assert "v.severity = $1" in sql
        assert params == ["CRITICAL"]

    def test_severity_plus_expands_to_higher_levels(self):
        intent = _intent(severity_filter="HIGH+")
        sql, params = build_query(intent)

        assert "v.severity IN" in sql
        assert "CRITICAL" in params
        assert "HIGH" in params
        assert "MEDIUM" not in params

    def test_date_range_adds_published_at_filter(self):
        intent = _intent(date_range="last 30 days")
        sql, params = build_query(intent)

        assert "v.published_at >= $1" in sql
        assert len(params) == 1
        cutoff = params[0]
        assert isinstance(cutoff, datetime)
        expected = datetime.now(tz=timezone.utc) - timedelta(days=30)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_combined_filters(self):
        """Ecosystem + severity + date range all applied together."""
        intent = _intent(
            ecosystems=["npm"],
            severity_filter="HIGH+",
            date_range="last 7 days",
        )
        sql, params = build_query(intent)

        assert "JOIN affected_packages ap" in sql
        assert "LOWER(ap.ecosystem) IN ($1)" in sql
        assert "v.severity IN" in sql
        assert "v.published_at >=" in sql
        assert params[0] == "npm"
        assert "CRITICAL" in params
        assert "HIGH" in params

    def test_order_by_prioritizes_kev_then_epss(self):
        intent = _intent(cve_ids=["CVE-2025-0001"])
        sql, _ = build_query(intent)

        kev_pos = sql.index("v.cisa_kev DESC")
        epss_pos = sql.index("v.epss_score DESC")
        cvss_pos = sql.index("v.cvss_score DESC")
        assert kev_pos < epss_pos < cvss_pos

    def test_result_limit(self):
        intent = _intent(cve_ids=["CVE-2025-0001"])
        sql, _ = build_query(intent)
        assert "LIMIT 50" in sql


# ── _parse_date_range ──────────────────────────────────────────────────────


class TestParseDateRange:
    def test_last_n_days(self):
        cutoff = _parse_date_range("last 7 days")
        expected = datetime.now(tz=timezone.utc) - timedelta(days=7)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_last_n_weeks(self):
        cutoff = _parse_date_range("last 2 weeks")
        expected = datetime.now(tz=timezone.utc) - timedelta(weeks=2)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_last_n_months(self):
        cutoff = _parse_date_range("last 3 months")
        expected = datetime.now(tz=timezone.utc) - timedelta(days=90)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_last_1_year(self):
        cutoff = _parse_date_range("last 1 year")
        expected = datetime.now(tz=timezone.utc) - timedelta(days=365)
        assert abs((cutoff - expected).total_seconds()) < 5

    def test_unrecognized_returns_none(self):
        assert _parse_date_range("since January 2025") is None

    def test_singular_unit(self):
        cutoff = _parse_date_range("last 1 day")
        expected = datetime.now(tz=timezone.utc) - timedelta(days=1)
        assert abs((cutoff - expected).total_seconds()) < 5


# ── execute_query ──────────────────────────────────────────────────────────


def _make_conn(vuln_rows=None, pkg_rows=None, exploit_rows=None, ref_rows=None):
    """Build a mock asyncpg connection that serves canned data."""
    conn = AsyncMock()

    call_count = 0

    async def _fetch(sql, *args):
        nonlocal call_count
        if "FROM vulnerabilities" in sql:
            return vuln_rows or []
        call_count += 1
        if call_count == 1:
            return pkg_rows or []
        if call_count == 2:
            return exploit_rows or []
        return ref_rows or []

    conn.fetch = AsyncMock(side_effect=_fetch)
    return conn


def _record(**fields):
    """Create a dict-like mock that mimics an asyncpg Record."""
    record = MagicMock()
    record.__getitem__ = lambda self, key: fields[key]
    record.keys = lambda: fields.keys()
    record.values = lambda: fields.values()
    record.items = lambda: fields.items()
    return record


class TestExecuteQuery:
    async def test_no_filters_returns_empty(self):
        conn = _make_conn()
        intent = _intent()
        results = await execute_query(conn, intent)

        assert results == []
        conn.fetch.assert_not_called()

    async def test_specific_cve_returns_enriched_rows(self):
        vuln = _record(
            cve_id="CVE-2025-1234",
            description="Test vuln",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            severity="CRITICAL",
            epss_score=0.92,
            epss_percentile=0.99,
            cisa_kev=True,
            published_at=datetime(2025, 1, 15, tzinfo=timezone.utc),
        )
        pkg = _record(
            cve_id="CVE-2025-1234",
            ecosystem="pypi",
            package_name="flask",
            vulnerable_versions=">=2.0.0 <2.3.1",
            patched_version="2.3.1",
        )
        exploit = _record(
            cve_id="CVE-2025-1234",
            source="exploitdb",
            url="https://exploit-db.com/12345",
            description="PoC for CVE-2025-1234",
        )
        ref = _record(
            cve_id="CVE-2025-1234",
            url="https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
        )

        conn = _make_conn(
            vuln_rows=[vuln],
            pkg_rows=[pkg],
            exploit_rows=[exploit],
            ref_rows=[ref],
        )

        intent = _intent(cve_ids=["CVE-2025-1234"], query_type="specific_cve")
        results = await execute_query(conn, intent)

        assert len(results) == 1
        r = results[0]
        assert r.cve_id == "CVE-2025-1234"
        assert r.cvss_score == 9.8
        assert r.cisa_kev is True
        assert len(r.affected_packages) == 1
        assert r.affected_packages[0]["package_name"] == "flask"
        assert len(r.exploits) == 1
        assert len(r.references) == 1

    async def test_multiple_results_sorted(self):
        vulns = [
            _record(
                cve_id="CVE-2025-0001",
                description="low severity vuln",
                cvss_score=3.1,
                cvss_vector=None,
                severity="LOW",
                epss_score=0.01,
                epss_percentile=0.10,
                cisa_kev=False,
                published_at=datetime(2025, 2, 1, tzinfo=timezone.utc),
            ),
            _record(
                cve_id="CVE-2025-0002",
                description="critical kev vuln",
                cvss_score=9.8,
                cvss_vector=None,
                severity="CRITICAL",
                epss_score=0.95,
                epss_percentile=0.99,
                cisa_kev=True,
                published_at=datetime(2025, 1, 15, tzinfo=timezone.utc),
            ),
        ]

        conn = _make_conn(vuln_rows=vulns)
        intent = _intent(ecosystems=["pypi"])
        results = await execute_query(conn, intent)

        assert len(results) == 2
        assert results[0].cve_id == "CVE-2025-0001"
        assert results[1].cve_id == "CVE-2025-0002"
