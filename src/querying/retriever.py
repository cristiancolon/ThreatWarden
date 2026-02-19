import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg

from .intent_parser import QueryIntent

# Severity levels ordered from most to least severe, used when the filter has
# a "+" suffix (meaning "at least this level").
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

_DATE_RANGE_RE = re.compile(r"last\s+(\d+)\s+(day|week|month|year)s?", re.IGNORECASE)

_RESULT_LIMIT = 50


# ---------------------------------------------------------------------------
# Public data structures
# ---------------------------------------------------------------------------

@dataclass
class VulnRow:
    """A single vulnerability result with its related sub-records."""
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    severity: str | None
    epss_score: float | None
    epss_percentile: float | None
    cisa_kev: bool
    published_at: datetime | None
    # Populated by a second query after the main query
    affected_packages: list[dict[str, Any]] = field(default_factory=list)
    exploits: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------

def needs_sql(intent: QueryIntent) -> bool:
    """Return True if this intent has structured filters worth querying.
    """
    return any([
        intent.cve_ids,
        intent.package_names,
        intent.ecosystems,
        intent.severity_filter,
        intent.date_range,
    ])


def build_query(intent: QueryIntent) -> tuple[str, list[Any]]:
    """Convert a QueryIntent into a parameterized SQL query.

    Returns (sql_string, params_list). The query always selects from
    `vulnerabilities` and optionally JOINs `affected_packages` when
    the intent references packages or ecosystems.
    """
    joins: list[str] = []
    conditions: list[str] = []
    params: list[Any] = []
    param_idx = 0

    def _next_param(value: Any) -> str:
        nonlocal param_idx
        param_idx += 1
        params.append(value)
        return f"${param_idx}"

    need_pkg_join = bool(intent.package_names or intent.ecosystems)
    if need_pkg_join:
        joins.append(
            "JOIN affected_packages ap ON ap.cve_id = v.cve_id"
        )

    # -- CVE IDs (exact match) --
    if intent.cve_ids:
        placeholders = ", ".join(_next_param(cid) for cid in intent.cve_ids)
        conditions.append(f"v.cve_id IN ({placeholders})")

    # -- Package names --
    if intent.package_names:
        placeholders = ", ".join(
            _next_param(name.lower()) for name in intent.package_names
        )
        conditions.append(f"LOWER(ap.package_name) IN ({placeholders})")

    # -- Ecosystems --
    if intent.ecosystems:
        placeholders = ", ".join(
            _next_param(eco.lower()) for eco in intent.ecosystems
        )
        conditions.append(f"LOWER(ap.ecosystem) IN ({placeholders})")

    # -- Severity --
    if intent.severity_filter:
        severity = intent.severity_filter.rstrip("+").upper()
        if intent.severity_filter.endswith("+"):
            idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 0
            allowed = _SEVERITY_ORDER[: idx + 1]
            placeholders = ", ".join(_next_param(s) for s in allowed)
            conditions.append(f"v.severity IN ({placeholders})")
        else:
            conditions.append(f"v.severity = {_next_param(severity)}")

    # -- Date range --
    if intent.date_range:
        cutoff = _parse_date_range(intent.date_range)
        if cutoff:
            conditions.append(f"v.published_at >= {_next_param(cutoff)}")

    # -- Assemble --
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    join_clause = " ".join(joins)

    sql = (
        f"SELECT DISTINCT v.cve_id, v.description, v.cvss_score, v.cvss_vector, "
        f"v.severity, v.epss_score, v.epss_percentile, v.cisa_kev, v.published_at "
        f"FROM vulnerabilities v {join_clause}{where} "
        f"ORDER BY "
        f"v.cisa_kev DESC, "
        f"v.epss_score DESC NULLS LAST, "
        f"v.cvss_score DESC NULLS LAST, "
        f"v.published_at DESC NULLS LAST "
        f"LIMIT {_RESULT_LIMIT}"
    )

    return sql, params


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

async def execute_query(
    conn: asyncpg.Connection,
    intent: QueryIntent,
) -> list[VulnRow]:
    """Run the SQL query for an intent and return enriched VulnRow objects.

    Returns an empty list when the intent has no structured filters.
    """
    if not needs_sql(intent):
        return []

    sql, params = build_query(intent)
    rows = await conn.fetch(sql, *params)

    results = [
        VulnRow(
            cve_id=r["cve_id"],
            description=r["description"],
            cvss_score=r["cvss_score"],
            cvss_vector=r["cvss_vector"],
            severity=r["severity"],
            epss_score=r["epss_score"],
            epss_percentile=r["epss_percentile"],
            cisa_kev=r["cisa_kev"],
            published_at=r["published_at"],
        )
        for r in rows
    ]

    if results:
        cve_ids = [r.cve_id for r in results]
        await _enrich_sub_records(conn, results, cve_ids)

    return results


# ---------------------------------------------------------------------------
# Sub-record enrichment
# ---------------------------------------------------------------------------

async def _enrich_sub_records(
    conn: asyncpg.Connection,
    results: list[VulnRow],
    cve_ids: list[str],
) -> None:
    """Fetch affected_packages, exploits, and references for the result set."""
    by_cve = {r.cve_id: r for r in results}

    pkg_rows = await conn.fetch(
        "SELECT cve_id, ecosystem, package_name, vulnerable_versions, patched_version "
        "FROM affected_packages WHERE cve_id = ANY($1::text[])",
        cve_ids,
    )
    for r in pkg_rows:
        by_cve[r["cve_id"]].affected_packages.append(dict(r))

    exploit_rows = await conn.fetch(
        "SELECT cve_id, source, url, description "
        "FROM exploits WHERE cve_id = ANY($1::text[])",
        cve_ids,
    )
    for r in exploit_rows:
        by_cve[r["cve_id"]].exploits.append(dict(r))

    ref_rows = await conn.fetch(
        "SELECT cve_id, url FROM cve_references WHERE cve_id = ANY($1::text[])",
        cve_ids,
    )
    for r in ref_rows:
        by_cve[r["cve_id"]].references.append(r["url"])


# ---------------------------------------------------------------------------
# Date range parsing
# ---------------------------------------------------------------------------

def _parse_date_range(text: str) -> datetime | None:
    """Convert a human-readable date range like 'last 7 days' into a UTC cutoff datetime."""
    match = _DATE_RANGE_RE.search(text)
    if not match:
        return None

    amount = int(match.group(1))
    unit = match.group(2).lower()

    now = datetime.now(tz=timezone.utc)
    if unit == "day":
        return now - timedelta(days=amount)
    if unit == "week":
        return now - timedelta(weeks=amount)
    if unit == "month":
        return now - timedelta(days=amount * 30)
    if unit == "year":
        return now - timedelta(days=amount * 365)
    return None
