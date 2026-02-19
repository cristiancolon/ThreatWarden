from datetime import datetime
from pathlib import Path

import asyncpg

from ingestion.base import (
    AffectedPackage,
    Exploit,
    NormalizedVulnerability,
    Reference,
)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


async def init_schema(conn: asyncpg.Connection) -> None:
    """Create all tables and indexes if they don't already exist."""
    sql = _SCHEMA_PATH.read_text()
    await conn.execute(sql)


# ---------------------------------------------------------------------------
# Top-level save
# ---------------------------------------------------------------------------

async def save_vulnerability(
    conn: asyncpg.Connection,
    vuln: NormalizedVulnerability,
) -> None:
    """Upsert a vulnerability and all its sub-records."""
    await _upsert_vulnerability(conn, vuln)
    if vuln.affected_packages:
        await _upsert_affected_packages(
            conn, vuln.cve_id, vuln.source, vuln.affected_packages,
        )
    if vuln.exploits:
        await _upsert_exploits(conn, vuln.cve_id, vuln.exploits)
    if vuln.references:
        await _upsert_references(
            conn, vuln.cve_id, vuln.source, vuln.references,
        )


# ---------------------------------------------------------------------------
# Sync metadata (high-water mark)
# ---------------------------------------------------------------------------

async def get_last_sync(
    conn: asyncpg.Connection,
    source_name: str,
) -> datetime | None:
    """Read the high-water mark timestamp for a source."""
    return await conn.fetchval(
        "SELECT last_successful_sync FROM sync_metadata WHERE source_name = $1",
        source_name,
    )


async def update_last_sync(
    conn: asyncpg.Connection,
    source_name: str,
    synced_at: datetime,
    count: int,
) -> None:
    """Write the high-water mark after a successful sync."""
    await conn.execute(
        """
        INSERT INTO sync_metadata (source_name, last_successful_sync, records_synced, updated_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT (source_name) DO UPDATE SET
            last_successful_sync = EXCLUDED.last_successful_sync,
            records_synced       = sync_metadata.records_synced + EXCLUDED.records_synced,
            updated_at           = NOW()
        """,
        source_name,
        synced_at,
        count,
    )


# ---------------------------------------------------------------------------
# Internal upserts
# ---------------------------------------------------------------------------

async def _upsert_vulnerability(
    conn: asyncpg.Connection,
    vuln: NormalizedVulnerability,
) -> None:
    await conn.execute(
        """
        INSERT INTO vulnerabilities (
            cve_id, description, cvss_score, cvss_vector, cvss_version,
            epss_score, epss_percentile, cisa_kev, cisa_kev_due_date,
            severity, published_at, modified_at, raw_sources
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, ARRAY[$13::text])
        ON CONFLICT (cve_id) DO UPDATE SET
            description     = COALESCE(EXCLUDED.description,     vulnerabilities.description),
            cvss_score      = COALESCE(EXCLUDED.cvss_score,      vulnerabilities.cvss_score),
            cvss_vector     = COALESCE(EXCLUDED.cvss_vector,     vulnerabilities.cvss_vector),
            cvss_version    = COALESCE(EXCLUDED.cvss_version,    vulnerabilities.cvss_version),
            epss_score      = COALESCE(EXCLUDED.epss_score,      vulnerabilities.epss_score),
            epss_percentile = COALESCE(EXCLUDED.epss_percentile, vulnerabilities.epss_percentile),
            cisa_kev        = EXCLUDED.cisa_kev OR vulnerabilities.cisa_kev,
            cisa_kev_due_date = COALESCE(EXCLUDED.cisa_kev_due_date, vulnerabilities.cisa_kev_due_date),
            severity        = COALESCE(EXCLUDED.severity,        vulnerabilities.severity),
            published_at    = COALESCE(EXCLUDED.published_at,    vulnerabilities.published_at),
            modified_at     = COALESCE(EXCLUDED.modified_at,     vulnerabilities.modified_at),
            raw_sources     = (
                SELECT array_agg(DISTINCT s)
                FROM unnest(vulnerabilities.raw_sources || EXCLUDED.raw_sources) AS s
            ),
            updated_in_db   = NOW()
        """,
        vuln.cve_id,
        vuln.description,
        vuln.cvss_score,
        vuln.cvss_vector,
        vuln.cvss_version,
        vuln.epss_score,
        vuln.epss_percentile,
        vuln.cisa_kev,
        vuln.cisa_kev_due_date,
        vuln.severity,
        vuln.published_at,
        vuln.modified_at,
        vuln.source,
    )


async def _upsert_affected_packages(
    conn: asyncpg.Connection,
    cve_id: str,
    source: str,
    packages: list[AffectedPackage],
) -> None:
    await conn.executemany(
        """
        INSERT INTO affected_packages
            (cve_id, ecosystem, package_name, vulnerable_versions, patched_version, source)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, ecosystem, package_name, source) DO UPDATE SET
            vulnerable_versions = EXCLUDED.vulnerable_versions,
            patched_version     = EXCLUDED.patched_version
        """,
        [
            (cve_id, pkg.ecosystem, pkg.package_name,
             pkg.vulnerable_versions, pkg.patched_version, source)
            for pkg in packages
        ],
    )


async def _upsert_exploits(
    conn: asyncpg.Connection,
    cve_id: str,
    exploits: list[Exploit],
) -> None:
    await conn.executemany(
        """
        INSERT INTO exploits
            (cve_id, source, source_id, url, description, discovered_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (cve_id, source, source_id) DO UPDATE SET
            url           = COALESCE(EXCLUDED.url,           exploits.url),
            description   = COALESCE(EXCLUDED.description,   exploits.description),
            discovered_at = COALESCE(EXCLUDED.discovered_at, exploits.discovered_at)
        """,
        [
            (cve_id, exp.source, exp.source_id or "", exp.url,
             exp.description, exp.discovered_at)
            for exp in exploits
        ],
    )


async def _upsert_references(
    conn: asyncpg.Connection,
    cve_id: str,
    source: str,
    references: list[Reference],
) -> None:
    await conn.executemany(
        """
        INSERT INTO cve_references (cve_id, url, ref_type, source)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (cve_id, url) DO UPDATE SET
            ref_type = COALESCE(EXCLUDED.ref_type, cve_references.ref_type),
            source   = COALESCE(EXCLUDED.source,   cve_references.source)
        """,
        [
            (cve_id, ref.url, ref.ref_type, source)
            for ref in references
        ],
    )
