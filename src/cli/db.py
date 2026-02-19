import typer
from rich.table import Table

from cli.common import async_command, console, get_pool

app = typer.Typer(help="Database inspection commands.")


@app.command()
@async_command
async def stats() -> None:
    """Show database record counts and basic statistics."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        vuln_count = await conn.fetchval("SELECT COUNT(*) FROM vulnerabilities")
        pkg_count = await conn.fetchval("SELECT COUNT(*) FROM affected_packages")
        exploit_count = await conn.fetchval("SELECT COUNT(*) FROM exploits")
        ref_count = await conn.fetchval("SELECT COUNT(*) FROM cve_references")
        kev_count = await conn.fetchval(
            "SELECT COUNT(*) FROM vulnerabilities WHERE cisa_kev = TRUE"
        )

        severity_rows = await conn.fetch(
            "SELECT severity, COUNT(*) AS cnt FROM vulnerabilities "
            "WHERE severity IS NOT NULL GROUP BY severity ORDER BY cnt DESC"
        )

        source_rows = await conn.fetch(
            "SELECT s, COUNT(*) AS cnt "
            "FROM vulnerabilities, unnest(raw_sources) AS s "
            "GROUP BY s ORDER BY cnt DESC"
        )

    table = Table(title="Database Statistics")
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("Vulnerabilities (CVEs)", str(vuln_count))
    table.add_row("Affected packages", str(pkg_count))
    table.add_row("Exploits", str(exploit_count))
    table.add_row("References", str(ref_count))
    table.add_row("CISA KEV entries", str(kev_count))

    console.print(table)

    if severity_rows:
        sev_table = Table(title="By Severity")
        sev_table.add_column("Severity", style="bold")
        sev_table.add_column("Count", justify="right")
        for r in severity_rows:
            sev_table.add_row(r["severity"], str(r["cnt"]))
        console.print(sev_table)

    if source_rows:
        src_table = Table(title="By Source")
        src_table.add_column("Source", style="bold")
        src_table.add_column("CVEs", justify="right")
        for r in source_rows:
            src_table.add_row(r["s"], str(r["cnt"]))
        console.print(src_table)

    await pool.close()
