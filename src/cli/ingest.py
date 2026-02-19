import asyncio
import os
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import typer
from rich.table import Table

from cli.common import async_command, console, err_console, get_pool, setup_logging
from db.writer import get_last_sync, init_schema, save_vulnerability, update_last_sync
from ingestion.base import Ingestor
from ingestion.cisa_kev import CISAKEVIngestor
from ingestion.epss import EPSSIngestor
from ingestion.exploitdb import ExploitDBIngestor
from ingestion.github import GithubIngestor
from ingestion.nvd import NVDIngestor
from ingestion.osv import OSVIngestor

app = typer.Typer(help="Ingestion service commands.")

ALL_INGESTORS: dict[str, type[Ingestor]] = {
    "nvd": NVDIngestor,
    "github": GithubIngestor,
    "osv": OSVIngestor,
    "exploitdb": ExploitDBIngestor,
    "cisa_kev": CISAKEVIngestor,
    "epss": EPSSIngestor,
}


async def _run_ingestor_loop(
    pool: asyncpg.Pool,
    ingestor: Ingestor,
    interval: int,
) -> None:
    """Run a single ingestor in a loop: fetch -> normalize -> save -> sleep."""
    import logging
    logger = logging.getLogger("threatwarden.scheduler")

    while True:
        source = ingestor.source_name()
        try:
            async with pool.acquire() as conn:
                since = await get_last_sync(conn, source)

            logger.info("%s: starting sync (since=%s)", source, since)
            raw = await ingestor.fetch_updates(since)
            normalized = ingestor.normalize_updates([r.raw_data for r in raw])
            logger.info("%s: fetched %d records, writing to db", source, len(normalized))

            async with pool.acquire() as conn:
                async with conn.transaction():
                    for vuln in normalized:
                        await save_vulnerability(conn, vuln)
                    await update_last_sync(
                        conn, source, datetime.now(timezone.utc), len(normalized),
                    )

            logger.info("%s: sync complete (%d records)", source, len(normalized))
        except Exception:
            logger.exception("%s: sync failed, will retry next cycle", source)

        await asyncio.sleep(interval)


@app.command()
@async_command
async def start() -> None:
    """Start the continuous ingestion scheduler."""
    setup_logging()
    pool = await get_pool()

    async with pool.acquire() as conn:
        await init_schema(conn)

    two_hours = int(os.getenv("FAST_INTERVAL", "7200"))
    daily = int(os.getenv("DAILY_INTERVAL", "86400"))

    schedule: list[tuple[Ingestor, int]] = [
        (NVDIngestor(), two_hours),
        (GithubIngestor(), two_hours),
        (OSVIngestor(), two_hours),
        (ExploitDBIngestor(), daily),
        (CISAKEVIngestor(), daily),
        (EPSSIngestor(), daily),
    ]

    console.print(
        f"[bold green]Starting scheduler[/] with {len(schedule)} ingestors",
    )

    async with asyncio.TaskGroup() as tg:
        for ingestor, interval in schedule:
            tg.create_task(_run_ingestor_loop(pool, ingestor, interval))


@app.command()
@async_command
async def sync(
    source: Optional[str] = typer.Option(None, help="Source name (e.g. nvd, github, osv)."),
    all_sources: bool = typer.Option(False, "--all", help="Sync all sources."),
) -> None:
    """Trigger a one-shot sync for one or all sources."""
    if not source and not all_sources:
        err_console.print("[red]Provide --source NAME or --all[/]")
        raise typer.Exit(1)

    targets: list[str] = list(ALL_INGESTORS.keys()) if all_sources else [source]

    for name in targets:
        if name not in ALL_INGESTORS:
            err_console.print(f"[red]Unknown source:[/] {name}")
            err_console.print(f"Available: {', '.join(ALL_INGESTORS.keys())}")
            raise typer.Exit(1)

    pool = await get_pool()
    async with pool.acquire() as conn:
        await init_schema(conn)

    for name in targets:
        ingestor = ALL_INGESTORS[name]()
        console.print(f"[bold]{name}:[/] syncing...")

        try:
            async with pool.acquire() as conn:
                since = await get_last_sync(conn, name)

            raw = await ingestor.fetch_updates(since)
            normalized = ingestor.normalize_updates([r.raw_data for r in raw])

            async with pool.acquire() as conn:
                async with conn.transaction():
                    for vuln in normalized:
                        await save_vulnerability(conn, vuln)
                    await update_last_sync(
                        conn, name, datetime.now(timezone.utc), len(normalized),
                    )

            console.print(f"[green]{name}:[/] {len(normalized)} records synced")
        except Exception as exc:
            err_console.print(f"[red]{name}: sync failed — {exc}[/]")

    await pool.close()


@app.command()
@async_command
async def status() -> None:
    """Show the last sync time and record count for each source."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT source_name, last_successful_sync, records_synced, updated_at "
            "FROM sync_metadata ORDER BY source_name"
        )

    table = Table(title="Ingestion Status")
    table.add_column("Source", style="bold")
    table.add_column("Last Sync")
    table.add_column("Records", justify="right")
    table.add_column("Updated At")

    if rows:
        for r in rows:
            last = r["last_successful_sync"]
            table.add_row(
                r["source_name"],
                last.strftime("%Y-%m-%d %H:%M:%S UTC") if last else "never",
                str(r["records_synced"]),
                r["updated_at"].strftime("%Y-%m-%d %H:%M:%S") if r["updated_at"] else "—",
            )
    else:
        table.add_row("—", "no syncs yet", "0", "—")

    console.print(table)
    await pool.close()
