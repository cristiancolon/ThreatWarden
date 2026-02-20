import argparse
import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import asyncpg
from dotenv import load_dotenv

from db.writer import get_last_sync, init_schema, save_vulnerability, update_last_sync
from ingestion.base import Ingestor
from ingestion.nvd import NVDIngestor
from ingestion.github import GithubIngestor
from ingestion.osv import OSVIngestor
from ingestion.cisa_kev import CISAKEVIngestor
from ingestion.epss import EPSSIngestor
from ingestion.exploitdb import ExploitDBIngestor

load_dotenv()
logger = logging.getLogger("threatwarden.scheduler")

OVERLAP_WINDOW = timedelta(hours=1)
WRITE_BATCH_SIZE = 2000


def build_ingestors(pool: asyncpg.Pool) -> dict[str, tuple[Ingestor, int]]:
    """Create every ingestor with its refresh interval (seconds)."""
    six_hours = int(os.getenv("FAST_INTERVAL", "21600"))
    daily = int(os.getenv("DAILY_INTERVAL", "86400"))
    return {
        "nvd": (NVDIngestor(), six_hours),
        "github": (GithubIngestor(), six_hours),
        "osv": (OSVIngestor(), six_hours),
        "exploitdb": (ExploitDBIngestor(pool), daily),
        "epss": (EPSSIngestor(), daily),
        "cisa_kev": (CISAKEVIngestor(), daily),
    }


async def sync_once(pool: asyncpg.Pool, ingestor: Ingestor) -> None:
    """Run a single sync cycle for an ingestor (no cooldown, no loop)."""
    source = ingestor.source_name()
    async with pool.acquire() as conn:
        since = await get_last_sync(conn, source)

    fetch_since = since - OVERLAP_WINDOW if since else None
    logger.info("%s: starting sync (since=%s)", source, fetch_since)

    written = 0
    buffer: list = []

    async for page in ingestor.fetch_updates(fetch_since):
        normalized = ingestor.normalize_updates([r.raw_data for r in page])
        buffer.extend(normalized)

        while len(buffer) >= WRITE_BATCH_SIZE:
            batch = buffer[:WRITE_BATCH_SIZE]
            buffer = buffer[WRITE_BATCH_SIZE:]
            async with pool.acquire() as conn:
                async with conn.transaction():
                    for vuln in batch:
                        await save_vulnerability(conn, vuln)
            written += len(batch)
            logger.info(
                "%s: wrote batch (%d records so far)", source, written,
            )

    if buffer:
        async with pool.acquire() as conn:
            async with conn.transaction():
                for vuln in buffer:
                    await save_vulnerability(conn, vuln)
        written += len(buffer)

    async with pool.acquire() as conn:
        await update_last_sync(
            conn, source, datetime.now(timezone.utc), written,
        )

    logger.info("%s: sync complete (%d records)", source, written)


async def run_ingestor(
    pool: asyncpg.Pool,
    ingestor: Ingestor,
    interval: int,
    *,
    ready_event: asyncio.Event | None = None,
    wait_for: asyncio.Event | None = None,
) -> None:
    """Run a single ingestor in a loop: cooldown → sync → sleep → repeat.

    ready_event – set after the first cycle so dependents know data is available.
    wait_for    – await this event before starting the first cycle.
    """
    if wait_for is not None:
        logger.info("%s: waiting for dependencies", ingestor.source_name())
        await wait_for.wait()

    while True:
        source = ingestor.source_name()
        try:
            async with pool.acquire() as conn:
                since = await get_last_sync(conn, source)

            if since is not None:
                elapsed = (datetime.now(timezone.utc) - since).total_seconds()
                if elapsed < interval:
                    remaining = interval - elapsed
                    logger.info(
                        "%s: last sync %d min ago, next in %d min",
                        source, int(elapsed / 60), int(remaining / 60),
                    )
                    if ready_event is not None:
                        ready_event.set()
                        ready_event = None
                    await asyncio.sleep(remaining)
                    continue

            await sync_once(pool, ingestor)
        except Exception:
            logger.exception("%s: sync failed, will retry next cycle", source)

        if ready_event is not None:
            ready_event.set()
            ready_event = None

        await asyncio.sleep(interval)


async def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatWarden ingestion scheduler")
    parser.add_argument(
        "--refresh",
        nargs="+",
        metavar="SOURCE",
        help="Force-refresh one or more sources immediately then exit. "
             "Valid: nvd, github, osv, exploitdb, epss, cisa_kev",
    )
    args = parser.parse_args()

    db_url = os.getenv("DB_URL", "postgresql://threatwarden:threatwarden@localhost:5432/threatwarden")
    pool = await asyncpg.create_pool(dsn=db_url)

    async with pool.acquire() as conn:
        await init_schema(conn)

    ingestors = build_ingestors(pool)

    if args.refresh:
        for name in args.refresh:
            if name not in ingestors:
                logger.error(
                    "unknown source %r (valid: %s)", name, ", ".join(ingestors),
                )
                continue
            ingestor, _ = ingestors[name]
            try:
                await sync_once(pool, ingestor)
            except Exception:
                logger.exception("%s: refresh failed", name)
        await pool.close()
        return

    logger.info("starting threatwarden scheduler with %d ingestors", len(ingestors))

    nvd_ready = asyncio.Event()

    async with asyncio.TaskGroup() as tg:
        for name, (ingestor, interval) in ingestors.items():
            ready = nvd_ready if name == "nvd" else None
            wait = nvd_ready if name == "exploitdb" else None
            tg.create_task(
                run_ingestor(
                    pool, ingestor, interval,
                    ready_event=ready, wait_for=wait,
                )
            )


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(main())
