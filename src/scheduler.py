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


async def run_ingestor(pool: asyncpg.Pool, ingestor: Ingestor, interval: int) -> None:
    """Run a single ingestor in a loop: fetch → normalize → save → sleep."""
    while True:
        source = ingestor.source_name()
        try:
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
        except Exception:
            logger.exception("%s: sync failed, will retry next cycle", source)

        await asyncio.sleep(interval)


async def main() -> None:
    db_url = os.getenv("DB_URL", "postgresql://threatwarden:threatwarden@localhost:5432/threatwarden")
    pool = await asyncpg.create_pool(dsn=db_url)

    async with pool.acquire() as conn:
        await init_schema(conn)

    six_hours = int(os.getenv("FAST_INTERVAL", "21600"))
    daily = int(os.getenv("DAILY_INTERVAL", "86400"))

    ingestors: list[tuple[Ingestor, int]] = [
        (NVDIngestor(), six_hours),
        (GithubIngestor(), six_hours),
        (OSVIngestor(), six_hours),
        (ExploitDBIngestor(), daily),
        (EPSSIngestor(), daily),
        (CISAKEVIngestor(), daily),
    ]

    logger.info("starting threatwarden scheduler with %d ingestors", len(ingestors))

    async with asyncio.TaskGroup() as tg:
        for ingestor, interval in ingestors:
            tg.create_task(run_ingestor(pool, ingestor, interval))


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(main())
