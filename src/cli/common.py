import asyncio
import logging
import os
from functools import wraps
from typing import Any, Callable, Coroutine

import asyncpg
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

console = Console()
err_console = Console(stderr=True)


def get_db_url() -> str:
    return os.getenv(
        "DB_URL",
        "postgresql://threatwarden:threatwarden@localhost:5432/threatwarden",
    )


async def get_pool() -> asyncpg.Pool:
    return await asyncpg.create_pool(dsn=get_db_url())


def async_command(fn: Callable[..., Coroutine]) -> Callable[..., Any]:
    """Decorator that lets Typer run an async function synchronously."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(fn(*args, **kwargs))
    return wrapper


def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
