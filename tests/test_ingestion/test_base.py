from unittest.mock import AsyncMock, patch

import httpx
import pytest

from ingestion.base import get_response_with_retry

_REQ = httpx.Request("GET", "https://test.example.com")


def _resp(status: int, **kwargs) -> httpx.Response:
    return httpx.Response(status, request=_REQ, **kwargs)


# ── Success path ──────────────────────────────────────────────────────────


async def test_returns_response_on_200():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_resp(200, json={"ok": True}))

    result = await get_response_with_retry(client, "https://x", headers={})

    assert result.status_code == 200
    assert result.json() == {"ok": True}
    client.get.assert_called_once()


# ── Retry behaviour ──────────────────────────────────────────────────────


async def test_retries_on_429_then_succeeds():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _resp(429),
        _resp(200, json={"ok": True}),
    ])

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await get_response_with_retry(client, "https://x", headers={})

    assert result.status_code == 200
    assert client.get.call_count == 2


async def test_retries_on_5xx_then_succeeds():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _resp(503),
        _resp(502),
        _resp(200, json={"data": []}),
    ])

    with patch("asyncio.sleep", new_callable=AsyncMock):
        result = await get_response_with_retry(client, "https://x", headers={})

    assert result.status_code == 200
    assert client.get.call_count == 3


async def test_exponential_backoff_delays():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(side_effect=[
        _resp(429),
        _resp(429),
        _resp(200, json={}),
    ])

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await get_response_with_retry(client, "https://x", headers={})

    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(1.0)
    mock_sleep.assert_any_call(2.0)


# ── Failure paths ─────────────────────────────────────────────────────────


async def test_raises_immediately_on_non_retryable_error():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_resp(404))

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await get_response_with_retry(client, "https://x", headers={})

    assert exc_info.value.response.status_code == 404
    client.get.assert_called_once()


async def test_raises_after_max_retries_exhausted():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_resp(429))

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(httpx.HTTPStatusError):
            await get_response_with_retry(
                client, "https://x", headers={}, max_retries=3,
            )

    assert client.get.call_count == 3


# ── Parameter forwarding ─────────────────────────────────────────────────


async def test_forwards_headers_and_params():
    client = AsyncMock(spec=httpx.AsyncClient)
    client.get = AsyncMock(return_value=_resp(200, json={}))

    await get_response_with_retry(
        client, "https://x",
        headers={"Authorization": "Bearer tok"},
        params={"page": 1},
    )

    _, kwargs = client.get.call_args
    assert kwargs["headers"] == {"Authorization": "Bearer tok"}
    assert kwargs["params"] == {"page": 1}
