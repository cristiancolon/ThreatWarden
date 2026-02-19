from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from querying.intent_parser import QueryIntent, parse_intent


def _mock_parse_response(intent: QueryIntent) -> MagicMock:
    """Build a mock that mimics the OpenAI beta.chat.completions.parse() response."""
    message = MagicMock()
    message.parsed = intent

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    return response


# ── parse_intent: structured field extraction ─────────────────────────────


async def test_package_check_query():
    expected = QueryIntent(
        ecosystems=["pypi"],
        package_names=["flask"],
        cve_ids=None,
        severity_filter="CRITICAL+",
        date_range=None,
        query_type="package_check",
        raw_search_query="critical vulnerabilities affecting flask 2.0.1",
    )

    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(expected),
        )
        MockClient.return_value = client

        result = await parse_intent("Is Flask 2.0.1 vulnerable to anything critical?")

    assert result.ecosystems == ["pypi"]
    assert result.package_names == ["flask"]
    assert result.severity_filter == "CRITICAL+"
    assert result.query_type == "package_check"
    assert result.cve_ids is None


async def test_specific_cve_query():
    expected = QueryIntent(
        ecosystems=None,
        package_names=None,
        cve_ids=["CVE-2025-29927"],
        severity_filter=None,
        date_range=None,
        query_type="specific_cve",
        raw_search_query="details about CVE-2025-29927",
    )

    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(expected),
        )
        MockClient.return_value = client

        result = await parse_intent("What's CVE-2025-29927?")

    assert result.cve_ids == ["CVE-2025-29927"]
    assert result.query_type == "specific_cve"
    assert result.ecosystems is None
    assert result.package_names is None


async def test_general_search_with_date_range():
    expected = QueryIntent(
        ecosystems=["npm"],
        package_names=None,
        cve_ids=None,
        severity_filter="CRITICAL",
        date_range="last 7 days",
        query_type="general_search",
        raw_search_query="new critical npm vulnerabilities this week",
    )

    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(expected),
        )
        MockClient.return_value = client

        result = await parse_intent("Any new critical vulnerabilities in the npm ecosystem this week?")

    assert result.ecosystems == ["npm"]
    assert result.severity_filter == "CRITICAL"
    assert result.date_range == "last 7 days"
    assert result.query_type == "general_search"


async def test_multi_package_query():
    expected = QueryIntent(
        ecosystems=["pypi"],
        package_names=["requests", "urllib3"],
        cve_ids=None,
        severity_filter=None,
        date_range=None,
        query_type="package_check",
        raw_search_query="known exploits for python requests and urllib3",
    )

    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(expected),
        )
        MockClient.return_value = client

        result = await parse_intent("Are there any known exploits for requests or urllib3 in Python?")

    assert result.package_names == ["requests", "urllib3"]
    assert result.ecosystems == ["pypi"]


# ── parse_intent: passes correct arguments to OpenAI ──────────────────────


async def test_passes_model_and_schema():
    expected = QueryIntent(
        ecosystems=None, package_names=None, cve_ids=["CVE-2025-0001"],
        severity_filter=None, date_range=None,
        query_type="specific_cve", raw_search_query="CVE-2025-0001",
    )

    with (
        patch("querying.intent_parser.AsyncOpenAI") as MockClient,
        patch("querying.intent_parser.os.getenv", return_value="gpt-4.1-mini"),
    ):
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(expected),
        )
        MockClient.return_value = client

        await parse_intent("Tell me about CVE-2025-0001")

    _, kwargs = client.beta.chat.completions.parse.call_args
    assert kwargs["model"] == "gpt-4.1-mini"
    assert kwargs["response_format"] is QueryIntent
    assert kwargs["temperature"] == 0.0
    assert kwargs["messages"][1]["content"] == "Tell me about CVE-2025-0001"


# ── parse_intent: error handling ──────────────────────────────────────────


async def test_raises_on_truncated_output():
    from openai import LengthFinishReasonError

    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            side_effect=LengthFinishReasonError(completion=MagicMock()),
        )
        MockClient.return_value = client

        with pytest.raises(ValueError, match="truncated"):
            await parse_intent("Some question")


async def test_raises_on_none_parsed():
    with patch("querying.intent_parser.AsyncOpenAI") as MockClient:
        client = AsyncMock()
        client.beta.chat.completions.parse = AsyncMock(
            return_value=_mock_parse_response(None),
        )
        MockClient.return_value = client

        with pytest.raises(ValueError, match="empty output"):
            await parse_intent("Some question")
