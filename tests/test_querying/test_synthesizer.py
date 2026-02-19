from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from querying.synthesizer import (
    CONVERSATIONAL_SYSTEM_PROMPT,
    GROUNDED_SYSTEM_PROMPT,
    synthesize,
)


def _mock_completion(content: str) -> MagicMock:
    message = MagicMock()
    message.content = content

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    return response


# ── synthesize: grounded path (context provided) ──────────────────────────


class TestSynthesizeWithContext:
    async def test_returns_model_response(self):
        ctx = "[CVE-2025-1234] (CRITICAL | CVSS 9.8)\nDescription: RCE in flask"
        expected_answer = "CVE-2025-1234 is a critical RCE. Upgrade flask to 2.3.1."

        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion(expected_answer),
            )
            MockClient.return_value = client

            result = await synthesize("Is flask vulnerable?", ctx)

        assert result == expected_answer

    async def test_uses_grounded_prompt_with_context(self):
        ctx = "[CVE-2025-1234] (CRITICAL)\nDescription: test vuln"

        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion("answer"),
            )
            MockClient.return_value = client

            await synthesize("question?", ctx)

        _, kwargs = client.chat.completions.create.call_args
        system_msg = kwargs["messages"][0]["content"]
        assert "Retrieved Context" in system_msg
        assert ctx in system_msg

    async def test_temperature_is_low(self):
        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion("answer"),
            )
            MockClient.return_value = client

            await synthesize("question?", "some context")

        _, kwargs = client.chat.completions.create.call_args
        assert kwargs["temperature"] == 0.1


# ── synthesize: conversational path (no context) ──────────────────────────


class TestSynthesizeConversational:
    async def test_uses_conversational_prompt_when_no_context(self):
        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion("A CVE is a ..."),
            )
            MockClient.return_value = client

            result = await synthesize("What is a CVE?", "")

        _, kwargs = client.chat.completions.create.call_args
        system_msg = kwargs["messages"][0]["content"]
        assert system_msg == CONVERSATIONAL_SYSTEM_PROMPT
        assert "Retrieved Context" not in system_msg
        assert result == "A CVE is a ..."

    async def test_user_question_passed_through(self):
        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion("answer"),
            )
            MockClient.return_value = client

            await synthesize("What does EPSS stand for?", "")

        _, kwargs = client.chat.completions.create.call_args
        user_msg = kwargs["messages"][1]["content"]
        assert user_msg == "What does EPSS stand for?"


# ── synthesize: model config ──────────────────────────────────────────────


class TestSynthesizeModelConfig:
    async def test_uses_llm_model_env_var(self):
        with (
            patch("querying.synthesizer.AsyncOpenAI") as MockClient,
            patch("querying.synthesizer.os.getenv", return_value="gpt-5.2"),
        ):
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion("answer"),
            )
            MockClient.return_value = client

            await synthesize("question?", "context")

        _, kwargs = client.chat.completions.create.call_args
        assert kwargs["model"] == "gpt-5.2"


# ── synthesize: error handling ────────────────────────────────────────────


class TestSynthesizeErrors:
    async def test_raises_on_truncated_output(self):
        from openai import LengthFinishReasonError

        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                side_effect=LengthFinishReasonError(completion=MagicMock()),
            )
            MockClient.return_value = client

            with pytest.raises(ValueError, match="truncated"):
                await synthesize("question?", "context")

    async def test_raises_on_none_content(self):
        with patch("querying.synthesizer.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.chat.completions.create = AsyncMock(
                return_value=_mock_completion(None),
            )
            MockClient.return_value = client

            with pytest.raises(ValueError, match="empty output"):
                await synthesize("question?", "context")
