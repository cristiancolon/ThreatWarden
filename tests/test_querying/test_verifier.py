from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from querying.verifier import (
    VerificationResult,
    VerifiedClaim,
    build_verified_response,
    verify,
)


def _mock_parse_response(result: VerificationResult) -> MagicMock:
    message = MagicMock()
    message.parsed = result

    choice = MagicMock()
    choice.message = message

    response = MagicMock()
    response.choices = [choice]
    return response


# ── verify: skips when no context ──────────────────────────────────────────


class TestVerifyNoContext:
    async def test_empty_context_skips_verification(self):
        result = await verify("", "Some LLM response")

        assert result.claims == []
        assert result.omissions == []

    async def test_no_llm_call_when_no_context(self):
        with patch("querying.verifier.AsyncOpenAI") as MockClient:
            result = await verify("", "Some response")

            MockClient.assert_not_called()
            assert result.claims == []


# ── verify: calls verifier model ───────────────────────────────────────────


class TestVerifyWithContext:
    async def test_returns_parsed_result(self):
        expected = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVE-2025-1234 has a CVSS score of 9.8",
                    status="supported",
                    evidence="[CVE-2025-1234] (CRITICAL | CVSS 9.8)",
                    rationale="CVSS score matches the context header.",
                ),
            ],
            omissions=[],
        )

        with patch("querying.verifier.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.beta.chat.completions.parse = AsyncMock(
                return_value=_mock_parse_response(expected),
            )
            MockClient.return_value = client

            result = await verify(
                "[CVE-2025-1234] (CRITICAL | CVSS 9.8)",
                "CVE-2025-1234 has a CVSS score of 9.8.",
            )

        assert len(result.claims) == 1
        assert result.claims[0].status == "supported"
        assert result.omissions == []

    async def test_passes_context_and_response_to_model(self):
        expected = VerificationResult(claims=[], omissions=[])

        with patch("querying.verifier.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.beta.chat.completions.parse = AsyncMock(
                return_value=_mock_parse_response(expected),
            )
            MockClient.return_value = client

            await verify("my context", "my response")

        _, kwargs = client.beta.chat.completions.parse.call_args
        user_msg = kwargs["messages"][1]["content"]
        assert "my context" in user_msg
        assert "my response" in user_msg

    async def test_uses_intent_model(self):
        expected = VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.verifier.AsyncOpenAI") as MockClient,
            patch("querying.verifier.os.getenv", return_value="gpt-4.1-mini"),
        ):
            client = AsyncMock()
            client.beta.chat.completions.parse = AsyncMock(
                return_value=_mock_parse_response(expected),
            )
            MockClient.return_value = client

            await verify("context", "response")

        _, kwargs = client.beta.chat.completions.parse.call_args
        assert kwargs["model"] == "gpt-4.1-mini"
        assert kwargs["temperature"] == 0.0


# ── verify: error handling ─────────────────────────────────────────────────


class TestVerifyErrors:
    async def test_raises_on_truncated_output(self):
        from openai import LengthFinishReasonError

        with patch("querying.verifier.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.beta.chat.completions.parse = AsyncMock(
                side_effect=LengthFinishReasonError(completion=MagicMock()),
            )
            MockClient.return_value = client

            with pytest.raises(ValueError, match="truncated"):
                await verify("context", "response")

    async def test_raises_on_none_parsed(self):
        with patch("querying.verifier.AsyncOpenAI") as MockClient:
            client = AsyncMock()
            client.beta.chat.completions.parse = AsyncMock(
                return_value=_mock_parse_response(None),
            )
            MockClient.return_value = client

            with pytest.raises(ValueError, match="empty output"):
                await verify("context", "response")


# ── build_verified_response ────────────────────────────────────────────────


class TestBuildVerifiedResponse:
    def test_all_supported_returns_unchanged(self):
        result = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVE-2025-1234 is critical",
                    status="supported",
                    evidence="[CVE-2025-1234] (CRITICAL)",
                    rationale="Matches context.",
                ),
            ],
            omissions=[],
        )
        original = "CVE-2025-1234 is a critical vulnerability."

        assert build_verified_response(original, result) == original

    def test_unsupported_claims_appended_as_warnings(self):
        result = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVE-2025-9999 affects nginx",
                    status="unsupported",
                    evidence=None,
                    rationale="CVE-2025-9999 does not appear in the context.",
                ),
            ],
            omissions=[],
        )
        output = build_verified_response("Some response mentioning CVE-2025-9999.", result)

        assert "could not be verified" in output
        assert "CVE-2025-9999 affects nginx" in output
        assert "does not appear in the context" in output

    def test_omissions_appended_as_additional_info(self):
        result = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVE-2025-1234 is critical",
                    status="supported",
                    evidence="[CVE-2025-1234] (CRITICAL)",
                    rationale="Matches.",
                ),
            ],
            omissions=[
                "CVE-2025-1234 is listed in CISA KEV as actively exploited.",
                "A patch is available in flask 2.3.1.",
            ],
        )
        output = build_verified_response("CVE-2025-1234 is critical.", result)

        assert "Additional information" in output
        assert "CISA KEV" in output
        assert "flask 2.3.1" in output

    def test_both_unsupported_and_omissions(self):
        result = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVSS is 10.0",
                    status="unsupported",
                    evidence=None,
                    rationale="Context says 9.8, not 10.0.",
                ),
            ],
            omissions=["Exploit available via ExploitDB."],
        )
        output = build_verified_response("CVSS is 10.0.", result)

        assert "could not be verified" in output
        assert "CVSS is 10.0" in output
        assert "Additional information" in output
        assert "ExploitDB" in output

    def test_empty_result_returns_unchanged(self):
        result = VerificationResult(claims=[], omissions=[])
        original = "No vulnerabilities found."

        assert build_verified_response(original, result) == original
