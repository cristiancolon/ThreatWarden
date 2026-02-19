from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from querying.engine import QueryResult, ask
from querying.intent_parser import QueryIntent
from querying.retriever import VulnRow
from querying.verifier import VerificationResult, VerifiedClaim


def _intent(**overrides) -> QueryIntent:
    defaults = dict(
        ecosystems=None,
        package_names=None,
        cve_ids=None,
        severity_filter=None,
        date_range=None,
        query_type="general_search",
        raw_search_query="test",
    )
    defaults.update(overrides)
    return QueryIntent(**defaults)


def _vuln_row(cve_id="CVE-2025-1234") -> VulnRow:
    return VulnRow(
        cve_id=cve_id,
        description="Test vulnerability",
        cvss_score=9.8,
        cvss_vector=None,
        severity="CRITICAL",
        epss_score=0.9,
        epss_percentile=0.99,
        cisa_kev=True,
        published_at=datetime(2025, 1, 15, tzinfo=timezone.utc),
        affected_packages=[{
            "package_name": "flask",
            "ecosystem": "pypi",
            "vulnerable_versions": ">=2.0 <2.3.1",
            "patched_version": "2.3.1",
        }],
        exploits=[],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1234"],
    )


# ── Full pipeline: grounded path (SQL results exist) ──────────────────────


class TestAskWithContext:
    async def test_returns_complete_query_result(self):
        intent = _intent(cve_ids=["CVE-2025-1234"], query_type="specific_cve")
        rows = [_vuln_row()]
        verification = VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.engine.parse_intent", new_callable=AsyncMock, return_value=intent),
            patch("querying.engine.execute_query", new_callable=AsyncMock, return_value=rows),
            patch("querying.engine.synthesize", new_callable=AsyncMock, return_value="CVE-2025-1234 is critical."),
            patch("querying.engine.verify", new_callable=AsyncMock, return_value=verification),
        ):
            conn = AsyncMock()
            result = await ask("What is CVE-2025-1234?", conn)

        assert isinstance(result, QueryResult)
        assert result.question == "What is CVE-2025-1234?"
        assert result.intent is intent
        assert result.rows == rows
        assert result.context != ""
        assert result.raw_answer == "CVE-2025-1234 is critical."
        assert result.final_answer == "CVE-2025-1234 is critical."

    async def test_passes_context_to_synthesize(self):
        intent = _intent(cve_ids=["CVE-2025-1234"], query_type="specific_cve")
        rows = [_vuln_row()]
        verification = VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.engine.parse_intent", new_callable=AsyncMock, return_value=intent),
            patch("querying.engine.execute_query", new_callable=AsyncMock, return_value=rows),
            patch("querying.engine.synthesize", new_callable=AsyncMock, return_value="answer") as mock_synth,
            patch("querying.engine.verify", new_callable=AsyncMock, return_value=verification),
        ):
            conn = AsyncMock()
            result = await ask("question?", conn)

        _, kwargs = mock_synth.call_args
        assert kwargs.get("context") or mock_synth.call_args[0][1]
        assert "CVE-2025-1234" in result.context

    async def test_verification_annotates_final_answer(self):
        intent = _intent(cve_ids=["CVE-2025-1234"], query_type="specific_cve")
        rows = [_vuln_row()]
        verification = VerificationResult(
            claims=[
                VerifiedClaim(
                    claim="CVSS is 10.0",
                    status="unsupported",
                    evidence=None,
                    rationale="Context says 9.8.",
                ),
            ],
            omissions=["KEV status was not mentioned."],
        )

        with (
            patch("querying.engine.parse_intent", new_callable=AsyncMock, return_value=intent),
            patch("querying.engine.execute_query", new_callable=AsyncMock, return_value=rows),
            patch("querying.engine.synthesize", new_callable=AsyncMock, return_value="CVSS is 10.0."),
            patch("querying.engine.verify", new_callable=AsyncMock, return_value=verification),
        ):
            conn = AsyncMock()
            result = await ask("question?", conn)

        assert "could not be verified" in result.final_answer
        assert "Additional information" in result.final_answer
        assert result.raw_answer == "CVSS is 10.0."


# ── Full pipeline: conversational path (no SQL results) ───────────────────


class TestAskConversational:
    async def test_empty_context_when_no_filters(self):
        intent = _intent()
        verification = VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.engine.parse_intent", new_callable=AsyncMock, return_value=intent),
            patch("querying.engine.execute_query", new_callable=AsyncMock, return_value=[]),
            patch("querying.engine.synthesize", new_callable=AsyncMock, return_value="A CVE is ..."),
            patch("querying.engine.verify", new_callable=AsyncMock, return_value=verification),
        ):
            conn = AsyncMock()
            result = await ask("What is a CVE?", conn)

        assert result.context == ""
        assert result.rows == []
        assert result.final_answer == "A CVE is ..."

    async def test_verify_receives_empty_context(self):
        intent = _intent()
        verification = VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.engine.parse_intent", new_callable=AsyncMock, return_value=intent),
            patch("querying.engine.execute_query", new_callable=AsyncMock, return_value=[]),
            patch("querying.engine.synthesize", new_callable=AsyncMock, return_value="answer"),
            patch("querying.engine.verify", new_callable=AsyncMock, return_value=verification) as mock_verify,
        ):
            conn = AsyncMock()
            await ask("What is a CVE?", conn)

        mock_verify.assert_called_once_with("", "answer")


# ── Pipeline ordering ─────────────────────────────────────────────────────


class TestPipelineOrder:
    async def test_stages_called_in_order(self):
        """Verify intent -> retrieve -> assemble -> synthesize -> verify."""
        call_order = []

        async def mock_parse_intent(q):
            call_order.append("parse_intent")
            return _intent(cve_ids=["CVE-2025-0001"], query_type="specific_cve")

        async def mock_execute_query(conn, intent):
            call_order.append("execute_query")
            return [_vuln_row()]

        async def mock_synthesize(q, ctx):
            call_order.append("synthesize")
            return "answer"

        async def mock_verify(ctx, resp):
            call_order.append("verify")
            return VerificationResult(claims=[], omissions=[])

        with (
            patch("querying.engine.parse_intent", side_effect=mock_parse_intent),
            patch("querying.engine.execute_query", side_effect=mock_execute_query),
            patch("querying.engine.synthesize", side_effect=mock_synthesize),
            patch("querying.engine.verify", side_effect=mock_verify),
        ):
            conn = AsyncMock()
            await ask("question?", conn)

        assert call_order == ["parse_intent", "execute_query", "synthesize", "verify"]
