from datetime import datetime, timezone

from querying.context_assembler import (
    _format_block,
    assemble_context,
    estimate_tokens,
)
from querying.retriever import VulnRow


def _vuln(
    cve_id="CVE-2025-1234",
    description="Remote code execution via crafted input",
    cvss_score=9.8,
    severity="CRITICAL",
    epss_score=0.87,
    epss_percentile=0.99,
    cisa_kev=True,
    published_at=None,
    affected_packages=None,
    exploits=None,
    references=None,
) -> VulnRow:
    return VulnRow(
        cve_id=cve_id,
        description=description,
        cvss_score=cvss_score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity=severity,
        epss_score=epss_score,
        epss_percentile=epss_percentile,
        cisa_kev=cisa_kev,
        published_at=published_at or datetime(2025, 1, 15, tzinfo=timezone.utc),
        affected_packages=affected_packages or [],
        exploits=exploits or [],
        references=references or [],
    )


# ── assemble_context ───────────────────────────────────────────────────────


class TestAssembleContext:
    def test_empty_rows_returns_empty_string(self):
        assert assemble_context([]) == ""

    def test_single_row_produces_block(self):
        row = _vuln(
            affected_packages=[{
                "package_name": "flask",
                "ecosystem": "pypi",
                "vulnerable_versions": ">=2.0.0 <2.3.1",
                "patched_version": "2.3.1",
            }],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1234"],
        )
        ctx = assemble_context([row])

        assert "[CVE-2025-1234]" in ctx
        assert "CRITICAL" in ctx
        assert "CVSS 9.8" in ctx
        assert "EPSS 0.87" in ctx
        assert "KEV: Yes" in ctx
        assert "Exploit: No" in ctx
        assert "flask (pypi)" in ctx
        assert "patched in 2.3.1" in ctx
        assert "Remote code execution" in ctx
        assert "nvd.nist.gov" in ctx

    def test_multiple_rows_separated_by_blank_line(self):
        rows = [_vuln(cve_id="CVE-2025-0001"), _vuln(cve_id="CVE-2025-0002")]
        ctx = assemble_context(rows)

        assert "CVE-2025-0001" in ctx
        assert "CVE-2025-0002" in ctx
        assert "\n\n" in ctx

    def test_budget_truncates_excess_rows(self):
        long_desc = "x" * 2000
        rows = [
            _vuln(cve_id=f"CVE-2025-{i:04d}", description=long_desc)
            for i in range(20)
        ]
        # Budget of 2000 tokens = ~8000 chars, enough for a few blocks but not all 20
        ctx = assemble_context(rows, token_budget=2000)

        assert "CVE-2025-0000" in ctx
        block_count = ctx.count("[CVE-")
        assert 1 <= block_count < 20

    def test_budget_zero_returns_empty(self):
        rows = [_vuln()]
        ctx = assemble_context(rows, token_budget=0)
        assert ctx == ""


# ── _format_block ──────────────────────────────────────────────────────────


class TestFormatBlock:
    def test_header_contains_all_signals(self):
        row = _vuln(exploits=[{"source": "exploitdb", "url": "https://exploit-db.com/1"}])
        block = _format_block(row)

        assert block.startswith("[CVE-2025-1234]")
        assert "CRITICAL" in block
        assert "CVSS 9.8" in block
        assert "EPSS 0.87" in block
        assert "KEV: Yes" in block
        assert "Exploit: Yes" in block

    def test_no_exploit_shows_no(self):
        row = _vuln(exploits=[])
        block = _format_block(row)
        assert "Exploit: No" in block

    def test_no_kev_shows_no(self):
        row = _vuln(cisa_kev=False)
        block = _format_block(row)
        assert "KEV: No" in block

    def test_missing_optional_fields(self):
        row = _vuln(
            cvss_score=None,
            epss_score=None,
            severity=None,
            description=None,
        )
        block = _format_block(row)

        assert "[CVE-2025-1234]" in block
        assert "CVSS" not in block
        assert "EPSS" not in block
        assert "Description" not in block

    def test_multiple_affected_packages(self):
        row = _vuln(affected_packages=[
            {"package_name": "flask", "ecosystem": "pypi",
             "vulnerable_versions": ">=2.0", "patched_version": "2.3.1"},
            {"package_name": "werkzeug", "ecosystem": "pypi",
             "vulnerable_versions": ">=1.0", "patched_version": "2.0.1"},
        ])
        block = _format_block(row)

        assert "flask (pypi)" in block
        assert "werkzeug (pypi)" in block
        assert ";" in block

    def test_exploit_with_url(self):
        row = _vuln(exploits=[
            {"source": "exploitdb", "url": "https://exploit-db.com/1", "description": "PoC"},
        ])
        block = _format_block(row)
        assert "exploitdb: https://exploit-db.com/1" in block

    def test_exploit_without_url_uses_description(self):
        row = _vuln(exploits=[
            {"source": "github", "url": "", "description": "Proof of concept script"},
        ])
        block = _format_block(row)
        assert "github: Proof of concept script" in block

    def test_long_exploit_description_truncated(self):
        row = _vuln(exploits=[
            {"source": "github", "url": "", "description": "A" * 200},
        ])
        block = _format_block(row)
        assert "..." in block

    def test_references_listed(self):
        row = _vuln(references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2025-1234",
            "https://github.com/advisories/GHSA-xxxx",
        ])
        block = _format_block(row)
        assert "Sources:" in block
        assert "nvd.nist.gov" in block
        assert "github.com" in block


# ── estimate_tokens ────────────────────────────────────────────────────────


class TestEstimateTokens:
    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_approximate_count(self):
        text = "a" * 400
        assert estimate_tokens(text) == 100
