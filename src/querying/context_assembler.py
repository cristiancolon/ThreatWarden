from .retriever import VulnRow

# ~4 characters per token is a reasonable approximation for English text.
# Can be swapped for tiktoken later for exact counts.
_CHARS_PER_TOKEN = 4
_DEFAULT_TOKEN_BUDGET = 15_000


def assemble_context(
    rows: list[VulnRow],
    token_budget: int = _DEFAULT_TOKEN_BUDGET,
) -> str:
    """Format vulnerability rows into a context string for the synthesis LLM.

    Each row becomes a structured text block. Blocks are appended in order
    (the retriever already sorts by KEV > EPSS > CVSS > recency) until the
    token budget is exhausted. Returns an empty string when rows is empty,
    signalling the synthesis step to answer conversationally.
    """
    if not rows:
        return ""

    char_budget = token_budget * _CHARS_PER_TOKEN
    blocks: list[str] = []
    chars_used = 0

    for row in rows:
        block = _format_block(row)
        block_len = len(block)

        if chars_used + block_len > char_budget:
            break

        blocks.append(block)
        chars_used += block_len

    return "\n\n".join(blocks)


def estimate_tokens(text: str) -> int:
    """Rough token count based on character length."""
    return len(text) // _CHARS_PER_TOKEN


# ---------------------------------------------------------------------------
# Block formatting
# ---------------------------------------------------------------------------

def _format_block(row: VulnRow) -> str:
    """Format a single VulnRow into a structured text block."""
    header = _format_header(row)
    lines = [header]

    affects = _format_affects(row.affected_packages)
    if affects:
        lines.append(affects)

    if row.description:
        lines.append(f"Description: {row.description}")

    exploit_line = _format_exploits(row.exploits)
    if exploit_line:
        lines.append(exploit_line)

    if row.references:
        lines.append(f"Sources: {', '.join(row.references)}")

    return "\n".join(lines)


def _format_header(row: VulnRow) -> str:
    """Build the header line: [CVE-ID] (SEVERITY | CVSS X.X | EPSS X.XX | KEV: Y/N | Exploit: Y/N)"""
    parts: list[str] = []

    if row.severity:
        parts.append(row.severity)
    if row.cvss_score is not None:
        parts.append(f"CVSS {row.cvss_score:.1f}")
    if row.epss_score is not None:
        parts.append(f"EPSS {row.epss_score:.2f}")

    parts.append(f"KEV: {'Yes' if row.cisa_kev else 'No'}")
    parts.append(f"Exploit: {'Yes' if row.exploits else 'No'}")

    return f"[{row.cve_id}] ({' | '.join(parts)})"


def _format_affects(packages: list[dict]) -> str | None:
    """Build the 'Affects:' line from affected package records."""
    if not packages:
        return None

    segments: list[str] = []
    for pkg in packages:
        name = pkg.get("package_name", "unknown")
        eco = pkg.get("ecosystem", "")
        versions = pkg.get("vulnerable_versions", "")
        patched = pkg.get("patched_version", "")

        segment = f"{name} ({eco})" if eco else name
        if versions:
            segment += f" versions {versions}"
        if patched:
            segment += f" — patched in {patched}"
        segments.append(segment)

    return f"Affects: {'; '.join(segments)}"


def _format_exploits(exploits: list[dict]) -> str | None:
    """Build the 'Exploits:' line summarizing known exploits."""
    if not exploits:
        return None

    entries: list[str] = []
    for exp in exploits:
        source = exp.get("source", "unknown")
        url = exp.get("url", "")
        desc = exp.get("description", "")
        if url:
            entries.append(f"{source}: {url}")
        elif desc:
            short = desc[:120] + "..." if len(desc) > 120 else desc
            entries.append(f"{source}: {short}")
        else:
            entries.append(source)

    return f"Exploits: {'; '.join(entries)}"
