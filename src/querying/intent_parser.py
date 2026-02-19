import os

from openai import AsyncOpenAI, LengthFinishReasonError
from pydantic import BaseModel


class QueryIntent(BaseModel):
    ecosystems: list[str] | None
    package_names: list[str] | None
    cve_ids: list[str] | None
    severity_filter: str | None
    date_range: str | None
    query_type: str
    raw_search_query: str


INTENT_SYSTEM_PROMPT = """\
You are a structured data extractor for a vulnerability intelligence system. \
Given a user's natural-language question about software vulnerabilities, extract \
the following fields. Return null for any field that the question does not mention \
or imply.

## Fields

- ecosystems: List of package ecosystem identifiers. Normalize common names:
    python/pip -> "pypi", javascript/js/node -> "npm", go/golang -> "Go",
    java -> "maven", rust -> "crates.io", c#/.net -> "nuget",
    ruby -> "rubygems", php -> "composer", dart/flutter -> "pub",
    elixir/erlang -> "erlang", swift -> "swift".
  Use the canonical name exactly as shown after the arrow.

- package_names: List of specific package names mentioned (e.g. ["flask", "requests"]). \
  Use lowercase. null if no specific packages are mentioned.

- cve_ids: List of CVE identifiers (e.g. ["CVE-2025-1234"]). \
  Use the exact CVE-YYYY-NNNNN format. null if none mentioned.

- severity_filter: Severity level filter. Use uppercase: "CRITICAL", "HIGH", "MEDIUM", "LOW". \
  Append "+" when the user means "at least this level" (e.g. "high or above" -> "HIGH+"). \
  null if no severity mentioned.

- date_range: A human-readable time window exactly as the user expressed it \
  (e.g. "last 7 days", "last 30 days", "this week", "since January 2025"). \
  null if no time constraint mentioned.

- query_type: Classify the question as one of:
    "specific_cve"   — the user asks about one or more specific CVE IDs
    "package_check"  — the user asks about vulnerabilities in specific packages
    "general_search" — a broad or exploratory question about vulnerabilities

- raw_search_query: A cleaned, rephrased version of the user's question suitable \
  for a semantic similarity search. Remove filler words and focus on the \
  vulnerability-relevant meaning.

## Examples

User: "Is Flask 2.0.1 vulnerable to anything critical?"
-> ecosystems: ["pypi"], package_names: ["flask"], cve_ids: null, \
severity_filter: "CRITICAL+", date_range: null, query_type: "package_check", \
raw_search_query: "critical vulnerabilities affecting flask 2.0.1"

User: "What's CVE-2025-29927?"
-> ecosystems: null, package_names: null, cve_ids: ["CVE-2025-29927"], \
severity_filter: null, date_range: null, query_type: "specific_cve", \
raw_search_query: "details about CVE-2025-29927"

User: "Any new critical vulnerabilities in the npm ecosystem this week?"
-> ecosystems: ["npm"], package_names: null, cve_ids: null, \
severity_filter: "CRITICAL", date_range: "last 7 days", query_type: "general_search", \
raw_search_query: "new critical npm vulnerabilities this week"

User: "Are there any known exploits for requests or urllib3 in Python?"
-> ecosystems: ["pypi"], package_names: ["requests", "urllib3"], cve_ids: null, \
severity_filter: null, date_range: null, query_type: "package_check", \
raw_search_query: "known exploits for python requests and urllib3"\
"""


async def parse_intent(question: str) -> QueryIntent:
    """Send the user's question to the intent model and return a validated QueryIntent."""
    client = AsyncOpenAI()
    model = os.getenv("INTENT_MODEL", "gpt-4.1-mini")

    try:
        response = await client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": INTENT_SYSTEM_PROMPT},
                {"role": "user", "content": question},
            ],
            response_format=QueryIntent,
            temperature=0.0,
        )
    except LengthFinishReasonError:
        raise ValueError(
            "Intent parsing failed: model output was truncated before completing "
            "the structured schema. Try a shorter or simpler question."
        )

    parsed = response.choices[0].message.parsed
    if parsed is None:
        raise ValueError("Intent parsing failed: model returned empty output.")
    return parsed
