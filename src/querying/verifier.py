"""
Inspired by ProveRAG (Fayyazi et al., 2024).
"""

import os

from openai import AsyncOpenAI, LengthFinishReasonError
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Structured output models
# ---------------------------------------------------------------------------

class VerifiedClaim(BaseModel):
    claim: str
    status: str  # "supported", "unsupported", "omitted"
    evidence: str | None
    rationale: str


class VerificationResult(BaseModel):
    claims: list[VerifiedClaim]
    omissions: list[str]


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

VERIFICATION_SYSTEM_PROMPT = """\
You are a factual verification engine for a vulnerability intelligence system. \
You will receive two inputs:

1. **Retrieved Context** — structured vulnerability data that was provided to \
   a synthesis model.
2. **Generated Response** — the answer that the synthesis model produced.

Your job is to verify every factual claim in the Generated Response against \
the Retrieved Context.

## Classification Rules

For each distinct factual claim in the response, classify it as:

- **supported**: The claim is directly backed by information in the context. \
  Set `evidence` to the relevant line(s) from the context.
- **unsupported**: The claim appears in the response but has NO backing in \
  the context. This includes hallucinated CVE IDs, wrong version numbers, \
  fabricated remediation advice, or any specific fact not present in the context. \
  Set `evidence` to null.
- **omitted**: Important information exists in the context but was NOT mentioned \
  in the response. Create a claim entry describing what was missed. \
  Set `evidence` to the relevant context line(s).

## Omissions

After classifying all claims from the response, scan the context for important \
information that was completely absent from the response. Add these as entries \
in the `omissions` list. Focus on:
- CVEs present in the context but not mentioned in the response.
- KEV status or active exploitation flags that were ignored.
- Available patches or remediation steps that were not recommended.
- Exploit availability that was not flagged.

## Important

- Be precise. Only mark a claim as "unsupported" if the context truly does \
  not contain the information. General knowledge statements (e.g. "CVSS scores \
  range from 0 to 10") are not claims that need context backing — skip them.
- Each claim should be a single, atomic factual statement.
- Do NOT verify opinions, hedging language, or meta-statements about the answer.\
"""

VERIFICATION_USER_TEMPLATE = """\
## Retrieved Context

{context}

## Generated Response

{response}\
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def verify(context: str, response: str) -> VerificationResult:
    """Run the verification pass on a synthesis response.

    Skips verification when there is no context (conversational queries
    have nothing to verify against), returning an empty result.
    """
    if not context:
        return VerificationResult(claims=[], omissions=[])

    client = AsyncOpenAI()
    model = os.getenv("INTENT_MODEL", "gpt-4.1-mini")

    try:
        result = await client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": VERIFICATION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": VERIFICATION_USER_TEMPLATE.format(
                        context=context, response=response,
                    ),
                },
            ],
            response_format=VerificationResult,
            temperature=0.0,
        )
    except LengthFinishReasonError:
        raise ValueError(
            "Verification failed: model output was truncated before completing "
            "the structured schema."
        )

    parsed = result.choices[0].message.parsed
    if parsed is None:
        raise ValueError("Verification failed: model returned empty output.")
    return parsed


def build_verified_response(
    original_response: str,
    result: VerificationResult,
) -> str:
    """Annotate the synthesis response based on verification results.

    - Unsupported claims get a warning appended.
    - Omissions are listed at the end.
    - If everything is supported and nothing is omitted, returns the
      original response unchanged.
    """
    unsupported = [c for c in result.claims if c.status == "unsupported"]
    omissions = result.omissions

    if not unsupported and not omissions:
        return original_response

    sections: list[str] = [original_response]

    if unsupported:
        warnings = "\n".join(
            f"- {c.claim} (Reason: {c.rationale})"
            for c in unsupported
        )
        sections.append(
            f"\n---\n**Note:** The following claims could not be verified "
            f"against the retrieved data and may be inaccurate:\n{warnings}"
        )

    if omissions:
        missed = "\n".join(f"- {o}" for o in omissions)
        sections.append(
            f"\n---\n**Additional information** from the retrieved data "
            f"that may be relevant:\n{missed}"
        )

    return "\n".join(sections)
