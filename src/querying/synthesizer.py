import os

from openai import AsyncOpenAI, LengthFinishReasonError

GROUNDED_SYSTEM_PROMPT = """\
You are a vulnerability intelligence analyst. Answer the user's question \
using ONLY the retrieved context below. Follow these rules strictly:

1. Always cite CVE IDs when referencing specific vulnerabilities.
2. When a patched version exists, recommend upgrading to it explicitly \
   (e.g. "upgrade flask to 2.3.1").
3. Flag exploit maturity clearly:
   - If a public proof-of-concept exists, say "a public PoC exists."
   - If CISA KEV lists it, say "actively exploited per CISA."
4. If the context contains no relevant vulnerabilities, say so clearly. \
   Do NOT fabricate CVE IDs, version numbers, or remediation advice.
5. Be concise but thorough. Prioritize actionable information.

## Retrieved Context

{context}\
"""

CONVERSATIONAL_SYSTEM_PROMPT = """\
You are a vulnerability intelligence analyst. The user is asking a general \
question that does not require looking up specific vulnerability data. \
Answer helpfully and accurately based on your general knowledge of \
cybersecurity and vulnerability management.

If the question is about a specific CVE, package, or vulnerability that \
you would need a database lookup to answer accurately, say: \
"I don't have specific data on that right now. Try asking about a \
specific CVE ID, package name, or severity level so I can look it up."\
"""


async def synthesize(question: str, context: str) -> str:
    """Generate a natural-language answer from the context and question.

    When context is empty (no SQL results / conversational query), the LLM
    answers from general knowledge using a different system prompt.
    """
    client = AsyncOpenAI()
    model = os.getenv("LLM_MODEL", "gpt-4.1-mini")

    if context:
        system = GROUNDED_SYSTEM_PROMPT.format(context=context)
    else:
        system = CONVERSATIONAL_SYSTEM_PROMPT

    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": question},
            ],
            temperature=0.1,
        )
    except LengthFinishReasonError:
        raise ValueError(
            "Synthesis failed: model output was truncated. "
            "The context may be too large for the model's output window."
        )

    content = response.choices[0].message.content
    if content is None:
        raise ValueError("Synthesis failed: model returned empty output.")
    return content
