from dataclasses import dataclass

import asyncpg

from .context_assembler import assemble_context
from .intent_parser import QueryIntent, parse_intent
from .retriever import VulnRow, execute_query
from .synthesizer import synthesize
from .verifier import VerificationResult, build_verified_response, verify


@dataclass
class QueryResult:
    """Complete result of a query pipeline run."""
    question: str
    intent: QueryIntent
    rows: list[VulnRow]
    context: str
    raw_answer: str
    verification: VerificationResult
    final_answer: str


async def ask(
    question: str,
    conn: asyncpg.Connection,
) -> QueryResult:
    """Run the full query pipeline for a user question.

    Steps:
        1. Parse intent — extract structured filters via LLM.
        2. Retrieve — run parameterized SQL (or skip if no filters).
        3. Assemble context — format results into text blocks.
        4. Synthesize — LLM generates a grounded answer (or conversational
           answer when context is empty).
        5. Verify — lightweight LLM checks claims against context.
        6. Build final answer — annotate with warnings / omissions.
    """
    intent = await parse_intent(question)
    rows = await execute_query(conn, intent)
    context = assemble_context(rows)
    raw_answer = await synthesize(question, context)
    verification = await verify(context, raw_answer)
    final_answer = build_verified_response(raw_answer, verification)

    return QueryResult(
        question=question,
        intent=intent,
        rows=rows,
        context=context,
        raw_answer=raw_answer,
        verification=verification,
        final_answer=final_answer,
    )
