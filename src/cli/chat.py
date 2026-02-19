from typing import Optional

import typer
from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.key_binding import KeyBindings
from rich.markdown import Markdown
from rich.panel import Panel

from cli.common import async_command, console, err_console, get_pool
from db.writer import init_schema
from querying.engine import ask


def _build_key_bindings() -> KeyBindings:
    """Enter submits. Trailing \\ + Enter inserts a newline."""
    kb = KeyBindings()

    @kb.add("enter")
    def _submit(event):
        buf = event.current_buffer
        if buf.text.endswith("\\"):
            buf.text = buf.text[:-1]
            buf.insert_text("\n")
        else:
            buf.validate_and_handle()

    return kb

app = typer.Typer(help="Query engine commands.")


def _render_answer(answer: str) -> None:
    """Render the final answer as a Rich markdown panel."""
    console.print()
    console.print(Panel(Markdown(answer), title="ThreatWarden", border_style="green"))
    console.print()


@app.command("query")
@async_command
async def one_shot(
    question: str = typer.Argument(..., help="The question to ask."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug info (intent, SQL rows)."),
) -> None:
    """Ask a single question and get an answer."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await init_schema(conn)

    with console.status("[bold cyan]Thinking...", spinner="dots"):
        async with pool.acquire() as conn:
            result = await ask(question, conn)

    if verbose:
        console.print(f"[dim]Intent:[/]  {result.intent}")
        console.print(f"[dim]SQL rows:[/] {len(result.rows)}")
        console.print(f"[dim]Context:[/] {len(result.context)} chars")
        claims = result.verification.claims
        unsupported = sum(1 for c in claims if c.status == "unsupported")
        console.print(f"[dim]Verification:[/] {len(claims)} claims, {unsupported} unsupported")

    _render_answer(result.final_answer)
    await pool.close()


@app.command("chat")
@async_command
async def chat_repl(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show debug info per query."),
) -> None:
    """Start an interactive chat session."""
    pool = await get_pool()

    async with pool.acquire() as conn:
        await init_schema(conn)

    console.print(
        Panel(
            "[bold]Welcome to ThreatWarden[/]\n"
            "Ask questions about vulnerabilities, packages, or CVEs.\n"
            "Press [bold cyan]Enter[/] to submit. "
            "Type [bold cyan][\\] then [bold cyan]Enter[/] for a new line.\n"
            "Type [bold cyan]exit[/] or [bold cyan]quit[/] to leave.",
            border_style="blue",
        )
    )

    session = PromptSession(
        key_bindings=_build_key_bindings(),
        multiline=True,
        prompt_continuation="… ",
    )

    while True:
        try:
            question = (await session.prompt_async(
                HTML("<b><ansicyan>&gt; </ansicyan></b>"),
            )).strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/]")
            break

        if not question:
            continue
        if question.lower() in ("exit", "quit", ":q"):
            console.print("[dim]Goodbye.[/]")
            break

        try:
            with console.status("[bold cyan]Thinking...", spinner="dots"):
                async with pool.acquire() as conn:
                    result = await ask(question, conn)

            if verbose:
                console.print(f"[dim]Intent:[/]  {result.intent}")
                console.print(f"[dim]SQL rows:[/] {len(result.rows)}")

            _render_answer(result.final_answer)
        except Exception as exc:
            err_console.print(f"[red]Error: {exc}[/]")

    await pool.close()
