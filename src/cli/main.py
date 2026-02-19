import typer

from cli.chat import app as chat_app
from cli.db import app as db_app
from cli.ingest import app as ingest_app

app = typer.Typer(
    name="threatwarden",
    help="ThreatWarden — vulnerability intelligence from the command line.",
    no_args_is_help=True,
)

app.add_typer(ingest_app, name="ingest")
app.add_typer(db_app, name="db")
app.add_typer(chat_app, name="")


if __name__ == "__main__":
    app()
