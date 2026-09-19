from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import typer

from .canary import CanaryGuard, load_master_key
from .crypto import protect_file, restore_file
from .signatures import inspect_file

app = typer.Typer(no_args_is_help=True)


def _guard(state_dir: Path) -> CanaryGuard:
    return CanaryGuard(state_dir, load_master_key())


@app.command("init-canaries")
def init_canaries(state_dir: Path) -> None:
    _guard(state_dir).initialize()
    typer.echo("initialized local and master canaries")


@app.command("verify-canaries")
def verify_canaries(state_dir: Path) -> None:
    status = _guard(state_dir).verify()
    typer.echo(json.dumps(dataclasses.asdict(status), indent=2))
    if not status.healthy:
        raise typer.Exit(code=2)


@app.command()
def inspect(path: Path) -> None:
    typer.echo(json.dumps(dataclasses.asdict(inspect_file(path)), indent=2))


@app.command()
def protect(state_dir: Path, source: Path, target: Path) -> None:
    protect_file(source, target, _guard(state_dir))
    typer.echo(f"protected: {target}")


@app.command()
def restore(state_dir: Path, source: Path, target: Path) -> None:
    restore_file(source, target, _guard(state_dir))
    typer.echo(f"restored: {target}")


if __name__ == "__main__":
    app()
