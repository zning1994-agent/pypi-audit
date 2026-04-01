"""CLI module for pypi-audit."""

import click


@click.command()
@click.argument("files", nargs=-1, type=click.Path(exists=True))
def main(files: tuple[str, ...]) -> None:
    """Main CLI entry point."""
    click.echo("pypi-audit - Python dependency security audit tool")
    if not files:
        click.echo("Usage: pypi-audit <dependency_file>...")
