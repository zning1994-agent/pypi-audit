"""pypi-audit CLI."""

import click


@click.group()
@click.version_option()
def cli() -> None:
    """Python dependency security auditor."""
    pass


@cli.command()
@click.argument("file", type=click.Path(exists=True))
def audit(file: str) -> None:
    """Audit a dependency file for security vulnerabilities."""
    from pypi_audit.parsers import RequirementsParser

    parser = RequirementsParser()
    result = parser.parse(file)

    click.echo(f"Parsed {len(result.dependencies)} dependencies from {file}")

    for dep in result.dependencies:
        click.echo(f"  - {dep}")


if __name__ == "__main__":
    cli()
