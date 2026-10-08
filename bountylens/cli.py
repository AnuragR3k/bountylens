import typer
from rich.console import Console
from rich.table import Table

from bountylens.core.recon import (
    run_subfinder,
    analyze_url,
    discover_endpoints,
)

from bountylens.core.triage import (
    extract_url_parameters,
    classify_form_inputs,
)

app = typer.Typer(
    name="bountylens",
    help="Bug bounty reconnaissance and triage assistant.",
    no_args_is_help=True,
)

console = Console()


@app.command()
def recon(target: str):
    """
    Discover subdomains for an authorized bug bounty target.
    """

    console.print()
    console.print("[bold cyan]BountyLens Recon[/bold cyan]")
    console.print("─" * 60)
    console.print(f"Target: [yellow]{target}[/yellow]")
    console.print()

    try:
        with console.status("[cyan]Running subfinder...[/cyan]"):
            subdomains = run_subfinder(target)

    except FileNotFoundError:
        console.print(
            "[red]✗ subfinder is not installed or not in PATH.[/red]"
        )
        raise typer.Exit(code=1)

    except Exception as exc:
        console.print(f"[red]✗ Recon failed: {exc}[/red]")
        raise typer.Exit(code=1)

    console.print(
        f"[green]✓[/green] Found "
        f"[bold]{len(subdomains)}[/bold] subdomains"
    )
    console.print()

    if not subdomains:
        console.print(
            "[yellow]No subdomains discovered.[/yellow]"
        )
        return

    table = Table(title="Discovered Assets")

    table.add_column("#", style="cyan", justify="right")
    table.add_column("Subdomain")

    for index, subdomain in enumerate(subdomains, start=1):
        table.add_row(
            str(index),
            subdomain,
        )

    console.print(table)


@app.command()
def analyze(url: str):
    """
    Analyze a single authorized URL and discover endpoints.
    """

    console.print()
    console.print("[bold cyan]BountyLens URL Analyzer[/bold cyan]")
    console.print("─" * 60)
    console.print(f"URL: [yellow]{url}[/yellow]")
    console.print()

    # ---------------------------------------------------------
    # HTTP ANALYSIS
    # ---------------------------------------------------------

    try:
        with console.status(
            "[cyan]Analyzing HTTP response...[/cyan]"
        ):
            result = analyze_url(url)

    except Exception as exc:
        console.print(
            f"[red]✗ HTTP analysis failed: {exc}[/red]"
        )
        raise typer.Exit(code=1)

    table = Table(title="HTTP Information")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row(
        "Status",
        str(result["status_code"]),
    )

    table.add_row(
        "Final URL",
        result["final_url"],
    )

    table.add_row(
        "Content-Type",
        str(result["content_type"]),
    )

    table.add_row(
        "Server",
        str(result["server"]),
    )

    table.add_row(
        "X-Powered-By",
        str(result["powered_by"]),
    )

    table.add_row(
        "Response Size",
        f"{result['content_length']} bytes",
    )

    console.print(table)

    # ---------------------------------------------------------
    # ENDPOINT DISCOVERY
    # ---------------------------------------------------------

    console.print()

    try:
        with console.status(
            "[cyan]Discovering endpoints...[/cyan]"
        ):
            endpoints = discover_endpoints(url)

    except Exception as exc:
        console.print(
            f"[red]✗ Endpoint discovery failed: {exc}[/red]"
        )
        raise typer.Exit(code=1)

    if not endpoints:
        console.print(
            "[yellow]No links or forms discovered.[/yellow]"
        )

        console.print()
        console.print(
            "[green]✓[/green] Analysis complete"
        )

        return

    endpoint_table = Table(
        title="Discovered Endpoints"
    )

    endpoint_table.add_column(
        "Type",
        style="cyan",
    )

    endpoint_table.add_column(
        "Method",
        style="green",
    )

    endpoint_table.add_column(
        "URL",
        overflow="fold",
    )

    endpoint_table.add_column(
        "Details",
        overflow="fold",
    )

    for endpoint in endpoints:

        endpoint_type = endpoint.get(
            "type",
            "unknown",
        )

        method = endpoint.get(
            "method",
            "GET",
        )

        endpoint_url = endpoint.get(
            "url",
            "",
        )

        details = ""

        # Link details
        if endpoint_type == "link":

            details = endpoint.get(
                "text",
                "",
            )

        # Form details
        elif endpoint_type == "form":

            inputs = endpoint.get(
                "inputs",
                [],
            )

            input_names = []

            for field in inputs:

                name = field.get(
                    "name"
                )

                if name:
                    input_names.append(name)

            details = ", ".join(
                input_names
            )

        endpoint_table.add_row(
            endpoint_type,
            method,
            endpoint_url,
            details,
        )

    console.print(endpoint_table)

        # ---------------------------------------------------------
    # PARAMETER INTELLIGENCE
    # ---------------------------------------------------------

    parameter_candidates = []

    for endpoint in endpoints:

        endpoint_url = endpoint.get("url", "")

        # Query parameters
        url_parameters = extract_url_parameters(
            endpoint_url
        )

        for parameter in url_parameters:

            parameter_candidates.append(
                {
                    "source": endpoint_url,
                    "name": parameter["name"],
                    "category": parameter["category"],
                    "type": "query",
                }
            )

        # Form parameters
        if endpoint.get("type") == "form":

            inputs = classify_form_inputs(
                endpoint.get("inputs", [])
            )

            for parameter in inputs:

                parameter_candidates.append(
                    {
                        "source": endpoint_url,
                        "name": parameter["name"],
                        "category": parameter["category"],
                        "type": "form",
                    }
                )

    # ---------------------------------------------------------
    # PARAMETER TABLE
    # ---------------------------------------------------------

    if parameter_candidates:

        console.print()

        parameter_table = Table(
            title="Parameter Intelligence"
        )

        parameter_table.add_column(
            "Parameter",
            style="cyan",
        )

        parameter_table.add_column(
            "Type",
            style="green",
        )

        parameter_table.add_column(
            "Category",
        )

        parameter_table.add_column(
            "Source",
            overflow="fold",
        )

        for parameter in parameter_candidates:

            parameter_table.add_row(
                parameter["name"],
                parameter["type"],
                parameter["category"],
                parameter["source"],
            )

        console.print(parameter_table)

        console.print()

        console.print(
            f"[green]✓[/green] Found "
            f"[bold]{len(parameter_candidates)}[/bold] "
            f"parameters"
        )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    console.print()

    links = sum(
        1
        for endpoint in endpoints
        if endpoint.get("type") == "link"
    )

    forms = sum(
        1
        for endpoint in endpoints
        if endpoint.get("type") == "form"
    )

    console.print(
        f"[green]✓[/green] Discovered "
        f"[bold]{len(endpoints)}[/bold] endpoints"
    )

    console.print(
        f"  Links: [cyan]{links}[/cyan]"
    )

    console.print(
        f"  Forms: [cyan]{forms}[/cyan]"
    )

    console.print()
    console.print(
        "[bold green]✓ Analysis complete[/bold green]"
    )


if __name__ == "__main__":
    app()