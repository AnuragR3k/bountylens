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

from bountylens.core.scoring import (
    score_parameter,
    priority_label,
)

from bountylens.core.output import (
    save_json,
)


app = typer.Typer(
    name="bountylens",
    help="Bug bounty reconnaissance and triage assistant.",
    no_args_is_help=True,
)

console = Console()


@app.command()
def recon(
    target: str = typer.Argument(
        ...,
        help="Authorized bug bounty target domain.",
    )
):
    """Discover subdomains for an authorized bug bounty target."""

    console.print(
        f"\n[bold cyan]BountyLens Recon[/bold cyan]\n"
        f"Target: {target}\n"
    )

    assets = run_subfinder(target)

    if not assets:
        console.print(
            "[yellow]No subdomains discovered.[/yellow]"
        )
        return

    table = Table(title="Discovered Assets")

    table.add_column(
        "Subdomain",
        style="cyan",
    )

    for asset in assets:
        table.add_row(asset)

    console.print(table)

    console.print(
        f"\n[green]✓ Found {len(assets)} assets[/green]"
    )


@app.command()
def analyze(
    url: str = typer.Argument(
        ...,
        help="Authorized URL to analyze.",
    )
):
    """Analyze a single authorized URL and discover endpoints."""

    console.print(
        f"\n[bold cyan]BountyLens URL Analyzer[/bold cyan]\n"
        f"URL: {url}\n"
    )

    # ---------------------------------------------------------
    # HTTP ANALYSIS
    # ---------------------------------------------------------

    try:
        info = analyze_url(url)

    except Exception as exc:
        console.print(
            f"[red]✗ HTTP analysis failed:[/red] {exc}"
        )
        raise typer.Exit(code=1)

    http_table = Table(
        title="HTTP Information"
    )

    http_table.add_column(
        "Property",
        style="cyan",
    )

    http_table.add_column("Value")

    http_table.add_row(
        "Status",
        str(info.get("status_code", "Unknown")),
    )

    http_table.add_row(
        "Final URL",
        info.get("final_url", "Unknown"),
    )

    http_table.add_row(
        "Content-Type",
        info.get("content_type", "Unknown"),
    )

    http_table.add_row(
        "Server",
        str(info.get("server") or "None"),
    )

    http_table.add_row(
        "X-Powered-By",
        str(info.get("powered_by") or "None"),
    )

    http_table.add_row(
        "Response Size",
        f"{info.get('content_length', 0)} bytes",
    )

    console.print(http_table)

    # ---------------------------------------------------------
    # ENDPOINT DISCOVERY
    # ---------------------------------------------------------

    try:
        endpoints = discover_endpoints(url)

    except Exception as exc:
        console.print(
            f"[red]✗ Endpoint discovery failed:[/red] {exc}"
        )
        raise typer.Exit(code=1)

    endpoint_table = Table(
        title="Discovered Endpoints"
    )

    endpoint_table.add_column(
        "Type",
        style="cyan",
    )

    endpoint_table.add_column("Method")
    endpoint_table.add_column("URL")
    endpoint_table.add_column("Details")

    link_count = 0
    form_count = 0

    for endpoint in endpoints:

        endpoint_type = endpoint.get(
            "type",
            "",
        )

        method = endpoint.get(
            "method",
            "GET",
        )

        endpoint_url = endpoint.get(
            "url",
            "",
        )

        if endpoint_type == "link":

            link_count += 1

            details = endpoint.get(
                "text",
                "",
            ).strip()

            endpoint_table.add_row(
                "link",
                method,
                endpoint_url,
                details,
            )

        elif endpoint_type == "form":

            form_count += 1

            inputs = endpoint.get(
                "inputs",
                [],
            )

            names = [
                field.get("name")
                for field in inputs
                if field.get("name")
            ]

            details = ", ".join(names)

            endpoint_table.add_row(
                "form",
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

        if endpoint.get("type") == "link":

            parameters = extract_url_parameters(
                endpoint.get("url", "")
            )

            for parameter in parameters:

                parameter["source"] = "URL"

                parameter["url"] = endpoint.get(
                    "url",
                    "",
                )

                parameter["method"] = endpoint.get(
                    "method",
                    "GET",
                )

            parameter_candidates.extend(
                parameters
            )

        elif endpoint.get("type") == "form":

            parameters = classify_form_inputs(
                endpoint.get("inputs", [])
            )

            for parameter in parameters:

                parameter["source"] = "FORM"

                parameter["url"] = endpoint.get(
                    "url",
                    "",
                )

                parameter["method"] = endpoint.get(
                    "method",
                    "GET",
                )

            parameter_candidates.extend(
                parameters
            )

    # ---------------------------------------------------------
    # PARAMETER TABLE
    # ---------------------------------------------------------

    if parameter_candidates:

        parameter_table = Table(
            title="Parameter Intelligence"
        )

        parameter_table.add_column(
            "Parameter",
            style="cyan",
        )

        parameter_table.add_column(
            "Source"
        )

        parameter_table.add_column(
            "Type"
        )

        parameter_table.add_column(
            "Category"
        )

        parameter_table.add_column(
            "URL"
        )

        for parameter in parameter_candidates:

            parameter_table.add_row(
                parameter.get(
                    "name",
                    "",
                ),
                parameter.get(
                    "source",
                    "",
                ),
                parameter.get(
                    "type",
                    "query",
                ),
                parameter.get(
                    "category",
                    "generic input",
                ),
                parameter.get(
                    "url",
                    "",
                ),
            )

        console.print(parameter_table)

    else:

        console.print(
            "\n[yellow]No parameters discovered.[/yellow]"
        )

    # ---------------------------------------------------------
    # INVESTIGATION PRIORITY
    # ---------------------------------------------------------

    scored_parameters = []

    for parameter in parameter_candidates:

        category = parameter.get(
            "category",
            "generic input",
        )

        score = score_parameter(
            category
        )

        scored_parameters.append(
            {
                **parameter,
                "score": score,
                "priority": priority_label(
                    score
                ),
            }
        )

    scored_parameters.sort(
        key=lambda item: item.get(
            "score",
            0,
        ),
        reverse=True,
    )

    if scored_parameters:

        priority_table = Table(
            title="Investigation Priority"
        )

        priority_table.add_column(
            "Parameter",
            style="cyan",
        )

        priority_table.add_column(
            "Category"
        )

        priority_table.add_column(
            "Score",
            justify="right",
        )

        priority_table.add_column(
            "Priority"
        )

        priority_table.add_column(
            "Source"
        )

        for parameter in scored_parameters:

            priority = parameter.get(
                "priority",
                "LOW",
            )

            if priority == "HIGH":

                priority_display = (
                    "[bold red]HIGH[/bold red]"
                )

            elif priority == "MEDIUM":

                priority_display = (
                    "[yellow]MEDIUM[/yellow]"
                )

            else:

                priority_display = (
                    "[green]LOW[/green]"
                )

            priority_table.add_row(
                parameter.get(
                    "name",
                    "",
                ),
                parameter.get(
                    "category",
                    "generic input",
                ),
                str(
                    parameter.get(
                        "score",
                        0,
                    )
                ),
                priority_display,
                parameter.get(
                    "source",
                    "",
                ),
            )

        console.print(priority_table)

    # ---------------------------------------------------------
    # JSON REPORT
    # ---------------------------------------------------------

    analysis_data = {
        "target": url,

        "http": {
            "status_code": info.get(
                "status_code"
            ),

            "final_url": info.get(
                "final_url"
            ),

            "method": info.get(
                "method"
            ),

            "content_type": info.get(
                "content_type"
            ),

            "server": info.get(
                "server"
            ),

            "powered_by": info.get(
                "powered_by"
            ),

            "content_length": info.get(
                "content_length"
            ),
        },

        "endpoints": endpoints,

        "parameters": scored_parameters,

        "summary": {
            "endpoint_count": len(
                endpoints
            ),

            "link_count": link_count,

            "form_count": form_count,

            "parameter_count": len(
                scored_parameters
            ),
        },
    }

    try:

        save_json(
            analysis_data,
            "outputs/analysis.json",
        )

        console.print(
            "\n[green]✓ JSON report saved to "
            "outputs/analysis.json[/green]"
        )

    except Exception as exc:

        console.print(
            f"\n[red]✗ Failed to save JSON report:"
            f"[/red] {exc}"
        )

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------

    console.print(
        f"\n[green]✓ Found "
        f"{len(parameter_candidates)} "
        f"parameters[/green]"
    )

    console.print(
        f"[green]✓ Discovered "
        f"{len(endpoints)} "
        f"endpoints[/green]"
    )

    console.print(
        f"  Links: {link_count}"
    )

    console.print(
        f"  Forms: {form_count}"
    )

    console.print(
        "[green]✓ Analysis complete[/green]\n"
    )


if __name__ == "__main__":
    app()