from urllib.parse import urlparse, parse_qs


INTERESTING_PARAMETERS = {
    "id": "object reference",
    "uid": "object reference",
    "user_id": "object reference",
    "userid": "object reference",
    "account": "object reference",
    "account_id": "object reference",
    "order_id": "object reference",
    "file": "file handling",
    "filename": "file handling",
    "path": "path handling",
    "redirect": "redirect",
    "redirect_uri": "redirect",
    "return": "redirect",
    "return_url": "redirect",
    "next": "redirect",
    "url": "URL handling",
    "uri": "URL handling",
    "query": "search/query",
    "q": "search/query",
    "search": "search/query",
}


def classify_parameter(name: str) -> str:
    """
    Classify a parameter based on its name.

    This does NOT prove a vulnerability.
    It identifies candidates for manual investigation.
    """

    normalized = name.lower().strip()

    return INTERESTING_PARAMETERS.get(
        normalized,
        "generic input",
    )


def extract_url_parameters(url: str) -> list[dict]:
    """
    Extract query parameters from a URL.
    """

    parsed = urlparse(url)

    parameters = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    results = []

    for name, values in parameters.items():

        results.append(
            {
                "name": name,
                "value": values[0] if values else "",
                "category": classify_parameter(name),
            }
        )

    return results


def classify_form_inputs(inputs: list[dict]) -> list[dict]:
    """
    Classify form input fields.
    """

    results = []

    for field in inputs:

        name = field.get("name")

        if not name:
            continue

        field_type = field.get(
            "type",
            "text",
        )

        results.append(
            {
                "name": name,
                "type": field_type,
                "category": classify_parameter(name),
            }
        )

    return results