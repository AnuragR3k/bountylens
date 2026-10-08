import subprocess
from typing import List
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import httpx


def run_subfinder(target: str) -> List[str]:
    """Discover subdomains using subfinder."""

    result = subprocess.run(
        ["subfinder", "-d", target, "-silent"],
        capture_output=True,
        text=True,
        timeout=300,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "subfinder failed"
        )

    return sorted(
        set(
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        )
    )


def analyze_url(url: str) -> dict:
    """Collect basic HTTP metadata from an authorized URL."""

    try:
        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=10,
        )
    except httpx.RequestError as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    headers = {
        key.lower(): value
        for key, value in response.headers.items()
    }

    return {
        "url": url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "method": "GET",
        "content_type": headers.get("content-type"),
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
        "content_length": len(response.content),
        "headers": dict(response.headers),
    }

def discover_endpoints(url: str) -> list[dict]:
    """Extract links and forms from an authorized web application."""

    try:
        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=10,
        )
    except httpx.RequestError as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    soup = BeautifulSoup(response.text, "html.parser")

    base_url = str(response.url)
    endpoints = []

    # Discover links
    for link in soup.find_all("a", href=True):
        href = link.get("href")

        if not href:
            continue

        absolute_url = urljoin(base_url, href)

        parsed = urlparse(absolute_url)

        if parsed.scheme not in {"http", "https"}:
            continue

        endpoints.append({
            "type": "link",
            "method": "GET",
            "url": absolute_url,
            "text": link.get_text(" ", strip=True),
        })

    # Discover forms
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "GET").upper()

        absolute_action = urljoin(base_url, action)

        inputs = []

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")

            if name:
                inputs.append({
                    "name": name,
                    "type": field.get("type", field.name),
                })

        endpoints.append({
            "type": "form",
            "method": method,
            "url": absolute_action,
            "inputs": inputs,
        })

    # Remove duplicates
    unique = {}

    for endpoint in endpoints:
        key = (
            endpoint["type"],
            endpoint["method"],
            endpoint["url"],
        )
        unique[key] = endpoint

    return list(unique.values())