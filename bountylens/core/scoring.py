CATEGORY_SCORES = {
    "object reference": 90,
    "file handling": 85,
    "URL handling": 80,
    "redirect": 75,
    "search/query": 60,
    "authentication input": 50,
    "generic input": 20,
}


def score_parameter(category: str) -> int:
    return CATEGORY_SCORES.get(category, 10)


def priority_label(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    return "LOW"
