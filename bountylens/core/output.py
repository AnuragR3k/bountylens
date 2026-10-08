import json
from pathlib import Path


def save_json(data: dict, output_file: str) -> None:
    path = Path(output_file)

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )
