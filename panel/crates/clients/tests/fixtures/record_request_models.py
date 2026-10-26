"""Record what the client API's request models (`panel/schemas.py`) report for a set of bodies.

Run from a checkout with the panel venv (pure pydantic, no Python-version-dependent case):
    python panel/crates/clients/tests/fixtures/record_request_models.py > request_models.json
Each case: the model, the body, and FastAPI's 422 issue list for it (`loc` without the leading
"body", `ctx.error` rendered as `{}` like FastAPI's encoder), or null when the body is valid.
"""
import json

from pydantic import ValidationError

from panel import schemas

CASES = [
    ("ClientImport", {"decisions": []}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": []}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": [["naive"]]}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": [["naive", "x", "y"]]}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": ["naive"]}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": [["nope", 5]]}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "items": [["naive", "bad user"]]}]}),
    ("ClientImport", {"decisions": [{"display_name": "", "client_id": "x" * 65, "items": [["naive", "ok"]]}]}),
    ("ClientImport", {"decisions": [{"display_name": "a", "client_id": None, "items": [["mieru", "ok"]]}], "extra": 1}),
    ("GrantsCreate", {"grants": []}),
    ("GrantsCreate", {"grants": [{"protocol": "naive", "runtime_username": "a", "node_id": "Bad"}]}),
    ("GrantsCreate", {"grants": [{"protocol": "naive", "runtime_username": "a", "options": [], "valid_from": "1.5"}]}),
    ("GrantsCreate", {"grants": [{"protocol": "naive", "runtime_username": "a", "valid_until": "12"}]}),
    ("GrantAdoptBatch", {"allow_rotation": "yes"}),
    ("GrantAdoptBatch", {"allow_rotation": 2, "protocol": "naive"}),
    ("GrantLabel", {"label": "x" * 65}),
    ("GrantLabel", {}),
    ("ClientState", {"state": "gone"}),
    ("ClientCreate", {"display_name": "x" * 129, "subscription": "maybe"}),
    ("ClientRename", {"display_name": ""}),
]


def issues(error: ValidationError) -> list:
    out = []
    for item in error.errors(include_url=False):
        entry = {"type": item["type"], "loc": list(item["loc"]), "msg": item["msg"], "input": item["input"]}
        if "ctx" in item:
            entry["ctx"] = {key: ({} if key == "error" else value) for key, value in item["ctx"].items()}
        out.append(entry)
    return out


def main() -> None:
    records = []
    for model, body in CASES:
        try:
            getattr(schemas, model).model_validate(body)
            result = None
        except ValidationError as error:
            result = issues(error)
        records.append({"model": model, "body": body, "issues": result})
    print(json.dumps(records, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
