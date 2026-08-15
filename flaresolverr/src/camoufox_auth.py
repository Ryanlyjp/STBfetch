from collections.abc import Mapping


def code_collection_allowed(login_result: Mapping[str, object], collect_codes: object) -> bool:
    return bool(collect_codes and login_result.get("success") is True)
