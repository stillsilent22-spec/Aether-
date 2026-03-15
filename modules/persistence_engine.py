import os
import json

def save_state_to_file(state: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, sort_keys=True, ensure_ascii=False)

def load_state_from_file(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_history_to_file(history: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False)

def load_history_from_file(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
