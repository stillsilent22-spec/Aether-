import json
from pathlib import Path
import shutil
import uuid

from modules.observer_engine import ObserverEngine
from modules.security_engine import encrypt_device_scoped_payload
from modules.session_engine import SessionContext


def _context() -> SessionContext:
    context = SessionContext(seed=123456)
    context.username = "tryharder997"
    context.session_id = "5f90b9e4-cc1f-44b1-b6d8-0123456789ab"
    return context


def _local_temp_dir() -> Path:
    path = Path("data/test_observer_learning") / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_observer_learning_filename_is_anonymized() -> None:
    temp_dir = _local_temp_dir()
    try:
        observer = ObserverEngine()
        observer.learning_store_dir = temp_dir
        context = _context()

        path = observer._learning_state_path(context)

        assert path.name.startswith("observer_learning_")
        assert "tryharder997" not in path.name
        assert context.session_id[:16] not in path.name
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_legacy_observer_learning_file_is_migrated() -> None:
    temp_dir = _local_temp_dir()
    try:
        observer = ObserverEngine()
        observer.learning_store_dir = temp_dir
        context = _context()
        legacy_path = observer._legacy_learning_state_path(context)
        state = {
            "version": 1,
            "learned_insights": ["local only"],
            "symmetry_history": [0.9],
        }
        envelope = encrypt_device_scoped_payload(
            payload=state,
            session_like=context,
            purpose="observer_learning",
            session_salt=context.session_id,
        )
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        legacy_path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")

        loaded = observer.load_learning_state(context)
        new_path = observer._learning_state_path(context)

        assert loaded["learned_insights"] == ["local only"]
        assert new_path.is_file()
        assert not legacy_path.exists()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
