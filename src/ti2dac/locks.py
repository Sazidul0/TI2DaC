"""Locks that also hold across processes: web jobs run in worker processes beside the server and the CLI."""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:   # Windows: in-process locking only
    fcntl = None   # type: ignore[assignment]

_local: dict[str, threading.Lock] = {}
_guard = threading.Lock()


@contextmanager
def file_lock(path: str | Path) -> Iterator[None]:
    """Exclusive lock on `path` (created if missing). The OS drops it when a killed process dies."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _guard:
        local = _local.setdefault(str(path.resolve()), threading.Lock())
    with local:
        if fcntl is None:
            yield
            return
        with open(path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
