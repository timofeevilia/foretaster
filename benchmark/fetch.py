"""Download files from public repositories at a pinned commit, with a local cache."""

import hashlib
import urllib.request
from pathlib import Path


def fetch_pinned(repository: str, revision: str, path: str, cache_dir: Path) -> bytes:
    """Return ``path`` of ``repository`` as it was at ``revision``.

    The commit hash makes the URL immutable, so a cached copy never goes stale.
    """
    key = hashlib.sha256(f"{repository}@{revision}:{path}".encode()).hexdigest()[:24]
    cached = cache_dir / f"{repository.replace('/', '--')}-{revision[:12]}-{key}"
    if not cached.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        url = f"https://raw.githubusercontent.com/{repository}/{revision}/{path}"
        with urllib.request.urlopen(url, timeout=120) as response:
            cached.write_bytes(response.read())
    return cached.read_bytes()


def combined_digest(files: dict[str, bytes]) -> str:
    """One SHA-256 over a set of files, independent of the order they were fetched in."""
    digest = hashlib.sha256()
    for path in sorted(files):
        digest.update(path.encode())
        digest.update(hashlib.sha256(files[path]).digest())
    return digest.hexdigest()
