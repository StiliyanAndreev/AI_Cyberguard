import gc
import logging
import os
import shutil
import stat
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

import git

from engine.config import CLONE_BASE_DIR, COMMIT_FETCH_COUNT

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = {"https", "http", "git", "ssh"}


def _remove_readonly(func, path: str, _) -> None:
    """Unlock read-only files on Windows before deletion."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception as exc:
        logger.warning("Could not remove %s: %s", path, exc)


def _normalize_github_url(url: str) -> str:
    """Strip GitHub web path suffixes like /tree/main/subdir — git clones repo roots only."""
    parsed = urlparse(url)
    if parsed.netloc in ("github.com", "www.github.com"):
        parts = parsed.path.strip("/").split("/")
        if len(parts) >= 2:
            return f"{parsed.scheme}://{parsed.netloc}/{parts[0]}/{parts[1]}"
    return url


def _validate_remote_url(url: str) -> None:
    """Raise ValueError for disallowed URL schemes."""
    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme '{parsed.scheme}' is not allowed. Use https/http/ssh.")
    if not parsed.netloc:
        raise ValueError("URL has no host — looks malformed.")


def _validate_local_path(path: str) -> str:
    """
    Resolve and return absolute path.
    Raises ValueError if the path tries to escape the project directory.
    """
    abs_path = os.path.realpath(os.path.abspath(path))
    # Allow any absolute path the user explicitly provides outside project dir
    # but block obvious traversal attempts like ../../etc/passwd
    raw = os.path.normpath(path)
    if ".." in Path(raw).parts:
        raise ValueError("Path contains '..' components — directory traversal is not allowed.")
    return abs_path


def _build_auth_url(url: str, token: str) -> str:
    """
    Embed token into URL for HTTPS cloning.
    Kept inside git_handler so the token never surfaces in session state or logs.
    """
    if url.startswith("https://"):
        return url.replace("https://", f"https://oauth2:{token}@", 1)
    if url.startswith("http://"):
        return url.replace("http://", f"http://oauth2:{token}@", 1)
    return url  # SSH — no embedding needed


def _cleanup_clones_dir() -> None:
    """Remove all previously cloned repos to free space before a new clone."""
    gc.collect()
    base = CLONE_BASE_DIR
    if not os.path.exists(base):
        return
    for item in os.listdir(base):
        old_path = os.path.join(base, item)
        try:
            time.sleep(0.1)  # let Windows release file handles
            shutil.rmtree(old_path, onerror=_remove_readonly)
        except Exception as exc:
            logger.warning("Could not delete clone dir %s: %s", old_path, exc)


def get_repo(path_or_url: str, is_cloud: bool = False, token: str = "") -> git.Repo:
    """
    Return a GitPython Repo object.

    For remote URLs the token is embedded internally and never stored outside
    this function.  For local paths, directory traversal is blocked.
    """
    os.makedirs(CLONE_BASE_DIR, exist_ok=True)

    if is_cloud:
        path_or_url = _normalize_github_url(path_or_url)
        _validate_remote_url(path_or_url)
        _cleanup_clones_dir()

        clone_url = _build_auth_url(path_or_url, token) if token else path_or_url
        # uuid4 suffix guarantees uniqueness even if called twice in the same second
        unique_dir = os.path.join(CLONE_BASE_DIR, f"repo_{uuid.uuid4().hex[:12]}")
        # Paranoia: remove target if it somehow already exists
        if os.path.exists(unique_dir):
            shutil.rmtree(unique_dir, onerror=_remove_readonly)
        return git.Repo.clone_from(clone_url, unique_dir)
    else:
        abs_path = _validate_local_path(path_or_url)
        if not os.path.isdir(abs_path):
            raise ValueError(f"Local path does not exist or is not a directory: {abs_path}")
        return git.Repo(abs_path)


def get_latest_commits(repo: git.Repo, count: int = COMMIT_FETCH_COUNT) -> list[git.Commit]:
    return list(repo.iter_commits(max_count=count))


def get_commit_diff(repo: git.Repo, commit: git.Commit) -> str:
    if not commit.parents:
        return repo.git.show(commit.hexsha)
    return repo.git.diff(commit.parents[0], commit)
