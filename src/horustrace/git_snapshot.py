"""Safe materialization of Git revisions for change-aware scanning."""
from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_GIT_ARCHIVE_BYTES = 512 * 1024 * 1024
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")


class GitSnapshotError(ValueError):
    """A Git revision could not be resolved or safely materialized."""


@dataclass(frozen=True, slots=True)
class GitSnapshot:
    ref: str
    commit: str
    root: Path
    skipped_non_regular_entries: int = 0


def _run_git(
    repo: Path,
    args: list[str],
    *,
    timeout: int = 30,
) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise GitSnapshotError("git executable is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitSnapshotError("git command exceeded the safety timeout") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        message = detail[-1] if detail else "git command failed"
        raise GitSnapshotError(message)
    return completed.stdout.strip()


def git_root(path: Path) -> Path:
    candidate = path.resolve()
    if candidate.is_file():
        candidate = candidate.parent
    if not candidate.exists():
        raise GitSnapshotError(f"repository path does not exist: {path}")
    value = _run_git(candidate, ["rev-parse", "--show-toplevel"])
    root = Path(value).resolve()
    if not root.is_dir():
        raise GitSnapshotError("git repository root is not a directory")
    return root


def remote_origin(repo: Path) -> str | None:
    """Return the configured origin URL without executing target code."""
    try:
        value = _run_git(repo, ["config", "--get", "remote.origin.url"])
    except GitSnapshotError:
        return None
    return value or None


def resolve_commit(repo: Path, ref: str) -> str:
    value = ref.strip()
    if not value or any(character in value for character in "\x00\r\n"):
        raise GitSnapshotError("git revision must be a nonempty single-line value")
    commit = _run_git(
        repo,
        ["rev-parse", "--verify", "--end-of-options", f"{value}^{{commit}}"],
    )
    if not _GIT_SHA_RE.fullmatch(commit):
        raise GitSnapshotError(f"git revision did not resolve to a commit: {value}")
    return commit.lower()


def _safe_member_path(root: Path, name: str) -> Path:
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts:
        raise GitSnapshotError("git archive contains an unsafe path")
    parts = [part for part in relative.parts if part not in {"", "."}]
    if not parts:
        return root
    destination = root.joinpath(*parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise GitSnapshotError("git archive path escapes the snapshot root") from exc
    return destination


@contextmanager
def materialize_git_ref(repo: Path, ref: str) -> Iterator[GitSnapshot]:
    """Materialize regular files from a Git commit without checking out target code."""
    repository = git_root(repo)
    commit = resolve_commit(repository, ref)

    with tempfile.TemporaryDirectory(prefix="horustrace-diff-") as temp_name:
        temp = Path(temp_name)
        archive_path = temp / "snapshot.tar"
        snapshot_root = temp / "snapshot"
        snapshot_root.mkdir()

        try:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "archive",
                    "--format=tar",
                    "--output",
                    str(archive_path),
                    commit,
                ],
                check=True,
                capture_output=True,
                timeout=60,
            )
        except FileNotFoundError as exc:
            raise GitSnapshotError("git executable is not available") from exc
        except subprocess.TimeoutExpired as exc:
            raise GitSnapshotError("git archive exceeded the safety timeout") from exc
        except subprocess.CalledProcessError as exc:
            detail = exc.stderr.decode("utf-8", errors="replace").strip()
            raise GitSnapshotError(detail or "git archive failed") from exc

        if archive_path.stat().st_size > MAX_GIT_ARCHIVE_BYTES:
            raise GitSnapshotError(
                "git archive exceeds the 512 MiB change-analysis safety limit"
            )

        skipped = 0
        try:
            with tarfile.open(archive_path, mode="r:") as archive:
                for member in archive:
                    destination = _safe_member_path(snapshot_root, member.name)
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isfile():
                        skipped += 1
                        continue
                    source = archive.extractfile(member)
                    if source is None:
                        raise GitSnapshotError(
                            f"git archive entry could not be read: {member.name}"
                        )
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source, destination.open("wb") as output:
                        shutil.copyfileobj(source, output)
        except (tarfile.TarError, OSError) as exc:
            raise GitSnapshotError("git archive could not be safely materialized") from exc

        yield GitSnapshot(
            ref=ref,
            commit=commit,
            root=snapshot_root,
            skipped_non_regular_entries=skipped,
        )
