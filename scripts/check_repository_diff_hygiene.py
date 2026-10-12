"""Fail-closed GitHub Actions diff hygiene gate.

The only empty-range exception is a newly created feature ref whose HEAD
is already in origin/main and whose tree matches the current main tree.
"""

import os
import re
import subprocess
import sys

ZERO_SHA = "0" * 40


class GateFailure(Exception):
    """The event cannot be safely audited."""


def git(*args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode != 0:
        raise GateFailure(f"Git command failed: git {' '.join(args)}")
    return process.stdout.strip()


def require_commit(label: str, sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise GateFailure(f"Invalid {label} SHA.")
    git("cat-file", "-e", f"{sha}^{{commit}}")


def check_diff(base: str, head: str) -> None:
    require_commit("base", base)
    if base == head:
        raise GateFailure("Empty commit comparison range outside verified exception.")
    print("Checking committed diff against selected base.")
    process = subprocess.run(
        ["git", "diff", "--check", base, head],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if process.returncode:
        if process.stdout:
            print(process.stdout, end="")
        raise GateFailure("Repository diff hygiene failed.")


def check_gate() -> None:
    head = git("rev-parse", "HEAD")
    require_commit("HEAD", head)
    if os.environ.get("GITHUB_SHA") != head:
        raise GateFailure("Checkout HEAD does not match GITHUB_SHA.")

    event = os.environ.get("GITHUB_EVENT_NAME")
    if event == "pull_request":
        base = os.environ.get("PR_BASE_SHA", "")
        check_diff(base, head)
        return

    if event != "push":
        raise GateFailure("Unsupported GitHub event.")

    ref = os.environ.get("GITHUB_REF", "")
    if ref != "refs/heads/main" and not ref.startswith("refs/heads/feature/"):
        raise GateFailure("Unexpected push ref.")
    if ref == "refs/heads/feature/":
        raise GateFailure("Empty feature branch name.")

    before = os.environ.get("PUSH_BEFORE_SHA", "")
    created = os.environ.get("PUSH_CREATED", "")
    after = os.environ.get("PUSH_AFTER_SHA", "")
    require_commit("push after", after)
    if after != head:
        raise GateFailure("Checkout HEAD does not match event after SHA.")
    if created not in {"true", "false"}:
        raise GateFailure("Unrecognized push creation flag.")

    if before == ZERO_SHA:
        if created != "true" or not ref.startswith("refs/heads/feature/"):
            raise GateFailure("Unexpected zero-before push event.")

        main_head = git("rev-parse", "refs/remotes/origin/main")
        require_commit("origin/main", main_head)
        base = git("merge-base", "refs/remotes/origin/main", head)
        require_commit("merge-base", base)

        if base == head:
            head_tree = git("rev-parse", f"{head}^{{tree}}")
            main_tree = git("rev-parse", f"{main_head}^{{tree}}")
            if head_tree != main_tree:
                raise GateFailure("Already-merged feature differs from main tree.")
            print("Verified already-merged feature with identical main tree.")
            return

        check_diff(base, head)
        return

    if created != "false":
        raise GateFailure("Push creation flag conflicts with nonzero before SHA.")
    require_commit("push before", before)
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", before, head],
        check=False,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        raise GateFailure("Push is not a verified fast-forward.")
    check_diff(before, head)


def main() -> int:
    try:
        check_gate()
    except (GateFailure, OSError) as error:
        print(f"Repository diff hygiene: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
