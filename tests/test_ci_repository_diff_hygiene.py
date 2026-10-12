"""Adversarial integration tests for the GitHub Actions diff hygiene gate."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_repository_diff_hygiene.py"
ZERO_SHA = "0" * 40


class GitFixture:
    def __init__(self, path: Path):
        self.path = path
        self.git("init", "-b", "main")
        self.git("config", "user.name", "CI Fixture")
        self.git("config", "user.email", "ci@example.invalid")
        self.commit("original\n")
        self.sync_main()

    def git(self, *args: str) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.path,
            capture_output=True,
            text=True,
            check=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def commit(self, content: str) -> str:
        (self.path / "example.txt").write_text(content, encoding="utf-8", newline="\n")
        self.git("add", "example.txt")
        self.git("commit", "-m", "Fixture commit")
        return self.git("rev-parse", "HEAD")

    def sync_main(self) -> None:
        self.git("update-ref", "refs/remotes/origin/main", self.git("rev-parse", "main"))

    def feature(self) -> None:
        self.git("switch", "-c", "feature/test")

    def merged_feature(self) -> str:
        self.feature()
        feature_sha = self.commit("feature text\n")
        self.git("switch", "main")
        self.git("merge", "--no-ff", "-m", "Merge feature", "feature/test")
        self.sync_main()
        self.git("switch", "feature/test")
        return feature_sha

    def gate(self, **overrides: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        head = self.git("rev-parse", "HEAD")
        env.update(
            GITHUB_EVENT_NAME="push",
            GITHUB_REF="refs/heads/feature/test",
            GITHUB_SHA=head,
            PUSH_AFTER_SHA=head,
            PUSH_CREATED="true",
            PUSH_BEFORE_SHA=ZERO_SHA,
            PR_BASE_SHA="",
        )
        env.update(overrides)
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=self.path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
        )


@pytest.fixture
def repo(tmp_path: Path) -> GitFixture:
    return GitFixture(tmp_path)


def test_new_feature_already_merged_same_tree_passes(repo: GitFixture) -> None:
    repo.merged_feature()
    assert repo.git("merge-base", "refs/remotes/origin/main", "HEAD") == repo.git(
        "rev-parse", "HEAD"
    )
    result = repo.gate()
    assert result.returncode == 0, result.stderr
    assert "Verified already-merged feature" in result.stdout


def test_already_merged_but_main_tree_changed_fails(repo: GitFixture) -> None:
    repo.merged_feature()
    repo.git("switch", "main")
    repo.commit("later main content\n")
    repo.sync_main()
    repo.git("switch", "feature/test")
    assert repo.gate().returncode != 0


def test_created_false_with_zero_before_fails(repo: GitFixture) -> None:
    repo.merged_feature()
    assert repo.gate(PUSH_CREATED="false").returncode != 0


def test_created_true_with_nonzero_before_fails(repo: GitFixture) -> None:
    repo.feature()
    old = repo.git("rev-parse", "HEAD")
    repo.commit("valid change\n")
    assert repo.gate(PUSH_CREATED="true", PUSH_BEFORE_SHA=old).returncode != 0


def test_main_ref_zero_before_rejected(repo: GitFixture) -> None:
    result = repo.gate(GITHUB_REF="refs/heads/main")
    assert result.returncode != 0


def test_push_after_sha_mismatch_fails(repo: GitFixture) -> None:
    repo.merged_feature()
    assert repo.gate(PUSH_AFTER_SHA="a" * 40).returncode != 0


def test_checkout_sha_mismatch_fails(repo: GitFixture) -> None:
    repo.merged_feature()
    assert repo.gate(GITHUB_SHA="a" * 40).returncode != 0


def test_new_feature_with_diff_passes(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("new feature\n")
    assert repo.gate().returncode == 0


def test_new_feature_with_bad_whitespace_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("new feature with trailing whitespace   \n")
    assert repo.gate().returncode != 0


def test_new_feature_at_main_identical_tree_passes(repo: GitFixture) -> None:
    repo.feature()
    assert repo.gate().returncode == 0  # Identical, already-merged tree is verified.


def test_normal_fast_forward_push_passes(repo: GitFixture) -> None:
    repo.feature()
    before = repo.git("rev-parse", "HEAD")
    repo.commit("after valid push\n")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA=before).returncode == 0


def test_normal_fast_forward_bad_whitespace_fails(repo: GitFixture) -> None:
    repo.feature()
    before = repo.git("rev-parse", "HEAD")
    repo.commit("invalid whitespace  \n")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA=before).returncode != 0


def test_non_fast_forward_push_fails(repo: GitFixture) -> None:
    repo.feature()
    old = repo.commit("old branch text\n")
    repo.git("reset", "--hard", "main")
    repo.commit("rewritten branch text\n")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA=old).returncode != 0


def test_normal_push_empty_range_fails(repo: GitFixture) -> None:
    repo.feature()
    before = repo.git("rev-parse", "HEAD")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA=before).returncode != 0


def test_pull_request_valid_diff_passes(repo: GitFixture) -> None:
    base = repo.git("rev-parse", "HEAD")
    repo.feature()
    repo.commit("PR valid change\n")
    assert repo.gate(GITHUB_EVENT_NAME="pull_request", PR_BASE_SHA=base).returncode == 0


def test_pull_request_whitespace_fails(repo: GitFixture) -> None:
    base = repo.git("rev-parse", "HEAD")
    repo.feature()
    repo.commit("PR bad change  \n")
    assert repo.gate(GITHUB_EVENT_NAME="pull_request", PR_BASE_SHA=base).returncode != 0


def test_missing_pr_base_fails(repo: GitFixture) -> None:
    assert repo.gate(GITHUB_EVENT_NAME="pull_request").returncode != 0


def test_unsupported_event_fails(repo: GitFixture) -> None:
    assert repo.gate(GITHUB_EVENT_NAME="workflow_dispatch").returncode != 0


def test_missing_origin_main_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.git("update-ref", "-d", "refs/remotes/origin/main")
    assert repo.gate().returncode != 0


def test_missing_before_commit_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("valid change\n")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA="b" * 40).returncode != 0


def test_invalid_before_sha_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("valid change\n")
    assert repo.gate(PUSH_CREATED="false", PUSH_BEFORE_SHA="not-a-sha").returncode != 0


def test_unsupported_branch_ref_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("valid change\n")
    assert repo.gate(GITHUB_REF="refs/heads/hotfix/demo").returncode != 0


def test_missing_push_creation_flag_fails(repo: GitFixture) -> None:
    repo.feature()
    repo.commit("valid change\n")
    assert repo.gate(PUSH_CREATED="").returncode != 0
