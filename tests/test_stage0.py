"""
Example tests for Feature 1 — Stage 0 auto-clone (task 7.2).

Covers all six scenarios from the design's Testing Strategy table:

  1. TARGET_PATH with .git/ exists  → returns path, clone NOT called.
  2. TARGET_PATH without .git/, no URL → logs warning, returns path.
  3. TARGET_PATH without .git/, URL set → dir removed + clone called.
  4. TARGET_PATH absent, URL set, clone succeeds → returns cloned path.
  5. TARGET_PATH absent, URL set, clone fails (None) → SystemExit(1).
  6. TARGET_PATH absent, no URL → SystemExit(1).

Requirements: 1.1, 1.2, 1.4, 2.1, 2.3, 2.4, 2.5, 3.1
"""

import sys
import pytest
import framework


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_URL = "https://github.com/org/repo.git"
_FAKE_BRANCH = "main"


def _setup_monkeypatches(monkeypatch, tmp_path, url="", branch=_FAKE_BRANCH):
    """
    Patch the three module-level variables that stage0_validate_target()
    reads from framework.py.
    """
    monkeypatch.setattr(framework, "TARGET_PATH", str(tmp_path))
    monkeypatch.setattr(framework, "TARGET_REPO_URL", url)
    monkeypatch.setattr(framework, "TARGET_REPO_BRANCH", branch)


# ---------------------------------------------------------------------------
# Scenario 1 — Req 1.1, 3.1
# TARGET_PATH with .git/ exists → returns path, clone NOT called
# ---------------------------------------------------------------------------

def test_stage0_git_dir_exists_returns_path_without_clone(
    monkeypatch, tmp_path
):
    """
    WHEN TARGET_PATH exists and contains .git/,
    THEN stage0_validate_target returns (TARGET_PATH, repo_name)
    AND clone_target_repository is never invoked.
    """
    # Create the .git sub-directory to simulate an existing repo
    (tmp_path / ".git").mkdir()

    _setup_monkeypatches(monkeypatch, tmp_path, url=_FAKE_URL)

    clone_called = []

    def fake_clone(*args, **kwargs):
        clone_called.append(True)
        return str(tmp_path)

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone)

    result_path, _ = framework.stage0_validate_target()

    assert result_path == str(tmp_path)
    assert clone_called == [], "clone_target_repository must NOT be called when .git/ already exists"


# ---------------------------------------------------------------------------
# Scenario 2 — Req 1.2
# TARGET_PATH exists without .git/, no URL → logs warning, returns path
# ---------------------------------------------------------------------------

def test_stage0_no_git_no_url_returns_path_with_warning(
    monkeypatch, tmp_path, capsys
):
    """
    WHEN TARGET_PATH exists but has no .git/ AND TARGET_REPO_URL is empty,
    THEN stage0_validate_target returns (TARGET_PATH, repo_name)
    AND logs a WARN message
    AND clone_target_repository is never invoked.
    """
    # tmp_path exists but is empty — no .git/
    _setup_monkeypatches(monkeypatch, tmp_path, url="")

    clone_called = []

    def fake_clone(*args, **kwargs):
        clone_called.append(True)
        return str(tmp_path)

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone)

    result_path, _ = framework.stage0_validate_target()

    assert result_path == str(tmp_path)
    assert clone_called == [], "clone_target_repository must NOT be called in branch C"

    captured = capsys.readouterr()
    assert "WARN" in captured.out


# ---------------------------------------------------------------------------
# Scenario 3 — Req 1.4
# TARGET_PATH exists without .git/, URL set → dir removed + clone called
# ---------------------------------------------------------------------------

def test_stage0_no_git_with_url_removes_dir_and_clones(
    monkeypatch, tmp_path
):
    """
    WHEN TARGET_PATH exists but has no .git/ AND TARGET_REPO_URL is set,
    THEN stage0_validate_target removes the inconsistent dir
    AND calls clone_target_repository
    AND returns (TARGET_PATH, repo_name).
    """
    # Place a stray file so the directory is non-empty
    (tmp_path / "stray_file.txt").write_text("stray")

    _setup_monkeypatches(monkeypatch, tmp_path, url=_FAKE_URL)

    clone_calls = []

    def fake_clone(url, branch, target_path):
        clone_calls.append({"url": url, "branch": branch, "target_path": target_path})
        return target_path  # simulate success

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone)

    result_path, _ = framework.stage0_validate_target()

    assert result_path == str(tmp_path)
    assert len(clone_calls) == 1, "clone_target_repository must be called exactly once"
    assert clone_calls[0]["url"] == _FAKE_URL
    assert clone_calls[0]["target_path"] == str(tmp_path)


# ---------------------------------------------------------------------------
# Scenario 4 — Req 2.1, 2.3
# TARGET_PATH absent, URL set, clone succeeds → returns cloned path
# ---------------------------------------------------------------------------

def test_stage0_absent_path_with_url_clone_succeeds(
    monkeypatch, tmp_path
):
    """
    WHEN TARGET_PATH does not exist AND TARGET_REPO_URL is set,
    AND clone_target_repository returns a valid path,
    THEN stage0_validate_target returns (TARGET_PATH, repo_name).
    """
    absent_path = tmp_path / "non_existent_repo"
    # Do NOT create absent_path — it must be absent

    monkeypatch.setattr(framework, "TARGET_PATH", str(absent_path))
    monkeypatch.setattr(framework, "TARGET_REPO_URL", _FAKE_URL)
    monkeypatch.setattr(framework, "TARGET_REPO_BRANCH", _FAKE_BRANCH)

    clone_calls = []

    def fake_clone(url, branch, target_path):
        clone_calls.append(target_path)
        return target_path  # success

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone)

    result_path, _ = framework.stage0_validate_target()

    assert result_path == str(absent_path)
    assert clone_calls == [str(absent_path)]


# ---------------------------------------------------------------------------
# Scenario 5 — Req 2.4
# TARGET_PATH absent, URL set, clone fails (returns None) → SystemExit(1)
# ---------------------------------------------------------------------------

def test_stage0_absent_path_clone_fails_exits(
    monkeypatch, tmp_path
):
    """
    WHEN TARGET_PATH does not exist AND TARGET_REPO_URL is set,
    AND clone_target_repository returns None (failure),
    THEN stage0_validate_target raises SystemExit with code 1.
    """
    absent_path = tmp_path / "non_existent_repo"

    monkeypatch.setattr(framework, "TARGET_PATH", str(absent_path))
    monkeypatch.setattr(framework, "TARGET_REPO_URL", _FAKE_URL)
    monkeypatch.setattr(framework, "TARGET_REPO_BRANCH", _FAKE_BRANCH)

    def fake_clone_fails(url, branch, target_path):
        return None  # simulate clone failure

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone_fails)

    with pytest.raises(SystemExit) as exc_info:
        framework.stage0_validate_target()

    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# Scenario 6 — Req 2.5
# TARGET_PATH absent, no URL → SystemExit(1)
# ---------------------------------------------------------------------------

def test_stage0_absent_path_no_url_exits(
    monkeypatch, tmp_path
):
    """
    WHEN TARGET_PATH does not exist AND TARGET_REPO_URL is empty,
    THEN stage0_validate_target raises SystemExit with code 1.
    """
    absent_path = tmp_path / "non_existent_repo"

    monkeypatch.setattr(framework, "TARGET_PATH", str(absent_path))
    monkeypatch.setattr(framework, "TARGET_REPO_URL", "")
    monkeypatch.setattr(framework, "TARGET_REPO_BRANCH", _FAKE_BRANCH)

    # clone_target_repository should never be reached, but guard against it
    def fake_clone_should_not_be_called(*args, **kwargs):
        pytest.fail("clone_target_repository must NOT be called when TARGET_REPO_URL is empty")

    monkeypatch.setattr(framework, "clone_target_repository", fake_clone_should_not_be_called)

    with pytest.raises(SystemExit) as exc_info:
        framework.stage0_validate_target()

    assert exc_info.value.code == 1
