# Implementation Plan: remote-repo-scan-and-virtual-patch

## Overview

This plan implements two surgical changes to `framework.py` plus one database migration:

1. **Feature 1 — Stage 0 auto-clone**: Extend `stage0_validate_target()` to call `clone_target_repository()` from `context_collector.py` when `TARGET_PATH` is absent or inconsistent, while preserving the existing GitHub Actions path.
2. **Feature 2 — Hardened virtual patch flow (Stage 3)**: Add explicit `git checkout` return-code check, a new `validate_virtual_patch()` function, and structured Supabase registration with `virtual_patch_path`, `virtual_patch_data`, and `previous_version`.
3. **Database migration**: Add `virtual_patch_path` and `virtual_patch_data` columns to `vulnerability_records`.
4. **Tests**: pytest example tests + Hypothesis property-based tests covering all 8 correctness properties.

No changes are made to `context_collector.py` or `ai_agent.py`.

---

## Tasks

- [x] 1. Add database migration for virtual patch columns
  - Create `database/migrate_add_virtual_patch_columns.sql` with:
    ```sql
    ALTER TABLE vulnerability_records
        ADD COLUMN IF NOT EXISTS virtual_patch_path TEXT,
        ADD COLUMN IF NOT EXISTS virtual_patch_data  TEXT;
    ```
  - The migration must use `ADD COLUMN IF NOT EXISTS` so it is idempotent and safe to re-run.
  - _Requirements: 8.2_

- [x] 2. Extend `stage0_validate_target()` in `framework.py` (Feature 1)
  - [x] 2.1 Add `clone_target_repository` to the import from `context_collector`
    - Modify the existing `from context_collector import (...)` block in `framework.py` to also import `clone_target_repository`.
    - No other change to the import block is needed.
    - _Requirements: 2.1_

  - [x] 2.2 Rewrite `stage0_validate_target()` with the five-branch decision table
    - Keep the existing log header (lines with `"=" * 60`, stage name, repo URL, branch, and path).
    - **Branch A** — `TARGET_PATH` exists **and** contains `.git/`: log "repositório alvo detectado como existente", return `(TARGET_PATH, get_target_repo_name())` unchanged (identical to current behavior).
    - **Branch B** — `TARGET_PATH` exists **but no** `.git/` **and** `TARGET_REPO_URL` configured: log warning about inconsistent directory, call `shutil.rmtree(TARGET_PATH, ignore_errors=True)`, then fall through to the clone branch.
    - **Branch C** — `TARGET_PATH` exists **but no** `.git/` **and no** `TARGET_REPO_URL`: log `"WARN"` that directory exists but is not a valid Git repo and `TARGET_REPO_URL` is unset; continue and return `(TARGET_PATH, get_target_repo_name())`.
    - **Branch D** — `TARGET_PATH` does **not** exist **and** `TARGET_REPO_URL` configured: call `clone_target_repository(TARGET_REPO_URL, branch=TARGET_REPO_BRANCH, target_path=TARGET_PATH)`.
    - **Branch E** — `TARGET_PATH` does **not** exist **and no** `TARGET_REPO_URL`: `log(..., "ERROR")` + `sys.exit(1)`.
    - After Branches B/D: if `clone_target_repository()` returns `None` → `log(..., "ERROR")` + `sys.exit(1)`; otherwise log success path and return `(TARGET_PATH, get_target_repo_name())`.
    - Function signature and return type remain `(str, str)` — no callers change.
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3_

- [x] 3. Checkpoint — verify Stage 0 in isolation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement `validate_virtual_patch()` in `framework.py` (Feature 2 — validator)
  - [x] 4.1 Write the `validate_virtual_patch(patch_data, ecosystem)` function
    - Add the function **above** `generate_virtual_patch()` in `framework.py`.
    - Signature: `def validate_virtual_patch(patch_data: dict, ecosystem: str) -> bool`
    - Step 1 — existence check: `os.path.isfile(patch_data["file_path"])`; on failure log warning and return `False`.
    - Step 2 — size check: `os.path.getsize(file_path) > 50`; on failure (size ≤ 50, including 0) log warning and return `False`.
    - Step 3 — syntax check (ecosystem-dependent):
      - `Python` → `subprocess.run([sys.executable, "-m", "py_compile", file_path], capture_output=True, text=True, timeout=30)`
      - `PHP` → `subprocess.run(["php", "-l", file_path], capture_output=True, text=True, timeout=30)`
      - `Node.js` → `subprocess.run(["node", "--check", file_path], capture_output=True, text=True, timeout=30)`
      - Other ecosystems → skip syntax check, return `True`
    - On syntax failure: log warning with `returncode` and `stderr[:200]`, attempt `os.remove(file_path)` (ignore `OSError`), return `False`.
    - If all checks pass, return `True`.
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

- [x] 5. Harden `generate_virtual_patch()` in `framework.py` (Feature 2 — git checkout check)
  - [x] 5.1 Add `git_result` parameter and explicit return-code check to the revert call inside `stage3_apply_patches()`
    - In the smoke-test-failure branch of `stage3_apply_patches()`, capture the result of `subprocess.run(["git", "checkout", "--", ...])` into a variable (e.g., `revert_result`).
    - Check `revert_result.returncode != 0`: if true, log an error with `revert_result.stderr[:300]`, execute the Supabase UPDATE to set `remediation_status = 'FAILED'` for the package, `conn.commit()`, increment `total_failed`, and `continue` to the next package — **do not** call `generate_virtual_patch()`.
    - Only proceed to `generate_virtual_patch()` when `revert_result.returncode == 0`.
    - The `git checkout` file list must remain ecosystem-aware: pass only the manifests for the current `ecosystem` — PHP → `composer.json`, `composer.lock`; Node.js → `package.json`, `package-lock.json`; Python → `requirements.txt`. Replace the current single hard-coded call that passes all five filenames.
    - _Requirements: 4.1, 4.2, 4.3_

  - [x] 5.2 Integrate `validate_virtual_patch()` into `stage3_apply_patches()` after `generate_virtual_patch()` returns
    - After `patch_data = generate_virtual_patch(...)` returns a non-`None` value, call `validate_virtual_patch(patch_data, ecosystem)`.
    - If validation returns `False`: attempt `os.remove(patch_data["file_path"])` (ignore `OSError`), execute UPDATE `remediation_status = 'FAILED'`, increment `total_failed`, `continue`.
    - If validation returns `True`: proceed with the existing UPDATE that sets `remediation_status = 'VIRTUAL_PATCH'`, adding `previous_version = %s` with value `old_ver`, `virtual_patch_path = %s`, `virtual_patch_data = %s`, and log the patch file path and byte size as required by Req 8.5.
    - This integration applies to **both** the smoke-test-failure path and the update-command-failure path within the loop.
    - _Requirements: 5.1, 5.5, 7.6, 7.7, 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 6. Checkpoint — verify Stage 3 end-to-end in isolation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Create the test suite
  - [x] 7.1 Set up `tests/` directory and `conftest.py`
    - Create `tests/__init__.py` (empty) and `tests/conftest.py` with shared fixtures:
      - `tmp_patch_dir(tmp_path)` — creates a `virtual_patches/` subdirectory and returns its parent path.
      - `mock_cursor` — returns a `MagicMock` that simulates a psycopg2 cursor (`execute`, `fetchall`, `fetchone`).
      - `mock_conn(mock_cursor)` — returns a `MagicMock` simulating a psycopg2 connection.
    - Add a `pytest.ini` or `pyproject.toml` `[tool.pytest.ini_options]` section pointing `testpaths = ["tests"]` if one does not exist.
    - _Requirements: 9.1 — 9.8 (infrastructure)_

  - [x] 7.2 Write example tests for Feature 1 (Stage 0)
    - File: `tests/test_stage0.py`
    - Use `monkeypatch` and `tmp_path` from pytest; patch `framework.clone_target_repository`, `framework.TARGET_PATH`, and `framework.TARGET_REPO_URL` as needed.
    - Cover all six scenarios from the design's Testing Strategy table:
      1. `TARGET_PATH` with `.git/` exists → returns path without calling `clone_target_repository`.
      2. `TARGET_PATH` without `.git/`, no URL → logs warning, returns path.
      3. `TARGET_PATH` without `.git/`, URL set → dir removed + `clone_target_repository` called.
      4. `TARGET_PATH` absent, URL set, clone succeeds → returns cloned path.
      5. `TARGET_PATH` absent, URL set, clone fails (returns `None`) → `SystemExit(1)`.
      6. `TARGET_PATH` absent, no URL → `SystemExit(1)`.
    - _Requirements: 1.1, 1.2, 1.4, 2.1, 2.3, 2.4, 2.5, 3.1_

  - [x] 7.3 Write example tests for Feature 2 (Stage 3 — revert and virtual patch)
    - File: `tests/test_stage3_virtual_patch.py`
    - Use `tmp_path`, `monkeypatch`, and `unittest.mock.patch`.
    - Cover all eight scenarios from the design's Testing Strategy table:
      1. `git checkout` returns 0 → `gerar_virtual_patch` is invoked.
      2. `git checkout` returns non-0 → `gerar_virtual_patch` not invoked; status = `FAILED`.
      3. `gerar_virtual_patch` returns `None` → status = `FAILED`, no `VIRTUAL_PATCH` UPDATE.
      4. `validate_virtual_patch` receives non-existent file → returns `False`, status = `FAILED`.
      5. Python file with invalid syntax → `py_compile` fails → returns `False`.
      6. PHP file with invalid syntax (mock `subprocess.run`) → returns `False`.
      7. Node.js file with invalid syntax (mock `subprocess.run`) → returns `False`.
      8. Validation passes → UPDATE contains `virtual_patch_path`, `virtual_patch_data`, `previous_version`.
    - _Requirements: 4.2, 4.3, 5.1, 5.5, 7.1–7.7, 8.1–8.5_

  - [ ]* 7.4 Write property test — Property 1: revert uses correct manifest files per ecosystem
    - File: `tests/test_properties.py`
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 1: revert usa manifestos corretos`
    - `@given(ecosystem=st.sampled_from(["PHP", "Node.js", "Python"]))` / `@settings(max_examples=100)`
    - Mock `subprocess.run`; call the revert logic extracted from `stage3_apply_patches()`; assert the `git checkout` call contains exactly the expected manifests for each ecosystem.
    - Expected sets: PHP → `{"composer.json", "composer.lock"}`; Node.js → `{"package.json", "package-lock.json"}`; Python → `{"requirements.txt"}`.
    - **Validates: Requirements 4.1**

  - [ ]* 7.5 Write property test — Property 2: `previous_version` equals installed version
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 2: previous_version preservada`
    - `@given(version=st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("Lu","Ll","Nd"), whitelist_characters=".-")))` / `@settings(max_examples=100)`
    - Mock cursor and `gerar_virtual_patch` / `validate_virtual_patch` (force success); call the virtual patch registration path; assert the UPDATE SQL received `old_ver` as the `previous_version` parameter.
    - **Validates: Requirements 4.4, 8.3**

  - [ ]* 7.6 Write property test — Property 3: virtual patch file extension matches ecosystem
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 3: extensão correta por ecossistema`
    - `@given(ecosystem=st.sampled_from(["PHP", "Node.js", "Python"]), package_name=st.text(min_size=1, max_size=50))` / `@settings(max_examples=100)`
    - Mock `google.generativeai.GenerativeModel.generate_content` to return a minimal valid patch string; call `gerar_virtual_patch()`; assert `result["file_path"].endswith(expected_ext)`.
    - **Validates: Requirements 5.2**

  - [ ]* 7.7 Write property test — Property 4: virtual patch header contains required fields
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 4: cabeçalho contém campos obrigatórios`
    - `@given(package_name=st.text(min_size=1, max_size=50), cves=st.lists(st.text(min_size=5, max_size=20), min_size=1, max_size=5))` / `@settings(max_examples=100)`
    - Mock Gemini to return a generated patch body prefixed with the header template from `gerar_virtual_patch()`; read the saved file; assert presence of package name, each CVE, and an ISO 8601 timestamp pattern (`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`).
    - **Validates: Requirements 5.3**

  - [ ]* 7.8 Write property test — Property 5: naming convention of virtual patch file
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 5: naming convention do arquivo`
    - `@given(package_name=st.text(min_size=1, max_size=60, alphabet=st.characters(whitelist_categories=("Lu","Ll","Nd"), whitelist_characters="/-_")), ecosystem=st.sampled_from(["PHP", "Node.js", "Python"]))` / `@settings(max_examples=100)`
    - Mock Gemini; call `gerar_virtual_patch()`; compute `safe_name = package_name.replace("/","_").replace("-","_")`; assert `result["file_path"]` ends with `f"{safe_name}_virtual_patch{ext}"`.
    - **Validates: Requirements 6.1**

  - [ ]* 7.9 Write property test — Property 6: return dict contains three required keys
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 6: retorno com três chaves`
    - `@given(package_name=st.text(min_size=1, max_size=50), cves=st.lists(st.text(min_size=5), min_size=1, max_size=3), ecosystem=st.sampled_from(["PHP", "Node.js", "Python"]))` / `@settings(max_examples=100)`
    - Mock Gemini with non-empty content; call `gerar_virtual_patch()`; assert all of `{"patch_code", "file_path", "justification"}` are present and non-empty in the result.
    - **Validates: Requirements 6.4**

  - [ ]* 7.10 Write property test — Property 7: validator rejects files at or below 50 bytes
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 7: rejeição de arquivos pequenos`
    - `@given(size=st.integers(min_value=0, max_value=50))` / `@settings(max_examples=100)`
    - Write a file of exactly `size` bytes to `tmp_path`; build a `patch_data` dict pointing to it; call `validate_virtual_patch(patch_data, "Python")`; assert the return value is `False`.
    - **Validates: Requirements 7.2**

  - [ ]* 7.11 Write property test — Property 8: `virtual_patch_path` and `virtual_patch_data` always persisted together
    - Tag: `# Feature: remote-repo-scan-and-virtual-patch, Property 8: path e data sempre juntos`
    - `@given(package_name=st.text(min_size=1, max_size=50), ecosystem=st.sampled_from(["PHP", "Node.js", "Python"]))` / `@settings(max_examples=100)`
    - Sub-case A (valid patch): mock cursor; force `validate_virtual_patch` to return `True`; invoke the Supabase UPDATE path; assert the `execute` call arguments contain non-`None` values for both `virtual_patch_path` and `virtual_patch_data` in the same statement.
    - Sub-case B (invalid patch): mock `validate_virtual_patch` to return `False`; assert no `VIRTUAL_PATCH` UPDATE is issued.
    - **Validates: Requirements 8.2**

- [x] 8. Final checkpoint — full test suite and regression check
  - Run `pytest tests/ -v` and confirm all non-optional tests pass.
  - Ensure all stages (0–4) execute correctly in an integration dry-run with mocked external calls.
  - Ensure all tests pass, ask the user if questions arise.

---

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP.
- Tasks 2 and 5 are the **only** files that must be modified: `framework.py` and `database/migrate_add_virtual_patch_columns.sql` (new file). `context_collector.py` and `ai_agent.py` are read-only.
- The `git checkout` in task 5.1 must pass only the manifests relevant to the current ecosystem — the existing code passes all five file names regardless of ecosystem, which is the regression being fixed.
- Property tests (7.4–7.11) that call `gerar_virtual_patch()` must mock `google.generativeai.GenerativeModel.generate_content` to avoid real network calls; use `unittest.mock.patch` targeting the `genai` module as imported by `ai_agent.py`.
- Hypothesis `@settings(max_examples=100)` is required on every property test per the design specification.
- `previous_version` column already exists in the schema; only `virtual_patch_path` and `virtual_patch_data` are new (task 1).

---

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1", "2.1", "7.1"] },
    { "id": 1, "tasks": ["2.2"] },
    { "id": 2, "tasks": ["4.1", "7.2"] },
    { "id": 3, "tasks": ["5.1"] },
    { "id": 4, "tasks": ["5.2", "7.3"] },
    { "id": 5, "tasks": ["7.4", "7.5", "7.6", "7.7", "7.8", "7.9", "7.10", "7.11"] }
  ]
}
```
