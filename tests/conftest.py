"""
Shared pytest fixtures for the remote-repo-scan-and-virtual-patch test suite.
"""
import pytest
from unittest.mock import MagicMock


@pytest.fixture
def tmp_patch_dir(tmp_path):
    """
    Creates a ``virtual_patches/`` subdirectory inside ``tmp_path`` and
    returns the *parent* path (i.e. ``tmp_path`` itself), which acts as the
    simulated ``TARGET_PATH`` for tests.

    Layout produced:
        tmp_path/
        └── virtual_patches/   ← pre-created so tests don't have to
    """
    (tmp_path / "virtual_patches").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture
def mock_cursor():
    """
    Returns a :class:`~unittest.mock.MagicMock` that simulates a
    psycopg2 cursor with the three most-used methods stubbed out:

    * ``execute``   – records the last SQL statement and parameters
    * ``fetchall``  – returns an empty list by default
    * ``fetchone``  – returns ``None`` by default
    """
    cursor = MagicMock()
    cursor.execute = MagicMock()
    cursor.fetchall = MagicMock(return_value=[])
    cursor.fetchone = MagicMock(return_value=None)
    return cursor


@pytest.fixture
def mock_conn(mock_cursor):
    """
    Returns a :class:`~unittest.mock.MagicMock` that simulates a
    psycopg2 connection.  ``conn.cursor()`` is a context manager that
    yields ``mock_cursor``, matching the ``with conn.cursor() as cur:``
    pattern used throughout ``framework.py``.

    Also stubs ``commit`` and ``rollback`` for side-effect assertions.
    """
    conn = MagicMock()
    # Support both the context-manager style and the direct-call style.
    conn.cursor.return_value.__enter__ = MagicMock(return_value=mock_cursor)
    conn.cursor.return_value.__exit__ = MagicMock(return_value=False)
    # Direct call (cur = conn.cursor()) also returns mock_cursor.
    conn.cursor.return_value = mock_cursor
    conn.commit = MagicMock()
    conn.rollback = MagicMock()
    return conn
