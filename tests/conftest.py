"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    """Create an empty per-target workspace directory."""
    workspace = tmp_path / "workspaces" / "example.com"
    workspace.mkdir(parents=True)
    return workspace
