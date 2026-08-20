"""Frontend resolution for `aegisai dashboard`."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegisai.cli import dashboard
from aegisai.core.exceptions import AegisError


class TestFrontendResolution:
    def test_a_directory_without_a_package_json_is_not_the_frontend(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Installed non-editable, `parents[3]` lands inside the virtualenv. An
        empty directory there must not be mistaken for the dashboard source."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "frontend" / "src" / "data").mkdir(parents=True)

        monkeypatch.setattr(dashboard, "__file__", str(tmp_path / "a/b/c/d/dashboard.py"))
        assert dashboard._find_frontend() is None

    def test_a_real_frontend_is_found_from_the_working_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fallback that rescues a non-editable install run from the repo."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "package.json").write_text("{}")
        # Point the source-checkout candidate somewhere with no frontend, so the
        # working-directory fallback is what answers.
        monkeypatch.setattr(dashboard, "__file__", str(tmp_path / "a/b/c/d/dashboard.py"))

        assert dashboard._find_frontend() == tmp_path / "frontend"

    def test_the_repo_checkout_resolves(self) -> None:
        """The layout the project actually ships."""
        found = dashboard._find_frontend()

        assert found is not None
        assert (found / "package.json").is_file()

    def test_a_missing_frontend_names_the_real_problem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It previously surfaced as an npm ENOENT about package.json, which
        pointed at the wrong tool entirely."""
        monkeypatch.setattr(dashboard, "FRONTEND_DIR", None)

        with pytest.raises(AegisError) as excinfo:
            dashboard._require_frontend()

        message = f"{excinfo.value} {getattr(excinfo.value, 'hint', '')}"
        assert "frontend" in message.lower()
        assert "npm" not in message.lower()
        # Names the way out for someone not in a checkout.
        assert "--out" in message
