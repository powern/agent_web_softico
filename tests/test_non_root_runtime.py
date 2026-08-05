from pathlib import Path
import unittest

from wp_guardian.config import GuardianConfig
from wp_guardian.runner import CommandResult
from wp_guardian.wordpress import WordPress


class RecordingRunner:
    def __init__(self) -> None:
        self.last_command: list[str] = []

    def run(self, args, *, cwd=None, timeout=None):
        self.last_command = [str(item) for item in args]
        return CommandResult(self.last_command, 0, "7.0.2", "")


class NonRootRuntimeTests(unittest.TestCase):
    def test_wp_cli_command_never_uses_allow_root(self) -> None:
        runner = RecordingRunner()
        config = GuardianConfig(wp_cli="/usr/local/bin/wp")
        wordpress = WordPress(config, runner)  # type: ignore[arg-type]

        wordpress.core_version(Path("/home/admin/web/softico.ua/public_html"))

        self.assertNotIn("--allow-root", runner.last_command)
        self.assertIn(
            "--path=/home/admin/web/softico.ua/public_html",
            runner.last_command,
        )

    def test_systemd_unit_runs_as_admin(self) -> None:
        unit = Path("systemd/wp-guardian.service").read_text(encoding="utf-8")

        self.assertIn("User=admin", unit)
        self.assertIn("Group=admin", unit)
        self.assertNotIn("User=root", unit)
        self.assertNotIn("Group=root", unit)

    def test_installer_uses_pep517_build_isolation(self) -> None:
        installer = Path("scripts/install.sh").read_text(encoding="utf-8")
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertNotIn("--no-build-isolation", installer)
        self.assertIn('"$VENV_DIR/bin/python" -m pip install .', installer)
        self.assertIn('"wheel"', pyproject)

    def test_installer_does_not_rename_installed_virtualenv(self) -> None:
        installer = Path("scripts/install.sh").read_text(encoding="utf-8")

        self.assertNotIn("VENV_NEW", installer)
        self.assertNotIn('mv "$VENV_NEW" "$VENV_DIR"', installer)
        self.assertIn('"$VENV_DIR/bin/wp-guardian" --version', installer)


if __name__ == "__main__":
    unittest.main()
