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

    def test_database_export_is_single_domain_and_non_root(self) -> None:
        runner = RecordingRunner()
        config = GuardianConfig(wp_cli="/usr/local/bin/wp")
        wordpress = WordPress(config, runner)  # type: ignore[arg-type]
        site = Path("/home/admin/web/softico.ua/public_html")
        target = Path("/home/admin/private-backups/wp-guardian/database.sql")

        wordpress.export_database(site, target, timeout=900)

        self.assertNotIn("--allow-root", runner.last_command)
        self.assertIn(f"--path={site}", runner.last_command)
        self.assertIn("db", runner.last_command)
        self.assertIn("export", runner.last_command)
        self.assertIn(str(target), runner.last_command)
        self.assertIn("--single-transaction", runner.last_command)

    def test_audit_systemd_unit_runs_as_admin(self) -> None:
        unit = Path("systemd/wp-guardian.service").read_text(encoding="utf-8")

        self.assertIn("User=admin", unit)
        self.assertIn("Group=admin", unit)
        self.assertNotIn("User=root", unit)
        self.assertNotIn("Group=root", unit)

    def test_mail_unit_is_privileged_but_cannot_access_hosted_sites(self) -> None:
        unit = Path("systemd/wp-guardian-mail.service").read_text(encoding="utf-8")

        self.assertIn("User=root", unit)
        self.assertIn("Group=root", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ProtectHome=true", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("/var/spool/exim4", unit)
        self.assertNotIn("WorkingDirectory=/home", unit)

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

    def test_installer_creates_private_backup_directory(self) -> None:
        installer = Path("scripts/install.sh").read_text(encoding="utf-8")

        self.assertIn('BACKUP_DIR="/home/admin/private-backups/wp-guardian"', installer)
        self.assertIn('"$BACKUP_DIR"', installer)
        self.assertIn("-m 0700", installer)
        self.assertIn("wp-guardian --config $CONFIG_FILE backup --domain softico.ua", installer)


if __name__ == "__main__":
    unittest.main()
