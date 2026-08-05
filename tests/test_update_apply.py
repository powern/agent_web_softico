import io
import json
import os
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from wp_guardian.config import GuardianConfig
from wp_guardian.models import Site
from wp_guardian.runner import CommandResult
from wp_guardian.update_apply import (
    UpdateApplyError,
    _canonical_digest,
    _validate_archive_members,
    _validate_preparation,
    apply_prepared_plugin_update,
)
from wp_guardian.update_plan import PlannedUpdate


class FakeRunner:
    pass


class FakeWordPress:
    def __init__(
        self,
        source_path: Path,
        *,
        status: str = "inactive",
        fail_update: bool = False,
        remove_on_failure: bool = False,
        checksum_available: bool = True,
    ) -> None:
        self.source_path = source_path
        self.status = status
        self.fail_update = fail_update
        self.remove_on_failure = remove_on_failure
        self.checksum_available = checksum_available
        self.update_calls = 0

    def component_info(self, site_path: Path, kind: str, name: str):
        version_file = self.source_path / "version.txt"
        if not version_file.is_file():
            return None
        return {
            "name": name,
            "status": self.status,
            "version": version_file.read_text(encoding="utf-8").strip(),
        }

    def update_plugin(self, site_path: Path, name: str, target_version: str, *, timeout=None):
        self.update_calls += 1
        if self.remove_on_failure:
            import shutil

            shutil.rmtree(self.source_path)
        else:
            (self.source_path / "version.txt").write_text(
                target_version,
                encoding="utf-8",
            )
            (self.source_path / "changed.php").write_text("changed", encoding="utf-8")
        if self.fail_update:
            return CommandResult(["wp", "plugin", "update"], 1, "", "update failed")
        return CommandResult(
            ["wp", "plugin", "update"],
            0,
            '[{"name":"example-plugin","status":"Updated"}]',
            "",
        )

    def has_checksum_manifest(self, name: str, version: str):
        return self.checksum_available

    def verify_plugin_checksum(self, site_path: Path, name: str, *, timeout=None):
        return CommandResult(["wp", "plugin", "verify-checksums"], 0, "Success", "")

    def verify_core(self, site_path: Path):
        return CommandResult(["wp", "core", "verify-checksums"], 0, "Success", "")


def make_component_and_archive(base: Path) -> tuple[Path, Path]:
    plugin_root = base / "web" / "example.com" / "public_html" / "wp-content" / "plugins"
    source = plugin_root / "example-plugin"
    source.mkdir(parents=True)
    (source / "version.txt").write_text("0.1.7", encoding="utf-8")
    (source / "plugin.php").write_text("<?php // old", encoding="utf-8")

    checkpoint = base / "private-backups" / "example.com" / "20260805T091325Z"
    checkpoint.mkdir(parents=True, mode=0o700)
    os.chmod(checkpoint, 0o700)
    archive_path = checkpoint / "component-plugin-example-plugin.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source, arcname=source.name)
    os.chmod(archive_path, 0o600)
    return source, archive_path


def plan_for(checkpoint: Path):
    return SimpleNamespace(
        blockers=[],
        backup_directory=str(checkpoint),
        updates=[
            PlannedUpdate(
                kind="plugin",
                name="example-plugin",
                status="inactive",
                current_version="0.1.7",
                target_version="0.1.8",
            )
        ],
        http_status=200,
        http_url="https://example.com/",
        http_time=0.2,
        core_version="7.0.2",
        core_checksum_ok=True,
    )


class UpdateApplyTests(unittest.TestCase):
    def test_successful_inactive_plugin_apply_writes_private_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, archive_path = make_component_and_archive(base)
            checkpoint = archive_path.parent
            site = Site("example.com", base / "web" / "example.com" / "public_html")
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            wordpress = FakeWordPress(source)
            preparation_id = "a" * 64

            with (
                patch(
                    "wp_guardian.update_apply._validate_preparation",
                    return_value=(
                        checkpoint,
                        {},
                        source,
                        archive_path,
                        "0.1.7",
                        "0.1.8",
                    ),
                ),
                patch("wp_guardian.update_apply._require_preflight"),
                patch(
                    "wp_guardian.update_apply.build_update_plan",
                    return_value=plan_for(checkpoint),
                ),
            ):
                result = apply_prepared_plugin_update(
                    config,
                    site,
                    wordpress,  # type: ignore[arg-type]
                    FakeRunner(),  # type: ignore[arg-type]
                    preparation_id=preparation_id,
                    kind="plugin",
                    name="example-plugin",
                    target_version="0.1.8",
                    now=datetime(2026, 8, 5, 9, 15, tzinfo=timezone.utc),
                )

            self.assertEqual(result.target_version, "0.1.8")
            self.assertEqual(
                (source / "version.txt").read_text(encoding="utf-8"),
                "0.1.8",
            )
            self.assertTrue(result.record_path.is_file())
            self.assertEqual(result.record_path.stat().st_mode & 0o777, 0o600)
            record = json.loads(result.record_path.read_text(encoding="utf-8"))
            self.assertFalse(record["rolled_back"])
            self.assertTrue(record["postflight"]["plugin_checksum_verified"])

    def test_failed_update_restores_snapshot_and_writes_rollback_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, archive_path = make_component_and_archive(base)
            checkpoint = archive_path.parent
            site = Site("example.com", base / "web" / "example.com" / "public_html")
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            wordpress = FakeWordPress(source, fail_update=True)

            with (
                patch(
                    "wp_guardian.update_apply._validate_preparation",
                    return_value=(checkpoint, {}, source, archive_path, "0.1.7", "0.1.8"),
                ),
                patch("wp_guardian.update_apply._require_preflight"),
                patch(
                    "wp_guardian.update_apply.build_update_plan",
                    return_value=plan_for(checkpoint),
                ),
            ):
                with self.assertRaisesRegex(UpdateApplyError, "restored automatically"):
                    apply_prepared_plugin_update(
                        config,
                        site,
                        wordpress,  # type: ignore[arg-type]
                        FakeRunner(),  # type: ignore[arg-type]
                        preparation_id="b" * 64,
                        kind="plugin",
                        name="example-plugin",
                        target_version="0.1.8",
                    )

            self.assertEqual(
                (source / "version.txt").read_text(encoding="utf-8"),
                "0.1.7",
            )
            self.assertFalse((source / "changed.php").exists())
            rollback = checkpoint / "update-rollback.json"
            self.assertTrue(rollback.is_file())
            self.assertTrue(json.loads(rollback.read_text(encoding="utf-8"))["rolled_back"])

    def test_failed_update_restores_snapshot_when_plugin_directory_disappears(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, archive_path = make_component_and_archive(base)
            checkpoint = archive_path.parent
            site = Site("example.com", base / "web" / "example.com" / "public_html")
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            wordpress = FakeWordPress(
                source,
                fail_update=True,
                remove_on_failure=True,
            )

            with (
                patch(
                    "wp_guardian.update_apply._validate_preparation",
                    return_value=(checkpoint, {}, source, archive_path, "0.1.7", "0.1.8"),
                ),
                patch("wp_guardian.update_apply._require_preflight"),
                patch(
                    "wp_guardian.update_apply.build_update_plan",
                    return_value=plan_for(checkpoint),
                ),
            ):
                with self.assertRaisesRegex(UpdateApplyError, "restored automatically"):
                    apply_prepared_plugin_update(
                        config,
                        site,
                        wordpress,  # type: ignore[arg-type]
                        FakeRunner(),  # type: ignore[arg-type]
                        preparation_id="c" * 64,
                        kind="plugin",
                        name="example-plugin",
                        target_version="0.1.8",
                    )

            self.assertTrue(source.is_dir())
            self.assertEqual(
                (source / "version.txt").read_text(encoding="utf-8"),
                "0.1.7",
            )

    def test_active_plugin_is_rejected_before_wp_cli_update(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, archive_path = make_component_and_archive(base)
            checkpoint = archive_path.parent
            site = Site("example.com", base / "web" / "example.com" / "public_html")
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            wordpress = FakeWordPress(source, status="active")

            with patch(
                "wp_guardian.update_apply._validate_preparation",
                return_value=(checkpoint, {}, source, archive_path, "0.1.7", "0.1.8"),
            ):
                with self.assertRaisesRegex(UpdateApplyError, "Plugin state changed"):
                    apply_prepared_plugin_update(
                        config,
                        site,
                        wordpress,  # type: ignore[arg-type]
                        FakeRunner(),  # type: ignore[arg-type]
                        preparation_id="d" * 64,
                        kind="plugin",
                        name="example-plugin",
                        target_version="0.1.8",
                    )

            self.assertEqual(wordpress.update_calls, 0)

    def test_snapshot_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                member = tarfile.TarInfo("../escape.php")
                data = b"bad"
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

            with self.assertRaisesRegex(UpdateApplyError, "unsafe path"):
                _validate_archive_members(archive_path, "example-plugin")

    def test_tampered_preparation_manifest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            source = site_path / "wp-content" / "plugins" / "example-plugin"
            source.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            checkpoint = config.backup_dir / "example.com" / "20260805T091325Z"
            checkpoint.mkdir(parents=True, mode=0o700)
            os.chmod(checkpoint, 0o700)
            payload = {
                "schema_version": 1,
                "created_at": "2026-08-05T09:13:25+00:00",
                "domain": "example.com",
                "site_path": str(site_path),
                "component": {
                    "kind": "plugin",
                    "name": "example-plugin",
                    "status": "inactive",
                    "current_version": "0.1.7",
                    "target_version": "0.1.8",
                    "source_path": str(source),
                },
            }
            preparation_id = _canonical_digest(payload)
            payload["preparation_id"] = preparation_id
            payload["component"]["target_version"] = "9.9.9"
            manifest = checkpoint / "update-preparation.json"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(manifest, 0o600)

            with self.assertRaisesRegex(UpdateApplyError, "ID does not match"):
                _validate_preparation(
                    config,
                    Site("example.com", site_path),
                    object(),  # type: ignore[arg-type]
                    preparation_id=preparation_id,
                    kind="plugin",
                    name="example-plugin",
                    target_version="0.1.8",
                    now=datetime(2026, 8, 5, 9, 15, tzinfo=timezone.utc),
                )

    def test_expired_preparation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            site_path = base / "web" / "example.com" / "public_html"
            source = site_path / "wp-content" / "plugins" / "example-plugin"
            source.mkdir(parents=True)
            config = GuardianConfig(
                sites_root=base / "web",
                backup_dir=base / "private-backups",
            )
            checkpoint = config.backup_dir / "example.com" / "20260805T091325Z"
            checkpoint.mkdir(parents=True, mode=0o700)
            os.chmod(checkpoint, 0o700)
            created_at = datetime(2026, 8, 5, 7, 0, tzinfo=timezone.utc)
            payload = {
                "schema_version": 1,
                "created_at": created_at.isoformat(),
                "domain": "example.com",
                "site_path": str(site_path),
                "component": {
                    "kind": "plugin",
                    "name": "example-plugin",
                    "status": "inactive",
                    "current_version": "0.1.7",
                    "target_version": "0.1.8",
                    "source_path": str(source),
                },
            }
            preparation_id = _canonical_digest(payload)
            payload["preparation_id"] = preparation_id
            manifest = checkpoint / "update-preparation.json"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(manifest, 0o600)

            with self.assertRaisesRegex(UpdateApplyError, "too old"):
                _validate_preparation(
                    config,
                    Site("example.com", site_path),
                    object(),  # type: ignore[arg-type]
                    preparation_id=preparation_id,
                    kind="plugin",
                    name="example-plugin",
                    target_version="0.1.8",
                    now=created_at + timedelta(hours=2),
                )


if __name__ == "__main__":
    unittest.main()
