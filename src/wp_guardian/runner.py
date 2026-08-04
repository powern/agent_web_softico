from __future__ import annotations

import json
import os
import pwd
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def json(self) -> Any:
        return json.loads(self.stdout or "null")


class CommandRunner:
    def __init__(self, timeout: int = 60) -> None:
        self.timeout = timeout

    @staticmethod
    def runtime_env() -> dict[str, str]:
        account = pwd.getpwuid(os.getuid())
        return {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": account.pw_dir,
            "USER": account.pw_name,
            "LOGNAME": account.pw_name,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: int | None = None,
    ) -> CommandResult:
        command = [str(item) for item in args]
        try:
            completed = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
                check=False,
                env=self.runtime_env(),
            )
            return CommandResult(
                command,
                completed.returncode,
                completed.stdout.strip(),
                completed.stderr.strip(),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(command, 124, stdout.strip(), stderr.strip(), True)
