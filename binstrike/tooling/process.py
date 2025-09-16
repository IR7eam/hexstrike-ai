from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence


@dataclass
class CommandResult:
    """Result of invoking an external process."""

    command: Sequence[str]
    stdout: str
    stderr: str
    returncode: int
    duration: float


class CommandExecutionError(RuntimeError):
    """Raised when an external command fails unexpectedly."""

    def __init__(self, result: CommandResult):
        message = (
            f"Command {' '.join(result.command)} failed with code {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        super().__init__(message)
        self.result = result


class CommandRunner:
    """Utility wrapper that executes external tools and captures their output."""

    def __init__(
        self,
        *,
        default_timeout: Optional[float] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.default_timeout = default_timeout
        self.env = dict(env) if env is not None else None

    def run(
        self,
        command: Iterable[str],
        *,
        cwd: Optional[Path] = None,
        timeout: Optional[float] = None,
        check: bool = False,
        text: bool = True,
    ) -> CommandResult:
        """Execute ``command`` and capture the output."""

        arguments = list(command)
        start_time = time.monotonic()
        completed = subprocess.run(  # noqa: S603  # trusted command provided by caller
            arguments,
            cwd=str(cwd) if cwd is not None else None,
            env=self.env,
            capture_output=True,
            timeout=timeout or self.default_timeout,
            text=text,
            check=False,
        )
        duration = time.monotonic() - start_time
        result = CommandResult(
            command=tuple(arguments),
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            duration=duration,
        )
        if check and result.returncode != 0:
            raise CommandExecutionError(result)
        return result
