import os.path

from robot.api.deco import keyword, library  # type: ignore

import ExecUtils

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SSH_SCRIPT = os.path.abspath(os.path.join(SCRIPT_DIR, "ssh.sh"))

@library
class SSH:
    @keyword
    async def execute(self, command: str) -> str:
        """
        Run a command via SSH and return its output.

        Args:
            command: The command to run.
        Returns:
            The output of the command.
        """
        result = ExecUtils.run(
            [SSH_SCRIPT, command],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()
