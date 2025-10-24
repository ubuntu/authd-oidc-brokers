import os

from robot.api.deco import keyword, library  # type: ignore
from robot.libraries.Process import Process
from robot.api import logger

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_command(command: str, *arguments):
    result = Process().run_process(command, *arguments)
    if result.rc == 0:
        return

    cmd = command if not arguments else f"{command} {' '.join(arguments)}"
    message = (f"Command '{cmd}' failed:\n"
               f"--- stdout ---\n{result.stdout}\n"
               f"--- stderr ---\n{result.stderr}")
    logger.error(message)
    raise RuntimeError(f"Command '{cmd}' failed")


@library
class Browser:
    @keyword
    async def login(self, username: str, password: str, usercode: str, output_dir: str = "."):
        """Perform device authentication with the given username, password and usercode."""
        login_script = os.path.join(SCRIPT_DIR, "browser_login.py")
        run_command(login_script, username, password, usercode, "--output-dir", output_dir)
