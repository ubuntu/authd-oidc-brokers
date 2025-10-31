import os

from robot.api.deco import keyword, library  # type: ignore
from robot.libraries.Process import Process
from robot.api import logger

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_command(args):
    result = Process().run_process(args[0], *args[1:])
    if result.rc == 0:
        return

    cmd = " ".join(args)
    message = (f"Command '{cmd}' failed:\n"
               f"--- stdout ---\n{result.stdout}\n"
               f"--- stderr ---\n{result.stderr}")
    logger.error(message)

    raise RuntimeError(f"Command '{cmd}' failed")


@library
class Browser:
    @keyword
    async def login(self, username: str, password: str, usercode: str, totp_secret: str, output_dir: str = "."):
        """Perform device authentication with the given username, password and
        usercode using a browser automation script. The window opened by the
        script is run off screen using Xvfb.
        """
        run_command([
            "/usr/bin/env",
            "GDK_BACKEND=x11",
            "xvfb-run", "-a",
            os.path.join(SCRIPT_DIR, "browser_login.py"),
            username,
            password,
            usercode,
            totp_secret,
            "--output-dir", output_dir,
        ])
