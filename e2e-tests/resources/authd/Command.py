from robot.api.deco import keyword, library  # type: ignore
from robot.libraries.Process import Process
from robot.output import LOGGER

@library
class Command:
    @keyword
    async def run(self, command: str, *arguments):
        result = Process().run_process(command, *arguments)
        if result.rc != 0:
            cmd = command if not arguments else f"{command} {' '.join(arguments)}"
            message = (f"Command '{cmd}' failed:\n"
                       f"--- stdout ---\n{result.stdout}\n"
                       f"--- stderr ---\n{result.stderr}")
            LOGGER.error(message)
            raise RuntimeError(f"Command '{cmd}' failed")
