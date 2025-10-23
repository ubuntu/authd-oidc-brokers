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
            LOGGER.error(f"Command '{cmd}' failed: {result.stderr}")
            raise RuntimeError(f"Command '{command}' failed")
