from robot.api.deco import keyword, library  # type: ignore


@library
class StringUtils:
    @keyword
    async def first_match(self, regex: str, text: str) -> str:
        """
        Match a regex against a string and return the first match.

        Args:
            regex: The regex to match.
            text: The text to match against.

        Returns:
            The first match.
        """
        import re

        match = re.search(regex, text)
        if match:
            return match.group(len(match.groups()))
        else:
            raise ValueError(f"No match found for {regex} in {text}")
