#!/usr/bin/env python3

from rich.console import Console


class Okland():
    """
    Generic functions

    """
    __Console__ = Console()

    def __toConsole__(self, message, style="dim"):
        self.__Console__.print(message, style=style)
        return True
