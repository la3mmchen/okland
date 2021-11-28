#!/usr/bin/env python3

import json
from rich.console import Console
import os

class Okland():
    """
    Generic functions
    
    """
    __Console__ = Console()


    def __toConsole__(self, message, style="dim"):
        self.__Console__.print(message, style=style)
        return True