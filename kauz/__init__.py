"""Kauz – the friendly security check for your Linux PC."""
import os as _os
import sys as _sys

if _os.geteuid() == 0:
    _sys.dont_write_bytecode = True  # never leave root-owned cache files in the user's folder
__version__ = "0.3.0"

DISCLAIMER = ("Kauz is a young hobby project and can make mistakes: it may miss problems or report "
              "harmless things. It is no replacement for professional security tools. "
              "Check every command before you run it.")
