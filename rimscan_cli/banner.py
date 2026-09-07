"""Terminal banner for the Rimscan CLI."""

from __future__ import annotations

import sys
from typing import TextIO

from . import __version__

UNICODE_BANNER = """\
██████╗ ██╗███╗   ███╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║████╗ ████║██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║██╔████╔██║███████╗██║     ███████║██╔██╗ ██║
██╔══██╗██║██║╚██╔╝██║╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║██║██║ ╚═╝ ██║███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝╚═╝     ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"""

ASCII_BANNER = """\
 ____  ___ __  __ ____   ____    _    _   _ 
|  _ \\|_ _|  \\/  / ___| / ___|  / \\  | \\ | |
| |_) || || |\\/| \\___ \\| |     / _ \\ |  \\| |
|  _ < | || |  | |___) | |___ / ___ \\| |\\  |
|_| \\_\\___|_|  |_|____/ \\____/_/   \\_\\_| \\_|"""

BANNER = UNICODE_BANNER


def _banner_for(output: TextIO) -> str:
    """Use line art when the destination encoding supports it."""
    encoding = getattr(output, "encoding", None) or "utf-8"
    try:
        UNICODE_BANNER.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return ASCII_BANNER
    return UNICODE_BANNER


def render_banner(stream: TextIO | None = None) -> None:
    """Print the startup banner to stderr unless another stream is supplied."""
    output = stream or sys.stderr
    print(_banner_for(output), file=output)
    print(f"rimscan-cli v{__version__} | rimscan.cloud", file=output)
    print("passive reconnaissance, done right", file=output)
    print(file=output)


if __name__ == "__main__":
    render_banner(sys.stdout)