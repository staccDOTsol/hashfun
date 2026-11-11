"""hashfun: PoW launchpad on a Bitcoin Core fork. Mined, not minted."""
__version__ = "0.1.0"

import sys as _sys

if _sys.version_info < (3, 10):  # before any module with newer syntax is imported
    raise SystemExit("hashfun needs Python 3.10 or newer (this is %d.%d). On a Mac: brew install python, "
                     "then run it with that python3." % _sys.version_info[:2])
