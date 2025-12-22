"""Entry point for running ad_spray as a module: python -m ad_spray"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
