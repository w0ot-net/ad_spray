#!/usr/bin/env python3
"""
Wrapper script for backward compatibility.
Entry point for the password spray tool.
"""

import sys
from ad_spray.cli import main

if __name__ == "__main__":
    sys.exit(main())
