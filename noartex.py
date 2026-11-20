#!/usr/bin/env python3
"""NOARTEX — entry point wrapper."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from cli.noartex.cli import main
if __name__ == "__main__":
    main()
