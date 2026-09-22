"""Entry point: `python3 -m certilens` or `certilens`."""

import sys

from .app import run


def main() -> int:
    return run(sys.argv)


if __name__ == "__main__":
    raise SystemExit(main())
