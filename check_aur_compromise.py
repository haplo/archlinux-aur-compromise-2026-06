#!/usr/bin/env python3
import subprocess
import sys


def get_installed() -> set[str]:
    result = subprocess.run(["pacman", "-Qq"], capture_output=True, text=True, check=True)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def get_bad() -> set[str]:
    with open("bad_pkg.txt", "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def main() -> int:
    installed = get_installed()
    bad = get_bad()
    matches = installed & bad

    if not matches:
        print("\033[32mSAFE\033[0m")
        return 0

    for pkg in matches:
        print(f"\033[31mMATCH {pkg}\033[0m")
    return 1


if __name__ == "__main__":
    sys.exit(main())
