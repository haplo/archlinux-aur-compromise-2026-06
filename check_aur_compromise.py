#!/usr/bin/env python3
import os
import subprocess
import sys


MALICIOUS_PATTERNS = [
    "atomic-lockfile",
    "lockfile-js",
    "js-digest",
    "bun add",
    "bun install",
]


def get_installed() -> set[str]:
    result = subprocess.run(["pacman", "-Qq"], capture_output=True, text=True, check=True)
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def get_bad() -> set[str]:
    with open("bad_pkg.txt", "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def _file_has_malicious(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
            for pat in MALICIOUS_PATTERNS:
                if pat in text:
                    return True
    except OSError:
        pass
    return False


def scan_clones(cache_dir: str) -> set[str]:
    """Scan git clones in cache_dir for malicious patterns in PKGBUILD / .install / .hook."""
    found: set[str] = set()
    if not os.path.isdir(cache_dir):
        return found

    for entry in os.listdir(cache_dir):
        pkg_path = os.path.join(cache_dir, entry)
        if not os.path.isdir(os.path.join(pkg_path, ".git")):
            continue

        for root, dirs, files in os.walk(pkg_path):
            if ".git" in dirs:
                dirs.remove(".git")
            for fname in files:
                if fname == "PKGBUILD" or fname.endswith(".install") or fname.endswith(".hook"):
                    if _file_has_malicious(os.path.join(root, fname)):
                        found.add(entry)
                        break
            if entry in found:
                break

    return found


def scan_git_metadata(cache_dir: str) -> set[str]:
    """Detect author impersonation (same name, gmail vs non-gmail emails) in recent commits."""
    found: set[str] = set()
    if not os.path.isdir(cache_dir):
        return found

    for entry in os.listdir(cache_dir):
        pkg_path = os.path.join(cache_dir, entry)
        if not os.path.isdir(os.path.join(pkg_path, ".git")):
            continue

        try:
            result = subprocess.run(
                ["git", "-C", pkg_path, "log", "--format=%an|%ae", "-n", "5"],
                capture_output=True,
                text=True,
                check=True,
            )
            commits = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            if len(commits) < 2:
                continue

            authors: dict[str, set[str]] = {}
            for commit in commits:
                if "|" not in commit:
                    continue
                name, email = commit.rsplit("|", 1)
                authors.setdefault(name, set()).add(email)

            for emails in authors.values():
                if len(emails) >= 2:
                    has_gmail = any(e.endswith("@gmail.com") for e in emails)
                    has_other = any(not e.endswith("@gmail.com") for e in emails)
                    if has_gmail and has_other:
                        found.add(entry)
                        break
        except (subprocess.CalledProcessError, OSError):
            pass

    return found


def scan_hooks() -> set[str]:
    """Scan installed pacman hooks for malicious patterns."""
    found: set[str] = set()
    hooks_dir = "/usr/share/libalpm/hooks/"
    if not os.path.isdir(hooks_dir):
        return found

    for entry in os.listdir(hooks_dir):
        path = os.path.join(hooks_dir, entry)
        if os.path.isfile(path) and _file_has_malicious(path):
            found.add(entry)

    return found


def main() -> int:
    installed = get_installed()
    bad = get_bad()
    matches = installed & bad

    clone_matches: set[str] = set()
    git_matches: set[str] = set()

    for cache in (os.path.expanduser("~/.cache/paru/clone"), os.path.expanduser("~/.cache/yay")):
        clone_matches |= scan_clones(cache)
        git_matches |= scan_git_metadata(cache)

    hook_matches = scan_hooks()

    # De-duplicate: don't re-report a package already flagged by the static list
    clone_matches -= matches
    git_matches -= matches

    if not (matches or clone_matches or git_matches or hook_matches):
        print("\033[32mSAFE\033[0m")
        return 0

    for pkg in sorted(matches):
        print(f"\033[31mMATCH {pkg}\033[0m")
    for pkg in sorted(clone_matches):
        print(f"\033[33mCLONE {pkg}\033[0m")
    for pkg in sorted(git_matches):
        print(f"\033[36mGIT {pkg}\033[0m")
    for fname in sorted(hook_matches):
        print(f"\033[35mHOOK {fname}\033[0m")

    return 1


if __name__ == "__main__":
    sys.exit(main())
