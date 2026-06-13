# AGENTS.md

## Project Overview

A tiny Arch Linux utility that checks whether any installed AUR packages appear on a known-compromised list.

## Files

| File | Purpose |
|------|---------|
| `check_aur_compromise.py` | Main script. Runs multiple checks (see below), prints colored results, exits 0/1. |
| `bad_pkg.txt` | Sorted list of compromised AUR package names (one per line). Source: https://md.archlinux.org/s/SxbqukK6IA |

## How it works

The script runs four checks in sequence:

1. **Static list check** — `get_installed()` shells out to `pacman -Qq` and intersects with `bad_pkg.txt`.
   - Match → prints `\033[31mMATCH <pkg>\033[0m`.

2. **Clone pattern scan** — Walks `~/.cache/paru/clone/` and `~/.cache/yay/` (all packages, installed or not). Reads `PKGBUILD`, `*.install`, and `*.hook` files for the following strings:
   - `atomic-lockfile`
   - `lockfile-js`
   - `js-digest`
   - `bun add`
   - `bun install`
   - Match → prints `\033[33mCLONE <pkg>\033[0m`.

3. **Git metadata scan** — In each clone, runs `git log --format='%an|%ae' -n 5`. Detects author impersonation: the same author name with both a `@gmail.com` email and a non-Gmail email in recent commits.
   - Match → prints `\033[36mGIT <pkg>\033[0m`.

4. **Installed hooks scan** — Reads `/usr/share/libalpm/hooks/` for the same malicious strings used in the clone scan.
   - Match → prints `\033[35mHOOK <file>\033[0m`.

If none of the four checks find anything, prints `\033[32mSAFE\033[0m` and returns `0`. Otherwise returns `1`.

## Conventions

- `bad_pkg.txt` must stay **sorted alphabetically**, one package per line, UTF-8 encoded.
- The script is intentionally minimal: no external dependencies beyond the Python standard library.
- Keep the `pacman` invocation exactly as `pacman -Qq` so it only emits package names.

## Background

The compromise indicators were gathered from the Arch Linux `aur-general` mailing-list thread:

- **Thread:** AUR REPORT THREAD  
- **URL:** https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/  
- **Last reviewed:** 2026-06-13

Key findings from the thread that informed the checks above:

- Attackers injected `npm install atomic-lockfile` into `.install`/`.hook` files across ~408 packages. The package was later renamed to `lockfile-js`.
- A second wave used `bun add js-digest` (and related packages like `axios`, `commander`, `execa`) across ~900 packages.
- Commits impersonated previous maintainers by keeping the real name but replacing the email with a fake Gmail address.
- New/suspicious AUR accounts adopted orphaned packages instantly and pushed malicious commits.
- The most effective community detection method was grepping the AUR git mirror for the malicious strings above.
