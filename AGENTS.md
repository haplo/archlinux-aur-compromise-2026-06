# AGENTS.md

## Project Overview

A tiny Arch Linux utility that checks whether any installed AUR packages appear on a known-compromised list.

## Files

| File | Purpose |
|------|---------|
| `check_aur_compromise.py` | Main script. Runs `pacman -Qq`, intersects with `bad_pkg.txt`, prints colored results, exits 0/1. |
| `bad_pkg.txt` | Sorted list of compromised AUR package names (one per line). |

## How it works

1. `get_installed()` shells out to `pacman -Qq` and returns a `set[str]` of installed package names.
2. `get_bad()` reads `bad_pkg.txt` and returns a `set[str]` of compromised package names.
3. `main()` computes the intersection.  
   - If empty → prints `\033[32mSAFE\033[0m` and returns `0`.  
   - Otherwise → prints `\033[31mMATCH <pkg>\033[0m` for each match and returns `1`.

## Conventions

- `bad_pkg.txt` must stay **sorted alphabetically**, one package per line, UTF-8 encoded.
- The script is intentionally minimal: no external dependencies beyond the Python standard library.
- Keep the `pacman` invocation exactly as `pacman -Qq` so it only emits package names.
