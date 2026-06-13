# Automated checks of Archlinux AUR compromise of Jun 2026

A tiny Arch Linux utility that checks whether any installed AUR packages appear on a known-compromised list, and scans local clones and system hooks for indicators of compromise.

## Install

```bash
git clone https://github.com/OWNER/archlinux-aur-compromise-2026-06.git
cd archlinux-aur-compromise-2026-06
python3 check_aur_compromise.py
```

No external dependencies are required — only the Python standard library.

## How it works

The script runs four checks in sequence:

1. **Static list** — compares installed packages (`pacman -Qq`) against a curated list of compromised AUR package names.
2. **Clone scan** — inspects `PKGBUILD`, `.install`, and `.hook` files in `~/.cache/paru/clone/` and `~/.cache/yay/` for malicious strings (e.g. `atomic-lockfile`, `bun add js-digest`).
3. **Git metadata** — checks recent commits for author impersonation (same name with both a Gmail and a non-Gmail address).
4. **Installed hooks** — scans `/usr/share/libalpm/hooks/` for the same malicious strings.

## Example outputs

### Safe system

```
SAFE
```

Exit code: `0`

### Unsafe system

```
MATCH actual-ai      # installed package is on the known-compromised list
CLONE some-pkg       # local clone contains malicious strings in build/hook files
GIT another-pkg      # recent commits show author impersonation (Gmail vs non-Gmail)
HOOK 99-malice.hook  # system alpm hook contains malicious strings
```

Exit code: `1`

## Sources

- Compromised package list and indicators gathered from the Arch Linux `aur-general` mailing-list thread: [AUR REPORT THREAD](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/thread/FGXPCB3ZVCJIV7FX323SBAX2JHYB7ZS4/)
- Full list of compromised packages: https://md.archlinux.org/s/SxbquK6IA
