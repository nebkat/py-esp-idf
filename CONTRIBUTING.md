# Contributing

## Requirements

- Python 3.10+
- `make` (for the binary build targets)

## Development install

Set up a virtualenv and install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

You can now run the CLI from source:

```bash
python -m idftool --help
```

## Building a standalone binary

The Makefile wraps PyInstaller. The first invocation creates the
`.venv` and installs build dependencies automatically.

```bash
make build           # PyInstaller onedir build → dist-onedir/idftool/
make build-onefile   # single-file binary       → dist/idftool
make install         # onedir → ~/.local/share/idftool, symlinked to ~/.local/bin/idftool
make uninstall
make clean           # remove venv, build/, dist/
```

Make sure `~/.local/bin` is on your `PATH`.

## Releases

Tag a commit on `main` with `vX.Y.Z` and push the tag — CI builds the
binaries and attaches them to a GitHub Release.

```bash
git tag vX.Y.Z
git push origin main vX.Y.Z
```

## Issues and pull requests

File issues and PRs on the
[GitHub repo](https://github.com/nebkat/py-esp-idf). Small, focused PRs
are easiest to review. Run a quick `python -m idftool --help` against
your branch before opening a PR to confirm argparse setup still parses.
