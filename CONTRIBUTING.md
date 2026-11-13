# Contributing

1. Create a focused branch and explain the change in the pull request.
2. Keep the CLI database-free and limited to passive or standard, non-intrusive
   checks. Anything that sends probes to the target's own servers must stay
   behind an explicit flag and require `--authorized`.
3. Never add credentials, private targets, or personal data to fixtures or examples.
4. Tests must run offline. Mock DNS and HTTP instead of contacting real hosts.
5. Run `python -m pip install -e ".[dev]"`, `python -m ruff check .` and
   `python -m pytest` before opening a pull request.
6. Preserve the authorization warnings in the CLI and documentation.
7. Unless you state otherwise, contributions you submit are licensed under the
   Apache License 2.0, the same as the project.

Code lives in `rimscan_cli/`: `cli.py` is the thin command-line layer, `scanner.py`
orchestrates a scan, `recon/` holds the individual scanning modules, and `data/` holds
the takeover fingerprints.

Only test domains you own or have explicit permission to assess.
