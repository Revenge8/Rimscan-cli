# Security policy

## Reporting a vulnerability

Please report security issues in rimscan-cli privately through GitHub: open the
repository's **Security** tab and choose **Report a vulnerability**. Do not open a public
issue. Include the version (`rimscan-cli --version`), what you did, and what you
expected, and allow reasonable time for a fix before disclosing publicly.

## Scope

In scope: the code in this repository (for example, secret values leaking into output,
requests sent to hosts that were not meant to be probed, or flaws in the `--authorized`
gating).

Out of scope: findings about third-party services the tool queries, and results from
scanning systems you do not own or have permission to test.

## Using the tool safely

Only scan domains you own or have explicit written permission to test. See the README
section "Scope and safety" for exactly what each option sends.
