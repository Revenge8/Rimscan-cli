# Rimscan CLI

Rimscan CLI is a standalone, database-free passive reconnaissance tool for
authorized security testing. It discovers subdomains, resolves DNS and CNAME
chains, audits DNS and TLS configuration, checks for common exposed secrets,
and identifies possible subdomain takeover candidates using public
fingerprints.

**Only scan domains you own or have explicit written permission to test.**
This tool is not a license to scan arbitrary third-party infrastructure.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

```bash
python -m rimscan_cli scan example.com --output results.json
python -m rimscan_cli scan example.com --authorized --secrets
python -m rimscan_cli scan example.com --authorized --zone-transfer --nuclei
```

The `--secrets` option performs HTTP requests to common public paths and
therefore requires an explicit `--authorized` confirmation. Results are printed
as JSON and can also be written with `--output`.

When `--nuclei` is used, the CLI invokes Nuclei with the fixed exclusion:

```text
-etags dos,fuzz,intrusive
```

The standalone CLI does not include Katana crawling, deep-scan tags, fuzzing,
SQL injection or XSS templates, SaaS authentication, billing, quotas,
notifications, a dashboard, Postgres, Redis, or Celery.

## Scope and safety

This repository intentionally performs discovery and standard read-only
auditing. It does not attempt exploitation or intrusive testing. Respect
provider terms, rate limits, and the scope of the authorization you received.

Want continuous monitoring, active vulnerability testing, and a dashboard?
Check out [Rimscan Cloud](https://rimscan.cloud).

## Development

```bash
python -m pytest
python -m rimscan_cli --help
```

## License

This project is available under the Elastic License 2.0. See [LICENSE](LICENSE)
for the complete license text. The takeover fingerprints are sourced from
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz);
review that project's terms before redistributing the fingerprint data.
