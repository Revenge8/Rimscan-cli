![RimScan](Rimscan.png)

# Rimscan CLI

![tests](https://github.com/Revenge8/Rimscan-cli/actions/workflows/tests.yml/badge.svg)

Rimscan CLI is a standalone, database-free tool for external attack-surface
reconnaissance of domains you are authorized to test. It discovers subdomains,
resolves DNS and CNAME chains, audits DNS and TLS configuration, checks for common
exposed secrets, and identifies possible subdomain takeover candidates using public
fingerprints.

**Only scan domains you own or have explicit written permission to test.**
This tool is not a license to scan arbitrary third-party infrastructure.

## Installation

Requires Python 3.10 or newer.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
python -m pip install .
```

This installs the `rimscan-cli` command. `python -m rimscan_cli` works as well.

## Usage

```bash
rimscan-cli scan example.com
rimscan-cli scan example.com --output results.json
rimscan-cli scan example.com --authorized --secrets
rimscan-cli scan example.com --authorized --zone-transfer --nuclei
rimscan-cli scan example.com --quiet --fail-on high    # CI use
```

Results are written to **stdout as JSON** (or to a file with `--output`).
The banner, progress lines and the findings summary go to **stderr**, so
`rimscan-cli scan example.com | jq .` always receives clean JSON. Use
`--quiet` to silence stderr completely. See [`examples/example-output.json`](examples/example-output.json)
for the shape of the output.

### Options

| Option | Description |
| --- | --- |
| `--authorized` | Confirm you own the target or may test it. Required by `--secrets`, `--zone-transfer` and `--nuclei`. |
| `--secrets` | Fetch a fixed list of well-known paths (`/.env`, `/config.js`, ...) and look for exposed credentials. |
| `--zone-transfer` | Attempt an AXFR against the domain's nameservers. |
| `--nuclei` | Run [Nuclei](https://github.com/projectdiscovery/nuclei) (installed separately) with `-etags dos,fuzz,intrusive`. |
| `--nuclei-rate-limit N` | Nuclei requests per second (default 75, at least 1). |
| `--include-third-party` | Let `--secrets` and `--nuclei` also probe hosts that CNAME to third-party services. Skipped by default. |
| `--bruteforce` | Also resolve a short list of common subdomain names. |
| `--no-certs` | Skip the TLS certificate audit. |
| `--sources LIST` | Comma-separated enumeration sources (default: all). |
| `--resolver IPS` | Comma-separated DNS resolver addresses. Applies to DNS lookups only; TLS and HTTP probes use the system resolver. |
| `--timeout SECONDS` | Network timeout, greater than 0 (default 10). |
| `-o`, `--output FILE` | Write JSON to a file instead of stdout. If the file cannot be written, the results are printed to stdout instead. |
| `--fail-on LEVEL` | Exit with status 1 if any finding is at or above `info`, `low`, `medium`, `high` or `critical`. |
| `-q`, `--quiet` | No banner, progress, summary or log warnings on stderr. |
| `--no-banner` | Do not print the banner. |
| `--verbose` | Debug logging. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Scan finished (and no finding reached `--fail-on`). |
| 1 | A finding at or above the `--fail-on` severity was reported. |
| 2 | Invalid arguments, a missing `--authorized`, or an output file that could not be written. |
| 3 | With `--fail-on`: no finding reached the threshold, but the scan was incomplete (see below). |
| 130 | Interrupted. |

A scan is **incomplete** when every enumeration source failed or timed out (and
`--bruteforce` was not used), when a DNS lookup in the DNS audit failed (this includes the
nameserver lookups behind `--zone-transfer`), or when at least half of the discovered hosts
could not be resolved (timeouts or errors). A smaller number of failed lookups only adds a
warning. In that case "no findings" does not mean the target is clean: the JSON has
`"incomplete": true`, the reasons are listed under `warnings`, and CI runs using `--fail-on`
exit with status 3 instead of passing silently.

### Output

The JSON document contains `schema_version`, `tool` (name and version), `scanned_at`,
`domain`, `wildcard_dns`, `wildcard_filtered`, `sources` (the outcome of each enumeration
source), `subdomains`, `resolutions`, `takeover_findings`, `dns_findings`, `warnings`,
`incomplete`, and, when enabled, `certificate_findings`, `secret_findings`, `nuclei`,
`active_targets` and `skipped_hosts`. Secret values are redacted in the output: a match is
shown as its first and last four characters, and the surrounding context is built around the
match with every credential found on that line redacted. A private-key finding shows its
`-----BEGIN ... PRIVATE KEY-----` header in full, because the header is public and tells you
what kind of key was exposed; any key material that follows it on the same line is replaced by
`[...]`.

## Data sent to third parties

To find subdomains, the target domain name is sent to these public services:

- [crt.sh](https://crt.sh)
- [Cert Spotter](https://sslmate.com/certspotter)
- [AlienVault OTX](https://otx.alienvault.com)
- [RapidDNS](https://rapiddns.io)
- [Wayback Machine](https://web.archive.org)
- [Anubis (jldc.me)](https://jldc.me)

Use `--sources` to choose a subset. The tool identifies itself with the
User-Agent `rimscan-cli/<version> (+https://rimscan.cloud)`. Nothing is sent
to Rimscan or any other server.

## Scope and safety

This tool combines public data sources with direct network checks:

- **Default scan:** DNS lookups, TLS handshakes with discovered hosts, and at
  most one HTTP request (HTTPS, then HTTP) to hosts whose CNAME points at a known
  third-party service, to check takeover fingerprints. These requests are not retried and
  redirects are not followed.
- **`--bruteforce`:** DNS lookups for a short wordlist.
- **`--secrets`:** GET requests for a fixed list of common paths on every selected host
  (redirects are not followed). A request that fails, including one that breaks while its
  body is being read, only skips that path.
- **`--zone-transfer`:** AXFR requests to the domain's nameservers, using each nameserver's
  A records, or its AAAA records if it has none.
- **`--nuclei`:** the separately installed Nuclei scanner, which sends active
  probes. Excluding the `dos`, `fuzz` and `intrusive` tags is not a guarantee
  that every template is passive.

Safeguards that apply to every active step:

- Hosts that resolve to a non-public address (loopback, private, link-local) are never
  probed, so a subdomain pointed at `127.0.0.1` or a cloud metadata address cannot make the
  tool contact internal services.
- `--secrets` and `--nuclei` skip hosts that CNAME to a known third-party service
  (the takeover fingerprints plus a built-in list of hosting platforms such as GitHub Pages,
  Heroku, Netlify and Shopify), because those servers are not yours. Pass
  `--include-third-party` only if you are authorized to test them. The list of hosts that
  were probed or skipped is in `active_targets` and `skipped_hosts`. The built-in list also
  contains large cloud providers (for example CloudFront, AWS load balancers and Azure web
  apps), so on a target that is mostly hosted there the default active scan can cover only a
  few hosts. Check `skipped_hosts.third_party` before reading "no findings" as "nothing
  exposed".
- `--zone-transfer` never sends a request to a nameserver whose address is non-public.
- Redirect responses are never treated as file content by the secret scan.
- A server-supplied `Retry-After` header is ignored, so a scanned host cannot stall the tool
  by asking it to wait.
- Caps: the TLS audit covers at most 100 hosts and the secret scan at most 50; a warning is
  added to the JSON `warnings` (and logged) when a cap truncates the list.

Use it only against targets you are explicitly authorized to test. Respect
provider terms, rate limits, and the scope of the authorization you received.

The standalone CLI does not include Katana crawling, deep-scan tags, fuzzing,
SQL injection or XSS templates, SaaS authentication, billing, quotas,
notifications, a dashboard, Postgres, Redis, or Celery.

## Limitations and false positives

- **Passive enumeration is incomplete.** Sources only know names that appear in certificate
  transparency logs, passive DNS or web archives. Hosts without a certificate history are
  not found.
- **Takeover results are candidates, not proofs.** `vulnerable` means a fingerprint matched;
  `likely` means the CNAME points at a takeover-prone service or dangles without a
  confirming fingerprint. Verify manually before reporting. Detection works by CNAME suffix:
  services identified by other means (for example nameserver delegation to DigitalOcean)
  and S3 website endpoints are not covered.
- **Wildcard DNS.** Answers that match the zone's wildcard are filtered out. A real host that
  shares its addresses or CNAME target with the wildcard is filtered too; the number of
  filtered hosts is reported as `wildcard_filtered`.
- **DNS audit.** SPF and DMARC are checked at the domain you pass. For a subdomain, DMARC is
  looked up at each parent down to two labels, which can be wrong under multi-label public
  suffixes such as `co.uk`.
- **TLS audit.** Verification uses the certifi CA bundle, a TLS 1.2 floor and non-strict
  X.509 checking, so results are the same on every supported Python version. Findings can
  still differ from what a browser with another trust store reports.
- **Secret scan.** It looks at a fixed list of paths only. The 40-character AWS secret
  pattern is reported only when "aws" or "secret" appears next to it and its entropy is high.
- **Enumeration sources fail often** (rate limits are common). Check `sources` and
  `warnings` in the output. The crt.sh response is read up to 50 MB; for a domain with more
  certificates than that, the source is reported as failed instead of returning a partial list.
- **DNS rebinding.** Non-public addresses are rejected using the lookup done during the scan.
  A host's DNS could answer differently when the probe connects; the tool does not pin the
  connection to the checked address.

## Rimscan, the hosted platform

`rimscan-cli` runs locally, on demand, and performs one-off reconnaissance.

[Rimscan](https://rimscan.cloud) is a hosted web platform built on the same reconnaissance
engine. Instead of running commands, you add a domain in a dashboard. The platform adds:

- **Continuous monitoring** on the Pro plan: targets are re-scanned automatically every
  two days.
- **Deep Scan** (Pro): active crawling with Katana and payload-based testing for issues such
  as SQL injection and XSS. This is intentionally outside the scope of this CLI.
- **A dashboard** with scan history and findings, severity and CVE information, and a
  per-finding triage status.

See [rimscan.cloud](https://rimscan.cloud) for current plans and availability.

## Development

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest
```

The test suite runs offline: all network and DNS access is mocked.

## License

This project is source-available under the Elastic License 2.0. See
[LICENSE](LICENSE) for the complete license text. The takeover fingerprints are
sourced from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz);
see [NOTICE](NOTICE) and review that project's terms before redistributing the fingerprint data.
