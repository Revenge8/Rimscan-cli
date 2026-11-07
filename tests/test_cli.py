import json
import subprocess
import sys
from pathlib import Path

import pytest

from rimscan_cli import cli
from rimscan_cli.recon.dns_audit import AuditSeverity, DNSAuditFinding
from rimscan_cli.recon.resolver import ResolutionResult, ResolutionStatus
from rimscan_cli.recon.secrets import SecretFinding
from rimscan_cli.recon.takeover import TakeoverFinding, TakeoverVerdict

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


@pytest.mark.parametrize("value,expected", [
    ("Example.COM", "example.com"),
    ("example.com.", "example.com"),
    ("bücher.de", "xn--bcher-kva.de"),
    ("a-b.example.co.uk", "a-b.example.co.uk"),
])
def test_normalize_accepts(value, expected):
    assert cli.normalize_domain(value) == expected


@pytest.mark.parametrize("value", [
    "", "localhost", "1.2.3.4", "::1", "https://example.com", "example.com/path",
    "user@example.com", "example.com:8080", "-bad.example.com", "a..b.com", "has space.com", "x" * 64 + ".com",
])
def test_normalize_rejects(value):
    with pytest.raises(ValueError):
        cli.normalize_domain(value)


@pytest.mark.parametrize("flag", ["--secrets", "--nuclei", "--zone-transfer"])
def test_active_flags_require_authorization(flag, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["scan", "example.com", flag, "--quiet"])
    assert exit_info.value.code == 2
    assert "--authorized" in capsys.readouterr().err


def test_unknown_source_and_bad_resolver_are_usage_errors(capsys):
    for extra in (["--sources", "nope"], ["--resolver", "not-an-ip"]):
        with pytest.raises(SystemExit) as exit_info:
            cli.main(["scan", "example.com", "-q", *extra])
        assert exit_info.value.code == 2


def fake_result():
    return {
        "domain": "example.com",
        "resolutions": [ResolutionResult("example.com", ResolutionStatus.A_RECORD, a_records=["1.1.1.1"])],
        "takeover_findings": [TakeoverFinding("a.example.com", TakeoverVerdict.VULNERABLE, "Ghost", ["x.ghost.io"], "e")],
        "dns_findings": [DNSAuditFinding("spf", AuditSeverity.MEDIUM, "example.com", "d")],
        "secret_findings": [SecretFinding("aws_access_key", "https://example.com/.env", 1, match=AWS_KEY, context=f"k={AWS_KEY}")],
        "nuclei": {"status": "completed", "findings": [{"severity": "critical"}]},
    }


def test_serialization_enums_and_secret_redaction():
    out = json.dumps(cli._to_jsonable(fake_result()))
    assert AWS_KEY not in out
    assert '"takeover_findings": [{"hostname": "a.example.com", "verdict": "vulnerable"' in out
    assert "AKIA...MPLE" in out


def test_severity_counts():
    counts = cli.severity_counts(cli._to_jsonable(fake_result()))
    assert counts == {"high": 2, "medium": 1, "critical": 1}


@pytest.fixture()
def patched_scan(monkeypatch):
    monkeypatch.setattr(cli, "scan_domain", lambda domain, **kw: cli._to_jsonable(fake_result()))
    monkeypatch.setattr(cli, "render_banner", lambda: print("BANNER"))


def test_stdout_is_pure_json_even_with_banner_and_progress(patched_scan, capsys):
    assert cli.main(["scan", "example.com"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["domain"] == "example.com"
    assert "BANNER" in captured.err and "findings:" in captured.err


def test_quiet_silences_stderr(patched_scan, capsys):
    cli.main(["scan", "example.com", "-q"])
    assert capsys.readouterr().err == ""


def test_output_file_not_duplicated_on_stdout(patched_scan, capsys, tmp_path):
    target = tmp_path / "nested" / "out.json"
    assert cli.main(["scan", "example.com", "-q", "-o", str(target)]) == 0
    assert capsys.readouterr().out == ""
    assert json.loads(target.read_text())["domain"] == "example.com"


def test_unwritable_output_returns_2_without_traceback(patched_scan, capsys, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    assert cli.main(["scan", "example.com", "-q", "-o", str(blocker / "out.json")]) == 2
    assert "cannot write" in capsys.readouterr().err


@pytest.mark.parametrize("level,code", [("none", 0), ("low", 1), ("critical", 1)])
def test_fail_on(patched_scan, level, code):
    assert cli.main(["scan", "example.com", "-q", "--fail-on", level]) == code


def test_fail_on_threshold_not_reached(monkeypatch):
    only_low = {"domain": "example.com", "dns_findings": [{"severity": "low"}]}
    monkeypatch.setattr(cli, "scan_domain", lambda domain, **kw: only_low)
    assert cli.main(["scan", "example.com", "-q", "--fail-on", "high"]) == 0


def test_nuclei_missing_binary(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert cli.run_nuclei(["a.example.com"])["status"] == "skipped"


def test_nuclei_command_and_parsing(monkeypatch):
    captured = {}
    line = json.dumps({"template-id": "t1", "host": "a.example.com", "matched-at": "https://a.example.com",
                       "info": {"name": "N", "severity": "high", "tags": ["cve"],
                                "classification": {"cve-id": ["CVE-2024-1"]}}})

    def fake_run(command, **kw):
        captured.update(command=command, kw=kw)
        return subprocess.CompletedProcess(command, 0, stdout=line + "\nnot json\n", stderr="")

    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    result = cli.run_nuclei(["a.example.com", "a.example.com"], rate_limit=20, timeout=99)
    command = captured["command"]
    assert command[command.index("-etags") + 1] == "dos,fuzz,intrusive"
    assert command[command.index("-rate-limit") + 1] == "20"
    assert captured["kw"]["timeout"] == 99
    assert result["findings"] == [{"template_id": "t1", "name": "N", "severity": "high", "host": "a.example.com",
                                   "matched_at": "https://a.example.com", "tags": ["cve"], "cve": ["CVE-2024-1"]}]


def test_nuclei_timeout_keeps_partial_output(monkeypatch):
    def fake_run(command, **kw):
        raise subprocess.TimeoutExpired(command, 1, output=b'{"template-id": "t", "info": {"severity": "low"}}\n')

    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    result = cli.run_nuclei(["a.example.com"], timeout=1)
    assert result["status"] == "timeout" and result["findings"][0]["template_id"] == "t"


def test_module_entrypoint_does_not_run_on_import():
    proc = subprocess.run(
        [sys.executable, "-c", "import rimscan_cli.__main__"], capture_output=True, text=True,
        cwd=Path(__file__).resolve().parents[1],
    )
    assert proc.returncode == 0 and proc.stderr == ""
