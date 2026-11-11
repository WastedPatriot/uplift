from pathlib import Path

from uplift.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
QUIET = str(FIXTURES / "linux_quiet.json")
MESSY = str(FIXTURES / "linux_messy.json")
WINDOWS = str(FIXTURES / "windows_messy.json")


def test_cli_exit_codes_and_dry_run(capsys):
    assert main(["--snapshot", QUIET, "--fail-on", "none"]) == 0
    quiet = capsys.readouterr()
    assert "Nothing interesting was found." in quiet.out

    assert main(["--snapshot", MESSY]) == 2
    messy = capsys.readouterr()
    assert "Extra account with uid 0" in messy.out
    assert "SECRET_HASH_VALUE" not in messy.out

    assert main(["--snapshot", WINDOWS, "--fail-on", "critical"]) == 2
    windows = capsys.readouterr()
    assert "LabPassword!" not in windows.out

    assert main(["--snapshot", QUIET, "--dry-run", "--os", "linux"]) == 0
    dry = capsys.readouterr()
    assert "suid_sgid" in dry.out
    assert "No checks were executed" in dry.out

    assert main(["--snapshot", str(FIXTURES / "missing.json")]) == 1
    assert main(["--format", "both"]) == 1


def test_elevator_music_and_up_go_to_stderr(capsys):
    assert main(["--snapshot", QUIET, "--elevator-music", "--up", "--fail-on", "none"]) == 0
    caught = capsys.readouterr()
    assert caught.err.count("[lift] Doors closing.") == 1
    assert "Ding." in caught.err
    assert "Nothing interesting was found." in caught.out


def test_reports_are_written_only_when_asked(tmp_path: Path, capsys):
    output = tmp_path / "report"
    assert main(["--snapshot", MESSY, "--format", "both", "-o", str(output), "--fail-on", "none"]) == 0
    html = (output / "uplift.html").read_text(encoding="utf-8")
    markdown = (output / "uplift.md").read_text(encoding="utf-8")
    assert "<style>" in html
    assert "http://" not in html
    assert "SECRET_HASH_VALUE" not in html
    assert "lab-linux" in markdown
    caught = capsys.readouterr()
    assert "wrote" in caught.out
    assert "Extra account" not in caught.out

    dry_dir = tmp_path / "dry"
    assert main(["--snapshot", QUIET, "--dry-run", "-o", str(dry_dir)]) == 0
    assert not dry_dir.exists()


def test_documented_examples_match_the_readme(capsys):
    root = Path(__file__).resolve().parents[1] / "examples"
    assert main(["--snapshot", str(root / "lab-linux.json"), "--fail-on", "none"]) == 0
    linux = capsys.readouterr().out
    assert "Account 'toor' has uid 0" in linux
    assert "SECRET_HASH_VALUE" not in linux
    assert "EVIL_LIB_PATH" not in linux
    assert main(["--snapshot", str(root / "lab-windows.json"), "--fail-on", "high"]) == 2
    windows = capsys.readouterr().out
    assert "AlwaysInstallElevated is set in both hives" in windows
    assert "LabPassword!" not in windows


def test_live_dry_run_on_this_machine(capsys):
    assert main(["--dry-run", "--os", "linux"]) == 0
    caught = capsys.readouterr()
    assert "capabilities" in caught.out
    assert "would check linux" in caught.out
