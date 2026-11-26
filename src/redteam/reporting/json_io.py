from __future__ import annotations

from pathlib import Path

from redteam.models import RunReport


def save_report(report: RunReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_report(path: Path) -> RunReport:
    return RunReport.model_validate_json(Path(path).read_text(encoding="utf-8"))
