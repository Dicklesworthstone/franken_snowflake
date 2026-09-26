#!/usr/bin/env python3
"""Fail when a crate's line coverage drops below its recorded floor.

Why this exists (bead oj0.43): the plan's testing standard says coverage is
tracked and cannot silently regress. It is a regression floor, never a target:
no test is written to raise the number. The floors live in docs/proof_lanes.md
between the `coverage-floor` markers (baseline minus 2 points, measured with
`cargo llvm-cov --workspace`). This gate runs in the release proof
(docs/RELEASE.md). Retire it if a better regression signal replaces it.

    check-coverage-floor.py                      measure, then compare
    check-coverage-floor.py --summary FILE       compare an existing
                                                 `cargo llvm-cov --json --summary-only` export
    check-coverage-floor.py --print-baseline ... print table rows for a new
                                                 baseline (never written automatically: raising
                                                 or lowering a floor is a reviewed doc change)

Prints one JSON line per crate ({crate, line_percent, floor, verdict}) and
exits 1 when a crate is below its floor, missing from the measurement, or
measured but absent from the table.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BEGIN = "<!-- coverage-floor:begin -->"
END = "<!-- coverage-floor:end -->"
ROW = re.compile(r"^\|\s*`?([a-z0-9-]+)`?\s*\|\s*([0-9.]+)\s*\|\s*([0-9.]+)\s*\|")
CRATE = re.compile(r"/crates/([a-z0-9-]+)/src/")


def floors(proof_lanes: str) -> dict[str, float]:
    start, end = proof_lanes.find(BEGIN), proof_lanes.find(END)
    if start < 0 or end < start:
        raise SystemExit("docs/proof_lanes.md has no coverage-floor table")
    table: dict[str, float] = {}
    for line in proof_lanes[start:end].splitlines():
        match = ROW.match(line)
        if match:
            table[match.group(1)] = float(match.group(3))
    return table


def per_crate(summary: dict) -> dict[str, float]:
    """Line coverage per crate from the llvm-cov export, library sources only
    (`crates/<crate>/src/`), summed over files."""
    totals: dict[str, list[int]] = {}
    for export in summary.get("data", []):
        for entry in export.get("files", []):
            match = CRATE.search(entry.get("filename", "").replace("\\", "/"))
            if not match:
                continue
            lines = entry.get("summary", {}).get("lines", {})
            count, covered = totals.setdefault(match.group(1), [0, 0])
            totals[match.group(1)] = [count + lines.get("count", 0), covered + lines.get("covered", 0)]
    return {
        crate: round(100.0 * covered / count, 1)
        for crate, (count, covered) in totals.items()
        if count
    }


def measure(root: Path) -> dict:
    with tempfile.TemporaryDirectory() as scratch:
        out = Path(scratch) / "coverage-summary.json"
        result = subprocess.run(
            ["cargo", "llvm-cov", "--workspace", "--locked", "--json", "--summary-only",
             "--output-path", str(out)],
            cwd=root, check=False, timeout=7200,
        )
        if result.returncode != 0:
            raise SystemExit(f"cargo llvm-cov failed with exit {result.returncode}")
        return json.loads(out.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--summary", help="an existing `cargo llvm-cov --json --summary-only` export")
    parser.add_argument("--print-baseline", metavar="DATE",
                        help="print table rows (baseline, floor = baseline - 2) and exit")
    args = parser.parse_args()
    root = Path(args.root)
    try:
        summary = (json.loads(Path(args.summary).read_text(encoding="utf-8"))
                   if args.summary else measure(root))
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"summary": "unusable", "reason": str(error)}))
        return 2
    measured = per_crate(summary)
    if args.print_baseline:
        for crate, percent in sorted(measured.items()):
            print(f"| `{crate}` | {percent:.1f} | {max(percent - 2.0, 0.0):.1f} |")
        return 0
    table = floors((root / "docs/proof_lanes.md").read_text(encoding="utf-8"))
    failed = 0
    for crate in sorted(set(table) | set(measured)):
        percent, floor = measured.get(crate), table.get(crate)
        if percent is None:
            verdict, reason = "fail", "not measured (crate gone or its tests did not run)"
        elif floor is None:
            verdict, reason = "fail", "measured but absent from the floor table"
        elif percent < floor:
            verdict, reason = "fail", f"below its floor by {floor - percent:.1f} points"
        else:
            verdict, reason = "pass", ""
        failed += verdict == "fail"
        print(json.dumps({"crate": crate, "line_percent": percent, "floor": floor,
                          "verdict": verdict, "reason": reason}, sort_keys=True))
    print(json.dumps({"crates": len(set(table) | set(measured)), "failed": failed}), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
