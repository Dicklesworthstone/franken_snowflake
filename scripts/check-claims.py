#!/usr/bin/env python3
"""Check the README's load-bearing capability claims against their evidence.

Why this exists (bead oj0.4): the 2026-09-23 audit found more than fifteen
README/CHANGELOG sentences that were false or had outlived their evidence. This
gate is part of the release proof (docs/RELEASE.md "Required Local Proof",
`dsr quality franken_snowflake`). Retire it once README claims are generated
from evidence instead of written by hand.

The ledger is docs/claims.toml, one [[claim]] per tagged README sentence:

    id            stable id; the README carries <!-- claim:<id> --> beside it
    heading       the README heading the claim sits under (without the #s)
    text          a verbatim substring of the claim (whitespace is normalized)
    evidence      list of "test:<package>::<test path>" | "live:<step>" |
                  "dsr:<run id>" | "manual:<note>"
    date          YYYY-MM-DD; required when evidence has dsr: or manual:
    max_age_days  optional age limit; live: evidence defaults to 30

Checks: every tag has an entry and every entry a tag; the heading exists and
its section holds both the text and the tag; every test: names a test that
`cargo test -p <package> --all-features -- --list` reports; live: evidence is
in docs/live_proof_state.json ({"steps": {"<step>": {"date": ..., "sha": ...}}}),
younger than its max_age_days and, with --release-sha, recorded for that sha;
dated evidence is younger than max_age_days when one is set.

Prints one JSON line per claim ({id, verdict, evidence, reasons}); exits 1 when
any claim fails, 2 when the ledger itself is unusable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

TAG = re.compile(r"<!--\s*claim:([a-z0-9][a-z0-9-]*)\s*-->")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")
LIVE_DEFAULT_MAX_AGE_DAYS = 30


def normalize(text: str) -> str:
    return " ".join(TAG.sub(" ", text).split())


def sections(readme: str) -> dict[str, str]:
    """Heading text -> the section body (up to the next heading of the same or a
    higher level). Fenced code blocks are not headings."""
    lines = readme.splitlines()
    marks = []
    fenced = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        match = None if fenced else HEADING.match(line)
        if match:
            marks.append((index, len(match.group(1)), match.group(2)))
    found: dict[str, str] = {}
    for position, (start, level, title) in enumerate(marks):
        end = len(lines)
        for later_start, later_level, _ in marks[position + 1:]:
            if later_level <= level:
                end = later_start
                break
        found.setdefault(title, "\n".join(lines[start + 1:end]))
    return found


def parse_listing(listing: str) -> dict[str, set[str]]:
    """`@@package <name>` blocks of libtest `--list --format terse` output."""
    tests: dict[str, set[str]] = {}
    package = None
    for line in listing.splitlines():
        if line.startswith("@@package "):
            package = line.split(" ", 1)[1].strip()
            tests.setdefault(package, set())
        elif package and (line.endswith(": test") or line.endswith(": benchmark")):
            tests[package].add(line.rsplit(": ", 1)[0])
    return tests


def cargo_listing(packages: list[str]) -> str:
    out = []
    for package in packages:
        result = subprocess.run(
            ["cargo", "test", "--locked", "-p", package, "--all-features", "--",
             "--list", "--format", "terse"],
            capture_output=True, text=True, check=False, timeout=3600,
        )
        if result.returncode != 0:
            sys.stderr.write(result.stderr[-4000:])
            raise SystemExit(f"cargo test --list failed for {package}")
        out.append(f"@@package {package}\n{result.stdout}")
    return "\n".join(out)


def age_days(date_text: str, today: dt.date) -> int:
    return (today - dt.date.fromisoformat(date_text)).days


def check(readme: str, ledger: dict, tests: dict[str, set[str]] | None,
          live_state: dict | None, today: dt.date,
          release_sha: str | None) -> list[dict]:
    claims = ledger.get("claim", [])
    results: list[dict] = []
    by_id: dict[str, dict] = {}
    for claim in claims:
        claim_id = claim.get("id", "")
        if claim_id in by_id:
            results.append({"id": claim_id, "verdict": "fail", "evidence": [],
                            "reasons": ["duplicate ledger id"]})
        by_id[claim_id] = claim
    tags = TAG.findall(readme)
    for tag in sorted(set(tags)):
        if tags.count(tag) > 1:
            results.append({"id": tag, "verdict": "fail", "evidence": [],
                            "reasons": ["the README tags this claim more than once"]})
        if tag not in by_id:
            results.append({"id": tag, "verdict": "fail", "evidence": [],
                            "reasons": ["tagged in the README but missing from the ledger"]})
    heading_sections = sections(readme)
    steps = (live_state or {}).get("steps", {})
    for claim_id, claim in by_id.items():
        reasons: list[str] = []
        evidence = claim.get("evidence", [])
        if isinstance(evidence, str):
            evidence = [evidence]
        if not evidence:
            reasons.append("no evidence")
        if claim_id not in tags:
            reasons.append("in the ledger but untagged in the README")
        section = heading_sections.get(claim.get("heading", ""))
        if section is None:
            reasons.append(f"heading not found: {claim.get('heading')!r}")
        else:
            if normalize(claim.get("text", "")) not in normalize(section):
                reasons.append("anchor text not found under its heading")
            if f"claim:{claim_id}" not in section.replace(" ", ""):
                reasons.append("the tag is not under the claim's heading")
        dated = any(item.split(":", 1)[0] in ("dsr", "manual") for item in evidence)
        max_age = claim.get("max_age_days")
        if dated:
            if "date" not in claim:
                reasons.append("dsr:/manual: evidence needs a date")
            elif max_age is not None and age_days(claim["date"], today) > max_age:
                reasons.append(f"evidence dated {claim['date']} is older than {max_age} days")
        for item in evidence:
            kind, _, rest = item.partition(":")
            if kind == "test":
                package, _, name = rest.partition("::")
                if tests is None:
                    reasons.append("no test listing to resolve test: evidence")
                elif name not in tests.get(package, set()):
                    reasons.append(f"no such test in {package}: {name}")
            elif kind == "live":
                step = steps.get(rest)
                limit = max_age if max_age is not None else LIVE_DEFAULT_MAX_AGE_DAYS
                if step is None:
                    reasons.append(f"no live proof state for step {rest!r}")
                elif age_days(step["date"], today) > limit:
                    reasons.append(f"live step {rest!r} ran {step['date']}, over {limit} days ago")
                elif release_sha and step.get("sha") != release_sha:
                    reasons.append(f"live step {rest!r} ran on {step.get('sha')}, not {release_sha}")
            elif kind not in ("dsr", "manual"):
                reasons.append(f"unknown evidence kind: {item!r}")
        results.append({"id": claim_id, "verdict": "fail" if reasons else "pass",
                        "evidence": evidence, "reasons": reasons})
    return results


def self_test() -> int:
    """The negative cases the gate must catch, plus the baseline that passes."""
    today = dt.date(2026, 9, 26)
    readme = (
        "# Title\n\n## Features\n\nThe driver cancels on drop. <!-- claim:drop -->\n"
        "It is fresh live. <!-- claim:fresh -->\n\n## Other\n\nUnrelated text.\n"
    )
    ledger = {"claim": [
        {"id": "drop", "heading": "Features", "text": "The driver cancels on drop.",
         "evidence": ["test:franken-snowflake-sqlapi::driver::tests::drop_cancels"]},
        {"id": "fresh", "heading": "Features", "text": "It is fresh live.",
         "evidence": ["live:read"]},
    ]}
    tests = {"franken-snowflake-sqlapi": {"driver::tests::drop_cancels"}}
    live = {"steps": {"read": {"date": "2026-09-20", "sha": "abc"}}}

    def failed(results: list[dict]) -> set[str]:
        return {result["id"] for result in results if result["verdict"] == "fail"}

    cases = {
        "baseline passes": failed(check(readme, ledger, tests, live, today, None)) == set(),
        "live evidence 31 days old fails": "fresh" in failed(check(
            readme, ledger, tests, {"steps": {"read": {"date": "2026-08-26", "sha": "abc"}}},
            today, None)),
        "a renamed cited test fails": "drop" in failed(check(
            readme, ledger, {"franken-snowflake-sqlapi": {"driver::tests::renamed"}},
            live, today, None)),
        "a tagged sentence without a ledger entry fails": "orphan" in failed(check(
            readme + "\nMore. <!-- claim:orphan -->\n", ledger, tests, live, today, None)),
        "a ledger entry without a README tag fails": "drop" in failed(check(
            readme.replace("<!-- claim:drop -->", ""), ledger, tests, live, today, None)),
        "anchor text under the wrong heading fails": "drop" in failed(check(
            readme, {"claim": [dict(ledger["claim"][0], heading="Other"), ledger["claim"][1]]},
            tests, live, today, None)),
        "live evidence for another release sha fails": "fresh" in failed(check(
            readme, ledger, tests, live, today, "def")),
    }
    for name, behaved in cases.items():
        print(json.dumps({"self_test": name, "behaved": behaved}))
    return 0 if all(cases.values()) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--test-list", help="precomputed `@@package` test listing")
    parser.add_argument("--write-test-list", help="run cargo, save the listing here, then check")
    parser.add_argument("--today", help="YYYY-MM-DD (default: today)")
    parser.add_argument("--release-sha", help="require live evidence recorded for this sha")
    parser.add_argument("--self-test", action="store_true", help="prove the negative cases")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    root = Path(args.root)
    try:
        ledger = tomllib.loads((root / "docs/claims.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"ledger": "unusable", "reason": str(error)}))
        return 2
    readme = (root / "README.md").read_text(encoding="utf-8")
    packages = sorted({
        item.split(":", 1)[1].split("::", 1)[0]
        for claim in ledger.get("claim", [])
        for item in (claim.get("evidence") or [])
        if item.startswith("test:")
    })
    if args.test_list:
        listing = Path(args.test_list).read_text(encoding="utf-8")
    else:
        listing = cargo_listing(packages)
        if args.write_test_list:
            Path(args.write_test_list).write_text(listing, encoding="utf-8")
    live_path = root / "docs/live_proof_state.json"
    try:
        live_state = (
            json.loads(live_path.read_text(encoding="utf-8")) if live_path.exists() else None
        )
    except (OSError, json.JSONDecodeError) as error:
        print(json.dumps({"live_proof_state": "unusable", "reason": str(error)}))
        return 2
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()
    results = check(readme, ledger, parse_listing(listing), live_state, today, args.release_sha)
    for result in results:
        print(json.dumps(result, sort_keys=True))
    failed = [result for result in results if result["verdict"] == "fail"]
    print(json.dumps({"claims": len(results), "failed": len(failed)}), file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
