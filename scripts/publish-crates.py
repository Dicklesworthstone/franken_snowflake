#!/usr/bin/env python3
"""Publish franken_snowflake crates to crates.io in topological order.

Respects crates.io rate limits and dependency propagation delays.
"""

import datetime
import email.utils
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import urllib.error

USER_AGENT = "OpenAI File Downloader, XaiImageApiFetch/1.0"

# Topological order of publishing
CRATES = [
    ("franken-snowflake-core", False),
    ("franken-snowflake-auth", False),
    ("franken-snowflake-frame", False),
    ("franken-snowflake-http", False),
    ("franken-snowflake-sqlapi", True),  # dev-dep cycle with testkit requires --no-verify
    ("franken-snowflake-testkit", False),
    ("franken-snowflake-cache", False),
    ("franken-snowflake-catalog", False),
    ("franken-snowflake-export", False),
    ("franken-snowflake-graph", False),
    ("franken-snowflake-text-indexing", False),
    ("franken-snowflake-mcp", False),
    ("franken-snowflake-tui", False),
    ("franken-snowflake-cli", False),
]

TARGET_VERSION = "0.0.4"


def is_already_published(crate_name: str, version: str) -> bool:
    url = f"https://crates.io/api/v1/crates/{crate_name}/{version}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("version", {}).get("num") == version
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        print(f"[{crate_name}] crates.io query HTTP {e.code}: {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[{crate_name}] crates.io query error: {e}", file=sys.stderr)
        return False
    return False


def wait_until_after(target_dt: datetime.datetime):
    now = datetime.datetime.now(datetime.timezone.utc)
    delay = (target_dt - now).total_seconds()
    if delay > 0:
        print(f"Sleeping {delay:.1f}s until {target_dt.isoformat()}...", flush=True)
        time.sleep(delay + 2)


def parse_rate_limit_reset(stderr_text: str) -> datetime.datetime | None:
    # Example: "Please try again after Sat, 12 Sep 2026 02:13:06 GMT"
    m = re.search(r"Please try again after\s+([A-Za-z0-9, :]+GMT)", stderr_text)
    if m:
        try:
            parsed = email.utils.parsedate_to_datetime(m.group(1))
            return parsed
        except Exception:
            pass
    return None


def publish_crate(crate_name: str, no_verify: bool, dry_run: bool = False) -> bool:
    if is_already_published(crate_name, TARGET_VERSION):
        print(f"✓ {crate_name} v{TARGET_VERSION} is already published on crates.io.")
        return True

    cmd = ["cargo", "publish", "--allow-dirty", "-p", crate_name]
    if no_verify:
        cmd.append("--no-verify")

    if dry_run:
        print(f"[DRY-RUN] Would run: {' '.join(cmd)}")
        return True

    max_attempts = 10
    for attempt in range(1, max_attempts + 1):
        print(f"[{attempt}/{max_attempts}] Publishing {crate_name} v{TARGET_VERSION}: {' '.join(cmd)}...")
        proc = subprocess.run(
            cmd,
            cwd="/data/projects/franken_snowflake",
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            print(f"✓ Published {crate_name} v{TARGET_VERSION} successfully!")
            print("Waiting 15 seconds for index propagation...")
            time.sleep(15)
            return True

        output = proc.stdout + "\n" + proc.stderr
        print(f"Publish failed (exit {proc.returncode}):\n{output}", file=sys.stderr)

        if "already uploaded" in output or "already exists" in output:
            print(f"✓ {crate_name} was already uploaded.")
            return True

        if "429 Too Many Requests" in output or "status 429" in output:
            reset_dt = parse_rate_limit_reset(output)
            if reset_dt:
                wait_until_after(reset_dt)
                continue
            else:
                print("Rate limited without parsed reset time. Waiting 120s...", flush=True)
                time.sleep(120)
                continue

        # If dependency index propagation issue (e.g., crate franken-snowflake-* not found in index yet)
        if "could not find" in output or "failed to select a version" in output or "no matching package named" in output:
            print("Dependency index not updated yet on crates.io. Waiting 20s and retrying...", flush=True)
            time.sleep(20)
            continue

        # Unrecoverable error
        print(f"Fatal error publishing {crate_name}", file=sys.stderr)
        return False

    return False


def main():
    dry_run = "--dry-run" in sys.argv
    single_crate = None
    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            single_crate = arg

    crates_to_publish = CRATES
    if single_crate:
        crates_to_publish = [(c, nv) for c, nv in CRATES if c == single_crate]
        if not crates_to_publish:
            print(f"Unknown crate: {single_crate}", file=sys.stderr)
            sys.exit(1)

    print(f"Starting crates.io publishing pipeline for franken_snowflake v{TARGET_VERSION}...")
    for idx, (crate_name, no_verify) in enumerate(crates_to_publish, start=1):
        print(f"\n========================================================")
        print(f"[{idx}/{len(crates_to_publish)}] Processing {crate_name}")
        print(f"========================================================")
        ok = publish_crate(crate_name, no_verify, dry_run=dry_run)
        if not ok:
            print(f"Pipeline stopped due to error on {crate_name}", file=sys.stderr)
            sys.exit(1)

    print("\n✓ All crates successfully published to crates.io!")


if __name__ == "__main__":
    main()
