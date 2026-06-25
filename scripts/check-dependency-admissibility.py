#!/usr/bin/env python3
"""Cargo-tree admissibility gate for franken_snowflake.

The gate scans every workspace package across default, no-default, production
feature, combined-production-feature, and dev/test feature lanes. It fails if a
forbidden runtime/framework/ORM crate, fp-io/orc-rust, or a third-party
Snowflake driver appears in any resolved lane.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


GATE = "dependency-admissibility"

FORBIDDEN_PACKAGES = {
    "tokio",
    "reqwest",
    "hyper",
    "hyper-util",
    "axum",
    "tower",
    "tower-http",
    "sqlx",
    "diesel",
    "sea-orm",
    "sea-orm-migration",
    "fp-io",
    "orc-rust",
}

THIRD_PARTY_SNOWFLAKE_PACKAGES = {
    "snowflake",
    "snowflake-api",
    "snowflake-connector",
    "snowflake-driver",
    "snowflake-rs",
    "snowflake-rust",
    "snowflake-sql-api",
    "snowflakedb",
}

CANDIDATE_GROUPS = {
    "fastmcp-rust": {
        "fastmcp-rust",
        "fastmcp",
        "fastmcp-core",
        "fastmcp-transport",
        "fastmcp-protocol",
        "fastmcp-server",
        "fastmcp-client",
        "fastmcp-derive",
        "fastmcp-console",
        "fastmcp-cli",
    },
    "frankensqlite-cache": {
        "fsqlite",
        "fsqlite-ast",
        "fsqlite-btree",
        "fsqlite-core",
        "fsqlite-error",
        "fsqlite-ext-fts5",
        "fsqlite-ext-json",
        "fsqlite-func",
        "fsqlite-mvcc",
        "fsqlite-pager",
        "fsqlite-parser",
        "fsqlite-planner",
        "fsqlite-types",
        "fsqlite-vdbe",
        "fsqlite-vfs",
        "fsqlite-wal",
    },
    "sqlmodel-frankensqlite": {
        "sqlmodel",
        "sqlmodel-core",
        "sqlmodel-frankensqlite",
        "sqlmodel-macros",
        "sqlmodel-query",
        "sqlmodel-schema",
        "sqlmodel-session",
    },
    "frankenpandas-frame": {"fp-columnar", "fp-types", "fp-frame"},
    "jsonwebtoken": {"jsonwebtoken"},
    "fastapi-rust-dev": {
        "fastapi-rust",
        "fastapi",
        "fastapi-openapi",
        "fastapi-output",
        "fastapi-router",
        "fastapi-types",
    },
    "frankensearch": {
        "frankensearch",
        "frankensearch-core",
        "frankensearch-durability",
        "frankensearch-fsfs",
        "frankensearch-fusion",
        "frankensearch-index",
        "frankensearch-lexical",
        "frankensearch-ops",
        "frankensearch-rerank",
        "frankensearch-storage",
    },
    "frankentorch-rerank": {
        "ft-api",
        "ft-autograd",
        "ft-core",
        "ft-data",
        "ft-device",
        "ft-dispatch",
        "ft-kernel-cpu",
        "ft-nn",
        "ft-optim",
        "ft-runtime",
        "ft-serialize",
    },
    "frankentui": {
        "ftui",
        "ftui-a11y",
        "ftui-backend",
        "ftui-core",
        "ftui-extras",
        "ftui-harness",
        "ftui-i18n",
        "ftui-layout",
        "ftui-pty",
        "ftui-render",
        "ftui-runtime",
        "ftui-simd",
        "ftui-style",
        "ftui-text",
        "ftui-tty",
        "ftui-web",
        "ftui-widgets",
    },
    "frankenmermaid": {
        "frankenmermaid-cli",
        "fm-cli",
        "fm-core",
        "fm-layout",
        "fm-parser",
        "fm-regression-harness",
        "fm-render-canvas",
        "fm-render-svg",
        "fm-render-term",
        "fm-wasm",
    },
    "franken-networkx": {
        "fnx-algorithms",
        "fnx-cgse",
        "fnx-classes",
        "fnx-conformance",
        "fnx-convert",
        "fnx-dispatch",
        "fnx-durability",
        "fnx-generators",
        "fnx-readwrite",
        "fnx-runtime",
        "fnx-views",
    },
    "toon": {"tru", "toon"},
}

PRODUCTION_FEATURES = {
    "compression",
    "export",
    "frankenpandas",
    "frankensearch",
    "graph",
    "live",
    "mcp",
    "rerank",
    "toon",
    "tui",
}

DEV_FEATURES = {
    "adapter-fixtures",
    "dev",
    "e2e",
    "fixtures",
    "mock",
    "testkit",
}

PACKAGE_RE = re.compile(r"^([A-Za-z0-9_.+-]+)\s+v[0-9]")


@dataclass(frozen=True)
class Lane:
    package: str
    name: str
    scope: str
    args: tuple[str, ...]


def emit(event: str, **fields: object) -> None:
    payload = {"gate": GATE, "event": event}
    payload.update(fields)
    print(json.dumps(payload, sort_keys=True))


def emit_error(event: str, **fields: object) -> None:
    payload = {"gate": GATE, "event": event}
    payload.update(fields)
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)


def run_command(args: list[str]) -> subprocess.CompletedProcess[str]:
    emit("command_start", command=" ".join(args))
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        emit_error(
            "command_failure",
            command=" ".join(args),
            returncode=result.returncode,
            stderr=result.stderr.strip(),
        )
        raise SystemExit(result.returncode)
    return result


def cargo_metadata() -> dict[str, object]:
    result = run_command(["cargo", "metadata", "--locked", "--format-version", "1"])
    return json.loads(result.stdout)


def package_names_from_tree(tree_output: str) -> set[str]:
    names: set[str] = set()
    for raw_line in tree_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = PACKAGE_RE.match(line)
        if match:
            names.add(match.group(1))
    return names


def candidate_groups_present(packages: set[str]) -> list[str]:
    present: list[str] = []
    for group, group_packages in CANDIDATE_GROUPS.items():
        if packages.intersection(group_packages):
            present.append(group)
    return sorted(present)


def third_party_snowflake_packages(packages: Iterable[str]) -> set[str]:
    offenders: set[str] = set()
    for package in packages:
        if package.startswith("franken-snowflake"):
            continue
        if package in THIRD_PARTY_SNOWFLAKE_PACKAGES:
            offenders.add(package)
        elif "snowflake" in package:
            offenders.add(package)
    return offenders


def violations(packages: set[str]) -> list[str]:
    direct = packages.intersection(FORBIDDEN_PACKAGES)
    snowflake = third_party_snowflake_packages(packages)
    return sorted(direct.union(snowflake))


def classify_features(features: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    production: list[str] = []
    dev: list[str] = []
    for feature in sorted(features):
        if feature == "default":
            continue
        if feature in DEV_FEATURES:
            dev.append(feature)
        elif feature in PRODUCTION_FEATURES:
            production.append(feature)
        else:
            # Fail closed: an unknown feature is treated as production until the
            # harness documents it as test-only.
            production.append(feature)
    return production, dev


def lanes_for_package(package: dict[str, object]) -> list[Lane]:
    name = str(package["name"])
    features = package.get("features", {})
    if not isinstance(features, dict):
        features = {}

    lanes = [
        Lane(
            package=name,
            name="production-default",
            scope="production",
            args=("--edges", "normal,build"),
        ),
        Lane(
            package=name,
            name="production-no-default-features",
            scope="production",
            args=("--no-default-features", "--edges", "normal,build"),
        ),
    ]

    production_features, dev_features = classify_features(features)
    for feature in production_features:
        lanes.append(
            Lane(
                package=name,
                name=f"production-feature:{feature}",
                scope="production-feature",
                args=(
                    "--no-default-features",
                    "--features",
                    feature,
                    "--edges",
                    "normal,build",
                ),
            )
        )

    if production_features:
        lanes.append(
            Lane(
                package=name,
                name="production-features:combined",
                scope="production-feature",
                args=(
                    "--no-default-features",
                    "--features",
                    ",".join(production_features),
                    "--edges",
                    "normal,build",
                ),
            )
        )

    for feature in dev_features:
        lanes.append(
            Lane(
                package=name,
                name=f"dev-feature:{feature}",
                scope="dev-feature",
                args=(
                    "--no-default-features",
                    "--features",
                    feature,
                    "--edges",
                    "all",
                ),
            )
        )

    return lanes


def dedupe_lanes(lanes: Iterable[Lane]) -> list[Lane]:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    deduped: list[Lane] = []
    for lane in lanes:
        key = (lane.package, lane.args)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(lane)
    return deduped


def scan_lane(lane: Lane) -> list[str]:
    command = [
        "cargo",
        "tree",
        "--locked",
        "-p",
        lane.package,
        "--prefix",
        "none",
        "--format",
        "{p}",
        *lane.args,
    ]
    result = run_command(command)
    packages = package_names_from_tree(result.stdout)
    lane_violations = violations(packages)
    emit(
        "lane_verdict",
        package=lane.package,
        lane=lane.name,
        scope=lane.scope,
        package_count=len(packages),
        candidate_groups=candidate_groups_present(packages),
        violations=lane_violations,
    )
    if lane_violations:
        emit_error(
            "lane_failure",
            package=lane.package,
            lane=lane.name,
            scope=lane.scope,
            violations=lane_violations,
        )
    return lane_violations


def run_self_test() -> None:
    synthetic_tree = """
    franken-snowflake-frame v0.0.0 (/repo/crates/franken-snowflake-frame)
    fp-io v0.1.0 (/dp/frankenpandas/crates/fp-io)
    orc-rust v0.8.0
    tokio v1.48.0
    snowflake-rs v0.4.0
    """
    packages = package_names_from_tree(synthetic_tree)
    found = violations(packages)
    expected = {"fp-io", "orc-rust", "tokio", "snowflake-rs"}
    missing = sorted(expected.difference(found))
    if missing:
        emit_error("self_test_failure", missing=missing, found=found)
        raise SystemExit(1)
    emit("self_test_verdict", fixture="fp-io-orc-rust-tokio", violations=found)


def workspace_packages(metadata: dict[str, object]) -> list[dict[str, object]]:
    workspace_members = set(metadata.get("workspace_members", []))
    packages = metadata.get("packages", [])
    if not isinstance(packages, list):
        return []
    selected: list[dict[str, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        if package.get("id") in workspace_members:
            selected.append(package)
    return sorted(selected, key=lambda package: str(package["name"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--self-test-only",
        action="store_true",
        help="run the parser/leak-detection self-test without invoking cargo",
    )
    args = parser.parse_args()

    emit(
        "start",
        cwd=str(Path.cwd()),
        cargo_target_dir=os.environ.get("CARGO_TARGET_DIR"),
        forbidden_packages=sorted(FORBIDDEN_PACKAGES),
        third_party_snowflake_packages=sorted(THIRD_PARTY_SNOWFLAKE_PACKAGES),
    )
    run_self_test()
    if args.self_test_only:
        emit("success", lanes_scanned=0)
        return 0

    metadata = cargo_metadata()
    packages = workspace_packages(metadata)
    all_lanes: list[Lane] = []
    for package in packages:
        all_lanes.extend(lanes_for_package(package))
    lanes = dedupe_lanes(all_lanes)

    emit(
        "scan_plan",
        workspace_packages=[package["name"] for package in packages],
        lanes=[
            {
                "package": lane.package,
                "lane": lane.name,
                "scope": lane.scope,
                "args": list(lane.args),
            }
            for lane in lanes
        ],
    )

    failure_count = 0
    for lane in lanes:
        failure_count += len(scan_lane(lane))

    if failure_count:
        emit_error("failure", lanes_scanned=len(lanes), violation_count=failure_count)
        return 1

    emit("success", lanes_scanned=len(lanes), violation_count=0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
