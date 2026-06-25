#!/usr/bin/env python3
"""Cargo-tree admissibility gate for franken_snowflake.

The gate scans every workspace package across default, no-default, production
feature, combined-production-feature, and dev/test feature lanes. It fails if a
forbidden runtime/framework/ORM crate, fp-io/orc-rust, a third-party Snowflake
driver, or more than one version of the single-version Franken runtime packages
appears in any resolved lane.
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
FSNOW_SKIP_FSQLITE_WINDOWS_PREREQ = "FSNOW_SKIP_FSQLITE_WINDOWS_PREREQ"
WORKSPACE_LANE_PACKAGE = "<workspace>"

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

SINGLE_VERSION_PACKAGES = {
    "asupersync",
    "asupersync-macros",
    "franken-decision",
    "franken-evidence",
    "franken-kernel",
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
PACKAGE_VERSION_RE = re.compile(r"^([A-Za-z0-9_.+-]+)\s+v([0-9][^\s]*)")


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


def package_versions_from_tree(tree_output: str) -> dict[str, set[str]]:
    versions: dict[str, set[str]] = {}
    for raw_line in tree_output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = PACKAGE_VERSION_RE.match(line)
        if match:
            versions.setdefault(match.group(1), set()).add(match.group(2))
    return versions


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


def single_version_violations(
    package_versions: dict[str, set[str]],
) -> list[dict[str, object]]:
    lane_violations: list[dict[str, object]] = []
    for package in sorted(SINGLE_VERSION_PACKAGES):
        versions = sorted(package_versions.get(package, set()))
        if len(versions) > 1:
            lane_violations.append({"package": package, "versions": versions})
    return lane_violations


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


def package_features(package: dict[str, object]) -> dict[str, list[str]]:
    features = package.get("features", {})
    if not isinstance(features, dict):
        return {}
    return features


def production_feature_owners(packages: list[dict[str, object]]) -> dict[str, list[str]]:
    owners: dict[str, list[str]] = {feature: [] for feature in sorted(PRODUCTION_FEATURES)}
    for package in packages:
        name = str(package["name"])
        for feature in package_features(package):
            if feature in PRODUCTION_FEATURES:
                owners[feature].append(name)
    return {feature: sorted(names) for feature, names in owners.items() if names}


def enforce_production_feature_coverage(packages: list[dict[str, object]]) -> int:
    owners = production_feature_owners(packages)
    missing = sorted(PRODUCTION_FEATURES.difference(owners))
    emit("production_feature_coverage", feature_owners=owners, missing_features=missing)
    if missing:
        emit_error(
            "production_feature_coverage_failure",
            missing_features=missing,
            remediation=(
                "Add an explicit feature alias to the owning workspace crate or "
                "remove the feature from PRODUCTION_FEATURES if it is no longer a "
                "supported production policy lane."
            ),
        )
    return len(missing)


def lanes_for_package(package: dict[str, object]) -> list[Lane]:
    name = str(package["name"])
    features = package_features(package)

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


def workspace_feature_lanes(packages: list[dict[str, object]]) -> list[Lane]:
    owners = production_feature_owners(packages)
    lanes = [
        Lane(
            package=WORKSPACE_LANE_PACKAGE,
            name="workspace-production-no-default-features",
            scope="workspace-production",
            args=("--workspace", "--no-default-features", "--edges", "normal,build"),
        )
    ]

    for feature in sorted(owners):
        lanes.append(
            Lane(
                package=WORKSPACE_LANE_PACKAGE,
                name=f"workspace-production-feature:{feature}",
                scope="workspace-production-feature",
                args=(
                    "--workspace",
                    "--no-default-features",
                    "--features",
                    feature,
                    "--edges",
                    "normal,build",
                ),
            )
        )

    if owners:
        lanes.append(
            Lane(
                package=WORKSPACE_LANE_PACKAGE,
                name="workspace-production-features:combined",
                scope="workspace-production-feature",
                args=(
                    "--workspace",
                    "--no-default-features",
                    "--features",
                    ",".join(sorted(owners)),
                    "--edges",
                    "normal,build",
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


def scan_lane(lane: Lane) -> int:
    command = ["cargo", "tree", "--locked"]
    if lane.package == WORKSPACE_LANE_PACKAGE:
        command.extend(lane.args)
    else:
        command.extend(["-p", lane.package, *lane.args])
    command.extend(["--prefix", "none", "--format", "{p}"])
    result = run_command(command)
    packages = package_names_from_tree(result.stdout)
    package_versions = package_versions_from_tree(result.stdout)
    lane_violations = violations(packages)
    lane_single_version_violations = single_version_violations(package_versions)
    emit(
        "lane_verdict",
        package=lane.package,
        lane=lane.name,
        scope=lane.scope,
        package_count=len(packages),
        candidate_groups=candidate_groups_present(packages),
        violations=lane_violations,
        single_version_violations=lane_single_version_violations,
    )
    if lane_violations or lane_single_version_violations:
        emit_error(
            "lane_failure",
            package=lane.package,
            lane=lane.name,
            scope=lane.scope,
            violations=lane_violations,
            single_version_violations=lane_single_version_violations,
        )
    return len(lane_violations) + len(lane_single_version_violations)


def is_fsqlite_windows_prereq_lane(lane: Lane) -> bool:
    return (
        sys.platform.startswith("win")
        and os.environ.get(FSNOW_SKIP_FSQLITE_WINDOWS_PREREQ) == "1"
        and lane.package == "franken-snowflake-cache"
        and any(arg == "frankensqlite" for arg in lane.args)
    )


def run_self_test() -> None:
    synthetic_tree = """
    franken-snowflake-frame v0.0.0 (/repo/crates/franken-snowflake-frame)
    fp-io v0.1.0 (/dp/frankenpandas/crates/fp-io)
    orc-rust v0.8.0
    tokio v1.48.0
    snowflake-rs v0.4.0
    asupersync v0.3.4
    asupersync v0.3.5 (/dp/asupersync)
    franken-kernel v0.3.4
    franken-kernel v0.3.5 (/dp/asupersync/franken_kernel)
    """
    packages = package_names_from_tree(synthetic_tree)
    found = violations(packages)
    expected = {"fp-io", "orc-rust", "tokio", "snowflake-rs"}
    missing = sorted(expected.difference(found))
    if missing:
        emit_error("self_test_failure", missing=missing, found=found)
        raise SystemExit(1)
    emit("self_test_verdict", fixture="fp-io-orc-rust-tokio", violations=found)

    package_versions = package_versions_from_tree(synthetic_tree)
    found_single_versions = {
        str(item["package"]): item["versions"]
        for item in single_version_violations(package_versions)
    }
    expected_single_versions = {
        "asupersync": ["0.3.4", "0.3.5"],
        "franken-kernel": ["0.3.4", "0.3.5"],
    }
    if found_single_versions != expected_single_versions:
        emit_error(
            "self_test_failure",
            fixture="single-version-runtime-packages",
            expected=expected_single_versions,
            found=found_single_versions,
        )
        raise SystemExit(1)
    emit(
        "self_test_verdict",
        fixture="single-version-runtime-packages",
        violations=found_single_versions,
    )

    feature_packages: list[dict[str, object]] = [
        {"name": "franken-snowflake-cli", "features": {"default": [], "toon": []}},
        {"name": "franken-snowflake-export", "features": {"export": []}},
        {"name": "franken-snowflake-frame", "features": {"frankenpandas": []}},
        {"name": "franken-snowflake-graph", "features": {"default": [], "graph": []}},
        {
            "name": "franken-snowflake-http",
            "features": {"compression": [], "live": []},
        },
        {"name": "franken-snowflake-mcp", "features": {"mcp": []}},
        {
            "name": "franken-snowflake-text-indexing",
            "features": {"frankensearch": [], "rerank": []},
        },
        {"name": "franken-snowflake-tui", "features": {"tui": []}},
    ]
    owners = production_feature_owners(feature_packages)
    missing_owners = sorted(PRODUCTION_FEATURES.difference(owners))
    workspace_lanes = workspace_feature_lanes(feature_packages)
    lane_names = {lane.name for lane in workspace_lanes}
    expected_lanes = {
        "workspace-production-no-default-features",
        "workspace-production-features:combined",
        *(f"workspace-production-feature:{feature}" for feature in PRODUCTION_FEATURES),
    }
    missing_lanes = sorted(expected_lanes.difference(lane_names))
    if missing_owners or missing_lanes:
        emit_error(
            "self_test_failure",
            fixture="production-feature-workspace-lanes",
            missing_owners=missing_owners,
            missing_lanes=missing_lanes,
        )
        raise SystemExit(1)
    emit(
        "self_test_verdict",
        fixture="production-feature-workspace-lanes",
        lane_count=len(workspace_lanes),
    )


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
        single_version_packages=sorted(SINGLE_VERSION_PACKAGES),
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
    all_lanes.extend(workspace_feature_lanes(packages))
    lanes = dedupe_lanes(all_lanes)

    coverage_failures = enforce_production_feature_coverage(packages)
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

    failure_count = coverage_failures
    skipped_count = 0
    for lane in lanes:
        if is_fsqlite_windows_prereq_lane(lane):
            skipped_count += 1
            emit(
                "lane_skipped",
                package=lane.package,
                lane=lane.name,
                scope=lane.scope,
                reason="upstream fsqlite-vfs/fsqlite-mvcc must gate nix with cfg(unix) before Windows cache-feature scanning",
            )
            continue
        failure_count += scan_lane(lane)

    if failure_count:
        emit_error(
            "failure",
            lanes_scanned=len(lanes) - skipped_count,
            lanes_skipped=skipped_count,
            violation_count=failure_count,
        )
        return 1

    emit(
        "success",
        lanes_scanned=len(lanes) - skipped_count,
        lanes_skipped=skipped_count,
        violation_count=0,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
