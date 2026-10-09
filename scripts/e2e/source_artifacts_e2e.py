#!/usr/bin/env python3
"""Exercise the installer's consumers against retained, real Cargo artifacts.

Run on the target platform after DSR/RCH admission, using the JSON stream from
that source build and independently bound producer paths/build identities.
Nothing builds inline, removes artifacts or substitutes a compiler/binary.
The original full installer, caller-policy, upgrade, service and performance
acceptance remains required separately. This is the artifact-consumer slice.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("messages", "source", "evidence-root", "canonical", "alias"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("version", "git-sha", "source-digest", "target"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--consumer", choices=("bash", "powershell"), required=True)
    parser.add_argument("--powershell", type=Path)
    args = parser.parse_args()
    require(args.evidence_root.is_absolute() and args.evidence_root.is_dir(),
            "An existing, admitted absolute evidence root is required")
    source = args.source.resolve(strict=True)
    manifest = source / "crates/franken-snowflake-cli/Cargo.toml"
    require(manifest.is_file(), "The actual CLI manifest is required")
    expected = [args.canonical.resolve(strict=True), args.alias.resolve(strict=True)]
    require(expected[0] != expected[1], "Two independently bound producer paths are required")
    require(all(path.is_file() for path in expected), "Actual compiled binaries are required")
    require(args.target not in ("", "unknown") and args.git_sha not in ("", "unknown")
            and len(args.source_digest) == 64
            and all(c in "0123456789abcdef" for c in args.source_digest),
            "A known source digest, commit and target from the admitted build are required")
    evidence = args.evidence_root / ("source-artifacts-" + uuid.uuid4().hex)
    evidence.mkdir()
    original = args.messages.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    messages = [json.loads(line) for line in original.decode("utf-8-sig").splitlines()]
    names = ["franken-snowflake", "fsnow"]
    outcomes = []

    if args.consumer == "bash":
        require(os.name != "nt", "The Bash consumer requires its native Unix platform")
        installer = source / "install.sh"
        text = installer.read_text(encoding="utf-8")
        marker = "<<'FSNOW_CARGO_ARTIFACTS_PY'\n"
        require(text.count(marker) == 1, "The actual inline Cargo consumer must be unique")
        body = text.split(marker, 1)[1].split("\nFSNOW_CARGO_ARTIFACTS_PY\n", 1)[0]
        consumer = evidence / "actual-installer-cargo-consumer.py"
        consumer.write_text(body + "\n", encoding="utf-8")
        command = [sys.executable, str(consumer)]

        def consume(path):
            result = subprocess.run(command + [str(path), str(manifest)] + names,
                                    capture_output=True, text=True, timeout=60)
            return result, result.stdout.splitlines() if result.returncode == 0 else []
    else:
        require(os.name == "nt", "The PowerShell consumer requires native Windows")
        require(args.powershell is not None and args.powershell.is_absolute()
                and args.powershell.is_file(), "An actual admitted PowerShell executable is required")
        installer = source / "install.ps1"
        consumer = evidence / "actual-installer-cargo-consumer.ps1"
        consumer.write_text(r'''param([string]$Installer, [string]$Messages, [string]$Manifest)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
try {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw 'Actual installer has PowerShell parse errors' }
    $found = @($ast.FindAll({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-CargoBuiltBinaries'
    }, $true))
    if ($found.Count -ne 1) { throw 'Actual Cargo consumer function must be unique' }
    . ([scriptblock]::Create($found[0].Extent.Text))
    $built = Get-CargoBuiltBinaries -MessagesPath $Messages -ManifestPath $Manifest -Names @('franken-snowflake', 'fsnow')
    ConvertTo-Json -InputObject @($built['franken-snowflake'], $built['fsnow']) -Compress
} catch {
    [Console]::Error.WriteLine($_.ToString())
    exit 1
}
''', encoding="utf-8")
        command = [str(args.powershell), "-NoProfile", "-NonInteractive", "-File", str(consumer), str(installer)]

        def consume(path):
            result = subprocess.run(command + [str(path), str(manifest)],
                                    capture_output=True, text=True, timeout=60)
            return result, json.loads(result.stdout) if result.returncode == 0 else []

    installer_hash = digest(installer)

    def run_case(name, rows, expected_error=None, raw=None):
        case = evidence / name
        case.mkdir()
        path = case / "cargo-messages.jsonl"
        path.write_bytes(raw if raw is not None else
                         ("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        result, paths = consume(path)
        (case / "stdout.txt").write_text(result.stdout, encoding="utf-8")
        (case / "stderr.txt").write_text(result.stderr, encoding="utf-8")
        (case / "returncode.txt").write_text(str(result.returncode) + "\n")
        if expected_error is None:
            require(result.returncode == 0, f"Actual consumer refused real build: {result.stderr}")
            require([Path(path).resolve(strict=True) for path in paths] == expected,
                    "Consumer paths differ from the independent admitted producer paths")
        else:
            require(result.returncode != 0 and not result.stdout.strip(),
                    f"{name} authorized invalid artifact metadata")
            require(expected_error in result.stderr, f"{name} failed for an unexpected reason: {result.stderr}")
        outcomes.append({"case": name, "returncode": result.returncode})

    run_case("real-cargo-output", messages, raw=original)
    binary_hashes = {name: digest(path) for name, path in zip(names, expected)}
    for name, path in zip(names, expected):
        result = subprocess.run([str(path), "capabilities", "--json", "--with-exe-hash"],
                                capture_output=True, text=True, timeout=60)
        (evidence / (name + "-capabilities.stdout.json")).write_text(result.stdout, encoding="utf-8")
        (evidence / (name + "-capabilities.stderr.txt")).write_text(result.stderr, encoding="utf-8")
        require(result.returncode == 0, f"Actual {name} capabilities failed")
        caps = json.loads(result.stdout)
        require(caps.get("ok") is True and caps.get("command_id") == "capabilities",
                f"Actual {name} did not return the capabilities contract")
        build = caps["data"]["build"]
        require(caps["data"]["version"] == args.version and build["version"] == args.version
                and build["git_sha"] == args.git_sha and build["source_digest"] == args.source_digest
                and build["target"] == args.target and build["profile"] == "release"
                and build["exe_sha256"] == binary_hashes[name],
                f"Actual {name} is not the independently bound source/target/release executable")
        outcomes.append({"case": name + "-native-build-identity", "returncode": result.returncode})

    def row_for(rows, name):
        found = [row for row in rows if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == name
                 and Path(row["manifest_path"]).resolve() == manifest.resolve()
                 and row.get("target", {}).get("kind") == ["bin"]
                 and row.get("profile", {}).get("test") is False]
        require(len(found) == 1, "The real emitted CLI artifact must be unique")
        return found[0]

    rows = copy.deepcopy(messages)
    rows.remove(row_for(rows, "fsnow"))
    run_case("missing-alias", rows, "both requested CLI binaries exactly once")
    rows = copy.deepcopy(messages)
    rows.insert(0, copy.deepcopy(row_for(rows, "franken-snowflake")))
    run_case("duplicate-canonical", rows, "more than one executable")
    rows = copy.deepcopy(messages)
    row_for(rows, "franken-snowflake")["manifest_path"] = str(evidence / "other-package/Cargo.toml")
    run_case("wrong-package", rows, "both requested CLI binaries exactly once")
    rows = copy.deepcopy(messages)
    row_for(rows, "franken-snowflake")["executable"] = str(evidence / ("absent-" + uuid.uuid4().hex))
    run_case("missing-emitted-file", rows, "executable is missing")
    rows = copy.deepcopy(messages)
    row_for(rows, "franken-snowflake")["executable"] = "./" + expected[0].name
    run_case("relative-emitted-file", rows, "absolute executable")
    rows = copy.deepcopy(messages)
    row_for(rows, "franken-snowflake")["target"]["kind"] = ["example"]
    run_case("wrong-target-kind", rows, "both requested CLI binaries exactly once")
    rows = copy.deepcopy(messages)
    row_for(rows, "franken-snowflake")["profile"]["test"] = True
    run_case("test-artifact", rows, "both requested CLI binaries exactly once")
    rows = copy.deepcopy(messages)
    finished = [row for row in rows if row.get("reason") == "build-finished"]
    require(len(finished) == 1 and finished[0]["success"] is True, "A real successful build-finished is required")
    finished[0]["success"] = False
    run_case("failed-build-with-artifacts", rows, "exactly one successful build-finished")
    rows = [row for row in copy.deepcopy(messages) if row.get("reason") != "build-finished"]
    run_case("incomplete-build-with-artifacts", rows, "exactly one successful build-finished")
    require(args.messages.read_bytes() == original, "Original producer stream was changed")
    require(all(digest(path) == binary_hashes[name] for name, path in zip(names, expected)),
            "Original compiled executable bytes were changed")
    require(digest(installer) == installer_hash, "Installer source changed during qualification")
    summary = {"scope": "real-cargo-artifact-consumer-and-native-build-identity",
               "consumer": args.consumer, "producer_messages_sha256": original_hash,
               "installer_sha256": installer_hash, "binary_sha256": binary_hashes,
               "cases": outcomes, "retained_evidence": str(evidence)}
    (evidence / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Source artifact E2E failed: {error}", file=sys.stderr)
        sys.exit(1)
