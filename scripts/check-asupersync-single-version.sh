#!/usr/bin/env bash
set -euo pipefail

gate="asupersync-single-version"
metadata_file="$(mktemp)"
trap 'rm -f "${metadata_file}"' EXIT

printf '{"gate":"%s","event":"metadata_start","command":"cargo metadata --locked --format-version 1"}\n' "${gate}"
cargo metadata --locked --format-version 1 >"${metadata_file}"

python3 - "${metadata_file}" <<'PY'
import json
import sys

metadata_path = sys.argv[1]
with open(metadata_path, "r", encoding="utf-8") as handle:
    metadata = json.load(handle)

packages = [package for package in metadata["packages"] if package["name"] == "asupersync"]
versions = sorted({package["version"] for package in packages})
package_ids = sorted(package["id"] for package in packages)

event = {
    "gate": "asupersync-single-version",
    "event": "metadata_result",
    "package_count": len(packages),
    "versions": versions,
    "package_ids": package_ids,
}
print(json.dumps(event, sort_keys=True))

if len(packages) != 1:
    failure = {
        "gate": "asupersync-single-version",
        "event": "failure",
        "reason": "expected exactly one resolved asupersync package",
        "package_count": len(packages),
        "versions": versions,
        "package_ids": package_ids,
    }
    print(json.dumps(failure, sort_keys=True), file=sys.stderr)
    sys.exit(1)
PY

printf '{"gate":"%s","event":"tree_start","command":"cargo tree --locked -i asupersync"}\n' "${gate}"
cargo tree --locked -i asupersync
printf '{"gate":"%s","event":"success"}\n' "${gate}"
