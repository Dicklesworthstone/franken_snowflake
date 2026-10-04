#!/usr/bin/env python3
"""Verify a downloaded six-target release without extracting or running it.

The caller supplies an independently trusted minisign key. A key downloaded
alongside the bundle is not an independent trust anchor. This gate checks bytes,
signatures and archive architecture; it does not prove installer or runtime
behavior, source identity, or live Snowflake connectivity.
"""

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import unittest
import zipfile


TARGETS = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
)
MAX_MEMBER = 256 * 1024**2
MAX_TOTAL = 512 * 1024**2
MAX_MEMBERS = 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checksum_rows(data):
    rows = {}
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+\*?([^/\\\s]+)", line)
        require(match is not None, "malformed checksum row")
        require(match[2] not in rows and match[2] not in (".", ".."),
                "duplicate or unsafe checksum filename")
        rows[match[2]] = match[1].lower()
    return rows


def binary_architecture(data, target):
    require(target in TARGETS, "unsupported target")
    amd = target.startswith("x86_64")
    if "linux" in target:
        require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01"
                and int.from_bytes(data[18:20], "little") == (62 if amd else 183),
                "ELF architecture mismatch")
    elif "darwin" in target:
        require(len(data) >= 32 and data[:4] == b"\xcf\xfa\xed\xfe"
                and int.from_bytes(data[4:8], "little") == (0x1000007 if amd else 0x100000c),
                "Mach-O architecture mismatch")
    else:
        require(len(data) >= 64 and data[:2] == b"MZ", "PE header missing")
        offset = int.from_bytes(data[60:64], "little")
        require(offset >= 64 and offset + 24 <= len(data)
                and data[offset:offset + 4] == b"PE\0\0"
                and int.from_bytes(data[offset + 4:offset + 6], "little") == (0x8664 if amd else 0xaa64),
                "PE architecture mismatch")


def archive_binaries(data, target):
    require(target in TARGETS, "unsupported target")
    require(len(data) <= MAX_MEMBER, "oversized compressed archive")
    names = set()
    binaries = {}
    total = 0
    expected = {name + (".exe" if "windows" in target else ""): name
                for name in ("franken-snowflake", "fsnow")}

    def admit(name, size):
        nonlocal total
        normalized = name.rstrip("/")
        path = PurePosixPath(normalized)
        require(normalized and not path.is_absolute() and ".." not in path.parts
                and "\\" not in name and not re.match(r"^[A-Za-z]:", name)
                and str(path) == normalized and normalized != ".",
                "unsafe archive member path")
        require(normalized not in names, "duplicate archive member")
        names.add(normalized)
        total += size
        require(len(names) <= MAX_MEMBERS and 0 <= size <= MAX_MEMBER
                and total <= MAX_TOTAL, "archive exceeds member/size budget")
        return path.name

    def take(leaf, mode, blob):
        if leaf not in expected:
            return
        name = expected[leaf]
        require(name not in binaries, "duplicate binary basename")
        require("windows" in target or mode & 0o111, "binary is not executable")
        binary_architecture(blob, target)
        binaries[name] = sha(blob)

    if "windows" in target:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            require(len(archive.infolist()) <= MAX_MEMBERS, "too many ZIP members")
            for item in archive.infolist():
                mode = item.external_attr >> 16
                kind = stat.S_IFMT(mode)
                require(kind in (0, stat.S_IFDIR if item.is_dir() else stat.S_IFREG),
                        "ZIP link or special member")
                require(not item.flag_bits & 1, "encrypted ZIP member")
                leaf = admit(item.filename, item.file_size)
                if not item.is_dir():
                    # Read every entry to check CRCs, after the cumulative budget.
                    take(leaf, mode, archive.read(item))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for item in archive:
                require(item.isdir() or item.isfile(), "tar link or special member")
                leaf = admit(item.name, item.size)
                if item.isfile():
                    with archive.extractfile(item) as stream:
                        blob = stream.read()
                    require(len(blob) == item.size, "truncated tar member")
                    take(leaf, item.mode, blob)
    require(set(binaries) == {"franken-snowflake", "fsnow"},
            "archive must contain both binary aliases")
    return binaries


def regular_bytes(path):
    require(path.is_file() and not path.is_symlink(), "nonregular input: " + str(path))
    require(path.stat().st_size <= MAX_MEMBER, "oversized input: " + str(path))
    return path.read_bytes()


def verify_bundle(bundle, version, public_key, trusted_key_sha256):
    require(re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version), "invalid version")
    require(re.fullmatch(r"[0-9a-f]{64}", trusted_key_sha256), "invalid trusted key digest")
    require(sha(regular_bytes(public_key)) == trusted_key_sha256, "trusted public key digest mismatch")
    primary = {"franken-snowflake-v" + version + "-" + target
               + (".zip" if "windows" in target else ".tar.gz"): target for target in TARGETS}
    expected = set(primary) | {name + suffix for name in primary for suffix in (".sha256", ".minisig")} \
        | {"SHA256SUMS", "SHA256SUMS.minisig"}
    require(bundle.is_dir() and not bundle.is_symlink(), "bundle must be a real directory")
    require({p.name for p in bundle.iterdir()} == expected, "exact 20-asset contract mismatch")
    before = {name: sha(regular_bytes(bundle / name)) for name in sorted(expected)}

    def signature(name):
        subprocess.run(["minisign", "-Vm", str(bundle / name), "-x", str(bundle / (name + ".minisig")),
                        "-p", str(public_key), "-q"], check=True, capture_output=True, timeout=60)

    signature("SHA256SUMS")
    hashes = checksum_rows(regular_bytes(bundle / "SHA256SUMS"))
    require(set(hashes) == set(primary), "signed manifest must name exactly six archives")
    binaries = {}
    for name, target in primary.items():
        blob = regular_bytes(bundle / name)
        require(sha(blob) == hashes[name], "signed archive hash mismatch: " + name)
        sidecar = regular_bytes(bundle / (name + ".sha256"))
        bare = sidecar.decode("utf-8").strip()
        require(bare.lower() == hashes[name] if re.fullmatch(r"[0-9a-fA-F]{64}", bare)
                else checksum_rows(sidecar) == {name: hashes[name]}, "checksum sidecar mismatch: " + name)
        signature(name)
        binaries[target] = archive_binaries(blob, target)
    require(before == {name: sha(regular_bytes(bundle / name)) for name in sorted(expected)}
            and {p.name for p in bundle.iterdir()} == expected
            and sha(regular_bytes(public_key)) == trusted_key_sha256,
            "inputs changed during verification")
    return {"status": "PASS", "version": version, "assets": before,
            "public_key_sha256": trusted_key_sha256, "binary_sha256": binaries,
            "boundary": "signed bytes and archive architecture only; no extraction, execution, installer, source or live-service proof"}


class ArchiveChecks(unittest.TestCase):
    @staticmethod
    def elf(machine=62):
        blob = bytearray(64)
        blob[:6] = b"\x7fELF\x02\x01"
        blob[18:20] = machine.to_bytes(2, "little")
        return bytes(blob)

    @staticmethod
    def tar(entries):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name, mode, kind, data in entries:
                item = tarfile.TarInfo(name)
                item.mode, item.type, item.size = mode, kind, len(data)
                archive.addfile(item, io.BytesIO(data))
        return stream.getvalue()

    def test_valid_aliases_and_nested_paths(self):
        entries = [("release/" + n, 0o755, tarfile.REGTYPE, self.elf())
                   for n in ("franken-snowflake", "fsnow")]
        self.assertEqual(set(archive_binaries(self.tar(entries), TARGETS[0])),
                         {"franken-snowflake", "fsnow"})

    def test_tar_rejects_unsafe_members(self):
        for name, mode, kind, blob in (
            ("../fsnow", 0o755, tarfile.REGTYPE, self.elf()),
            ("/fsnow", 0o755, tarfile.REGTYPE, self.elf()),
            ("C:/fsnow", 0o755, tarfile.REGTYPE, self.elf()),
            ("release\\fsnow", 0o755, tarfile.REGTYPE, self.elf()),
            ("fsnow", 0o755, tarfile.SYMTYPE, b""),
            ("fsnow", 0o644, tarfile.REGTYPE, self.elf()),
            ("fsnow", 0o755, tarfile.REGTYPE, self.elf(183)),
        ):
            with self.subTest(name=name, kind=kind, mode=mode):
                with self.assertRaises(ValueError):
                    archive_binaries(self.tar([(name, mode, kind, blob)]), TARGETS[0])

    def test_duplicate_basenames_and_missing_alias(self):
        for names in (("franken-snowflake",), ("fsnow", "other/fsnow", "franken-snowflake")):
            with self.subTest(names=names), self.assertRaises(ValueError):
                archive_binaries(self.tar([(n, 0o755, tarfile.REGTYPE, self.elf()) for n in names]), TARGETS[0])

    def test_checksum_names_and_duplicates(self):
        digest = "a" * 64
        self.assertEqual(checksum_rows((digest.upper() + " *archive.zip\n").encode()), {"archive.zip": digest})
        for text in (digest + " ../escape", digest + " x\\y", digest + " a\n" + digest + " a", "bad archive.zip"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                checksum_rows(text.encode())

    def test_truncated_pe_and_unknown_target(self):
        with self.assertRaises(ValueError):
            binary_architecture(b"MZ" + bytes(62), TARGETS[4])
        with self.assertRaises(ValueError):
            binary_architecture(self.elf(), "unknown")

    def test_zip_rejects_links_paths_and_duplicate_names(self):
        pe = bytearray(88)
        pe[:2] = b"MZ"
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\0\0"
        pe[68:70] = (0x8664).to_bytes(2, "little")
        for names, mode, error in ((["../fsnow.exe"], stat.S_IFREG | 0o755, "unsafe"),
                                   (["fsnow.exe"], stat.S_IFLNK | 0o777, "special"),
                                   (["fsnow.exe", "nested/fsnow.exe"], stat.S_IFREG | 0o755, "duplicate")):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, "w") as archive:
                for name in names:
                    item = zipfile.ZipInfo(name)
                    item.create_system = 3
                    item.external_attr = mode << 16
                    archive.writestr(item, pe)
            with self.subTest(names=names, mode=mode), self.assertRaisesRegex(ValueError, error):
                archive_binaries(stream.getvalue(), TARGETS[4])

    def test_budget_applies_before_member_read(self):
        # A header advertises a huge body but supplies none. Admission must
        # reject the size rather than reach tarfile's truncated-read exception.
        item = tarfile.TarInfo("oversized")
        item.size = MAX_MEMBER + 1
        malformed = gzip.compress(item.tobuf() + bytes(1024))
        with self.assertRaisesRegex(ValueError, "budget"):
            archive_binaries(malformed, TARGETS[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--trusted-key-sha256")
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveChecks))
        return 0 if result.wasSuccessful() else 1
    if not all((args.bundle, args.version, args.public_key, args.trusted_key_sha256)):
        parser.error("--bundle, --version, --public-key and --trusted-key-sha256 are required")
    try:
        print(json.dumps(verify_bundle(args.bundle, args.version, args.public_key, args.trusted_key_sha256), indent=2))
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
