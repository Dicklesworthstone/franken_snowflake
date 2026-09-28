#!/usr/bin/env python3
"""Cell-by-cell differential of `franken-snowflake query run` against the
official Snowflake Python connector, both arms live in the same invocation
(bead oj0.22).

One type-matrix SELECT (every wire type, edge values, NULLs) runs through the
fsnow binary (`typed.v1` rows) and through `snowflake-connector-python` with
the same profile handles. Both sides are normalized to one canonical form and
compared cell by cell; the per-column verdicts go to --out, and the exit code
is 1 on any mismatch (a mismatch is a finding to file, not a harness failure).

Run it through uv so the connector version is pinned:

    uv run --with snowflake-connector-python==4.7.5 python3 \\
        scripts/differential-python-connector.py --bin <franken-snowflake> \\
        --profile <profile> --out <verdicts.json>

Canonical forms: decimals compare as decimal values; floats exactly, with
NaN/Infinity spelled out; DATE as YYYY-MM-DD; TIME and timestamps to the
MICROSECOND, because Python's datetime stops there (the fsnow fraction is cut
to six digits and the comparison says so); TIMESTAMP_LTZ as the UTC instant
(both arms run with TIMEZONE=UTC); TIMESTAMP_TZ as wall clock plus offset;
BINARY as lower-case hex; VARIANT/OBJECT/ARRAY as parsed JSON.

Connector auth, per the official docs (consulted 2026-09-28):
- PAT: the token is the `password` argument (user-guide/programmatic-access-tokens,
  "Using a programmatic access token as a password");
- key pair: authenticator SNOWFLAKE_JWT with private_key_file and
  private_key_file_pwd (python-connector-connect, key-pair section);
- OAuth: authenticator "oauth" with `token` (python-connector-connect, OAuth).

`--self-test` checks the normalization and the comparison offline (no
connector, no account), including a planted mismatch that must be reported.
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import json
import math
import os
import subprocess
import sys
import tempfile
from typing import Any

# One row; every documented wire type; edge values; typed NULLs.
TYPE_MATRIX_SQL = """SELECT
  12345::NUMBER(38,0) AS num_int,
  99999999999999999999999999999999999999::NUMBER(38,0) AS num_max,
  -123.45::NUMBER(10,2) AS num_scale2,
  '0.1234567890123456789012345678901234567'::NUMBER(38,37) AS num_scale37,
  NULL::NUMBER(10,2) AS num_null,
  1.5::FLOAT AS float_val,
  'NaN'::FLOAT AS float_nan,
  'inf'::FLOAT AS float_inf,
  '-inf'::FLOAT AS float_ninf,
  '1.5'::DECFLOAT AS decfloat_val,
  TRUE AS bool_true,
  NULL::BOOLEAN AS bool_null,
  'text; with ''quote''' AS text_val,
  '2026-09-04'::DATE AS date_val,
  '1969-07-20'::DATE AS date_pre_epoch,
  '12:34:56.123456789'::TIME AS time_ns,
  '2026-09-04 12:34:56.123456789'::TIMESTAMP_NTZ AS ts_ntz,
  '1969-12-31 23:59:59.5'::TIMESTAMP_NTZ AS ts_ntz_pre_epoch,
  '2026-09-04 12:34:56.123456789'::TIMESTAMP_LTZ AS ts_ltz,
  '2026-09-04 12:34:56.123456789 +05:30'::TIMESTAMP_TZ AS ts_tz_east,
  '2026-09-04 12:34:56 -08:00'::TIMESTAMP_TZ AS ts_tz_west,
  '2026-09-04 12:34:56 +00:00'::TIMESTAMP_TZ AS ts_tz_utc,
  NULL::TIMESTAMP_TZ AS ts_null,
  TO_BINARY('676F6C64656E', 'HEX') AS binary_val,
  PARSE_JSON('{"k":[1,{"nested":true}],"s":"v"}') AS variant_val,
  OBJECT_CONSTRUCT('k', 1) AS object_val,
  ARRAY_CONSTRUCT(1, 'two') AS array_val"""

MISSING = object()


# ---------------------------------------------------------------- normalization

def cut_fraction(text: str) -> str:
    """Cut an ISO time/timestamp fraction to microseconds (six digits)."""
    if "." not in text:
        return text
    head, rest = text.split(".", 1)
    digits = ""
    for char in rest:
        if not char.isdigit():
            break
        digits += char
    tail = rest[len(digits):]
    micro = (digits + "000000")[:6]
    return f"{head}.{micro}{tail}"


def canonical_fsnow(value: Any, column: dict) -> Any:
    """A typed.v1 cell in canonical form, by the column's json_repr."""
    if value is None:
        return None
    repr_ = column.get("json_repr")
    if repr_ in ("integer", "decimal_string"):
        return ("decimal", decimal.Decimal(str(value)))
    if repr_ == "float":
        if isinstance(value, str):
            return ("float", value)
        return ("float", repr(float(value)))
    if repr_ == "bool":
        return ("bool", bool(value))
    if repr_ == "date":
        return ("date", value)
    if repr_ in ("time", "timestamp_ntz", "timestamp_utc", "timestamp_offset"):
        text = cut_fraction(value)
        if repr_ == "timestamp_utc" and text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return (repr_, text)
    if repr_ == "hex":
        return ("hex", str(value).lower())
    if repr_ == "json":
        return ("json", value)
    return ("text", value)


def canonical_python(value: Any, column: dict) -> Any:
    """A connector value in canonical form, guided by the fsnow column."""
    if value is None:
        return None
    repr_ = column.get("json_repr")
    if isinstance(value, bool):
        return ("bool", value)
    if repr_ in ("integer", "decimal_string"):
        return ("decimal", decimal.Decimal(str(value)))
    if repr_ == "float":
        number = float(value)
        if math.isnan(number):
            return ("float", "NaN")
        if math.isinf(number):
            return ("float", "Infinity" if number > 0 else "-Infinity")
        return ("float", repr(number))
    if isinstance(value, dt.datetime):
        if repr_ == "timestamp_ntz":
            return (repr_, cut_fraction(value.replace(tzinfo=None).isoformat(timespec="microseconds")))
        if repr_ == "timestamp_utc":
            utc = value.astimezone(dt.timezone.utc) if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
            return (repr_, utc.isoformat(timespec="microseconds"))
        return (repr_, value.isoformat(timespec="microseconds"))
    if isinstance(value, dt.date):
        return ("date", value.isoformat())
    if isinstance(value, dt.time):
        return ("time", value.isoformat(timespec="microseconds"))
    if isinstance(value, (bytes, bytearray)):
        return ("hex", bytes(value).hex())
    if repr_ == "json":
        return ("json", json.loads(value) if isinstance(value, str) else value)
    if repr_ == "hex":
        return ("hex", str(value).lower())
    return ("text", value)


def compare(columns: list[dict], fsnow_row: list, python_row: list) -> list[dict]:
    """Per-column verdicts: match, or a mismatch with both canonical values."""
    verdicts = []
    for index, column in enumerate(columns):
        left = fsnow_row[index] if index < len(fsnow_row) else MISSING
        right = python_row[index] if index < len(python_row) else MISSING
        if left is MISSING or right is MISSING:
            verdicts.append({"column": column.get("name"), "verdict": "missing"})
            continue
        ours = canonical_fsnow(left, column)
        theirs = canonical_python(right, column)
        verdict = {"column": column.get("name"), "type": column.get("type"),
                   "json_repr": column.get("json_repr"),
                   "verdict": "match" if ours == theirs else "mismatch"}
        if ours != theirs:
            verdict["fsnow"] = str(ours)
            verdict["python_connector"] = str(theirs)
        verdicts.append(verdict)
    return verdicts


# ---------------------------------------------------------------- live arms

def profile_env(profile: str) -> tuple[str, dict]:
    suffix = "".join(c.upper() if c.isalnum() else "_" for c in profile if c.isalnum() or c in ".-_")
    prefix = f"FRANKEN_SNOWFLAKE_{suffix}" if suffix else "FRANKEN_SNOWFLAKE_PROFILE"

    def get(key: str) -> str | None:
        value = os.environ.get(f"{prefix}_{key}", "").strip()
        return value or None

    return prefix, {key: get(key) for key in (
        "ACCOUNT", "USER", "AUTH", "WAREHOUSE", "DATABASE", "SCHEMA", "ROLE",
        "PAT", "OAUTH_BEARER", "PRIVATE_KEY_PEM", "PRIVATE_KEY_PASSPHRASE")}


def connector_account(raw: str) -> str:
    """The connector's `account`: the identifier without scheme or host suffix."""
    text = raw.strip()
    for scheme in ("https://", "http://"):
        if text.lower().startswith(scheme):
            text = text[len(scheme):]
    text = text.split("/", 1)[0]
    for suffix in (".snowflakecomputing.com", ".snowflakecomputing.cn"):
        if text.lower().endswith(suffix):
            text = text[: -len(suffix)]
    return text


def connector_kwargs(env: dict, key_dir: str) -> dict:
    """connect() arguments for the profile's auth lane (the documented forms)."""
    kwargs = {
        "account": connector_account(env["ACCOUNT"] or ""),
        "user": env["USER"],
        "session_parameters": {"TIMEZONE": "UTC", "MULTI_STATEMENT_COUNT": "1"},
    }
    for key in ("WAREHOUSE", "DATABASE", "SCHEMA", "ROLE"):
        if env[key]:
            kwargs[key.lower()] = env[key]
    lane = (env["AUTH"] or "").lower()
    if lane in ("pat", "programmatic_access_token"):
        kwargs["password"] = env["PAT"]
    elif lane in ("oauth", "oauth_bearer", "oauth_bearer_token"):
        kwargs["authenticator"] = "oauth"
        kwargs["token"] = env["OAUTH_BEARER"]
    elif lane in ("key_pair_jwt", "jwt"):
        os.makedirs(key_dir, exist_ok=True)
        path = os.path.join(key_dir, "key.p8")
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as handle:
            handle.write(env["PRIVATE_KEY_PEM"] or "")
        kwargs["authenticator"] = "SNOWFLAKE_JWT"
        kwargs["private_key_file"] = path
        if env["PRIVATE_KEY_PASSPHRASE"]:
            kwargs["private_key_file_pwd"] = env["PRIVATE_KEY_PASSPHRASE"]
    else:
        raise SystemExit(f"auth lane `{lane}` is not wired for the Python connector arm")
    return kwargs


def run_python_arm(env: dict, sql: str, key_dir: str):
    import snowflake.connector  # imported here so --self-test needs no connector

    connection = snowflake.connector.connect(**connector_kwargs(env, key_dir))
    try:
        cursor = connection.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        names = [column[0] for column in cursor.description]
    finally:
        connection.close()
    return names, [list(row) for row in rows], snowflake.connector.__version__


def run_fsnow_arm(binary: str, profile: str, sql: str) -> dict:
    done = subprocess.run([binary, "query", "run", "--profile", profile, "--sql", sql, "--json"],
                          capture_output=True, text=True, check=False)
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError as error:
        raise SystemExit(f"fsnow arm printed no envelope (exit {done.returncode}): {error}") from error


# ---------------------------------------------------------------- self-test

def self_test() -> int:
    columns = [
        {"name": "N", "json_repr": "integer"}, {"name": "D", "json_repr": "decimal_string"},
        {"name": "F", "json_repr": "float"}, {"name": "NAN", "json_repr": "float"},
        {"name": "B", "json_repr": "bool"}, {"name": "DT", "json_repr": "date"},
        {"name": "T", "json_repr": "time"}, {"name": "NTZ", "json_repr": "timestamp_ntz"},
        {"name": "LTZ", "json_repr": "timestamp_utc"}, {"name": "TZ", "json_repr": "timestamp_offset"},
        {"name": "BIN", "json_repr": "hex"}, {"name": "V", "json_repr": "json"},
        {"name": "S", "json_repr": "string"}, {"name": "NUL", "json_repr": "decimal_string"},
    ]
    east = dt.timezone(dt.timedelta(hours=5, minutes=30))
    fsnow_row = [12345, "-123.450", 1.5, "NaN", True, "1969-07-20", "12:34:56.123456789",
                 "2026-09-04T12:34:56.123456789", "2026-09-04T12:34:56.123456789Z",
                 "2026-09-04T12:34:56.123456789+05:30", "676F6C64656E",
                 {"k": [1, {"nested": True}]}, "text", None]
    python_row = [12345, decimal.Decimal("-123.45"), 1.5, float("nan"), True, dt.date(1969, 7, 20),
                  dt.time(12, 34, 56, 123456), dt.datetime(2026, 9, 4, 12, 34, 56, 123456),
                  dt.datetime(2026, 9, 4, 12, 34, 56, 123456, tzinfo=dt.timezone.utc),
                  dt.datetime(2026, 9, 4, 12, 34, 56, 123456, tzinfo=east), b"golden",
                  '{"k":[1,{"nested":true}]}', "text", None]
    verdicts = compare(columns, fsnow_row, python_row)
    failures = [v for v in verdicts if v["verdict"] != "match"]
    ok = not failures
    print(json.dumps({"case": "equal values in both arms' native forms match", "ok": ok,
                      "failures": failures}))
    # Planted mismatches a naive comparison would miss or invent.
    planted = [
        ("a different offset is a mismatch", 9,
         dt.datetime(2026, 9, 4, 12, 34, 56, 123456, tzinfo=dt.timezone.utc)),
        ("a microsecond off is a mismatch", 7, dt.datetime(2026, 9, 4, 12, 34, 56, 123457)),
        ("a different decimal is a mismatch", 1, decimal.Decimal("-123.46")),
        ("NULL against a value is a mismatch", 13, decimal.Decimal("0")),
    ]
    for label, index, wrong in planted:
        row = list(python_row)
        row[index] = wrong
        caught = compare(columns, fsnow_row, row)[index]["verdict"] == "mismatch"
        ok = ok and caught
        print(json.dumps({"case": label, "ok": caught}))
    accounts = {"https://myorg-acct.snowflakecomputing.com": "myorg-acct",
                "myorg-acct": "myorg-acct", "xy12345.cn-northwest-1.snowflakecomputing.cn": "xy12345.cn-northwest-1"}
    for raw, want in accounts.items():
        got = connector_account(raw)
        ok = ok and got == want
        print(json.dumps({"case": f"account {raw}", "ok": got == want, "got": got}))
    base = {"ACCOUNT": "https://myorg-acct.snowflakecomputing.com", "USER": "SVC", "WAREHOUSE": "WH",
            "DATABASE": None, "SCHEMA": None, "ROLE": None, "PAT": None, "OAUTH_BEARER": None,
            "PRIVATE_KEY_PEM": None, "PRIVATE_KEY_PASSPHRASE": None}
    with tempfile.TemporaryDirectory() as key_dir:
        lanes = {
            "pat": ({"PAT": "p"}, {"password": "p"}),
            "oauth": ({"OAUTH_BEARER": "o"}, {"authenticator": "oauth", "token": "o"}),
            "key_pair_jwt": ({"PRIVATE_KEY_PEM": "-----BEGIN PRIVATE KEY-----", "PRIVATE_KEY_PASSPHRASE": "w"},
                             {"authenticator": "SNOWFLAKE_JWT", "private_key_file_pwd": "w"}),
        }
        for lane, (secrets, want) in lanes.items():
            kwargs = connector_kwargs({**base, "AUTH": lane, **secrets}, os.path.join(key_dir, lane))
            got = {key: kwargs.get(key) for key in want}
            good = got == want and kwargs["account"] == "myorg-acct" and kwargs["warehouse"] == "WH"
            if lane == "key_pair_jwt":
                mode = os.stat(kwargs["private_key_file"]).st_mode & 0o777
                good = good and mode == 0o600
            ok = ok and good
            print(json.dumps({"case": f"connect() arguments for {lane}", "ok": good}))
    print(json.dumps({"self_test": "pass" if ok else "fail"}))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--bin", help="the franken-snowflake binary")
    parser.add_argument("--profile", help="the live profile both arms use")
    parser.add_argument("--out", help="write the verdicts here")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not (args.bin and args.profile and args.out):
        parser.error("--bin, --profile and --out are required (or --self-test)")
    _, env = profile_env(args.profile)
    envelope = run_fsnow_arm(args.bin, args.profile, TYPE_MATRIX_SQL)
    if not envelope.get("ok"):
        raise SystemExit(f"fsnow arm failed: {json.dumps(envelope.get('error'))}")
    columns = envelope["data"]["columns"]
    fsnow_rows = envelope["data"]["rows"]
    with tempfile.TemporaryDirectory() as key_dir:
        names, python_rows, version = run_python_arm(env, TYPE_MATRIX_SQL, key_dir)
    if [c.get("name") for c in columns] != names:
        raise SystemExit(f"column lists differ: fsnow {[c.get('name') for c in columns]} vs connector {names}")
    verdicts = compare(columns, fsnow_rows[0] if fsnow_rows else [], python_rows[0] if python_rows else [])
    mismatches = [v for v in verdicts if v["verdict"] != "match"]
    report = {
        "schema": "franken_snowflake.differential_python_connector.v1",
        "connector_version": version,
        "fsnow_build": envelope.get("build") or None,
        "fsnow_receipt_hash": envelope.get("receipt_hash"),
        "precision": "time and timestamps compared to the microsecond (Python datetime)",
        "columns": len(verdicts),
        "mismatches": len(mismatches),
        "verdicts": verdicts,
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
        handle.write("\n")
    print(json.dumps({"columns": len(verdicts), "mismatches": len(mismatches)}))
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
