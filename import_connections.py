#!/usr/bin/env python3
"""
Import NetworkManager connections and KWallet secrets exported by
export_connections.sh.

Usage:
    import_connections.py [-o|--overwrite] [-d DIR|--dir DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import dbus

# ---------------------------------------------------------------------------

IMPORT_DIR  = Path.home() / "nm-wallet-export"
NM_DIR      = Path("/etc/NetworkManager/system-connections")
WALLET      = "kdewallet"
APPID       = "import_connections"
FOLDER      = "Network Management"
OVERWRITE   = False     # default; overridden by --overwrite

KWALLET_SERVICE = "org.kde.kwalletd6"
KWALLET_PATH    = "/modules/kwalletd6"
KWALLET_IFACE   = "org.kde.KWallet"

# Entry type constants (KWallet)
TYPE_PASSWORD = 1
TYPE_STREAM   = 2
TYPE_MAP      = 3

# ---------------------------------------------------------------------------


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """Run a command, raising on failure."""
    return subprocess.run(cmd, check=True, **kw)


def install_connections() -> None:
    print("=== Installing NetworkManager connections ===")
    src_dir = IMPORT_DIR / "connections"
    if not src_dir.is_dir():
        print(f"  No connections directory: {src_dir}")
        return

    for src in sorted(src_dir.iterdir()):
        if not src.is_file():
            continue
        dst = NM_DIR / src.name

        # read uuid from source
        new_uuid = ""
        for line in src.read_text().splitlines():
            if line.startswith("uuid="):
                new_uuid = line.split("=", 1)[1]
                break

        # check destination via sudo (root-owned)
        exists = subprocess.run(
            ["sudo", "test", "-f", str(dst)]
        ).returncode == 0

        if exists:
            print(f"\nConnection already exists: {src.name}")
            try:
                existing = subprocess.check_output(
                    ["sudo", "grep", "^uuid=", str(dst)],
                    text=True,
                ).strip().split("=", 1)[1]
            except subprocess.CalledProcessError:
                existing = "?"
            print(f"  Existing UUID: {existing}")
            print(f"  Import UUID:   {new_uuid}")
            if OVERWRITE:
                print("  Overwriting")
                sh(["sudo", "cp", str(src), str(dst)])
            else:
                print("  Skipping")
        else:
            print(f"\nInstalling: {src.name}")
            sh(["sudo", "cp", str(src), str(dst)])

    print("\n=== Fixing permissions ===")
    sh(["sudo", "chmod", "600", "-R", str(NM_DIR)])


# ---------------------------------------------------------------------------
# KWallet helpers
# ---------------------------------------------------------------------------


def open_wallet() -> tuple[dbus.Interface, int]:
    bus  = dbus.SessionBus()
    obj  = bus.get_object(KWALLET_SERVICE, KWALLET_PATH)
    kw   = dbus.Interface(obj, KWALLET_IFACE)

    handle = int(kw.open(WALLET, dbus.Int64(0), APPID))
    if handle == 0:
        raise RuntimeError(f"cannot open wallet {WALLET!r}")

    # Ensure folder exists (no-op if present)
    try:
        kw.createFolder(handle, FOLDER, APPID)
    except dbus.DBusException:
        pass

    return kw, handle


def encode_qmap(d: dict[str, str]) -> bytes:
    """
    Serialize a dict[str,str] in the QDataStream format used by
    KWallet's writeMap (which expects a QByteArray containing
    a serialized QMap<QString,QString>).

    Format:
        quint32  count
        for each item:
            QString key
            QString value

    QString:
        qint32 len_in_bytes  (or 0xFFFFFFFF for null)
        UTF-16BE bytes
    """
    def qstring(s: str) -> bytes:
        if s is None:
            return struct.pack(">I", 0xFFFFFFFF)
        data = s.encode("utf-16-be")
        return struct.pack(">I", len(data)) + data

    out = struct.pack(">I", len(d))
    for k, v in d.items():
        out += qstring(k) + qstring(v)
    return out


def write_map(kw: dbus.Interface, handle: int, key: str,
              value: dict[str, str]) -> int:
    blob = encode_qmap(value)
    ba   = dbus.ByteArray(blob)
    return int(kw.writeMap(handle, FOLDER, key, ba, APPID))


def has_entry(kw: dbus.Interface, handle: int, key: str) -> bool:
    return bool(kw.hasEntry(handle, FOLDER, key, APPID))


def entry_type(kw: dbus.Interface, handle: int, key: str) -> int:
    try:
        return int(kw.entryType(handle, FOLDER, key, APPID))
    except dbus.DBusException:
        return 0


# ---------------------------------------------------------------------------


def import_secrets() -> None:
    print("\n=== Preparing KWallet ===")
    kw, handle = open_wallet()

    print("\n=== Importing KWallet secrets ===")
    sec_dir = IMPORT_DIR / "secrets"
    if not sec_dir.is_dir():
        print(f"  No secrets directory: {sec_dir}")
        return

    for entryfile in sorted(sec_dir.glob("*.entryname")):
        base        = entryfile.stem
        secretfile  = sec_dir / f"{base}.secret"
        entry       = entryfile.read_text().strip()

        print(f"\nProcessing wallet entry:\n  {entry}")

        if not secretfile.is_file():
            print(f"  Missing secret file: {secretfile.name}, skipping")
            continue

        # Load secret as JSON dict (export script writes JSON map)
        try:
            data = json.loads(secretfile.read_text())
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
        except (json.JSONDecodeError, ValueError):
            # Fallback: treat file content as a single password value
            text = secretfile.read_text().strip()
            data = {"password": text}
            print("  (secret file is not JSON, wrapped as {'password': ...})")

        # Stringify everything
        data = {str(k): str(v) for k, v in data.items()}

        if has_entry(kw, handle, entry):
            etype = entry_type(kw, handle, entry)
            print(f"  Secret already exists (type={etype})")
            if not OVERWRITE:
                print("  Skipping")
                continue
            print("  Overwriting")
        else:
            print("  Importing as Map entry")

        rc = write_map(kw, handle, entry, data)
        if rc != 0:
            print(f"  WARNING: writeMap returned {rc}")
            continue

        etype = entry_type(kw, handle, entry)
        if etype == TYPE_MAP:
            print("  Import OK (Map)")
        else:
            print(f"  WARNING: stored entry type is {etype} (expected 3)")


# ---------------------------------------------------------------------------


def reload_nm() -> None:
    print("\n=== Reloading NetworkManager ===")
    sh(["sudo", "nmcli", "connection", "reload"])
    sh(["sudo", "systemctl", "restart", "NetworkManager"])


# ---------------------------------------------------------------------------


def main() -> int:
    global IMPORT_DIR, OVERWRITE

    parser = argparse.ArgumentParser(
        description="Import NetworkManager connections and KWallet secrets."
    )
    parser.add_argument(
        "-o", "--overwrite",
        action="store_true",
        help="overwrite existing connection files and wallet entries",
    )
    parser.add_argument(
        "-d", "--dir",
        type=Path,
        default=IMPORT_DIR,
        help=f"import directory (default: {IMPORT_DIR})",
    )
    args = parser.parse_args()

    IMPORT_DIR = args.dir
    OVERWRITE  = args.overwrite

    if not IMPORT_DIR.is_dir():
        print(f"ERROR: import directory not found: {IMPORT_DIR}",
              file=sys.stderr)
        return 1

    print(f"Import dir: {IMPORT_DIR}")
    print(f"Overwrite:  {OVERWRITE}")

    install_connections()
    import_secrets()
    reload_nm()

    print("\n=== Done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())