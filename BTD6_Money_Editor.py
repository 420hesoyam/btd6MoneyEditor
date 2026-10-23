#!/usr/bin/env python3
"""
BTD6 Monkey Money Editor (console)

Finds the Bloons TD 6 Profile.Save automatically (Epic/Heroic, Steam, Windows
Store and common Ninja Kiwi folders), decrypts it, lets you enter the desired
monkey money amount, makes a timestamped backup, edits the save and verifies
that the result can be read back.

Usage:
    python BTD6_Money_Editor.py
    python BTD6_Money_Editor.py --money 1000000000
    python BTD6_Money_Editor.py --save "C:\\path\\Profile.Save" --money 5000000000

Options:
    -s, --save PATH   Use a specific Profile.Save file
    -m, --money AMT   New monkey money amount (supports commas, 1k/1m/1b, max)
    -y, --yes         Do not ask for confirmation
        --dry-run     Only detect saves and print current values
        --force       Allow editing while BloonsTD6.exe is running
        --no-pause    Do not wait for Enter before closing
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

PROFILE_NAME = "Profile.Save"
PASSWORD = b"11"
PBKDF2_ITERATIONS = 10
SALT_LENGTH = 24
DEFAULT_AMOUNT = 1_000_000_000
MAX_SAFE_INT32 = 2_147_483_647
MAX_ALLOWED = 1_000_000_000_000_000  # 1 quadrillion

MONEY_RE = re.compile(r'"monkeyMoney"\s*:\s*(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)')
TS_RE = re.compile(r'"timeStamp"\s*:\s*"([^"]*)"')
EPOCH_1AD = datetime(1, 1, 1, tzinfo=timezone.utc)

AES = None


class SaveError(Exception):
    pass


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def get_aes():
    """Import pycryptodome, installing it with pip if it is missing."""
    global AES
    if AES is not None:
        return AES
    try:
        from Crypto.Cipher import AES as _AES
        AES = _AES
        return AES
    except ImportError:
        print("pycryptodome is required. Installing it with pip ...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "pycryptodome"]
            )
        except Exception:
            print()
            print("Could not install pycryptodome automatically.")
            print("Open a console and run:")
            print(f'  "{sys.executable}" -m pip install pycryptodome')
            raise SystemExit(1)
        try:
            from Crypto.Cipher import AES as _AES
            AES = _AES
            return AES
        except ImportError:
            print("pycryptodome installed but still cannot be imported.")
            raise SystemExit(1)


# ---------------------------------------------------------------------------
# Save parsing / crypto
# ---------------------------------------------------------------------------

@dataclass
class SaveInfo:
    path: Path
    raw: bytes
    text: str
    money: float
    money_start: int
    money_end: int
    is_plain: bool
    version: int = 0
    extra_len: int = 0
    save_count: int = 0
    salt: bytes = b""
    data_offset: int = 0
    mtime: float = 0.0


def derive_key(salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, PBKDF2_ITERATIONS, 32)


def decrypt_payload(ciphertext: bytes, salt: bytes) -> bytes:
    aes = get_aes()
    key = derive_key(salt)
    iv, aes_key = key[:16], key[16:32]
    padded = aes.new(aes_key, aes.MODE_CBC, iv).decrypt(ciphertext)
    try:
        return zlib.decompress(padded)
    except zlib.error as exc:
        raise SaveError("decryption failed (wrong password or unsupported format)") from exc


def encrypt_payload(plaintext: bytes, salt: bytes) -> bytes:
    aes = get_aes()
    key = derive_key(salt)
    iv, aes_key = key[:16], key[16:32]
    compressed = zlib.compress(plaintext, 3)
    pad = 16 - (len(compressed) % 16)
    padded = compressed + bytes([pad]) * pad
    return aes.new(aes_key, aes.MODE_CBC, iv).encrypt(padded)


def load_save(path: Path, require_text: bool = True) -> SaveInfo:
    """Read and validate a BTD6 Profile.Save (encrypted or plain JSON)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SaveError(f"cannot read file: {exc}") from exc

    mtime = path.stat().st_mtime

    # Plain JSON fallback (some old/other-platform saves are not encrypted).
    stripped = raw.lstrip(b"\xef\xbb\xbf").lstrip()
    if stripped.startswith(b"{"):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SaveError("plain save is not valid UTF-8") from exc
        m = MONEY_RE.search(text)
        if not m:
            raise SaveError("monkeyMoney field not found in plain save")
        return SaveInfo(
            path=path, raw=raw, text=text, money=float(m.group(1)),
            money_start=m.start(1), money_end=m.end(1), is_plain=True,
            mtime=mtime,
        )

    if len(raw) < 76:
        raise SaveError("file is too small to be a BTD6 Profile.Save")

    version, extra_len = struct.unpack_from("<ii", raw, 0)
    if extra_len < 28 or extra_len > 4096:
        raise SaveError(f"unsupported header (version={version}, extraLen={extra_len})")

    header_end = 8 + extra_len
    salt_offset = header_end + 8          # skip the 8-byte pwIdx field
    data_offset = salt_offset + SALT_LENGTH
    if data_offset >= len(raw):
        raise SaveError("truncated save header")

    salt = raw[salt_offset:data_offset]
    ciphertext = raw[data_offset:]
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise SaveError("encrypted data length is not a multiple of 16")

    plaintext = decrypt_payload(ciphertext, salt)
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SaveError("decrypted data is not valid UTF-8") from exc

    matches = list(MONEY_RE.finditer(text))
    if not matches:
        raise SaveError("monkeyMoney field not found after decryption")
    if len(matches) > 1:
        raise SaveError("more than one monkeyMoney field found; refusing to edit")

    m = matches[0]
    save_count = struct.unpack_from("<i", raw, 8)[0] if extra_len >= 4 else 0

    return SaveInfo(
        path=path, raw=raw, text=text, money=float(m.group(1)),
        money_start=m.start(1), money_end=m.end(1), is_plain=False,
        version=version, extra_len=extra_len, save_count=save_count,
        salt=salt, data_offset=data_offset, mtime=mtime,
    )


# ---------------------------------------------------------------------------
# Locating Profile.Save
# ---------------------------------------------------------------------------

def steam_roots() -> list[Path]:
    roots: set[Path] = set()

    # Registry (Windows).
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") as key:
            value, _ = winreg.QueryValueEx(key, "SteamPath")
            roots.add(Path(value))
    except Exception:
        pass

    for env in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.environ.get(env)
        if base:
            roots.add(Path(base) / "Steam")

    for letter in "CDEFGHIJ":
        roots.add(Path(f"{letter}:\\Steam"))
        roots.add(Path(f"{letter}:\\SteamLibrary"))

    # Extra Steam libraries listed in libraryfolders.vdf.
    libraries = set(roots)
    for root in list(roots):
        vdf = root / "steamapps" / "libraryfolders.vdf"
        if not vdf.is_file():
            continue
        try:
            text = vdf.read_text(encoding="utf-8", errors="ignore")
            for match in re.finditer(r'"path"\s*"([^"]+)"', text):
                libraries.add(Path(match.group(1).replace("\\\\", "\\")))
        except OSError:
            pass

    return [p for p in libraries if p.is_dir()]


def is_backup_location(path: Path) -> bool:
    """Ignore Profile.Save files that live inside a backup folder."""
    for part in path.parts:
        lowered = part.lower()
        if lowered.startswith(("profilebackup", "profile_backup", "profile-backup")):
            return True
        if lowered in ("profilebackups", "btd6_profile_backups"):
            return True
    return False


def find_save_candidates() -> list[Path]:
    seen: set[Path] = set()
    found: list[Path] = []

    def add(path: Path):
        if is_backup_location(path):
            return
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved in seen:
            return
        seen.add(resolved)
        if resolved.is_file():
            found.append(resolved)

    home = Path.home()

    # Main Ninja Kiwi data folders (Epic/Heroic, Steam-wrapper, store builds).
    for base in (
        home / "AppData" / "LocalLow" / "Ninja Kiwi",
        home / "AppData" / "Roaming" / "Ninja Kiwi",
        home / "AppData" / "Local" / "Ninja Kiwi",
    ):
        if base.is_dir():
            for path in base.rglob(PROFILE_NAME):
                add(path)

    # Steam userdata for app id 960090.
    for root in steam_roots():
        for path in root.glob(f"userdata/*/960090/**/{PROFILE_NAME}"):
            add(path)

    # Windows Store / Xbox package folders.
    packages = home / "AppData" / "Local" / "Packages"
    if packages.is_dir():
        for folder in packages.glob("*Ninja*"):
            for path in folder.rglob(PROFILE_NAME):
                add(path)

    # A save dropped next to the script or in the current directory.
    for base in {Path.cwd(), Path(__file__).resolve().parent}:
        add(base / PROFILE_NAME)

    return found


def collect_valid_saves() -> tuple[list[SaveInfo], list[tuple[Path, str]]]:
    valid: list[SaveInfo] = []
    errors: list[tuple[Path, str]] = []
    for path in find_save_candidates():
        try:
            valid.append(load_save(path))
        except Exception as exc:
            errors.append((path, str(exc)))
    valid.sort(key=lambda info: (info.mtime, info.save_count), reverse=True)
    return valid, errors


def choose_save(args) -> SaveInfo:
    if args.save:
        raw_path = args.save.strip().strip('"').strip("'")
        path = Path(os.path.expandvars(os.path.expanduser(raw_path)))
        if not path.is_file():
            raise SaveError(f"file not found: {path}")
        return load_save(path)

    valid, errors = collect_valid_saves()

    if not valid:
        if errors:
            print("Found files, but none look like a readable BTD6 save:")
            for path, error in errors:
                print(f"  - {path}  ({error})")
        print()
        print("Could not find a readable Profile.Save automatically.")
        if not sys.stdin.isatty():
            raise SaveError("specify the save file with --save PATH")
        for _ in range(3):
            try:
                entered = input(
                    "Enter the full path to Profile.Save (or drag & drop it here): "
                ).strip().strip('"').strip("'")
            except EOFError as exc:
                raise SaveError("no console input; use --save PATH") from exc
            if not entered:
                raise SaveError("no path entered")
            path = Path(os.path.expandvars(os.path.expanduser(entered)))
            try:
                return load_save(path)
            except Exception as exc:
                print(f"  Not usable: {exc}")
        raise SaveError("could not read a valid save file")

    if len(valid) == 1:
        return valid[0]

    if not sys.stdin.isatty():
        print("Multiple readable saves found:")
        for info in valid:
            print(f"  {info.path}")
        raise SaveError("choose one explicitly with --save PATH")

    print("Multiple readable saves found:")
    for index, info in enumerate(valid, 1):
        when = datetime.fromtimestamp(info.mtime).strftime("%Y-%m-%d %H:%M")
        print(f"  [{index}] {info.path}")
        print(
            f"      version={info.version or 'plain'}  "
            f"saveCount={info.save_count}  "
            f"money={format_money(info.money)}  modified={when}"
        )
    while True:
        try:
            choice = input(f"Select save [1-{len(valid)}] (default 1): ").strip()
        except EOFError as exc:
            raise SaveError("no console input; use --save PATH") from exc
        if not choice:
            return valid[0]
        if choice.isdigit() and 1 <= int(choice) <= len(valid):
            return valid[int(choice) - 1]
        print("  Invalid choice, try again.")


# ---------------------------------------------------------------------------
# Editing
# ---------------------------------------------------------------------------

def format_money(value: float) -> str:
    try:
        if float(value).is_integer():
            return f"{int(value):,}"
        return f"{value:,.2f}"
    except (ValueError, OverflowError):
        return str(value)


def parse_amount(text: str) -> int:
    cleaned = text.strip().lower().replace(",", "").replace("_", "").replace(" ", "")
    if cleaned in ("max", "maximum"):
        return MAX_SAFE_INT32
    if not cleaned:
        raise ValueError("empty amount")

    multiplier = 1
    if cleaned[-1] in ("k", "m", "b"):
        multiplier = {"k": 1_000, "m": 1_000_000, "b": 1_000_000_000}[cleaned[-1]]
        cleaned = cleaned[:-1]

    if not re.fullmatch(r"\d+(?:\.\d+)?", cleaned):
        raise ValueError("enter a whole number (examples: 1000000000, 1b, max)")

    try:
        amount = int(Decimal(cleaned) * multiplier)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("invalid number") from exc

    if amount < 0:
        raise ValueError("amount cannot be negative")
    if amount > MAX_ALLOWED:
        raise ValueError(f"amount is too large (maximum {MAX_ALLOWED:,})")
    return amount


def format_amount_for_save(original_text: str, amount: int) -> str:
    lowered = original_text.lower()
    if "." in lowered or "e" in lowered:
        return f"{amount}.0"
    return str(amount)


def build_timestamp(now: datetime) -> str:
    return now.astimezone().isoformat(timespec="microseconds")


def datetime_binary(iso_text: str) -> int:
    try:
        moment = datetime.fromisoformat(iso_text)
        if moment.tzinfo is None:
            moment = moment.astimezone()
        moment = moment.astimezone(timezone.utc)
    except ValueError:
        moment = datetime.now(timezone.utc)
    ticks = ((moment - EPOCH_1AD) // timedelta(microseconds=1)) * 10
    return ticks | (1 << 62)  # DateTimeKind.Utc


def apply_edit(info: SaveInfo, amount: int) -> str:
    """Return the edited JSON text."""
    new_text = (
        info.text[:info.money_start]
        + format_amount_for_save(info.text[info.money_start:info.money_end], amount)
        + info.text[info.money_end:]
    )

    now_text = build_timestamp(datetime.now())
    if TS_RE.search(new_text):
        new_text = TS_RE.sub(
            lambda match: f'"timeStamp":"{now_text}"', new_text, count=1
        )
    return new_text


def rebuild_save(info: SaveInfo, new_text: str) -> bytes:
    encoded = new_text.encode("utf-8")
    if info.is_plain:
        return encoded

    encrypted = encrypt_payload(encoded, info.salt)
    header = bytearray(info.raw[:info.data_offset])

    # Increment the per-save counter.
    if info.extra_len >= 4:
        new_count = info.save_count + 1
        if new_count > MAX_SAFE_INT32:
            new_count = 1
        struct.pack_into("<i", header, 8, new_count)

    # Keep the header datetime in sync with the JSON timeStamp.
    ts_match = TS_RE.search(new_text)
    timestamp = ts_match.group(1) if ts_match else build_timestamp(datetime.now())
    if info.extra_len >= 28:
        struct.pack_into("<q", header, 36, datetime_binary(timestamp))

    return bytes(header) + encrypted


def game_is_running() -> bool:
    if os.name != "nt":
        return False
    try:
        result = subprocess.run(
            ["tasklist", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, errors="ignore", timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return "bloonstd6" in result.stdout.lower()
    except Exception:
        return False


def make_backup(path: Path) -> Path:
    documents = Path.home() / "Documents"
    root = documents if documents.is_dir() else Path.home()
    root = root / "BTD6_Profile_Backups"
    root.mkdir(parents=True, exist_ok=True)

    label = path.parent.name
    for parent in path.parents:
        if parent.name in ("PRODUCTION", "current"):
            continue
        if parent.name and parent.name not in ("link",):
            label = parent.name
            break

    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    backup_dir = root / f"{label}_{stamp}"
    counter = 1
    while backup_dir.exists():
        backup_dir = root / f"{label}_{stamp}_{counter}"
        counter += 1
    backup_dir.mkdir()

    shutil.copy2(path, backup_dir / path.name)
    sibling_bak = path.with_name("Profile.bak")
    if sibling_bak.is_file():
        shutil.copy2(sibling_bak, backup_dir / "Profile.bak")

    restore = (
        "BTD6 Profile.Save backup\n"
        "========================\n\n"
        f"Original file: {path}\n"
        f"Backup made:   {datetime.now().isoformat(timespec='seconds')}\n\n"
        "To restore:\n"
        "  1. Close Bloons TD 6 completely.\n"
        f"  2. Copy Profile.Save from this folder back to:\n     {path}\n"
        f"     (and optionally Profile.bak to {sibling_bak})\n"
    )
    (backup_dir / "RESTORE.txt").write_text(restore, encoding="utf-8")
    return backup_dir


def write_and_verify(info: SaveInfo, new_data: bytes, amount: int, backup_file: Path):
    temp_path = info.path.with_name(info.path.name + ".tmp")
    try:
        with open(temp_path, "wb") as handle:
            handle.write(new_data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, info.path)
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    try:
        check = load_save(info.path)
        if int(check.money) != amount:
            raise SaveError(
                f"verification failed: file contains {check.money!r} instead of {amount}"
            )
        return check
    except Exception:
        # Put the original back if anything about the new file is wrong.
        try:
            shutil.copy2(backup_file, info.path)
            print("Verification failed - the original save was restored.")
        except Exception as restore_error:
            print(f"Verification failed AND restore failed: {restore_error}")
        raise


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Edit Bloons TD 6 monkey money safely, with automatic backup.",
    )
    parser.add_argument("-s", "--save", help="path to Profile.Save")
    parser.add_argument("-m", "--money", help="new monkey money amount")
    parser.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    parser.add_argument("--dry-run", action="store_true", help="only detect/read saves")
    parser.add_argument("--force", action="store_true", help="allow editing while the game runs")
    parser.add_argument("--no-pause", action="store_true", help="do not wait for Enter at exit")
    return parser.parse_args(argv)


def print_save_info(info: SaveInfo):
    when = datetime.fromtimestamp(info.mtime).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Save file   : {info.path}")
    print(f"Format      : {'plain JSON' if info.is_plain else f'encrypted v{info.version}'}")
    if not info.is_plain:
        print(f"Save count  : {info.save_count}")
    print(f"Modified    : {when}")
    print(f"Monkey money: {format_money(info.money)}")


def run(args) -> int:
    print("=" * 62)
    print("  Bloons TD 6 - Monkey Money Editor")
    print("=" * 62)
    print()

    if args.dry_run:
        if args.save:
            raw_path = args.save.strip().strip('"').strip("'")
            path = Path(os.path.expandvars(os.path.expanduser(raw_path)))
            infos, errors = [load_save(path)], []
        else:
            infos, errors = collect_valid_saves()

        if not infos:
            print("No readable BTD6 saves found.")
            for path, error in errors:
                print(f"  - {path}  ({error})")
            return 1

        for index, save_info in enumerate(infos, 1):
            if len(infos) > 1:
                print(f"[{index}]")
            print_save_info(save_info)
            print()
        print("Dry run - no changes made.")
        return 0

    info = choose_save(args)
    print_save_info(info)
    print()

    if game_is_running() and not args.force:
        print("BloonsTD6.exe is running. Close the game completely and run this again.")
        print("(Advanced: use --force to edit anyway.)")
        return 1

    if args.money is not None:
        try:
            amount = parse_amount(args.money)
        except ValueError as exc:
            print(f"Invalid --money value: {exc}")
            return 1
    else:
        if not sys.stdin.isatty():
            print("No --money value given and no console available.")
            return 1
        print(f"Enter the amount you want (default: {DEFAULT_AMOUNT:,}).")
        print("You can use 1k / 1m / 1b or 'max' (2,147,483,647).")
        while True:
            entered = input("New monkey money: ").strip()
            if not entered:
                amount = DEFAULT_AMOUNT
                break
            if entered.lower() in ("q", "quit", "exit"):
                print("Cancelled.")
                return 0
            try:
                amount = parse_amount(entered)
                break
            except ValueError as exc:
                print(f"  {exc}")

    if abs(info.money - amount) < 0.5:
        print(f"Monkey money is already {format_money(amount)} - nothing to do.")
        return 0

    if amount > MAX_SAFE_INT32:
        print()
        print(
            f"WARNING: {amount:,} is above the signed 32-bit range "
            f"({MAX_SAFE_INT32:,})."
        )
        print("The game may display or handle it incorrectly.")
        if not args.yes and sys.stdin.isatty():
            if input("Continue anyway? (y/N): ").strip().lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        print()

    if not args.yes:
        print()
        print(f"Change {format_money(info.money)} -> {format_money(amount)} ?")
        if sys.stdin.isatty():
            if input("Apply this change? (y/N): ").strip().lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        else:
            print("No confirmation possible in this console; use --yes.")
            return 1

    print()
    print("Creating backup ...")
    backup_dir = make_backup(info.path)
    backup_file = backup_dir / info.path.name
    print(f"Backup: {backup_dir}")

    new_text = apply_edit(info, amount)
    new_data = rebuild_save(info, new_text)
    print(f"Writing save ({len(new_data):,} bytes) ...")

    check = write_and_verify(info, new_data, amount, backup_file)

    print()
    print("SUCCESS")
    print(f"  Monkey money : {format_money(check.money)}")
    print(f"  Save file    : {check.path}")
    print(f"  Backup       : {backup_dir}")
    print()
    print("Start the game and check the main menu.")
    return 0


def main() -> int:
    if os.name == "nt":
        try:
            os.system("title BTD6 Monkey Money Editor")
        except Exception:
            pass

    args = parse_args()
    exit_code = 0
    try:
        exit_code = run(args)
    except KeyboardInterrupt:
        print("\nCancelled.")
        exit_code = 130
    except SaveError as exc:
        print(f"\nERROR: {exc}")
        exit_code = 1
    except EOFError:
        print("\nNo console input available.")
        print("Use: --save PATH --money AMOUNT --yes")
        exit_code = 1
    except Exception as exc:
        print(f"\nUNEXPECTED ERROR: {exc}")
        exit_code = 1
    finally:
        if not args.no_pause:
            try:
                input("\nPress Enter to exit...")
            except (EOFError, KeyboardInterrupt):
                pass
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
