"""CRYPT: runnable batch obfuscation and separate AES-256 file protection."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import struct
import sys
import zlib

MAGIC = b"BYPASS-AES256\x00\x01"
OBF_MAGIC = b"BYPASS-OBF\x00\x01"
LEGACY_HEADER = b"\xff\xfe&cls\r\n"
MAX_SIZE = 128 * 1024 * 1024
SALT_SIZE, NONCE_SIZE = 16, 12
KDF_N, KDF_R, KDF_P = 2**17, 8, 1
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE


class ToolError(Exception):
    pass


def read_input(path: Path) -> bytes:
    if not path.is_file():
        raise ToolError(f"Not a regular file: {path}")
    with path.open("rb") as source:
        data = source.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        raise ToolError("File exceeds the 128 MiB safety limit.")
    return data


def save_new(path: Path, data: bytes) -> Path:
    """Exclusive creation, including competing processes; never replace a file."""
    if not path.parent.is_dir():
        raise ToolError(f"Output folder does not exist: {path.parent}")
    created = False
    try:
        with path.open("xb") as target:
            created = True
            # Best-effort protection on platforms with POSIX permissions.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise
    return path


def crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.exceptions import InvalidTag
        return AESGCM, Scrypt, InvalidTag
    except ImportError as exc:
        raise ToolError("AES support is missing. Run: python -m pip install -r requirements.txt") from exc


def key_from_password(password: str, salt: bytes) -> bytes:
    if not password:
        raise ToolError("The password cannot be empty.")
    _, Scrypt, _ = crypto()
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    if len(data) > MAX_SIZE:
        raise ToolError("File exceeds the 128 MiB safety limit.")
    AESGCM, _, _ = crypto()
    salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
    header = MAGIC + salt + nonce
    return header + AESGCM(key_from_password(password, salt)).encrypt(nonce, data, header)


def decrypt_bytes(data: bytes, password: str) -> bytes:
    if len(data) < HEADER_SIZE + 16 or not data.startswith(MAGIC):
        raise ToolError("Not a supported BYPASS encrypted file, or its header is damaged.")
    if len(data) > MAX_SIZE + HEADER_SIZE + 16:
        raise ToolError("Encrypted file exceeds the size limit.")
    AESGCM, _, InvalidTag = crypto()
    header = data[:HEADER_SIZE]
    salt = header[len(MAGIC):len(MAGIC) + SALT_SIZE]
    nonce = header[-NONCE_SIZE:]
    try:
        return AESGCM(key_from_password(password, salt)).decrypt(nonce, data[HEADER_SIZE:], header)
    except InvalidTag as exc:
        raise ToolError("Wrong password or damaged/tampered file. Nothing was decrypted.") from exc


def read_container(path: Path, overhead: int) -> bytes:
    if not path.is_file():
        raise ToolError(f"Not a regular file: {path}")
    with path.open("rb") as source:
        data = source.read(MAX_SIZE + overhead + 1)
    if len(data) > MAX_SIZE + overhead:
        raise ToolError("Container exceeds the size limit.")
    return data


def obfuscate_bytes(data: bytes) -> bytes:
    """Compressed, randomized reversible encoding; intentionally NOT encryption."""
    if len(data) > MAX_SIZE:
        raise ToolError("File exceeds the 128 MiB safety limit.")
    mask = secrets.token_bytes(32)
    packed = zlib.compress(data, level=9)
    scrambled = bytes(value ^ mask[i % len(mask)] for i, value in enumerate(packed))
    return OBF_MAGIC + struct.pack(">Q", len(data)) + hashlib.sha256(data).digest() + mask + base64.b64encode(scrambled)


def restore_bytes(data: bytes) -> bytes:
    head = len(OBF_MAGIC)
    if not data.startswith(OBF_MAGIC) or len(data) < head + 72:
        raise ToolError("Not a supported BYPASS obfuscated file.")
    length = struct.unpack(">Q", data[head:head + 8])[0]
    if length > MAX_SIZE:
        raise ToolError("Restored file would exceed the size limit.")
    digest = data[head + 8:head + 40]
    mask = data[head + 40:head + 72]
    try:
        packed = base64.b64decode(data[head + 72:], validate=True)
        packed = bytes(value ^ mask[i % 32] for i, value in enumerate(packed))
        decoder = zlib.decompressobj()
        original = decoder.decompress(packed, length + 1)
        if len(original) != length or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ValueError("Invalid compressed data")
        if not hmac.compare_digest(hashlib.sha256(original).digest(), digest):
            raise ValueError("Checksum mismatch")
        return original
    except (ValueError, zlib.error) as exc:
        raise ToolError("Obfuscated file is damaged or invalid.") from exc


def restored_name(source: Path, suffix: str) -> Path:
    name = source.name[:-len(suffix)] if source.name.lower().endswith(suffix) else source.name
    original = Path(name)
    return source.with_name(original.stem + ".restored" + original.suffix)


def process(action: str, source: Path, output: Path | None = None, password: str | None = None) -> Path:
    if action in ("encrypt", "decrypt") and password is None:
        password = getpass.getpass("Password: ")
        if action == "encrypt":
            if len(password) < 12:
                raise ToolError("Use at least 12 characters; a long unique passphrase is recommended.")
            if password != getpass.getpass("Confirm password: "):
                raise ToolError("Passwords do not match.")
    if action == "encrypt":
        if password is None or len(password) < 12:
            raise ToolError("Use a password of at least 12 characters.")
        result = encrypt_bytes(read_input(source), password)
        destination = output or source.with_name(source.name + ".bpaes")
    elif action == "decrypt":
        result = decrypt_bytes(read_container(source, HEADER_SIZE + 16), password or "")
        destination = output or restored_name(source, ".bpaes")
    elif action == "pack":
        if source.suffix.lower() not in (".bat", ".cmd"):
            raise ToolError("Batch obfuscation accepts .bat and .cmd files only.")
        result = obfuscate_bytes(read_input(source))
        destination = output or source.with_name(source.name + ".obf")
    elif action == "restore":
        container = read_container(source, MAX_SIZE // 2 + 1024 * 1024)
        if container.startswith(LEGACY_HEADER):
            result = container[len(LEGACY_HEADER):]
            if len(result) > MAX_SIZE:
                raise ToolError("Restored file exceeds the size limit.")
            destination = output or source.with_name(source.stem + ".restored" + source.suffix)
        else:
            result = restore_bytes(container)
            destination = output or restored_name(source, ".obf")
    elif action in ("obfuscate", "legacy"):
        if source.suffix.lower() not in (".bat", ".cmd"):
            raise ToolError("Legacy mode accepts .bat and .cmd files only.")
        original = read_input(source)
        if original.startswith(LEGACY_HEADER):
            raise ToolError("This file already has the legacy header.")
        result = LEGACY_HEADER + original
        destination = output or source.with_name(source.stem + "___" + source.suffix)
    else:
        raise ToolError("Unknown operation.")
    return save_new(destination, result)


BANNER = (
    " ▄▄· ▄▄▄   ▄· ▄▌ ▄▄▄· ▄▄▄▄▄",
    "▐█ ▌▪▀▄ █·▐█▪██▌▐█ ▄█ •██  ",
    "██ ▄▄▐▀▀▄ ▐█▌▐█▪ ██▀·  ▐█.▪",
    "▐███▌▐█•█▌ ▐█▀·.▐█▪·•  ▐█▌·",
    "·▀▀▀ .▀  ▀  ▀ • .▀     ▀▀▀ ",
)


def setup_console() -> bool:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if os.name == "nt":
        try:
            import ctypes
            kernel = ctypes.windll.kernel32
            kernel.SetConsoleOutputCP(65001)
            handle = kernel.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel.SetConsoleMode(handle, mode.value | 4))
        except (AttributeError, OSError):
            return False
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def menu() -> int:
    color = setup_console() and "NO_COLOR" not in os.environ
    colors = (34, 94, 36, 96, 96)
    print("\n\n")
    for line, shade in zip(BANNER, colors):
        print(f"\033[{shade}m                    {line}\033[0m" if color else "                    " + line)
    print("\n                    LOCAL FILE PROTECTION\n")
    actions = {"1": "obfuscate", "2": "encrypt", "3": "decrypt", "4": "restore", "5": "pack"}
    while True:
        print("    ╔══» [1] Obfuscate batch → runnable .bat / .cmd")
        print("    ╠══» [2] Encrypt file    → AES-256-GCM")
        print("    ╠══» [3] Decrypt file")
        print("    ╠══» [4] Restore obfuscated batch")
        print("    ╠══» [5] Pack batch → .obf (storage only)")
        print("    ╚══» [0] Exit\n")
        choice = input("    Select: ").strip()
        if choice == "0":
            return 0
        if choice not in actions:
            print("\nChoose a number from 0 to 5.\n")
            continue
        source = Path(input("    Input path (drag a file here): ").strip().strip('"'))
        if actions[choice] == "obfuscate":
            print("    Appearance-only compatibility mode, not security; test on your Windows version.")
        try:
            destination = process(actions[choice], source)
            print(f"\n    Saved: {destination}\n    Original file kept unchanged.\n")
        except (ToolError, OSError, MemoryError) as exc:
            print(f"\n    Error: {exc}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("obfuscate", "restore", "encrypt", "decrypt", "legacy", "pack"))
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("-o", "--output", type=Path, help="New output path; existing paths are never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.action is None:
            return menu()
        if args.input is None:
            parser.error("an input file is required")
        print(f"Saved: {process(args.action, args.input, args.output)}")
        return 0
    except (ToolError, OSError, MemoryError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Original files are unchanged.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
