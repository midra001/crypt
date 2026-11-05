# CRYPT — batch obfuscation & AES-256 file protection

## Windows setup

Install Python 3.10+, extract all files into one folder, then run:

```powershell
py -3 -m pip install -r requirements.txt
```

Double-click `main.bat` for the CRYPT menu, or drop a batch file onto it to obfuscate it.

## Menu

1. **Obfuscate:** creates `name___.bat` / `name___.cmd` using the original runnable-header method. No restoration step, Python runtime, or third-party package is added to the resulting batch file.
2. **Encrypt:** password-protects any file with AES-256-GCM, creating `.bpaes`.
3. **Decrypt:** authenticates and restores encrypted files.
4. **Restore:** removes the runnable header, or restores `.obf` containers from the previous version.
5. **Pack:** retains the previous compressed/scrambled `.obf` format as an explicitly storage-only option.

The main obfuscation operation preserves the original tool's output format: the exact `FF FE 26 63 6C 73 0D 0A` header followed by the source bytes unchanged. This is **the original appearance-only technique, not stronger obfuscation or encryption**. Execution depends on Windows `cmd.exe` handling of that header; test your scripts on the target Windows version. The tool does not automatically execute outputs.

AES encryption is separate: encrypted files cannot run until decrypted. Passwords are requested through hidden prompts. Encryption requires at least 12 characters and confirmation. There is no password recovery.

## Command line

```powershell
py -3 crypt.py obfuscate "example.bat"
py -3 crypt.py restore "example___.bat"
py -3 crypt.py encrypt "private.txt"
py -3 crypt.py decrypt "private.txt.bpaes"
py -3 crypt.py pack "example.bat"
py -3 crypt.py restore "example.bat.obf"
```

The `legacy` command remains an alias for the original header method. The `crypt.py` filename and existing encryption/container signatures remain unchanged for compatibility. Use `-o` to choose a new output path. Existing files are never overwritten; originals are retained.

## Encryption

AES-256-GCM uses a fresh 16-byte salt, 12-byte nonce, and 128-bit authentication tag. Scrypt derives the 32-byte key with N=131072, r=8, p=1. The format header is authenticated. Wrong passwords or tampering produce no plaintext output.

Inputs are limited to 128 MiB. Allow several times that much RAM plus roughly 128 MiB for scrypt. File names, sizes, timestamps, and permissions are not confidential metadata preserved by the container. Python does not guarantee secure erasure of secrets from memory. Keep backups; this is not an audited security product.

## Tests

```powershell
py -3 -m unittest -v test_crypt.py
```

Tests check byte-for-byte compatibility with the original header, restoration, output collisions, source preservation, packing, AES round trips, and tamper detection. These checks do not establish Windows execution compatibility or console rendering; those require testing on Windows.
