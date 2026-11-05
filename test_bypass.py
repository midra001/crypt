import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bypass as b


class ProtectionTests(unittest.TestCase):
    password = "correct horse battery staple"

    @classmethod
    def setUpClass(cls):
        cls.data = bytes(range(256)) * 16 + b"\r\n@echo off\r\necho hello\r\n"
        cls.encrypted = b.encrypt_bytes(cls.data, cls.password)

    def test_aes_binary_round_trip(self):
        self.assertEqual(b.decrypt_bytes(self.encrypted, self.password), self.data)

    def test_aes_randomized(self):
        self.assertNotEqual(self.encrypted, b.encrypt_bytes(self.data, self.password))

    def test_wrong_password(self):
        with self.assertRaises(b.ToolError):
            b.decrypt_bytes(self.encrypted, "wrong password")

    def test_ciphertext_and_header_tampering(self):
        for index in (len(b.MAGIC), b.HEADER_SIZE - 1, b.HEADER_SIZE, len(self.encrypted) - 1):
            corrupted = bytearray(self.encrypted)
            corrupted[index] ^= 1
            with self.subTest(index=index), self.assertRaises(b.ToolError):
                b.decrypt_bytes(bytes(corrupted), self.password)

    def test_truncation_and_foreign_format(self):
        for value in (b"", b"foreign", self.encrypted[:-1], self.encrypted[:b.HEADER_SIZE]):
            with self.subTest(length=len(value)), self.assertRaises(b.ToolError):
                b.decrypt_bytes(value, self.password)

    def test_empty_encryption(self):
        self.assertEqual(b.decrypt_bytes(b.encrypt_bytes(b"", self.password), self.password), b"")

    def test_obfuscation_round_trip_and_randomness(self):
        for value in (b"", self.data, b"a" * 100000, b"\xff\xfe\x00\r\n"):
            with self.subTest(length=len(value)):
                first = b.obfuscate_bytes(value)
                self.assertEqual(b.restore_bytes(first), value)
                self.assertNotEqual(first, b.obfuscate_bytes(value))

    def test_corrupt_obfuscation(self):
        value = bytearray(b.obfuscate_bytes(self.data))
        value[len(b.OBF_MAGIC) + 8] ^= 1
        for damaged in (b"", bytes(value), bytes(value[:-1])):
            with self.assertRaises(b.ToolError):
                b.restore_bytes(damaged)

    def test_bad_compression_and_trailing_data(self):
        value = b.obfuscate_bytes(self.data)
        for damaged in (value + b"!!!!", value[:len(b.OBF_MAGIC) + 72] + b"AAAA"):
            with self.assertRaises(b.ToolError):
                b.restore_bytes(damaged)

    def test_obfuscation_size_guard(self):
        with patch.object(b, "MAX_SIZE", 16):
            with self.assertRaises(b.ToolError):
                b.obfuscate_bytes(b"x" * 17)
            with self.assertRaises(b.ToolError):
                b.restore_bytes(b.OBF_MAGIC + (17).to_bytes(8, "big") + b"x" * 64)

    def test_file_paths_collisions_and_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "spaces & unicode Ω.bat"
            source.write_bytes(self.data)
            legacy = b.process("legacy", source)
            self.assertEqual(legacy.name, source.stem + "___.bat")
            self.assertEqual(legacy.read_bytes(), b.LEGACY_HEADER + self.data)
            with self.assertRaises(FileExistsError):
                b.process("legacy", source)
            with self.assertRaises(b.ToolError):
                b.process("legacy", legacy)
            obfuscated = b.process("pack", source)
            restored = b.process("restore", obfuscated)
            self.assertEqual(restored.name, "spaces & unicode Ω.restored.bat")
            self.assertEqual(restored.read_bytes(), self.data)
            with self.assertRaises(FileExistsError):
                b.process("obfuscate", source, source)
            self.assertEqual(source.read_bytes(), self.data)

    def test_default_obfuscation_preserves_original_runnable_format(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "hello.cmd"
            original = b"@echo off\r\necho hello %*\r\nexit /b 7\r\n"
            source.write_bytes(original)
            result = b.process("obfuscate", source)
            self.assertEqual(result.name, "hello___.cmd")
            self.assertEqual(result.read_bytes(), b.LEGACY_HEADER + original)
            self.assertEqual(source.read_bytes(), original)
            restored = b.process("restore", result)
            self.assertEqual(restored.read_bytes(), original)
            with self.assertRaises(b.ToolError):
                b.process("obfuscate", result)

    def test_encrypt_decrypt_files_and_no_partial_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "private.bin"
            source.write_bytes(self.data)
            encrypted = b.process("encrypt", source, password=self.password)
            failed_output = Path(directory) / "should-not-exist"
            with self.assertRaises(b.ToolError):
                b.process("decrypt", encrypted, failed_output, password="wrong")
            self.assertFalse(failed_output.exists())
            restored = b.process("decrypt", encrypted, password=self.password)
            self.assertEqual(restored.read_bytes(), self.data)
            self.assertEqual(source.read_bytes(), self.data)

    def test_reject_short_password_and_non_batch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.txt"
            source.write_bytes(b"test")
            with self.assertRaises(b.ToolError):
                b.process("encrypt", source, password="short")
            for action in ("legacy", "obfuscate"):
                with self.assertRaises(b.ToolError):
                    b.process(action, source)


if __name__ == "__main__":
    unittest.main()
