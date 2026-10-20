"""
Automated tests for crypto_manager.py (run with: python -m unittest -v).

Every test works inside a temporary directory that is deleted afterwards,
so your real documents are never touched.
"""

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto_manager as cm  # noqa: E402

# Fast Scrypt settings for most tests (the real default is used in one test).
FAST = cm.KdfParams(n_log2=12, r=8, p=1)
PASSWORD = "correct horse battery staple"
SMALL_CHUNK = cm.MIN_CHUNK_SIZE  # 4096 bytes -> multi-chunk files without huge data


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CryptoTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    # helpers ---------------------------------------------------------------
    def make_file(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def encrypt(self, src: Path, **kwargs) -> Path:
        kwargs.setdefault("kdf_params", FAST)
        return cm.encrypt_file(src, PASSWORD, **kwargs)

    def leftover_temp_files(self):
        return [p.name for p in self.dir.rglob("*") if p.name.endswith(".tmp")]

    def craft_encrypted(self, path: Path, name_bytes: bytes, plaintext=b"data"):
        """Build a valid encrypted file with an arbitrary stored filename."""
        salt, prefix = os.urandom(16), os.urandom(8)
        header = cm.build_header(FAST, salt, prefix, cm.DEFAULT_CHUNK_SIZE, name_bytes)
        key = cm.derive_key(PASSWORD.encode(), salt, FAST)
        body = AESGCM(key).encrypt(cm.make_nonce(prefix, 0), plaintext,
                                   cm.make_aad(header, True))
        path.write_bytes(header + body)


class RoundTripTests(CryptoTestCase):
    def test_text_file_round_trip(self):
        src = self.make_file("notes.txt", "Hello, wörld! 你好\n".encode("utf-8") * 50)
        enc = self.encrypt(src)
        self.assertEqual(enc.name, "notes.txt.enc")
        src.unlink()
        out = cm.decrypt_file(enc, PASSWORD)
        self.assertEqual(out.name, "notes.txt")
        self.assertEqual(out.read_bytes(), "Hello, wörld! 你好\n".encode("utf-8") * 50)

    def test_binary_files_round_trip_exactly(self):
        samples = {
            "photo.png": b"\x89PNG\r\n\x1a\n" + os.urandom(30_000),
            "doc.pdf": b"%PDF-1.7\n" + os.urandom(70_000) + b"\n%%EOF",
            "archive.zip": b"PK\x03\x04" + os.urandom(12_345),
            "data.csv": b"a,b,c\n1,2,3\n" * 1000,
        }
        for name, data in samples.items():
            with self.subTest(name=name):
                src = self.make_file(name, data)
                enc = self.encrypt(src)
                out = cm.decrypt_file(enc, PASSWORD, self.dir / ("restored_" + name))
                self.assertEqual(out.read_bytes(), data)

    def test_chunk_boundary_sizes(self):
        # empty, 1 byte, just below / exactly at / just above chunk multiples
        for size in (0, 1, SMALL_CHUNK - 1, SMALL_CHUNK, SMALL_CHUNK + 1,
                     SMALL_CHUNK * 3, SMALL_CHUNK * 3 + 7):
            with self.subTest(size=size):
                data = os.urandom(size)
                src = self.make_file(f"f{size}.bin", data)
                enc = self.encrypt(src, chunk_size=SMALL_CHUNK)
                out = cm.decrypt_file(enc, PASSWORD, self.dir / f"out{size}.bin")
                self.assertEqual(out.read_bytes(), data)

    def test_default_scrypt_parameters_round_trip(self):
        data = os.urandom(5000)
        src = self.make_file("secret.bin", data)
        enc = cm.encrypt_file(src, PASSWORD)  # real, slower default parameters
        info = cm.inspect_encrypted_file(enc)
        self.assertEqual((info.kdf_params.n_log2, info.kdf_params.r, info.kdf_params.p), (17, 8, 1))
        out = cm.decrypt_file(enc, PASSWORD, self.dir / "secret_restored.bin")
        self.assertEqual(out.read_bytes(), data)

    def test_unicode_password_normalisation(self):
        src = self.make_file("a.txt", b"x")
        enc = cm.encrypt_file(src, "caf\u00e9-pass", kdf_params=FAST)   # composed é
        out = cm.decrypt_file(enc, "cafe\u0301-pass", self.dir / "b.txt")  # e + accent
        self.assertEqual(out.read_bytes(), b"x")

    def test_progress_callback_reaches_total(self):
        src = self.make_file("p.bin", os.urandom(SMALL_CHUNK * 3 + 5))
        calls = []
        self.encrypt(src, chunk_size=SMALL_CHUNK, progress=lambda d, t: calls.append((d, t)))
        self.assertEqual(calls[-1][0], calls[-1][1])
        self.assertEqual(calls, sorted(calls))


class OriginalFileTests(CryptoTestCase):
    def test_original_is_unchanged_after_encryption_and_decryption(self):
        src = self.make_file("keep.bin", os.urandom(9000))
        before, mtime = sha256(src), src.stat().st_mtime_ns
        enc = self.encrypt(src)
        self.assertEqual((sha256(src), src.stat().st_mtime_ns), (before, mtime))
        cm.decrypt_file(enc, PASSWORD, self.dir / "copy.bin")
        self.assertEqual(sha256(src), before)
        self.assertTrue(src.exists())

    def test_every_encryption_uses_fresh_salt_and_nonce(self):
        src = self.make_file("same.txt", b"identical content")
        first = self.encrypt(src, destination=self.dir / "one.enc")
        second = self.encrypt(src, destination=self.dir / "two.enc")
        a, b = cm.inspect_encrypted_file(first), cm.inspect_encrypted_file(second)
        self.assertNotEqual(a.salt, b.salt)
        self.assertNotEqual(a.nonce_prefix, b.nonce_prefix)
        self.assertNotEqual(first.read_bytes(), second.read_bytes())

    def test_plaintext_is_not_visible_in_encrypted_file(self):
        marker = b"TOP-SECRET-MARKER-1234567890"
        src = self.make_file("m.txt", marker * 20)
        self.assertNotIn(marker, self.encrypt(src).read_bytes())


class WrongPasswordAndTamperingTests(CryptoTestCase):
    def setUp(self):
        super().setUp()
        self.data = os.urandom(SMALL_CHUNK * 3 + 100)
        self.src = self.make_file("secret_note.txt", self.data)
        self.enc = self.encrypt(self.src, chunk_size=SMALL_CHUNK)
        self.blob = self.enc.read_bytes()
        self.header_size = cm.inspect_encrypted_file(self.enc).header_size

    def assert_decrypt_fails(self, blob: bytes, exc=cm.AuthenticationError):
        bad = self.dir / "bad.enc"
        bad.write_bytes(blob)
        out = self.dir / "should_not_exist.bin"
        with self.assertRaises(exc):
            cm.decrypt_file(bad, PASSWORD, out)
        self.assertFalse(out.exists(), "no plaintext may be produced on failure")
        self.assertEqual(self.leftover_temp_files(), [])

    def test_wrong_password_rejected_without_output(self):
        out = self.dir / "wrong.bin"
        with self.assertRaises(cm.AuthenticationError):
            cm.decrypt_file(self.enc, "wrong password", out)
        self.assertFalse(out.exists())
        self.assertEqual(self.leftover_temp_files(), [])

    def test_wrong_password_does_not_create_default_output(self):
        self.src.unlink()
        with self.assertRaises(cm.AuthenticationError):
            cm.decrypt_file(self.enc, "nope-nope-nope")
        self.assertFalse(self.src.exists())

    def test_ciphertext_tampering_detected_everywhere(self):
        for position in (self.header_size, self.header_size + 5000, len(self.blob) // 2,
                         len(self.blob) - 1):
            with self.subTest(position=position):
                tampered = bytearray(self.blob)
                tampered[position] ^= 0x01
                self.assert_decrypt_fails(bytes(tampered))

    def test_header_tampering_detected(self):
        salt_offset = 9
        name_offset = cm.HEADER_FIXED_SIZE  # first character of the stored filename
        for label, position in (("salt", salt_offset), ("filename", name_offset),
                                ("nonce prefix", 25)):
            with self.subTest(field=label):
                tampered = bytearray(self.blob)
                tampered[position] ^= 0x01
                self.assert_decrypt_fails(bytes(tampered))

    def test_truncation_detected(self):
        block = SMALL_CHUNK + cm.TAG_LENGTH
        cases = {
            "last 10 bytes cut": self.blob[:-10],
            "last chunk removed": self.blob[: self.header_size + 3 * block],
            "first chunks only": self.blob[: self.header_size + block],
        }
        for label, blob in cases.items():
            with self.subTest(case=label):
                self.assert_decrypt_fails(blob)

    def test_truncated_header_and_empty_data(self):
        self.assert_decrypt_fails(self.blob[:20], cm.CorruptedFileError)
        self.assert_decrypt_fails(self.blob[:self.header_size], cm.CorruptedFileError)

    def test_appended_data_detected(self):
        self.assert_decrypt_fails(self.blob + b"extra bytes")
        self.assert_decrypt_fails(self.blob + os.urandom(SMALL_CHUNK + cm.TAG_LENGTH))

    def test_chunk_reordering_detected(self):
        block = SMALL_CHUNK + cm.TAG_LENGTH
        h = self.header_size
        chunks = [self.blob[h + i * block: h + (i + 1) * block] for i in range(3)]
        swapped = self.blob[:h] + chunks[1] + chunks[0] + chunks[2] + self.blob[h + 3 * block:]
        self.assert_decrypt_fails(swapped)


class FormatValidationTests(CryptoTestCase):
    def test_plain_file_rejected_as_unsupported(self):
        for name, data in (("plain.txt", b"just text, not encrypted"), ("empty.enc", b""),
                           ("tiny.enc", b"SF")):
            with self.subTest(name=name):
                path = self.make_file(name, data)
                with self.assertRaises(cm.UnsupportedFormatError):
                    cm.decrypt_file(path, PASSWORD, self.dir / "out.bin")
                with self.assertRaises(cm.UnsupportedFormatError):
                    cm.inspect_encrypted_file(path)

    def test_unsupported_version_rejected(self):
        enc = self.encrypt(self.make_file("a.txt", b"hello"))
        blob = bytearray(enc.read_bytes())
        blob[4] = 99
        enc.write_bytes(bytes(blob))
        with self.assertRaises(cm.UnsupportedFormatError):
            cm.decrypt_file(enc, PASSWORD, self.dir / "out.txt")

    def test_unsupported_kdf_rejected(self):
        enc = self.encrypt(self.make_file("a.txt", b"hello"))
        blob = bytearray(enc.read_bytes())
        blob[5] = 7
        enc.write_bytes(bytes(blob))
        with self.assertRaises(cm.UnsupportedFormatError):
            cm.decrypt_file(enc, PASSWORD, self.dir / "out.txt")

    def test_dangerous_scrypt_settings_rejected_before_any_work(self):
        enc = self.encrypt(self.make_file("a.txt", b"hello"))
        blob = bytearray(enc.read_bytes())
        blob[6] = 30  # N = 2**30 would need ~128 GiB of memory
        enc.write_bytes(bytes(blob))
        with self.assertRaises(cm.CorruptedFileError):
            cm.decrypt_file(enc, PASSWORD, self.dir / "out.txt")

    def test_inspect_returns_original_name(self):
        src = self.make_file("My Report (final).pdf", b"%PDF")
        info = cm.inspect_encrypted_file(self.encrypt(src))
        self.assertEqual(info.original_name, "My Report (final).pdf")
        self.assertEqual(info.version, cm.FORMAT_VERSION)


class InvalidInputTests(CryptoTestCase):
    def test_empty_and_non_text_passwords_rejected(self):
        src = self.make_file("a.txt", b"hello")
        for bad in ("", None, 12345, b"bytes"):
            with self.subTest(password=bad):
                with self.assertRaises(cm.InvalidInputError):
                    cm.encrypt_file(src, bad, kdf_params=FAST)
        self.assertFalse((self.dir / "a.txt.enc").exists())

    def test_overlong_password_rejected(self):
        src = self.make_file("a.txt", b"hello")
        with self.assertRaises(cm.InvalidInputError):
            cm.encrypt_file(src, "x" * (cm.MAX_PASSWORD_LENGTH + 1), kdf_params=FAST)

    def test_empty_password_rejected_for_decryption(self):
        enc = self.encrypt(self.make_file("a.txt", b"hello"))
        with self.assertRaises(cm.InvalidInputError):
            cm.decrypt_file(enc, "", self.dir / "o.txt")

    def test_missing_file_and_folder_rejected(self):
        with self.assertRaises(cm.InvalidInputError):
            cm.encrypt_file(self.dir / "missing.txt", PASSWORD, kdf_params=FAST)
        with self.assertRaises(cm.InvalidInputError):
            cm.encrypt_file(self.dir, PASSWORD, kdf_params=FAST)
        with self.assertRaises(cm.InvalidInputError):
            cm.decrypt_file(self.dir / "missing.enc", PASSWORD)

    def test_invalid_options_rejected(self):
        src = self.make_file("a.txt", b"hello")
        with self.assertRaises(cm.InvalidInputError):
            cm.encrypt_file(src, PASSWORD, kdf_params=cm.KdfParams(n_log2=3))
        with self.assertRaises(cm.InvalidInputError):
            cm.encrypt_file(src, PASSWORD, kdf_params=FAST, chunk_size=10)

    def test_missing_output_folder_rejected(self):
        src = self.make_file("a.txt", b"hello")
        with self.assertRaises(cm.InvalidInputError):
            self.encrypt(src, destination=self.dir / "no_such_folder" / "a.enc")

    def test_already_encrypted_file_is_flagged(self):
        enc = self.encrypt(self.make_file("a.txt", b"hello"))
        with self.assertRaises(cm.AlreadyEncryptedError):
            self.encrypt(enc, destination=self.dir / "double.enc")
        double = self.encrypt(enc, destination=self.dir / "double.enc", allow_reencrypt=True)
        inner = cm.decrypt_file(double, PASSWORD, self.dir / "inner.enc")
        self.assertEqual(inner.read_bytes(), enc.read_bytes())


class OverwriteProtectionTests(CryptoTestCase):
    def test_encryption_never_overwrites_by_default(self):
        src = self.make_file("a.txt", b"hello")
        target = self.make_file("a.txt.enc", b"PRECIOUS EXISTING DATA")
        with self.assertRaises(cm.OutputExistsError):
            self.encrypt(src)
        self.assertEqual(target.read_bytes(), b"PRECIOUS EXISTING DATA")
        self.assertEqual(self.leftover_temp_files(), [])

    def test_encryption_overwrites_only_when_approved(self):
        src = self.make_file("a.txt", b"hello")
        target = self.make_file("a.txt.enc", b"old")
        self.encrypt(src, overwrite=True)
        self.assertTrue(cm.looks_like_encrypted(target))

    def test_decryption_never_overwrites_by_default(self):
        src = self.make_file("a.txt", b"original")
        enc = self.encrypt(src)
        src.write_bytes(b"newer edits that must survive")
        with self.assertRaises(cm.OutputExistsError):
            cm.decrypt_file(enc, PASSWORD)
        self.assertEqual(src.read_bytes(), b"newer edits that must survive")
        cm.decrypt_file(enc, PASSWORD, overwrite=True)
        self.assertEqual(src.read_bytes(), b"original")

    def test_output_cannot_be_the_input_file(self):
        src = self.make_file("a.txt", b"hello")
        with self.assertRaises(cm.InvalidInputError):
            self.encrypt(src, destination=src, overwrite=True)
        self.assertEqual(src.read_bytes(), b"hello")

    def test_suggest_unique_path(self):
        self.make_file("a.pdf.enc", b"1")
        self.make_file("a.pdf (1).enc", b"2")
        self.assertEqual(cm.suggest_unique_path(self.dir / "a.pdf.enc").name, "a.pdf (2).enc")
        self.assertEqual(cm.suggest_unique_path(self.dir / "free.txt").name, "free.txt")


class FilenameSafetyTests(CryptoTestCase):
    def test_unsafe_names_rejected(self):
        bad_names = ["", ".", "..", "../evil.txt", "..\\evil.txt", "a/b.txt", "a\\b.txt",
                     "C:\\Windows\\x.dll", "x:y.txt", "con", "CON.txt", "nul.tar.gz",
                     "LPT1", "name.", "name ", "a\x00b.txt", "bad|name", 'q"uote',
                     "star*.txt", "a" * 300]
        for name in bad_names:
            with self.subTest(name=name):
                with self.assertRaises(cm.InvalidFilenameError):
                    cm.sanitize_filename(name)

    def test_safe_names_accepted(self):
        for name in ["report final.pdf", "ünïcode_名前.txt", ".gitignore", "file.tar.gz",
                     "console.txt", "a (1).docx"]:
            with self.subTest(name=name):
                self.assertEqual(cm.sanitize_filename(name), name)

    def test_malicious_stored_filenames_rejected_and_nothing_written(self):
        outside = self.dir / "outside"
        outside.mkdir()
        inside = self.dir / "inside"
        inside.mkdir()
        for index, evil in enumerate([b"../outside/pwned.txt", b"..\\outside\\pwned.txt",
                                      b"/etc/passwd", b"C:\\pwned.txt", b"CON", b".."]):
            with self.subTest(name=evil):
                enc = inside / f"evil{index}.enc"
                self.craft_encrypted(enc, evil)
                with self.assertRaises(cm.InvalidFilenameError):
                    cm.decrypt_file(enc, PASSWORD)
                with self.assertRaises(cm.InvalidFilenameError):
                    cm.inspect_encrypted_file(enc)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(sorted(p.name for p in inside.iterdir() if not p.name.startswith("evil")), [])

    def test_stored_name_is_only_the_base_name(self):
        sub = self.dir / "deep" / "folder"
        sub.mkdir(parents=True)
        src = sub / "inner.txt"
        src.write_bytes(b"data")
        info = cm.inspect_encrypted_file(self.encrypt(src))
        self.assertEqual(info.original_name, "inner.txt")

    def test_unicode_filename_round_trip(self):
        src = self.make_file("résumé 2026 – 名前.txt", b"unicode name")
        enc = self.encrypt(src)
        src.unlink()
        self.assertEqual(cm.decrypt_file(enc, PASSWORD).name, "résumé 2026 – 名前.txt")

    def test_invalid_utf8_filename_is_reported_as_corrupted(self):
        enc = self.dir / "bad_utf8.enc"
        self.craft_encrypted(enc, b"\xff\xfe\xfa.txt")
        with self.assertRaises(cm.CorruptedFileError):
            cm.decrypt_file(enc, PASSWORD)


if __name__ == "__main__":
    unittest.main(verbosity=2)
