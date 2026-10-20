"""
crypto_manager.py - encryption, decryption and the encrypted-file format.

This module contains NO GUI code. It only deals with files, passwords and
cryptography, so it can be tested on its own (see tests/test_crypto_manager.py).

Cryptography used (all from the trusted ``cryptography`` library):
    * AES-256-GCM  - authenticated encryption (confidentiality + tamper detection)
    * Scrypt       - turns the password into a 256-bit key (slow on purpose)
    * os.urandom() - cryptographically secure random salt and nonce

Encrypted file format, version 1 ("SFES")
-----------------------------------------
All numbers are big-endian.

    Offset  Size  Field
    ------  ----  ------------------------------------------------------------
    0       4     Magic bytes b"SFES"            (identifies the format)
    4       1     Format version                  (currently 1)
    5       1     KDF id                          (1 = Scrypt)
    6       1     Scrypt N as a power of two      (17 means N = 2**17)
    7       1     Scrypt r
    8       1     Scrypt p
    9       16    Salt                            (random, new for every file)
    25      8     Nonce prefix                    (random, new for every file)
    33      4     Chunk size in bytes             (plaintext bytes per chunk)
    37      2     Length of the original filename in bytes
    39      L     Original filename, UTF-8        (a name only, never a path)
    39+L    ...   Ciphertext chunks

Everything up to and including the filename is the "header".

The file content is split into chunks (1 MiB by default) so that big files do
not have to fit in memory. Every chunk is encrypted separately with AES-GCM:

    nonce      = nonce_prefix (8 bytes) + chunk counter (4 bytes)
    AAD        = header bytes + one flag byte (0x01 for the last chunk, else 0x00)
    chunk data = AES-GCM ciphertext + 16-byte authentication tag

Why this design is safe:
    * The header is authenticated as AAD in every chunk, so changing the salt,
      the Scrypt settings, the chunk size or the stored filename is detected.
    * The counter inside the nonce stops chunks from being reordered, and the
      "last chunk" flag stops truncation or appending of whole chunks.
    * A new random salt gives a new key for every file, and the nonce prefix is
      random as well, so a (key, nonce) pair is never reused.
    * While decrypting, plaintext is written to a temporary file and moved to
      its final name only after EVERY chunk has been authenticated.
"""

from __future__ import annotations

import os
import re
import struct
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Optional, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PathLike = Union[str, "os.PathLike[str]"]
ProgressCallback = Callable[[int, int], None]  # (bytes_done, bytes_total)

# --------------------------------------------------------------------------
# Format constants
# --------------------------------------------------------------------------
MAGIC = b"SFES"
FORMAT_VERSION = 1
KDF_SCRYPT = 1

KEY_LENGTH = 32            # 32 bytes = 256-bit key
SALT_LENGTH = 16
NONCE_PREFIX_LENGTH = 8
COUNTER_LENGTH = 4
TAG_LENGTH = 16            # AES-GCM authentication tag

DEFAULT_CHUNK_SIZE = 1024 * 1024        # 1 MiB
MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAX_CHUNKS = 2 ** (8 * COUNTER_LENGTH)

MAX_FILENAME_BYTES = 255
MAX_PASSWORD_LENGTH = 1024
ENCRYPTED_EXTENSION = ".enc"

_HEADER_STRUCT = struct.Struct(">4sBBBBB16s8sIH")
HEADER_FIXED_SIZE = _HEADER_STRUCT.size  # 39 bytes


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------
class CryptoError(Exception):
    """Base class for every error raised on purpose by this module."""


class InvalidInputError(CryptoError):
    """Bad password, missing file, bad option, ..."""


class OutputExistsError(CryptoError):
    """The output file already exists and overwriting was not approved."""

    def __init__(self, path: Path):
        super().__init__(f"The file '{path.name}' already exists. "
                         "Nothing was overwritten.")
        self.path = path


class AlreadyEncryptedError(CryptoError):
    """The input already looks like a file produced by this application."""


class UnsupportedFormatError(CryptoError):
    """The file is not an encrypted file of a supported format/version."""


class CorruptedFileError(CryptoError):
    """The encrypted file is damaged, truncated or has invalid settings."""


class InvalidFilenameError(CryptoError):
    """A filename is unsafe (path separators, reserved names, ...)."""


class AuthenticationError(CryptoError):
    """AES-GCM authentication failed (wrong password OR modified file)."""


# --------------------------------------------------------------------------
# Scrypt parameters
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class KdfParams:
    """Scrypt settings. Defaults: N=2**17, r=8, p=1 (about 128 MiB of RAM)."""

    n_log2: int = 17
    r: int = 8
    p: int = 1

    @property
    def n(self) -> int:
        return 1 << self.n_log2

    def validate(self) -> None:
        """Reject values that are absurdly weak or that could exhaust memory."""
        if not 12 <= self.n_log2 <= 20:
            raise ValueError("Scrypt N exponent must be between 12 and 20.")
        if not 1 <= self.r <= 16:
            raise ValueError("Scrypt r must be between 1 and 16.")
        if not 1 <= self.p <= 4:
            raise ValueError("Scrypt p must be between 1 and 4.")
        if 128 * self.n * self.r > 512 * 1024 * 1024:
            raise ValueError("Scrypt settings would need more than 512 MiB of memory.")


DEFAULT_KDF_PARAMS = KdfParams()


@dataclass(frozen=True)
class EncryptedFileInfo:
    """Information read from the header of an encrypted file."""

    version: int
    kdf_params: KdfParams
    salt: bytes
    nonce_prefix: bytes
    chunk_size: int
    original_name: str
    header_size: int


# --------------------------------------------------------------------------
# Filename and path helpers
# --------------------------------------------------------------------------
_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} \
    | {f"LPT{i}" for i in range(1, 10)}
_FORBIDDEN_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')


def sanitize_filename(name: str) -> str:
    """
    Return ``name`` if it is a safe plain filename, otherwise raise
    InvalidFilenameError. A filename is NOT a path: no folders, no drive
    letters, no '..', no characters or names that Windows does not allow.
    """
    if not isinstance(name, str) or not name:
        raise InvalidFilenameError("The stored filename is empty.")
    if len(name.encode("utf-8", errors="replace")) > MAX_FILENAME_BYTES:
        raise InvalidFilenameError("The stored filename is too long.")
    if _FORBIDDEN_CHARS.search(name):
        raise InvalidFilenameError("The stored filename contains characters that "
                                   "are not allowed (such as / \\ : * ? \" < > |).")
    if name in (".", ".."):
        raise InvalidFilenameError("The stored filename is not valid.")
    if name.endswith((" ", ".")):
        raise InvalidFilenameError("The stored filename may not end with a dot or space.")
    if name.split(".")[0].strip().upper() in _WINDOWS_RESERVED:
        raise InvalidFilenameError("The stored filename is a reserved Windows name.")
    return name


def default_encrypted_path(source: PathLike) -> Path:
    """'report.pdf' -> 'report.pdf.enc' (same folder). Keeps the original type visible."""
    source = Path(source)
    return source.with_name(source.name + ENCRYPTED_EXTENSION)


def default_decrypted_path(source: PathLike, info: EncryptedFileInfo) -> Path:
    """Folder of the .enc file + the (validated) original filename."""
    return Path(source).with_name(sanitize_filename(info.original_name))


def suggest_unique_path(path: PathLike) -> Path:
    """'a.pdf.enc' -> 'a.pdf (1).enc' -> 'a.pdf (2).enc' ... first one that is free."""
    path = Path(path)
    if not path.exists():
        return path
    for i in range(1, 10_000):
        candidate = path.with_name(f"{path.stem} ({i}){path.suffix}")
        if not candidate.exists():
            return candidate
    raise InvalidInputError("Could not find a free filename in that folder.")


def looks_like_encrypted(path: PathLike) -> bool:
    """True if the file starts with this application's magic bytes."""
    try:
        with open(path, "rb") as handle:
            return handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


# --------------------------------------------------------------------------
# Low-level building blocks (public so the tests can use them)
# --------------------------------------------------------------------------
def prepare_password(password: str) -> bytes:
    """Validate the password and convert it to bytes (Unicode NFC, then UTF-8)."""
    if not isinstance(password, str):
        raise InvalidInputError("The password must be text.")
    if password == "":
        raise InvalidInputError("The password must not be empty.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise InvalidInputError(f"The password is too long (maximum {MAX_PASSWORD_LENGTH} characters).")
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_key(password_bytes: bytes, salt: bytes, params: KdfParams) -> bytes:
    """Scrypt: password + salt -> 32-byte AES key."""
    kdf = Scrypt(salt=salt, length=KEY_LENGTH, n=params.n, r=params.r, p=params.p)
    return kdf.derive(password_bytes)


def build_header(params: KdfParams, salt: bytes, nonce_prefix: bytes,
                 chunk_size: int, name_bytes: bytes) -> bytes:
    """Serialise the header (see the format table at the top of this file)."""
    return _HEADER_STRUCT.pack(
        MAGIC, FORMAT_VERSION, KDF_SCRYPT, params.n_log2, params.r, params.p,
        salt, nonce_prefix, chunk_size, len(name_bytes)) + name_bytes


def make_nonce(nonce_prefix: bytes, counter: int) -> bytes:
    """12-byte GCM nonce = 8 random bytes + 4-byte chunk counter."""
    if counter >= MAX_CHUNKS:
        raise InvalidInputError("The file is too large for this format.")
    return nonce_prefix + counter.to_bytes(COUNTER_LENGTH, "big")


def make_aad(header: bytes, is_last_chunk: bool) -> bytes:
    """Additional authenticated data for one chunk."""
    return header + (b"\x01" if is_last_chunk else b"\x00")


def parse_header(stream: BinaryIO) -> Tuple[EncryptedFileInfo, bytes]:
    """
    Read and validate the header from ``stream``.
    Returns (info, raw_header_bytes). Raises UnsupportedFormatError,
    CorruptedFileError or InvalidFilenameError.
    """
    fixed = stream.read(HEADER_FIXED_SIZE)
    if fixed[:len(MAGIC)] != MAGIC:
        raise UnsupportedFormatError(
            "This is not an encrypted file created by this application.")
    if len(fixed) < HEADER_FIXED_SIZE:
        raise CorruptedFileError("The encrypted file is truncated (incomplete header).")

    (_, version, kdf_id, n_log2, r, p, salt, nonce_prefix,
     chunk_size, name_len) = _HEADER_STRUCT.unpack(fixed)

    if version != FORMAT_VERSION:
        raise UnsupportedFormatError(
            f"Unsupported file format version {version} "
            f"(this application understands version {FORMAT_VERSION}).")
    if kdf_id != KDF_SCRYPT:
        raise UnsupportedFormatError("The file uses an unsupported key-derivation method.")

    params = KdfParams(n_log2=n_log2, r=r, p=p)
    try:
        params.validate()
    except ValueError as exc:
        raise CorruptedFileError(f"The encrypted file has invalid settings: {exc}") from None
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise CorruptedFileError("The encrypted file has an invalid chunk size.")
    if not 1 <= name_len <= MAX_FILENAME_BYTES:
        raise CorruptedFileError("The encrypted file has an invalid filename length.")

    name_bytes = stream.read(name_len)
    if len(name_bytes) != name_len:
        raise CorruptedFileError("The encrypted file is truncated (incomplete header).")
    try:
        original_name = name_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise CorruptedFileError("The stored filename is not valid text.") from None
    sanitize_filename(original_name)  # raises InvalidFilenameError if unsafe

    info = EncryptedFileInfo(version, params, salt, nonce_prefix, chunk_size,
                             original_name, HEADER_FIXED_SIZE + name_len)
    return info, fixed + name_bytes


def inspect_encrypted_file(path: PathLike) -> EncryptedFileInfo:
    """Validate the structure of an encrypted file WITHOUT needing the password."""
    path = Path(path)
    _require_regular_file(path)
    with open(path, "rb") as handle:
        info, _ = parse_header(handle)
    if path.stat().st_size < info.header_size + TAG_LENGTH:
        raise CorruptedFileError("The encrypted file is truncated (no data).")
    return info


# --------------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------------
def _require_regular_file(path: Path) -> None:
    if not path.exists():
        raise InvalidInputError(f"File not found: {path}")
    if not path.is_file():
        raise InvalidInputError(f"'{path.name}' is not a regular file.")


def _check_destination(source: Path, dest: Path, overwrite: bool) -> None:
    if dest.exists():
        if dest.is_dir():
            raise InvalidInputError("The output location is a folder, not a file.")
        if os.path.samefile(source, dest):
            raise InvalidInputError("The output file must be different from the input file.")
        if not overwrite:
            raise OutputExistsError(dest)
    if not dest.parent.is_dir():
        raise InvalidInputError("The output folder does not exist.")


def _remove_quietly(path: Optional[str]) -> None:
    if path:
        try:
            os.remove(path)
        except OSError:
            pass


def _finish(tmp_path: str, dest: Path, overwrite: bool) -> None:
    """Move the finished temporary file to its final name."""
    if not overwrite and dest.exists():  # appeared while we were working
        raise OutputExistsError(dest)
    os.replace(tmp_path, dest)


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def encrypt_file(source: PathLike, password: str, destination: Optional[PathLike] = None, *,
                 overwrite: bool = False, allow_reencrypt: bool = False,
                 kdf_params: KdfParams = DEFAULT_KDF_PARAMS,
                 chunk_size: int = DEFAULT_CHUNK_SIZE,
                 progress: Optional[ProgressCallback] = None) -> Path:
    """
    Encrypt ``source`` with ``password`` and return the path of the .enc file.

    The source is only read, never changed. The output is written to a
    temporary file first and renamed on success, so a failure never leaves a
    half-written output. An existing output is replaced only if
    ``overwrite=True``.
    """
    source = Path(source)
    _require_regular_file(source)
    password_bytes = prepare_password(password)
    try:
        kdf_params.validate()
    except ValueError as exc:
        raise InvalidInputError(str(exc)) from None
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise InvalidInputError("Invalid chunk size.")
    if not allow_reencrypt and looks_like_encrypted(source):
        raise AlreadyEncryptedError(
            "This file was already encrypted by this application. "
            "Encrypting it again is usually a mistake.")

    dest = Path(destination) if destination else default_encrypted_path(source)
    _check_destination(source, dest, overwrite)

    name_bytes = sanitize_filename(source.name).encode("utf-8")
    salt = os.urandom(SALT_LENGTH)
    nonce_prefix = os.urandom(NONCE_PREFIX_LENGTH)
    header = build_header(kdf_params, salt, nonce_prefix, chunk_size, name_bytes)
    key = derive_key(password_bytes, salt, kdf_params)
    aead = AESGCM(key)

    total = source.stat().st_size
    fd, tmp_path = tempfile.mkstemp(prefix=".sfes-", suffix=".tmp", dir=dest.parent)
    try:
        with open(source, "rb") as fin, os.fdopen(fd, "wb") as fout:
            fout.write(header)
            counter = 0
            done = 0
            chunk = fin.read(chunk_size)
            while True:
                # Read one chunk ahead so we know whether this one is the last.
                following = fin.read(chunk_size) if len(chunk) == chunk_size else b""
                is_last = not following
                fout.write(aead.encrypt(make_nonce(nonce_prefix, counter), chunk,
                                        make_aad(header, is_last)))
                counter += 1
                done += len(chunk)
                if progress:
                    progress(done, total)
                if is_last:
                    break
                chunk = following
            fout.flush()
            os.fsync(fout.fileno())
        _finish(tmp_path, dest, overwrite)
    except BaseException:
        _remove_quietly(tmp_path)
        raise
    return dest


def decrypt_file(source: PathLike, password: str, destination: Optional[PathLike] = None, *,
                 overwrite: bool = False,
                 progress: Optional[ProgressCallback] = None) -> Path:
    """
    Decrypt ``source`` and return the path of the recovered file.

    By default the file is restored next to the .enc file under its original
    name. Plaintext appears under its final name only after every chunk has
    been authenticated; on any failure nothing is left behind.
    """
    source = Path(source)
    _require_regular_file(source)
    password_bytes = prepare_password(password)

    with open(source, "rb") as probe:
        info, _ = parse_header(probe)
    dest = Path(destination) if destination else default_decrypted_path(source, info)
    _check_destination(source, dest, overwrite)

    total = source.stat().st_size
    fd, tmp_path = tempfile.mkstemp(prefix=".sfes-", suffix=".tmp", dir=dest.parent)
    try:
        with open(source, "rb") as fin, os.fdopen(fd, "wb") as fout:
            info, header = parse_header(fin)
            key = derive_key(password_bytes, info.salt, info.kdf_params)
            aead = AESGCM(key)
            block = info.chunk_size + TAG_LENGTH

            counter = 0
            current = fin.read(block)
            if len(current) < TAG_LENGTH:
                raise CorruptedFileError("The encrypted file is truncated (no data).")
            while True:
                following = fin.read(block) if len(current) == block else b""
                is_last = not following
                try:
                    plain = aead.decrypt(make_nonce(info.nonce_prefix, counter), current,
                                         make_aad(header, is_last))
                except InvalidTag:
                    raise AuthenticationError(
                        "Either the password is wrong, or the file was modified, damaged "
                        "or cut short. These cases cannot be told apart, so no "
                        "recovered file was created.") from None
                fout.write(plain)
                counter += 1
                if progress:
                    progress(min(info.header_size + counter * block, total), total)
                if is_last:
                    break
                current = following
                if len(current) < TAG_LENGTH:  # leftover bytes too short to hold a tag
                    raise AuthenticationError(
                        "The file appears to be damaged or cut short.")
            fout.flush()
            os.fsync(fout.fileno())
        _finish(tmp_path, dest, overwrite)
    except BaseException:
        _remove_quietly(tmp_path)
        raise
    return dest
