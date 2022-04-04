# 2022 eCTF
# Host Tool Utility File
# Kyle Scaplen
#
# (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System
# CTF (eCTF). This code is being provided only for educational purposes for the
# 2022 MITRE eCTF competition, and may not meet MITRE standards for quality.
# Use this code at your own risk!

import logging
from pathlib import Path
import socket
import os
from sys import stderr
from Crypto.PublicKey.RSA import RsaKey
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import ChaCha20


LOG_FORMAT = "%(asctime)s:%(name)-12s%(levelname)-8s %(message)s"
log = logging.getLogger(Path(__file__).name)

CONFIGURATION_ROOT = Path("/configuration")
FIRMWARE_ROOT = Path("/firmware")
PRIVATE_KEY = Path("/secrets/private-key.pem")
RELEASE_MESSAGES_ROOT = Path("/messages")

RESP_OK = b"\x00"


def print_banner(s: str) -> None:
    """Print an underlined string to stdout

    Args:
        s (str): the string to print
    """
    width = len(s)
    line = "-" * width
    banner = f"\n{line}\n{s}\n{line}"
    print(banner, file=stderr)


class PacketIterator:
    BLOCK_SIZE = 0x400

    def __init__(self, data: bytes):
        self.data = data
        self.index = 0
        self.size = len(data)

    def __iter__(self):
        return [
            self.data[i : i + self.BLOCK_SIZE]
            for i in range(0, len(self.data), self.BLOCK_SIZE)
        ].__iter__()


def send_packets(sock: socket.socket, data: bytes):
    packets = PacketIterator(data)

    for num, packet in enumerate(packets):
        log.debug(f"Sending Packet {num} ({len(packet)} bytes)...")
        sock.sendall(packet)
        resp = sock.recv(1)  # Wait for an OK from the bootloader

        if resp != RESP_OK:
            exit(f"ERROR: Bootloader responded with {repr(resp)}")
            
def read_bytes_from_file(fileName: str):
    in_file = open(fileName, "rb")
    data = in_file.read(32)
    in_file.close()
    return data

def import_RSA_key_from_file(fileName: str):
    print(os.listdir('.'))
    key_path = Path(fileName)
    key = RSA.import_key(key_path.read_text())
    return key

def rsa_encrypt(data: bytes, key: RsaKey):
    cipher = PKCS1_OAEP.new(key)
    cipher_text = cipher.encrypt(data)
    # return is bytes type
    return cipher_text

"""
** Only used for testing, leave it commented otherwise.

def get_public_key(key: RsaKey):
    return key.publickey()
"""

def generate_signature(data: bytes, private_key: RsaKey):
    hashed_object = SHA256.new(data)
    verifier_object = pkcs1_15.new(private_key)
    signature = verifier_object.sign(hashed_object)
    return signature

"""

** Only used for testing, leave it commented otherwise.

def verify_signature(data: bytes, signature: bytes, public_key: RsaKey):
    verifier_object = pkcs1_15.new(public_key)
    hashed_object = SHA256.new(data)
    try:
        verifier_object.verify(hashed_object, signature)
        return True
    except(ValueError, TypeError):
        return False
"""

def encrypt_chacha(data: bytes, key: bytes):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(data)
    
    return cipher.nonce + ciphertext

def decrypt_chacha(ciphertext: bytes, key: bytes, nonce: bytes):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    return plaintext