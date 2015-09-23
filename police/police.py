#!/usr/bin/python

""" Police Directory Service v1.2"""

import socket
import sys
import struct
import random
import json

from os import urandom

HOST = 'vuln2014.picoctf.com'
PORT = 21212

def xor(buf, key):
    """ Repeated key xor """

    encrypted = []
    for i, cr in enumerate(buf):
        k = key[i % len(key)]
        encrypted += [cr ^ k]
    return bytes(encrypted)

def secure_pad(buf):
    """ Ensure message is padded to block size. """
    key = urandom(5)
    buf = bytes([0x13, 0x33, 0x7B, 0xEE, 0xF0]) + buf
    buf = buf + urandom(16 - len(buf) % 16)
    enc = xor(buf, key)
    return enc

def remove_pad(buf):
    """ Removes the secure padding from the msg. """
    if len(buf) > 0 and len(buf) % 16 == 0:
        encrypted_key = buf[:5]
        key = xor(encrypted_key, bytes([0x13, 0x33, 0x7B, 0xEE, 0xF0]))
        dec = xor(buf, key)
        return dec[5:-2] #dec[5:20]

def generate_cookie():
    """ Generates random transaction cookie. """
    cookie = random.randrange(1, 1e8)
    return cookie

def secure_send(s, cookie, entry):
    """ Sends msg back to the client securely. """

    data = struct.pack("!B2LHL", 0xFF, cookie, 0, 1, entry)
    encrypted = secure_pad(data)
    s.sendall(encrypted)

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(struct.pack("!i", 0xAA))
    
    data = b''
    while len(data) % 16 != 0 or data == b'':
        data += s.recv(1024)
    print(len(remove_pad(data)))
    magic, cookie, msglen, msg = struct.unpack("!B2L128s", remove_pad(data))
    
    print(msg)
    
    officers = []
    badges = []
    curBadge = 0
    entryCount = 0
    entry = 0
    while True:
        secure_send(s, cookie, entry)
        data = b''
        while len(data) == 0:
            data = s.recv(1024)
        magic, cookie, msglen, msg = struct.unpack("!B2L128s", remove_pad(data))
        
        msg = msg[0:msg.find(b'\0')]
        print(msg)
        if msg == b"INVALID ENTRY -- OFFICER DOES NOT EXIST":
            break
        officers.append(msg)
        
        entry += 1
    
    badges = set()
    for (i, officer) in enumerate(officers):
        badge = json.loads(officer.decode('utf-8'))["BADGE"]
        if badge in badges:
            print(badge)
            break
        badges.add(badge)
        print(officer)
    
    s.close()
