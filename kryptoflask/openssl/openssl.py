"""
Kryptoflask OpenSSL System Calls


"""

import os
import sys
import json
import datetime
import asyncio
import logging
import subprocess
import time
import kryptoflask

from time import sleep
from threading import Thread
from flask import Flask, redirect, url_for, request, render_template
from werkzeug import secure_filename

from . import openssl

UPLOAD_FOLDER = os.getcwd() + '/uploads'

def generate_key( bytes, base64=None):
    key_dir=os.path.join(UPLOAD_FOLDER, "key-file.txt")
    
    key_file = open(key_dir, 'w+')
    if base64 is None:

        print(base64, file=sys.stderr)
        p = subprocess.Popen(
            ['openssl', 'rand', '-hex', bytes],
            stdout=key_file
        )
    elif base64 is True:
        print(base64, file=sys.stderr)
        p = subprocess.Popen(
            ['openssl', 'rand', '-base64', bytes],
            stdout=key_file
        )

    p.wait()

    key_file = open(key_dir, 'r')

    key = key_file.read()

    data = {
        'key' : key
    }

    return data

def generate_key_iv( bytes ):
    key_dir=os.path.join(UPLOAD_FOLDER, "key-file.txt")
    iv_dir=os.path.join(UPLOAD_FOLDER, "iv-file.txt")
    #print(iv_dir, key_dir)

    key_file = open(key_dir, 'w+')
    iv_file = open(iv_dir, 'w+')
    #print(iv_file, key_file)

    p1 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(int(bytes)*2)],
        stdout=key_file
    )
    p2 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(int(bytes))],
        stdout=iv_file
    )
    
    exit_codes = [p.wait() for p in [p1, p2]]

    key_file = open(key_dir, 'r')
    iv_file = open(iv_dir, 'r')
    #print(iv_file, key_file)

    iv = iv_file.read()
    key = key_file.read()
    print('IV ' + iv + 'Key ' + key)

    data = {
        'iv' : iv,
        'key' : key
    }

    return data

# openssl enc -aes-256-cbc -e -in $file -out $file.dec -K $key -iv $iv

def encrypt_file( input_file, key, iv, cipher = None):
    file_path = os.path.join(UPLOAD_FOLDER, input_file)
    enc_file = os.path.join(UPLOAD_FOLDER,  input_file + ".enc")

    if cipher is not None:
        print('Cipher selected: ' + cipher, file=sys.stderr)

        print('Encrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        if 'aes' in cipher:
            if '128' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-128-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-128-ecb', '-e', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
            if '192' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-192-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-192-ecb', '-e', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
            if '256' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-256-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-256-ecb', '-e', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
    else:
        print('Encrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        try:
            p = subprocess.Popen(
                ['openssl', 'enc', '-aes-256-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE
            )
            p.wait()
            return {'ok':'ok'}
        except:
            print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
            return {'error':'failed'}


# openssl enc -aes-256-cbc -e -in $file -out $file.dec -K $key -iv $iv
def decrypt_file( input_file, key, iv, cipher = None ):
    file_path = os.path.join(UPLOAD_FOLDER, input_file)
    enc_file = os.path.join(UPLOAD_FOLDER, file_path.rsplit('.',1)[0] + ".dec")

    if cipher is not None:
        print('Cipher selected: ' + cipher, file=sys.stderr)

        print('Decrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        if 'aes' in cipher:
            if '128' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-128-cbc', '-d', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-128-ecb', '-d', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}

            elif '192' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-192-cbc', '-d', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-256-ecb', '-d', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}

            elif '256' in cipher:
                if 'cbc' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-256-cbc', '-d', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}
                elif 'ecb' in cipher:
                    try:
                        p = subprocess.Popen(
                            ['openssl', 'enc', '-aes-256-ecb', '-d', '-in', file_path, '-out', enc_file, '-K', key],
                            stdin = subprocess.PIPE,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE
                        )
                        p.wait()
                        return {'ok':'ok'}
                    except:
                        print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
                        return {'error':'failed'}

        # elif 'aria' in cipher:
        # elif 'camellia' in cipher:
        # elif 'des' in cipher:
        # elif 'rc' in cipher
    else:
        print('Decrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        try:
            p = subprocess.Popen(
                ['openssl', 'enc', '-aes-256-cbc', '-d', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE
            )
            p.wait()
            return {'ok':'ok'}
        except:
            print('Failed to decrypt: ' + str(file_path), file=sys.stderr)
            return {'error':'failed'}
