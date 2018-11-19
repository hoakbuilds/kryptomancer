"""
Kryptoflask OpenSSL System Calls


"""

import os
import sys
import requests
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

def generate_key_iv( bytes ):
    key_dir=os.path.join(UPLOAD_FOLDER, "key-file.txt")
    iv_dir=os.path.join(UPLOAD_FOLDER, "iv-file.txt")
    print(iv_dir, key_dir)

    key_file = open(key_dir, 'w+')
    iv_file = open(iv_dir, 'w+')
    print(iv_file, key_file)

    subprocess.Popen(
        ['openssl', 'rand', '-hex', str(2*int(bytes))],
        stdout=key_file
    )
    subprocess.Popen(
        ['openssl', 'rand', '-hex', bytes],
        stdout=iv_file
    )
    
    time.sleep(0.1)

    key_file = open(key_dir, 'r')
    iv_file = open(iv_dir, 'r')
    print(iv_file, key_file)

    iv = iv_file.read()
    key = key_file.read()
    print(iv, key)

    data = {
        'iv' : iv,
        'key' : key
    }

    return data

# openssl enc -aes-256-cbc -e -in $file -out $file.dec -K $key -iv $iv

def encrypt_file( input_file, key, iv ):
    file_path = os.path.join(UPLOAD_FOLDER, input_file)
    enc_file = os.path.join(UPLOAD_FOLDER,  input_file + ".dec")
    subprocess.Popen(
        ['openssl', 'enc', '-aes-256-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv]
    )