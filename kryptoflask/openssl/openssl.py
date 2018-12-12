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

UPLOADS_FOLDER = os.getcwd() + '/uploads'
OPENSSL_OUTPUT_FOLDER = os.getcwd() + '/openssl_out'
TEMP_FOLDER = os.getcwd() + '/temp'

def generate_key( bytes, base64=None):
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key-file.txt")
    
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

def generate_aes_key_iv( bytes ):
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key-file.txt")
    iv_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "iv-file.txt")
    #print(iv_dir, key_dir)

    key_file = open(key_dir, 'w+')
    iv_file = open(iv_dir, 'w+')
    #print(iv_file, key_file)

    p1 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(int(bytes))],
        stdout=key_file
    )
    p2 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(16)],
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

def generate_3des_key_iv():
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key-file.txt")
    iv_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "iv-file.txt")
    #print(iv_dir, key_dir)

    key_file = open(key_dir, 'w+')
    iv_file = open(iv_dir, 'w+')
    #print(iv_file, key_file)

    p1 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(24)],
        stdout=key_file
    )
    p2 = subprocess.Popen(
        ['openssl', 'rand', '-hex', str(8)],
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

def digest_file( input_file, hash_algorithm ):

    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, input_file+'.'+str(hash_algorithm))
    key_file = open(key_dir, 'w+')

    file_path = os.path.join(UPLOADS_FOLDER, input_file)
    hash = '-' + hash_algorithm

    p1 = subprocess.Popen(
        ['openssl', 'dgst', hash, file_path,],
        stdout=key_file
    )
    p1.wait()
    key_file = open(key_dir, 'r')

    digest = key_file.read().split('=')[1]

    print('Digest'+hash_algorithm+ ' ' + digest)

    data = {
        'hash' : digest
    }

    return data

def hmac_file( input_file, hash_algorithm, key ):

    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key-file.txt")
    key_file = open(key_dir, 'w+')

    file_path = os.path.join(UPLOADS_FOLDER, input_file)
    hash = '-' + hash_algorithm

    p1 = subprocess.Popen(
        ['openssl', 'dgst', hash, '-hmac', key, file_path,],
        stdout=key_file
    )
    p1.wait()
    key_file = open(key_dir, 'r')

    hmac = key_file.read().split('=')[1]

    print('HMAC'+hash_algorithm+ ' ' + hmac)

    data = {
        'hmac' : hmac
    }

    return data


def encrypt_file( input_file, key, iv, cipher = None, base64=None):
    file_path = os.path.join(UPLOADS_FOLDER, input_file)
    enc_file = os.path.join(UPLOADS_FOLDER,  input_file + ".enc")

    if cipher is not None:
        print('Cipher selected: ' + cipher, file=sys.stderr)
        input_cipher = '-' + cipher
        print('Encrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        try:
            if base64 is not None:
                p = subprocess.Popen(
                    ['openssl', 'enc', input_cipher, '-e', '-a', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                    stdin = subprocess.PIPE,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.PIPE
                )
            else:
                p = subprocess.Popen(
                    ['openssl', 'enc', input_cipher, '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv],
                    stdin = subprocess.PIPE,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.PIPE
                )
            p.wait()
            return {'ok':'ok'}
        except:
            print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
            return {'error':'failed'}


def decrypt_file( input_file, key, iv, cipher = None, base64=None ):
    file_path = os.path.join(UPLOADS_FOLDER, input_file)
    dec_file = os.path.join(UPLOADS_FOLDER, file_path.rsplit('.',1)[0] + ".dec")

    if cipher is not None:
        print('Cipher selected: ' + cipher, file=sys.stderr)
        input_cipher = '-' + cipher
        print('Decrypting file: ' + str(file_path) +'\nWith Key:  ' +str(key) + 'And IV:   ' +str(iv), file=sys.stderr)
        try:
            if base64 is not None:
                p = subprocess.Popen(
                    ['openssl', 'enc', input_cipher, '-d', '-a', '-in', file_path, '-out', dec_file, '-K', key, '-iv', iv],
                    stdin = subprocess.PIPE,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.PIPE
                )
            else:
                p = subprocess.Popen(
                    ['openssl', 'enc', input_cipher, '-d', '-in', file_path, '-out', dec_file, '-K', key, '-iv', iv],
                    stdin = subprocess.PIPE,
                    stdout = subprocess.PIPE,
                    stderr = subprocess.PIPE
                )
                
            p.wait()
            return {'ok':'ok'}
        except:
            print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
            return {'error':'failed'}


#openssl genrsa -out mykey.pem
#will actually produce a public - private key pair. The pair is stored in the generated mykey.pem file.
def generate_rsa( output_file ):
    file_path = os.path.join(TEMP_FOLDER, output_file + '.pem')
    print(file_path, file=sys.stderr)
    try:
            
        p = subprocess.Popen(
                ['openssl', 'genrsa', '-out', file_path],
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE
            )
                
        p.wait()
        return {'ok':'ok'}
    except:
        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
        return {'error':'failed'}

#openssl rsa -in mykey.pem -pubout -out mykey.pub
#will extract the public key and print that out. Here is a link to a page that describes this better.
def rsa_pubout( input_file ):
    input_file_path = os.path.join(TEMP_FOLDER, input_file)
    file_path = os.path.join(TEMP_FOLDER, input_file + '.pub')
    print(input_file_path, file=sys.stderr)
    print(file_path, file=sys.stderr)
    p = subprocess.Popen(['touch', file_path]) # creating the output file before using it to prevent throwing errors
    p.wait()
    try:
            
        p = subprocess.Popen(
                ['openssl', 'rsa', '-in', input_file_path, '-pubout', '-out', file_path ],
                stdin = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE
            )
                
        p.wait()
        return {'ok':'ok'}
    except:
        print('Failed to encrypt: ' + str(file_path), file=sys.stderr)
        return {'error':'failed'}

# openssl rsa -in teste1.pem.pub -pubin (to view PK)
# or
# openssl rsa -in teste1.pem (to view SK)
#this function will receive a .pem file and extract the PK/SK to show the user in the app
def view_key_from_pem( input_file ):
    input_file_path = os.path.join(TEMP_FOLDER, input_file) #concat input file name and temp folder path
    split = input_file.split('.')[-1] #check file extension
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key."+split) #concat output file name and openssl's output folder path

    key_file = open(key_dir, 'w+')
    print(input_file_path, file=sys.stderr)
    
    if split == 'pem':
        try:            
            p = subprocess.Popen(
                    ['openssl', 'rsa', '-in', input_file_path],
                    stdout=key_file
                )
                    
            p.wait()
        except:
            print('Failed to extract SK from: ' + str(input_file_path), file=sys.stderr)
            return {'error':'failed'}
    elif split == 'pub':
        try:            
            p = subprocess.Popen(
                    ['openssl', 'rsa', '-in', input_file_path, '-pubin', ],
                    stdout=key_file
                )
                    
            p.wait()
        except:
            print('Failed to extract PK from: ' + str(input_file_path), file=sys.stderr)
            return {'error':'failed'}

    key_file = open(key_dir, 'r')

    key = key_file.read()
    if 'pem' in split:
        data = {
            'sk' : key
        }
    elif 'pub' in split:
        data = {
            'pk' : key
        }
    return data

# openssl dgst -HASH -sign PRIVATE_KEY FILE_TO_SIGN > FILE.SIG
# openssl dgst -sha256 -sign /private-key-file.pem file-to-sign > file.sig
def sign_file_with_private_key( file_to_verify, private_key_file , hash_algorithm):
    input_file_path = os.path.join(UPLOADS_FOLDER, file_to_verify) #concat input file name and uploads folder path
    private_key_file_path = os.path.join(TEMP_FOLDER, private_key_file) #concat private key file name and temp folder path
    output_file_path = os.path.join(UPLOADS_FOLDER, file_to_verify+".sig")#concat output file name and uploads folder path
    p = subprocess.Popen(['touch', output_file_path]) # creating the output file before using it to prevent throwing errors
    p.wait()
    split = private_key_file.split('.')[-1] #get PK file extension used for assertion in signing procedure
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key."+split) #concat output file name and openssl's output folder path


    key_file = open(key_dir, 'w+')
    print(input_file_path, file=sys.stderr)

    hash = '-' + hash_algorithm
    print("openssl dgst " + hash + " -sign " + private_key_file_path +" -out " +output_file_path + " "+input_file_path )
    
    if split == 'pem':
        try:
            p1 = subprocess.Popen(
                ['openssl', 'dgst', hash, '-sign', private_key_file_path, '-out', output_file_path, input_file_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            p1.wait()

            return {'ok':'ok'}

        except:
            return {'error':'failed_to_sign'}

    else:
        return {'error':'invalid_pk_file'}



# openssl dgst -HASH -verify PUBLIC_KEY_TO_VERIFY -signature SIGNED_FILE_TO_VERIFY FILE_TO_VERIFY > VERIFICATION_RESULT
# openssl dgst -sha256 -verify /private-key-file.pem.pub -signature /file.sig file-to-sign > verif_result.txt

def verify_file_with_public_key( file_to_verify, public_key_file, signed_file, hash_algorithm ):
    signed_file_path = os.path.join(UPLOADS_FOLDER, signed_file) #concat signed file name and uploads folder path
    input_file_path = os.path.join(UPLOADS_FOLDER, file_to_verify) #concat input file name and uploads folder path
    public_key_file_path = os.path.join(TEMP_FOLDER, public_key_file) #concat public key file name and temp folder path
    output_file_path = os.path.join(UPLOADS_FOLDER, file_to_verify+".ver")#concat output file name and uploads folder path
    p = subprocess.Popen(['touch', output_file_path]) # creating the output file before using it to prevent throwing errors
    p.wait()
    split = public_key_file.split('.')[-1] #get PK file extension used for assertion in signing procedure
    key_dir=os.path.join(OPENSSL_OUTPUT_FOLDER, "key."+split) #concat output file name and openssl's output folder path

    key_file = open(key_dir, 'w+')
    print(input_file_path, file=sys.stderr)

    hash = '-' + hash_algorithm
    print("openssl dgst " + hash + " -sign " + public_key_file_path +" -signature " + signed_file_path + " -out " +output_file_path + " "+input_file_path )
    

    if split == 'pub':
        try:
            p1 = subprocess.Popen(
                ['openssl', 'dgst', hash, '-verify', public_key_file_path, '-signature', signed_file_path, '-out', output_file_path, input_file_path ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            p1.wait()

            return {'ok':'ok'}

        except:
            return {'error':'failed_to_verify'}

    else:
        return {'error':'invalid_pk_file'}


