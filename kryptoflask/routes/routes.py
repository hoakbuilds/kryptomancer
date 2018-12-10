"""
Kryptoflask Application Routes


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

from . import routes
from kryptoflask.openssl import (
    generate_aes_key_iv, generate_3des_key_iv, generate_key, encrypt_file,
    decrypt_file, digest_file
)

UPLOAD_FOLDER = os.getcwd() + '/uploads'

@routes.route('/')
def index():

    return render_template('index.html')

@routes.route('/crypter/generate_keys_from_selected_files', methods=['GET', 'POST']) 
def generate_keys_from_files():
    """
    Esta função serve a página do Crypter com chaves geradas para cada um dos ficheiros selecionados
    Retorna o nome do ficheiro e o seu conteudo
    """
    print('/crypter/generate_keys_from_selected_files', file=sys.stderr)
    files = get_uploaded_files()
    selected_cipher = request.form.get('selected_cipher')
    if selected_cipher is None:
        return render_template('file_crypter.html', listdir=files)
    selected_files = request.form.getlist('selected_files')
    if selected_files is not None:
        for file in selected_files:
            print(file, file=sys.stderr)
        enc_info = generate_keys_for_files(selected_files, selected_cipher)
    else:
        return render_template('file_crypter.html', listdir=files)
    return render_template('file_crypter.html', listdir=files , enc_info=enc_info['data'])

@routes.route('/crypter/', methods=['GET', 'POST']) 
def crypter():
    """
    Esta função serve uma página com um form de upload de ficheiros
    Retorna o nome do ficheiro e o seu conteudo
    """
    print('crypter', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            files = get_uploaded_files()
            return render_template('file_crypter.html', listdir=files)
            
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, file.filename))
            files = get_uploaded_files()
            return render_template('file_crypter.html', name=filename, listdir=files)
        else:
            files = get_uploaded_files()
            return render_template('file_crypter.html', error="File not supported.", listdir=files)
    else:
        files = get_uploaded_files()

    return render_template('file_crypter.html', listdir=files)

@routes.route('/digester/', methods=['GET', 'POST']) 
def digester():
    """
    Esta função serve uma página com um form de upload de ficheiros
    Retorna o nome do ficheiro e o seu conteudo
    """
    print('crypter', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            files = get_uploaded_files()
            return render_template('digester.html', listdir=files)
            
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, file.filename))
            files = get_uploaded_files()
            return render_template('digester.html', name=filename, listdir=files)
        else:
            files = get_uploaded_files()
            return render_template('digester.html', error="File not supported.", listdir=files )
    else:
        files = get_uploaded_files()

    return render_template('digester.html', listdir=files)

@routes.route('/crypter/encrypt_all', methods=['GET','POST'])
@routes.route('/encrypt_file/', methods=['GET','POST'])
def encrypt():
    """
    Esta função é chamada quando o botão "Encrypt" da página "File_Crypter" é pressionado
    Retorna o nome dos ficheiros apagados
    """
    print('encrypt', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        files = get_uploaded_files()
        selected_cipher = request.form.get('selected_cipher')
        if selected_cipher is None:
            return render_template('file_crypter.html', listdir=files, enc_info=[])
        base64 = request.form.get('base64_encoding')
        print(base64, file=sys.stderr)
        iv = request.form.get('encryption_iv')
        if iv:
            print('-------------Input IV: ' + str(iv), file=sys.stderr)

        key = request.form.get('encryption_key')
        if key:
            print('-------------Input KEY: ' + str(key), file=sys.stderr)
        selected_files = request.form.getlist('selected_files')
        if selected_files is not None:
            print('------------ Files Selected:', file=sys.stderr)
            for f in selected_files:
                print(f, file=sys.stderr)
            if iv and key:     
                if base64:
                    enc_info = encrypt_list_of_files(selected_files, selected_cipher, key=key, iv=iv, base64=True)
                else:
                    enc_info = encrypt_list_of_files(selected_files, selected_cipher, key=key, iv=iv)
            else:
                if base64:
                    enc_info = encrypt_list_of_files(selected_files, selected_cipher, base64=True)
                else:
                    enc_info = encrypt_list_of_files(selected_files, selected_cipher)
            print('------------ Files Encrypted:', file=sys.stderr)
            for item in enc_info:
                print(item, file=sys.stderr)
        else:
            return render_template('file_crypter.html', listdir=files, enc_info=enc_info['data'])
        files = get_uploaded_files()
        return render_template('file_crypter.html', listdir=files,  enc_info=enc_info['data'])


@routes.route('/digest_file/', methods=['GET','POST'])
def digest():
    """
    """
    print('digest', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        selected_hash_algorithm = request.form.get('selected_cipher')
        if selected_hash_algorithm is not None:
            print('------------ Hash Algorithm Selected: ' + selected_hash_algorithm, file=sys.stderr)

        selected_files = request.form.getlist('selected_files')
        if selected_files is not None:
            print('------------ Files Selected:', file=sys.stderr)
            digest_list = []
            for f in selected_files:
                print(f, file=sys.stderr)
                digest_info = digest_file(input_file=f, hash_algorithm=selected_hash_algorithm)
                digest_info['filename'] = f
                digest_list.append(digest_info)

            print(digest_list)

        files = get_uploaded_files()
        return render_template('digester.html', listdir=files, digest_info=digest_list)


@routes.route('/decrypt_file/', methods=['GET','POST'])
def decrypt():
    """
    Esta função é chamada quando o botão "Encrypt" da página "File_Crypter" é pressionado
    Retorna o nome dos ficheiros apagados
    """
    print('decrypt', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        selected_cipher = request.form.get('selected_cipher')
        iv = request.form['encryption_iv']
        if iv is not None:
            print('-------------Input IV: ' + str(iv), file=sys.stderr)

        key = request.form['encryption_key']
        if key is not None:
            print('-------------Input KEY: ' + str(key), file=sys.stderr)
            
        selected_files = request.form.getlist('selected_files')
        if selected_files is not None:
            print('-------------Selected Encrypted Files: ', file=sys.stderr)
            for f in selected_files:
                print(f, file=sys.stderr)
                enc_info = decrypt_single_file(f, key, iv, selected_cipher)
            print('------------ Files Decrypted:', file=sys.stderr)
            for item in enc_info:
                print(item, file=sys.stderr)
        else:
            files = get_uploaded_files()
            return render_template('file_crypter.html', listdir=files)
        files = get_uploaded_files()
        return render_template('file_crypter.html', listdir=files)

@routes.route('/generate', methods=['GET', 'POST'])
@routes.route('/generate/<int:bits>', methods=['GET'])
def generate(bits=128):
    
    if request.method == 'POST':
        form = request.form.get('base64_encoding')
        size = request.form.get('size')
        if size is not '':
            if form:
                print(form, file=sys.stderr)
                data = generate_key( bytes= str(int(size)), base64=True)
            else:
                data = generate_key( bytes= str(int(size)))
        else:
            return render_template('password_gen.html', data=[])
    elif bits == 128 or bits == 192 or bits == 256 :
        data = generate_aes_key_iv( bytes= str(int(bits/8)) )
    elif bits == 192:
        data = generate_3des_key_iv()
    else:
        data = generate_key( bytes=str(int(bits/8)))
    
    
    return render_template('password_gen.html',  data=data)

# Deleting files
@routes.route('/crypter/delete_all/', methods=['GET', 'POST'])
@routes.route('/delete_file/', methods=['GET', 'POST'])
def delete_file():
    #print('delete_file', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        selected_files = request.form.getlist('selected_files')
        if selected_files is not None: # Deletes selected files in select form
            print('------------ Files Selected:', file=sys.stderr)
            for f in selected_files:
                print(f,  file=sys.stderr)
                filename = os.path.join(UPLOAD_FOLDER, f)
                print(filename, file=sys.stderr)
                os.remove(filename)
        else:# Deletes all files
            files = get_uploaded_files()
            for f in files:
                print(f,  file=sys.stderr)
                filename = os.path.join(UPLOAD_FOLDER, f)
                print(filename, file=sys.stderr)
                os.remove(filename)
        selected_enc_files = request.form.getlist('selected_enc_files')
        if selected_enc_files is not None:  # Deletes selected files in select form 
            print('------------ Encrypted Files Selected:', file=sys.stderr)
            for f in selected_enc_files:
                print(f,  file=sys.stderr)
                filename = os.path.join(UPLOAD_FOLDER, f)
                print(filename, file=sys.stderr)
                os.remove(filename)
        else: # Deletes all files
            files = get_uploaded_files()
            for f in files:
                print(f,  file=sys.stderr)
                filename = os.path.join(UPLOAD_FOLDER, f)
                print(filename, file=sys.stderr)
                os.remove(filename)

        files = get_uploaded_files()
        return render_template('file_crypter.html', listdir=files, enc_info=[])

    files = get_uploaded_files()
    return render_template('file_crypter.html', listdir=files, enc_info=[])

            

# Base 64 encoding
def encode_file(): 
    print("soon")

# Encrypts a list of files, works with input key & iv as well
def encrypt_list_of_files(files, cipher=None, key=None, iv=None, base64=None): #Default values for key and IV are None
    #print('encrypt_list_of_files', file=sys.stderr)
    if files == None:
        return []
    else:
        result = {}
        obj_list = []
        for f in files:
            obj = {}
            obj['filename'] = f
            if cipher is not None:
                if key is not None and iv is not None: # If a key and iv from input exists
                    obj['iv'] = iv
                    obj['key'] = key
                else:
                    if 'aes' in cipher:
                        size = int(cipher.split('-')[1])
                        data = generate_aes_key_iv(bytes=str(int(size/8)))
                        obj['iv'] = data['iv']
                        obj['key'] = data['key']
                    elif 'des' in cipher:
                        data = generate_3des_key_iv()
                        obj['iv'] = data['iv']
                        obj['key'] = data['key']
                print('ENCRYPTING FILE: '+str(f), file=sys.stderr)
                if base64 is not None:
                    res = encrypt_file(f, obj['key'], obj['iv'], cipher, base64=True)  
                else: 
                    res = encrypt_file(f, obj['key'], obj['iv'], cipher)  
                if 'ok' in res:
                    print('ok', file=sys.stderr)
                    obj_list.append(obj)
                elif 'error' in res:
                    print('error', file=sys.stderr)
                    pass
            #print(obj_list, file=sys.stderr)
        result['data'] = obj_list
        return result

# Decrypts a list of files
def decrypt_single_file(filename, key, iv, cipher=None):
    print('decrypt_file', file=sys.stderr)
    if filename == None:
        return []
    else:
        result = {}
        print('DECRYPTING FILE: '+str(filename), file=sys.stderr)
        if cipher is not None:
            res = decrypt_file(filename, key, iv, cipher=cipher.lower())
        else:
            res = decrypt_file(filename, key, iv)
        if 'ok' in res:
            print('ok', file=sys.stderr)
        elif 'error' in res:
            print('error', file=sys.stderr)
            pass
        #print(obj_list, file=sys.stderr)
        return result

# Decrypts a list of files
def decrypt_list_of_files(files):
    print('decrypt_list_of_files', file=sys.stderr)
    if files == None:
        return []
    else:
        result = {}
        obj_list = []
        for f in files:
            obj = {}
            obj['filename'] = f
            data = generate_key_iv(bytes=str(16))
            obj['iv'] = data['iv']
            obj['key'] = data['key']
            print('DECRYPTING FILE: '+str(f), file=sys.stderr)
            res = encrypt_file(f, obj['key'], obj['iv'])
            if 'ok' in res:
                print('ok', file=sys.stderr)
                obj_list.append(obj)
            elif 'error' in res:
                print('error', file=sys.stderr)
                pass
            #print(obj_list, file=sys.stderr)
        result['data'] = obj_list
        return result

def generate_keys_for_files(files, selected_cipher):
    print('generate_keys_for_files', file=sys.stderr)
    if files == None:
        return []
    else:
        if 'aes' in selected_cipher:
            size = selected_cipher.split('-')[1]
        elif 'des' in selected_cipher:
            size = None
        result = {}
        obj_list = []
        for f in files:
            obj = {}
            obj['filename'] = f
            if size is not None:
                data = generate_aes_key_iv(bytes=str(int(int(size)/8)))
            else:
                data = generate_3des_key_iv()
            obj['iv'] = data['iv']
            obj['key'] = data['key']
            obj_list.append(obj)
            print(obj_list, file=sys.stderr)
        result['data'] = obj_list
        return result

# Gets uploaded files and encrypted files, returns a tuple of lists (encrypted ones and non-encrypted)
def get_uploaded_files():
    listdir = os.listdir(UPLOAD_FOLDER)
    res = {}
    dec = []
    enc = []
    untouched = []

    for f in listdir:
        if '.enc' in f:
            enc.append(f)
        elif '.dec' in f:
            dec.append(f)
        else:
            untouched.append(f)
    
    res['decrypted'] = dec
    res['encrypted'] = enc
    res['untouched'] = untouched
    return res
