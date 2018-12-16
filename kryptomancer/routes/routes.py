"""
kryptomancer Application Routes


"""

import os
import sys
import json
import datetime
import asyncio
import logging
import subprocess
import time
import kryptomancer


from time import sleep
from threading import Thread
from flask import Flask, redirect, url_for, request, render_template
from werkzeug import secure_filename

from . import routes
from kryptomancer.openssl import (
    generate_aes_key_iv, generate_3des_key_iv, generate_key, encrypt_file,
    decrypt_file, digest_file, generate_rsa, hmac_file,
    view_key_from_pem, sign_file_with_private_key, verify_file_with_public_key
)
from kryptomancer.openssl import rsa_encrypt as rsa_enc
from kryptomancer.openssl import rsa_decrypt as rsa_dec

UPLOAD_FOLDER = os.getcwd() + '/uploads'
RSA_FOLDER = os.getcwd() + '/temp'
OPENSSL_OUTPUT_FOLDER = os.getcwd() + '/openssl_out'

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
    if selected_files:
        for file in selected_files:
            print(file, file=sys.stderr)
        enc_info = generate_keys_for_files(selected_files, selected_cipher)
    else:
        return render_template('file_crypter.html', listdir=files)
    return render_template('file_crypter.html', listdir=files , gen_info=enc_info['data'])

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

@routes.route('/rsa_crypter/', methods=['GET', 'POST']) 
def rsa_crypter():
    """
    Esta função serve uma página com um form de upload de ficheiros
    Retorna o nome do ficheiro e o seu conteudo
    """
    print('rsa_crypter', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            pass
        else:            
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file:
                filename = secure_filename(file.filename)
                if filename.split('.')[-1] == 'pem':
                    file.save(os.path.join(RSA_FOLDER, file.filename))
                else:
                    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
                files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
                return render_template('rsa_crypter.html', name=filename, listdir=files)
        
            files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
            return render_template('rsa_crypter.html', error="File not supported.", listdir=files)
    
    files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
    return render_template('rsa_crypter.html', listdir=files)

@routes.route('/rsa_encrypt/', methods=['POST'])
def rsa_encrypt():
    print('rsa_encrypt',file=sys.stderr)
    if request.method == 'POST':
        public_key_file = request.form.get('selected_files')
        if public_key_file is None:
            return render_template('rsa_crypter.html',  data=[], listdir=files)
        file_to_encrypt = request.form.getlist('uploaded_files')
        if not file_to_encrypt:
            return render_template('rsa_crypter.html',  data=[], listdir=files)
        
        data_list = []
        for f in file_to_encrypt:
            print(public_key_file, f, file=sys.stderr)
            data = rsa_enc(input_file=f, key_file=public_key_file)
            data['filename'] = f
            data['encryption_file'] = public_key_file
            if 'ok' in data:
                data['status'] = data['ok']
            else:
                data['status'] = data['error']
            data_list.append(data)

        files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
        return render_template('rsa_crypter.html',  data=data, listdir=files)

    files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
    return render_template('rsa_crypter.html', listdir=files)


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
        print("Base64: " + str(base64), file=sys.stderr)
        iv = request.form.get('encryption_iv')
        if iv:
            print('-------------Input IV:\n' + str(iv), file=sys.stderr)

        key = request.form.get('encryption_key')
        if key:
            print('-------------Input KEY:\n' + str(key), file=sys.stderr)
        selected_files = request.form.getlist('selected_files')
        if selected_files:
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
        if selected_files:
            print('------------ Files Selected:', file=sys.stderr)
            digest_list = []
            for f in selected_files:
                print(f, file=sys.stderr)
                digest_info = digest_file(input_file=f, hash_algorithm=selected_hash_algorithm)
                digest_info['filename'] = f
                digest_info['algorithm'] = selected_hash_algorithm
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
        if selected_files:
            print('-------------Selected Encrypted Files: ', file=sys.stderr)
            dec_list = []
            for f in selected_files:
                print(f, file=sys.stderr)
                dec_info = decrypt_single_file(f, key, iv, selected_cipher)
                dec_info['filename'] = f
                dec_info['algorithm'] = selected_cipher
                if 'ok' in dec_info:
                    dec_info['status'] = dec_info['ok']
                elif 'error' in dec_info:
                    dec_info['status'] = dec_info['error']
                

                print(dec_info, file=sys.stderr)
                print('------------ ', file=sys.stderr)
                dec_list.append(dec_info)
            print('------------ Files Decrypted:', file=sys.stderr)
            print(dec_list, file=sys.stderr)
            for item in dec_list:
                print(item, file=sys.stderr)

            files = get_uploaded_files()
            return render_template('file_crypter.html', listdir=files, dec_info=dec_list)
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
            try:
                size = int(size)
            except:
                return render_template('password_gen.html', data=[])
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

@routes.route('/hmac', methods=['GET', 'POST'])
def hmac_calculator():
    print('hmac', file=sys.stderr)
    if request.method == 'POST':
        files = get_uploaded_files()
        selected_files = request.form.getlist('selected_files')
        if selected_files:
            print('------------ Files Selected:', file=sys.stderr)
            hmac_key = request.form.get('hmac_key')
            hash_algorithm = request.form.get('hash_algorithm')

            print(hmac_key, hash_algorithm,  file=sys.stderr)
            if hmac_key is not '':
                hmac_list = []
                for f in selected_files:
                    print(f,  file=sys.stderr)
                    hmac_info = hmac_file(input_file=f,
                                         hash_algorithm=hash_algorithm,
                                        key=hmac_key)
                    hmac_info['filename']=f
                    hmac_info['algorithm']=hash_algorithm
                    hmac_list.append(hmac_info)
                print(hmac_list)
                return render_template('hmac.html', hmac_info=hmac_list, listdir = files)
            else:
                return render_template('hmac.html', data=[], listdir = files)
        else:
            return render_template('hmac.html', data=[], listdir = files)
    
    files = get_uploaded_files()
    
    return render_template('hmac.html',  data=[], listdir=files)

@routes.route('/signify', methods=['GET', 'POST'])
def signify():
    print('signify', file=sys.stderr)
    if request.method == 'POST':
        print('post', file=sys.stderr)
        print(request.__dict__, file=sys.stderr)
        if 'file' not in request.files:
            pass
        else:  
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file:
                filename = secure_filename(file.filename)
                print(filename, file=sys.stderr)
                file.save(os.path.join(UPLOAD_FOLDER, file.filename))
                files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
                return render_template('sign.html', name=filename, listdir=files)

        files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
        private_key_file = request.form.get('sign_selected_files')
        if private_key_file is None:
            return render_template('sign.html',  data=[], listdir=files)
        file_to_sign = request.form.getlist('sign_uploaded_files')
        if file_to_sign:
            return render_template('sign.html',  data=[], listdir=files)
        hash = request.form.get('selected_cipher')
        data_list = []
        for f in file_to_sign:
            data = sign_file_with_private_key(file_to_verify=f,
                                            private_key_file=private_key_file,
                                            hash_algorithm=hash)
            data['filename'] = f
            data_list.append(data)
        
        files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
        return render_template('sign.html',  data=data_list, listdir=files)
    
    print('get', file=sys.stderr)
    files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
    
    return render_template('sign.html',  data=[], listdir=files)

@routes.route('/verify', methods=['GET', 'POST'])
def verify():
    print('verify', file=sys.stderr)
    if request.method == 'POST':
        print('post', file=sys.stderr)
        print(request.__dict__, file=sys.stderr)
        if 'file' not in request.files:
            pass
        else:           
            file = request.files['file']
            # if user does not select file, browser also
            # submit an empty part without filename
            if file:
                filename = secure_filename(file.filename)
                print(filename, file=sys.stderr)
                split = filename.split('.')[-1]
                if split == 'pem' or split == 'pub':
                    file.save(os.path.join(RSA_FOLDER, file.filename))
                else:
                    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
                files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
                return render_template('verify.html', name=filename, listdir=files)

        files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
        public_key_file = request.form.get('selected_files')
        if public_key_file is None:
            return render_template('verify.html',  data=[], listdir=files)
        file_to_sign = request.form.getlist('uploaded_files')
        if file_to_sign:
            return render_template('verify.html',  data=[], listdir=files)
        if len(file_to_sign) != 2:
            return render_template('verify.html',  data=[], listdir=files)
        hash = request.form.get('selected_cipher')

        for f in file_to_sign:
            if f.split('.')[-1] == 'sig':
                file_signature = f
            else:
                file_to_verify = f

        data_list = []
        data = verify_file_with_public_key(file_to_verify=file_to_verify,
                                        public_key_file=public_key_file,
                                        signed_file=file_signature,
                                        hash_algorithm=hash)
        data['filename'] = f
        data_list.append(data)

        return render_template('verify.html',  data=data_list, listdir=files)
    
    files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
    
    return render_template('verify.html',  data=[], listdir=files)



@routes.route('/gen_rsa', methods=['GET', 'POST'])
def gen_rsa():
    print('gen_rsa', file=sys.stderr)
    if request.method == 'POST':
        sk = request.form.get('sk_file')
        if sk is not '':
            print(sk, file=sys.stderr)
            data = generate_rsa(sk_file=sk)
            if 'ok' in data:
                files = get_temporary_files()
                for f in files:
                    print(f, file=sys.stderr)
        else:
            files = get_temporary_files()
            return render_template('rsa_gen.html', data=[], listdir = files)
    
    files = get_temporary_files()
    
    return render_template('rsa_gen.html',  data=[], listdir=files)

@routes.route('/view_key', methods=['POST'])
def view_key():
    print('view_key', file=sys.stderr)
    if request.method == 'POST':
        selected_files = request.form.getlist('selected_files')
        if selected_files:
            key_list = []
            for f in selected_files:
                print(f)
                data = view_key_from_pem(f)
                data['filename'] = f
                key_list.append(data)
            print(key_list, file=sys.stderr)
            files = get_temporary_files()
            return render_template('rsa_gen.html',  rsa_data=key_list, listdir=files)
        files = get_temporary_files()
        return render_template('rsa_gen.html',  data=[], listdir=files)
    files = get_temporary_files()
    return render_template('rsa_gen.html',  data=[], listdir=files)




# Deleting files
@routes.route('/delete_file/', methods=['GET', 'POST'])
def delete_file():
    #print('delete_file', file=sys.stderr)
    if request.method == 'POST':
        # check if the post request has the file part
        redirect_rsa = None
        redirect_sign = None
        selected_files = request.form.getlist('selected_files')
        if selected_files: # Deletes selected files in select form
            print('------------ Files Selected:', file=sys.stderr)
            for f in selected_files:
                print(f,  file=sys.stderr)
                split = f.split('.')[-1]
                if split == 'pub' or split == 'pem':
                    filename = os.path.join(RSA_FOLDER, f)
                    print(filename, file=sys.stderr)
                else:
                    filename = os.path.join(UPLOAD_FOLDER, f)
                    print(filename, file=sys.stderr)
                try:
                    os.remove(filename)
                except:
                    pass

        uploaded_files = request.form.getlist('uploaded_files')

        if uploaded_files: # Deletes selected files in select form
            print('------------ Files Selected From Uploaded Files:', file=sys.stderr)
            for f in uploaded_files:
                print(f,  file=sys.stderr)
                split = f.split('.')[-1]
                if split == 'sig':
                    filename = os.path.join(UPLOAD_FOLDER, f)
                    print(filename, file=sys.stderr)
                try:
                    os.remove(filename)
                except:
                    pass
                    
        selected_files = request.form.getlist('sign_selected_files')
        if selected_files: # Deletes selected files in select form
            print('------------ Files Selected From Sign/Verify:', file=sys.stderr)
            print(selected_files, file=sys.stderr)
            redirect_sign=True
            for f in selected_files:
                print(f,  file=sys.stderr)
                split = f.split('.')[-1]
                if split == 'pub' or split == 'pem':
                    filename = os.path.join(RSA_FOLDER, f)
                else:
                    filename = os.path.join(UPLOAD_FOLDER, f)
                    print(filename, file=sys.stderr)
                try:
                    os.remove(filename)
                except:
                    pass

        uploaded_files = request.form.getlist('sign_uploaded_files')

        if uploaded_files: # Deletes selected files in select form
            print('------------ Files Selected From Sign/Verify Uploaded Files:', file=sys.stderr)
            redirect_sign=True
            for f in uploaded_files:
                print(f,  file=sys.stderr)
                split = f.split('.')[-1]
                if split == 'sig':
                    filename = os.path.join(UPLOAD_FOLDER, f)
                    print(filename, file=sys.stderr)
                try:
                    os.remove(filename)
                except:
                    pass
        if redirect_rsa == True:
            files = get_temporary_files()
            return render_template('rsa_gen.html', listdir=files, enc_info=[])   
        if redirect_sign == True :
            files = {**get_temporary_files(), **get_uploaded_files()} #joins two dicts :)
            return render_template('sign.html', listdir=files, enc_info=[])   
        else:
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
                    obj['algorithm'] = cipher
                    obj['status'] = 'ok'
                    print('ok', file=sys.stderr)
                    obj_list.append(obj)
                elif 'error' in res:
                    obj['algorithm'] = cipher
                    obj['status'] = 'error'
                    print('error', file=sys.stderr)
                    pass
            #print(obj_list, file=sys.stderr)
        result['data'] = obj_list
        return result

# Decrypts a list of files
def decrypt_single_file(filename, key, iv, cipher=None):
    if filename == None:
        return []
    else:
        result = {}
        print('DECRYPTING FILE: '+str(filename), file=sys.stderr)
        if cipher is not None:
            res = decrypt_file(filename, key, iv, cipher=cipher.lower())
        else:
            res = decrypt_file(filename, key, iv)
        res['iv'] = iv
        res['key'] = key
        print('decrypt_single_file', file=sys.stderr)
        print(res, file=sys.stderr)
        return res

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

# Gets temporary app files
# These may be .pem files
def get_temporary_files():
    listdir = os.listdir(RSA_FOLDER)
    res = {}
    sk = []
    pk = []
    signed = []

    for f in listdir:
        split = f.split('.')[-1]
        if split == 'pem':
            sk.append(f)
        elif split == 'pub':
            pk.append(f)
        elif split == 'sig':
            signed.append(f)

    
    res['sk'] = sk
    res['pk'] = pk
    res['signed'] = signed
    return res

# Gets uploaded files and encrypted files, returns an object with 3 lists, encrypted files, decrypted and untouched
def get_uploaded_files():
    listdir = os.listdir(UPLOAD_FOLDER)
    res = {}
    dec = []
    enc = []
    signed = []
    verified = []
    untouched = []

    for f in listdir:
        split = f.split('.')[-1]
        if split == 'enc' or split == 'rsaenc':
            enc.append(f)
        elif split == 'dec'or split == 'rsadec':
            dec.append(f)
        elif split == 'sig':
            signed.append(f)
        elif split == 'ver':
            verified.append(f)
        else:
            untouched.append(f)
    
    res['decrypted'] = dec
    res['encrypted'] = enc
    res['untouched'] = untouched
    res['signed'] = signed
    res['verified'] = verified
    return res
