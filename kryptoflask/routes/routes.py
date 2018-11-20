"""
Kryptoflask Application Routes


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

from . import routes
from kryptoflask.openssl import (
    generate_key_iv, generate_key, encrypt_file 
)

UPLOAD_FOLDER = os.getcwd() + '/uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@routes.route('/')
def index():

    return render_template('index.html')

@routes.route('/crypter/', methods=['GET', 'POST']) 
def crypter():
    """
    Esta função serve uma página com um form de upload de ficheiros
    Retorna o nome do ficheiro e o seu conteudo
    """

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            files, enc = get_uploaded_files()
            selected_file = request.form.get('files')
            if selected_file == None:
                print('why')
                print(request.form['selected_files'], file=sys.stderr)
                return render_template('file_crypter.html', listdir=os.listdir(UPLOAD_FOLDER), enc_files=enc)
            else:
                print('wtf')
                print(selected_file, file=sys.stderr)
            return render_template('file_crypter.html', listdir=os.listdir(UPLOAD_FOLDER), enc_files=enc)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, file.filename))
            return render_template('file_crypter.html', name=filename, listdir=os.listdir(UPLOAD_FOLDER) )
        else:
            return render_template('file_crypter.html', error="File not supported." )
    else:
        files, enc = get_uploaded_files()

    return render_template('file_crypter.html', listdir=files, enc_files=enc)

@routes.route('/encrypt/', methods=['GET', 'POST'])
def encrypt():
    """
    Esta função é chamada quando o botão "Encrypt" da página "File_Crypter" é pressionado
    Retorna o nome dos ficheiros apagados
    """

    if request.method == 'POST':
        # check if the post request has the file part
        print(request.form, file=sys.stderr)
    
    listdir = os.listdir(UPLOAD_FOLDER)
    res = []
    for f in listdir:
        print(f)
        try:
            res.append(f)
        except:
            print("failed to delete file: " + f)
        
    return redirect('/crypter/')

@routes.route('/password_generator/', methods=['GET'])
def password_generator():
    
    return render_template('password_gen.html', data = None)

@routes.route('/generate', methods=['GET', 'POST'])
@routes.route('/generate/<int:bits>', methods=['GET'])
def generate(bits=256):

    if request.method == 'POST':
        data = generate_key( bytes= str(request.form['size']))
    elif bits == 128 or bits == 256 or bits == 512 :
        data = generate_key_iv( bytes= str(int(bits/8)) )
    else:
        data = generate_key( bytes=str(bits))
    
    
    return render_template('password_gen.html',  data=data)

# Deleting files

def delete_file():
    print("soon")

# Base 64 encoding

def encode_file(): 
    print("soon")
# Gets uploaded files and encrypted files, returns a tuple of lists (encrypted ones and non-encrypted)

def get_uploaded_files():
    listdir = os.listdir(UPLOAD_FOLDER)
    res = []
    enc = []
    for f in listdir:
        if '.dec' in f:
            enc.append(f)
        else:
            res.append(f)
    return res, enc