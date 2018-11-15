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

from time import sleep
from threading import Thread
from flask import Flask, redirect, url_for, request, render_template
from werkzeug import secure_filename

from . import routes
import kryptoflask

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
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(UPLOAD_FOLDER, file.filename))
            return render_template('file_crypter.html', name=filename, listdir=os.listdir(UPLOAD_FOLDER) )
        else:
            return render_template('file_crypter.html', error="file not supported" )

    return render_template('file_crypter.html')

@routes.route('/encrypt/', methods=['GET', 'POST'])
def encrypt():
    """
    Esta função é chamada quando o botão "Encrypt" da página "File_Crypter" é pressionado
    Retorna o nome dos ficheiros apagados
    """

    print(UPLOAD_FOLDER)
    listdir = os.listdir(UPLOAD_FOLDER)
    print(listdir)
    res = []
    for f in listdir:
        print(f)
        try:
            os.remove(os.path.join(UPLOAD_FOLDER, f))
            res.append(f)
        except:
            print("failed to delete file: " + f)
        
    return render_template('file_crypter.html', data=res)

# openssl enc -aes-256-cbc -e -in $file -out $file.dec -K $key -iv $iv

def file_encryption( input_file, key, iv ):
    file_path = os.path.join(UPLOAD_FOLDER, input_file)
    enc_file = os.path.join(UPLOAD_FOLDER,  input_file + ".dec")
    subprocess.Popen(
        ['openssl', 'enc', '-aes-256-cbc', '-e', '-in', file_path, '-out', enc_file, '-K', key, '-iv', iv]
    )

@routes.route('/password_generator/', methods=['GET'])
def password_generator():
    
    return render_template('password_gen.html', data = None)

@routes.route('/generate', methods=['GET'])
def generate():
    key_dir=os.path.join(UPLOAD_FOLDER, "key-file.txt")
    iv_dir=os.path.join(UPLOAD_FOLDER, "iv-file.txt")
    print(iv_dir, key_dir)

    key_file = open(key_dir, 'w+')
    iv_file = open(iv_dir, 'w+')
    print(iv_file, key_file)

    subprocess.Popen(
        ['openssl', 'rand', '-hex', '32'],
        stdout=key_file
    )
    subprocess.Popen(
        ['openssl', 'rand', '-hex', '16'],
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
    print(data)
    return render_template('password_gen.html',  data=data)

def do_stuff():
    # do whatever you need to do
    response = "This is response from Python backend"
    return response