

"""
kryptomancer app module

Launches and runs the kryptomancer app

Waits until the flask app is running in a separate thread and 
then creates a webview instance to run the app as a native app
in windows, linux and macOS

"""

import os
import sys
import json
import datetime
import logging

from http.client import HTTPConnection
from time import sleep
from threading import Thread
from flask import Flask, url_for, render_template, jsonify, request, make_response, redirect

from kryptomancer.routes import *
from kryptomancer.openssl import OPENSSL_OUTPUT_FOLDER, UPLOADS_FOLDER, TEMP_FOLDER

path_to_static = os.getcwd() + '/static'
path_to_templates = os.getcwd() + '/templates'

logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder=path_to_templates, static_folder= path_to_static)

app.register_blueprint(routes)


def run_server(docker=None):
    if docker is not None:
        app.run(host='0.0.0.0',threaded=True, port=5000, debug=True)        
    else:
        app.run(host='127.0.0.1',threaded=True, port=5000)

def url_ok(url, port):
    """
    Checks if given url and port have a ready http connection

    """

    try:
        conn = HTTPConnection(url, port)
        conn.request("GET", "/")
    except ConnectionRefusedError:
        logger.exception("Server not started")
        return False

    try:
        r = conn.getresponse()
        return r.status == 200
    except:
        logger.exception("Server error")

def check_folders(): #function to check if the app folders exist, if they don't creates them
    if not os.path.isdir(OPENSSL_OUTPUT_FOLDER):
        os.makedirs(OPENSSL_OUTPUT_FOLDER)
    if not os.path.isdir(UPLOADS_FOLDER):
        os.makedirs(UPLOADS_FOLDER)
    if not os.path.isdir(TEMP_FOLDER):
        os.makedirs(TEMP_FOLDER)
    