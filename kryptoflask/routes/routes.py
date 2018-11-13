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

from time import sleep
from threading import Thread
from flask import Flask, redirect, url_for, request, render_template

from . import routes

@routes.route('/')
def index():

    return render_template('index.html')

@routes.route('/test')
def test():
    
    return render_template('test.html', data=do_stuff())

def do_stuff():
    # do whatever you need to do
    response = "This is response from Python backend"
    return response