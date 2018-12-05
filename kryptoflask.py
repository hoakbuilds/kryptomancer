#!/usr/bin/env python

import os
import sys
import json
import datetime
import logging
import webview

from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
from threading import Thread, Lock
from time import sleep

from kryptoflask import url_ok, run_server

logger = logging.getLogger(__name__)
server_lock = Lock()

if __name__ == '__main__':

    run_server()
    """webview.create_window("kryptoflask",
                        "http://127.0.0.1:5000",
                        min_size=(1280, 720))"""