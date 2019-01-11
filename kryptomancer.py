#!/usr/bin/env python

import os
import sys
import json
import datetime
import logging
import sys
import threading
import webview

from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
from threading import Thread, Lock
from time import sleep

from kryptomancer import url_ok, run_server, check_folders

logger = logging.getLogger(__name__)

if __name__ == '__main__':

    check_folders()

    if 'docker' in sys.argv:
        run_server(docker=True)
    elif 'threaded' in sys.argv:
        t = threading.Thread(target=run_server, args=[])
        try:
            t.start()
            logger.info("Starting server")
            sleep(0.5)
            while not url_ok("127.0.0.1", 5000):
                sleep(0.5)
            logger.info("Server started")
        except:
            logger.warning("Failed to start kryptoflask threaded server.")

    else:
        webview.create_window("kryptomancer",
                        "http://127.0.0.1:5000", resizable=True)
