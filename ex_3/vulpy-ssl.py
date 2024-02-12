#!/usr/bin/env python3

from flask import Flask, g, redirect, request
import os

from mod_hello import mod_hello
from mod_user import mod_user
from mod_posts import mod_posts
from mod_mfa import mod_mfa

import libsession

app = Flask('vulpy')
app.config['SECRET_KEY'] = os.environ['VULPY_SECRET_KEY']

app.register_blueprint(mod_hello, url_prefix='/hello')
app.register_blueprint(mod_user, url_prefix='/user')
app.register_blueprint(mod_posts, url_prefix='/posts')
app.register_blueprint(mod_mfa, url_prefix='/mfa')


@app.route('/')
def do_home():
    return redirect('/posts')

@app.before_request
def before_request():
    g.session = libsession.load(request)

if __name__ == '__main__':
    DEBUG = (_.lower() == 'true') if (_ := os.environ.get("VULPY_DEBUG", None)) is not None else False
    app.run(debug = DEBUG, host='127.0.1.1', ssl_context=('/tmp/acme.cert', '/tmp/acme.key'))
