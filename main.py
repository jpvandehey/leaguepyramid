#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import string
import re
import urllib2
import random
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def get_user_api(username):
    pass

def hash_cookie(s):
    h = hashlib.sha256(SECRET + s).hexdigest()
    return s+'|'+str(h)

def validate_pw(user_input, salt, pw):
    return hashlib.sha256(user_input+salt).hexdigest() == pw

def hash_pw(s):
    salt = make_salt()
    return hashlib.sha256(s+salt).hexdigest()+'|'+salt

def make_salt():
    r = ''
    for i in range(5):
        r += random.choice(string.letters)
    return r

def valid_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)

def verify_password(password, verify):
    return password == verify

#Generic Handler class
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Main Application Handler
class MainHandler(Handler):
    def render_main(self):
        self.render("header.html")
        self.render("main.html")
    
    def get(self):
        self.render_main()
        
class SignupHandler(Handler):
    def render_signup(self):
        self.render("header.html")
        self.render("signup.html")
    
    def get(self):
        self.render_signup()
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler,)
], debug=True)
