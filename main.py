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
import json
import logging

from google.appengine.ext import db

API_PATH = 'https://prod.api.pvp.net/'
#Move this to a seperate file in the application and add a GIT exclusion to it.
API_KEY = '?api_key=1483e7e5-b3f5-464a-90cf-97eae090febc'
SECRET = 'H3ll0myFr1enDS'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def get_user_api(username, region):
    api_user_by_name = 'api/lol/' + region + '/v1.4/summoner/by-name/'
    url = API_PATH + 'api/lol/' + region.lower() + '/v1.4/summoner/by-name/' + username.lower() + '?api_key=1483e7e5-b3f5-464a-90cf-97eae090febc'
    user_response = json.loads(urllib2.urlopen(url).read())
    
    return user_response

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

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    summoner_id = db.IntegerProperty(required = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def render_main(self):
        self.render("header.html")
        self.render("main.html")
    
    def get(self):
        self.render_main()
        
class SignupHandler(Handler):
    def render_signup(self, json="", password_error="", verify_error=""):
        self.render("header.html")
        self.render("signup.html", json=json, password_error=password_error, verify_error=verify_error)
    
    def get(self):
        self.render_signup()
        
    def post(self):
        password_error = ""
        verify_error = ""
        
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        region = self.request.get('region')
        
        if not valid_password(password):
            password_error = "Please enter valid password."
        
        if not verify_password(password, verify):
            verify_error = "Passwords do not match."
        
        if password_error != "" or verify_error != "":
            self.render_signup(password_error=password_error, verify_error=verify_error)
        else:
            json = get_user_api(username, region)
            logging.error(json)
        
        
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler,)
], debug=True)
