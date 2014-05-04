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

from google.appengine.api import memcache
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
    region = db.StringProperty(required = True)
    league = db.StringProperty(required = True)

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
    def render_signup(self, json="", summoner_image=""):
        self.render("header.html")
        self.render("signup.html", json=json, summoner_image=summoner_image)
    
    def get(self):
        self.render_signup()
        
    def post(self):
        
        username = self.request.get('username')
        region = self.request.get('region')
        
        json = get_user_api(username, region)   
                 
        icon_id = json[username]['profileIconId']
        summoner_id = json[username]['id']

class verifySummonerHandler(Handler):
    def render_verify(self, profile_icon="", username="", region=""):
        self.render("header.html")
        self.render("verifysummoner.html", profile_icon=profile_icon, username=username, region=region)
    
    def post(self):
        username = self.request.get('username')
        region = self.request.get('region')    
        #Cache this   
        json = get_user_api(username, region)
        profile_icon = json[username]['profileIconId']
        
        if(profile_icon == '0'):
            verify_icon = '1'
        else:
            verify_icon = '0'
            
        memcache.set('%s:verify_icon' % username, verify_icon)
        
        self.render_verify(profile_icon=verify_icon, username=username, region=region)
        
class confirmSummonerHandler(Handler):
    
    def render_errors(self, password_error="", verify_error="", verification_error="", verify_icon=""):                
        self.render("header.html")
        self.render("verifysummoner.html", )

    def post(self):
        password_error = ""
        verify_error = ""
        verification_error = ""
        
        username = self.request.get('username')
        region = self.request.get('region')
        password = self.request.get('password')
        verify = self.request.get('verify')
        
        verify_icon = str(memcache.get('%s:verify_icon' % username))
        json = get_user_api(username, region)
        player_icon = str(json[username]['profileIconId'])
        
        if not valid_password(password):
            password_error = "Invalid password."
            
        if not verify_password(password, verify):
            verify_error = "Passwords don't match."
            
        if verify_icon != player_icon:
            verification_error = "Please change your icon to the shown icon."
            logging.error(verify_icon == player_icon)
        
        if not valid_password(password) or not verify_password(password, verify) or verify_icon != player_icon:
            self.render_errors(password_error, verify_error, verification_error, verify_icon)
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie', 'username=%s' % str(hash_cookie(username)))      
            g = User(username = username, password = hash_pw(password), summoner_id = json[username]['id'])
            g.put()
            logging.error('Success!')
            self.redirect('/welcome')
        
        
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignupHandler),
    ('/verify_summoner', verifySummonerHandler),
    ('/verify_summoner/confirm', confirmSummonerHandler),
], debug=True)
