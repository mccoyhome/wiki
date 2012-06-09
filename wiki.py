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
import re
import jinja2
import os
import hashlib
import hmac
import random
import string
import datetime
import json
import time

from google.appengine.ext import db
from google.appengine.api import memcache

jinja_environment = jinja2.Environment(
    autoescape=True,
    loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')),
    extensions=['jinja2.ext.autoescape']
    )

def make_salt():
	r = random.SystemRandom()
	return ''.join(r.sample(string.letters + string.digits, 5))

def make_hash(name, pw, salt=''):
    if not salt:
        salt = make_salt()
    h = hmac.new(salt, name + pw, digestmod=hashlib.sha256).hexdigest()
    return ('%s|%s' % (h, salt))

def valid_hash(name, pw, h):
    salt = h.split('|')[1]
    test = make_hash(name, pw, salt)
    return test == h

def gray_style(lst):
	if n, x in enumerate(lst):
		if n % 2 == 0:
			yield x, ''
		else:
			yield x, 'gray'

def notfound(self):
	self.error(404)
	self.write('<h1>404: Not Found</h1>Sorry but that page does not exist.')


def logged_in(self):
	user_cookie = str(self.request.cookies.get('user_id'))
	if user_cookie == 'None':
		return None
	name = user_cookie[0:user_cookie.find('|')]
	returned_hash = user_cookie[user_cookie.find('|')+1:]
	entry = db.GqlQuery("select * from Users where username=:1 limit 1", name).get()
	if entry:
		if entry.password == returned_hash:
			return name
	else:
		return None


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)
	
PASS_RE = re.compile(r"^.{3,20}$")
def valid_pass(password):
	return PASS_RE.match(password)
	
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(mail):
	return EMAIL_RE.match(mail)

class Wiki(db.Model):

	Wiki_page = db.TextProperty(required = False)
	Wiki_url = db.StringProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

class Users(db.Model):

	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)

# def Wiki_content(update = False):
# 	contents = memcache.get('Wiki')
# 	if contents is None or update:
# 		contents = db.GqlQuery("select * from Wiki limit 1").get()
# 		if not contents:
# 			contents =''
# 		memcache.set('Wiki', contents)
# 	return contents



class Signup(webapp2.RequestHandler):

	def write_form(self, name_error='', pass_error='',verify_error='', mail_error='', username='', email=''):
		template = jinja_environment.get_template('signup.html')

		self.response.out.write(template.render (
										bad_name = name_error,
										bad_pass = pass_error,
										bad_verify = verify_error,
										bad_mail = mail_error,
										username = username,
										email = email
										))
		
	def get(self):
		next_url = self.request.headers.get('referrer','/')
		self.write_form()
		
	def post(self):

		next_url = str(self.request.get('next_url'))
		if not next_url or next_url.startswith('/login'):
			next_url = '/'


		E_username = str(self.request.get('username'))
		E_password = self.request.get('password')
		E_verify = self.request.get('verify')
		E_email = self.request.get('email')

		username = valid_username(E_username)
		if not username:
			name_error = "That's not a valid username,"
		else:
			name_error = ''
			
		password = valid_pass(E_password)
		if not password:
			pass_error = "That wasn't a valid password."
		else:
			pass_error = ''
			
		valid = E_verify == E_password
		if not valid:
			verify_error = "Your passwords didn't match."
		else:
			verify_error = ''
			
		mail_error = ''
		
		if E_email:
			if not valid_email(E_email):
				mail_error = "That's not a valid email."
		else:
			E_email = ''
	
		if not (username and password and valid and mail_error == ''):
			self.write_form(name_error, pass_error, verify_error, mail_error, E_username, E_email)
		else:
			entry = db.GqlQuery("select * from Users where username=:1 limit 1", E_username).get()
			if entry: # user already in database, check password matches
				stored_hash = str(entry.password)
				if valid_hash(E_username, E_password,  stored_hash):
					self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (E_username, stored_hash))
					self.redirect(next_url)
			if not entry: # new user
				hashed_pw = make_hash(E_username,E_password)
				a = Users(username=E_username, password=hashed_pw, email=E_email)
				a.put()
				self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (E_username, hashed_pw))
				self.redirect(next_url)
	
			name_error = "That username is already used"
			self.write_form(name_error, pass_error, verify_error, mail_error, E_username, E_email)

class Login(webapp2.RequestHandler):

	def write_form(self, name_error='', pass_error='', loginerror='',  username=''):
		template = jinja_environment.get_template('login.html')

		self.response.out.write(template.render (
										bad_name = name_error,
										bad_pass = pass_error,
										log_error = loginerror,
										username = username,
										))

	def get(self):
		self.write_form()

	def post(self):
		E_username = str(self.request.get('username'))
		E_password = self.request.get('password')
		ident = self.request.get("ident")

		username = valid_username(E_username)
		if not username:
			name_error = "That's not a valid username,"
		else:
			name_error = ''

		password = valid_pass(E_password)
		if not password:
			pass_error = "That wasn't a valid password."
		else:
			pass_error = ''

		if not (username and password):
			self.write_form(name_error, pass_error, '',  E_username)
		else:
			entry = db.GqlQuery("select * from Users where username=:1 limit 1", E_username).get()
			if entry:
				stored_hash = str(entry.password)
				if valid_hash(E_username, E_password,  stored_hash):
					self.response.headers.add_header('Set-Cookie', 'user_id=%s|%s; Path=/' % (E_username, stored_hash))
					self.redirect(ident)
				else:
					self.write_form('', '','Invalid username or password',  E_username)		
			else:
				self.write_form('', '', "Don't know you, %s. Have you signed up?" % E_username, E_username)


class Handler(webapp2.RequestHandler):

	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		params['user'] = self.user
		params['gray-style'] = gray_style
		# t = jinja_environment.get_template(template)
		return render_str(template, **params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class EditPage(Handler):

	def get(self, ident):

		name = logged_in(self)
		edit = 'active'
		if name == None:
			self.redirect('/login')

		content = db.GqlQuery("SELECT * FROM Wiki where Wiki_url= :1 order by created desc limit 1",ident).get()

		if not content:
			page = ''
		else:
			page = content.Wiki_page
			if not page:
				page = ''

		self.render("wiki_edit.html", content = page, name = name, edit = edit, ident = ident[:5])

	def post(self, ident):

		name = logged_in(self)
		if name == None:
			self.redirect('/login')

		content = self.request.get("content")
		
		if content:
			c = Wiki(Wiki_page = content, Wiki_url = ident[:5])
			c.put()
		else:
			c = Wiki(Wiki_page = '', Wiki_url = ident[:5])
			c.put()

		self.redirect(ident[:5])


class WikiPage(Handler):

	def get(self, ident):

		name = logged_in(self)
		edit = True
		if name == None:
			edit = False

		content = db.GqlQuery("SELECT * FROM Wiki where Wiki_url= :1 order by created desc limit 1",ident).get()
		if not content:
			if edit:
				self.redirect("_edit" + ident)
			else:
				self.redirect('/login')
		else:
			page = content.Wiki_page
			if not page:
				page = ''
			self.render("wiki.html", content = page, name = name, edit = edit, ident = content.Wiki_url)

	def post(self, ident):

		name = logged_in(self)
		if name == None:
			self.redirect('/login')

		self.redirect("_edit" + ident)


class Logout(Handler):

    def get(self):
    	ident = self.request.get("ident")
    	self.response.headers.add_header('Set-Cookie', "user_id=; Path=/")
    	self.redirect(ident)





PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([	('/signup', Signup),
								('/login', Login),
								('/logout', Logout),
								('/_edit' + PAGE_RE, EditPage),
								(PAGE_RE, WikiPage),
								],
								debug=True)

