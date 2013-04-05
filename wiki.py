import webapp2
import jinja2
import os
import re
import hmac
import random
import string
from google.appengine.api import memcache
from google.appengine.ext import db

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)), autoescape=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
PAGEURI_RE = r'(^[a-zA-Z0-9_-]+)'

secret = 'jana'

def get_salt():
		return ''.join(random.choice(string.ascii_letters) for x in range(5))

def make_pwd_hash(pwd, salt):
		ret_str= hmac.new(salt, pwd).hexdigest()
		return '%s|%s' %(ret_str, salt)
		
def make_secure_hash(val):
		return  '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(pwd):
    return pwd and PASS_RE.match(pwd)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

def check_secure_cookie(cookie_val):
	val = cookie_val.split('|')[0]
	#print val
	if cookie_val == make_secure_hash(val):
		return val




class UserAccount(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def register(cls, name, pwd, email=''):
		salt = get_salt()
		pwd_hash = make_pwd_hash(pwd, salt)
		return UserAccount(username = name,
							password = pwd_hash,
							email = email)

	@classmethod
	def login(cls, user, pwd):
		user_row = db.GqlQuery("SELECT * FROM UserAccount WHERE username=:1", user).get()
		org_pwd = user_row.password
		org_salt = org_pwd.split('|')[1]
		if org_pwd == make_pwd_hash(str(pwd), str(org_salt)):
			return user
		else:
			return None


class WikiData(db.Model):
	pageUri = db.StringProperty(required=True)
	pageContent = db.TextProperty()
	lastModified = db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_environment.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, logged_in=self.user, **kw))

	def set_cookie_val(self, name, val):
		self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, make_secure_hash(val)))

	def read_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_cookie(cookie_val)

	def remove_cookie(self, name):
		val = str('')
		self.set_cookie_val(name, val)

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_cookie('user_id')
		u = db.GqlQuery('SELECT * FROM UserAccount WHERE username=:1', uid)
		uname = u.get()
		if uname:
			uname.username
		self.user = uid and uname.username

class Signup(Handler):

	def render_signup(self, username="", email="", uerror="", perror="", eerror=""):
		self.render("signup.html", username=username, email=email, uerror=uerror, perror=perror, eerror=eerror)

	def get(self):
		self.render_signup()

	def post(self):
		username = self.request.get("username")
		pwd = self.request.get("password")
		ver = self.request.get("verify")
		email = self.request.get("email")
		have_error = False
		params = dict(username=username,
			email=email)

		if not valid_username(username):
			params['uerror'] = "That's not a valid username"
			have_error = True

		if not valid_password(pwd):
			params['perror'] = "That's not a valid password"
			have_error = True
		elif pwd != ver:
			params['perror'] = "Your passwords did not match"
			have_error = True

		if not valid_email(email):
			params['eerror'] = "That's not a valid email"
			if not email=='':
				have_error = True
		ua = db.GqlQuery('SELECT name FROM UserAccount WHERE username=:1', username)
		
		if ua.get():
			params['uerror'] = "User name already exists"
			have_error = True

		if have_error:
			self.render_signup(**params)
		else:
			ua = UserAccount.register(str(username), pwd, email)
			ua.put()
			self.set_cookie_val('user_id', str(username))
			self.redirect("/wiki/")

class Login(Handler):

	def render_login(self, username="", error=""):
		self.render('login.html', username=username, error=error)


	def get(self):
		self.render_login()

	def post(self):
		params = dict()
		user = self.request.get("username")
		pwd = self.request.get("password")
		if UserAccount.login(str(user), str(pwd)):
			self.set_cookie_val('user_id', str(user))
			self.redirect("/wiki/")
		else:
			params['username'] = user
			params['error'] = "Invalid username or password"
			self.render_login(**params)

class Logout(Handler):

	def get(self):
		self.remove_cookie('user_id')
		self.redirect("/wiki/")

class MainWiki(Handler):

	def get(self):
		self.redirect('/wiki/home')

class Wikipage(Handler):
	def get(self, page):
		uri_id = page.split('/')[2]
		p = db.GqlQuery('SELECT * FROM WikiData WHERE pageUri=:1 ORDER BY lastModified DESC LIMIT 1000', uri_id)
		p = list(p)

		if not p:
			self.error(302)
			self.redirect('/wiki/_edit/'+uri_id)
		else:
			if not self.user:
				self.render('wikipage.html', post=p[0], pageUri=uri_id)
			else:
				ver = self.request.get('v')
				if ver:
					postnum = int(ver)-1
					post = p[postnum]
					self.render('wikipage.html', post=post, pageUri=uri_id)
				else:
					self.render('wikipage.html', post=p[0], pageUri=uri_id)



class EditPage(Handler):
	def render_edit(self, content=""):
		self.render('edit.html', content=content)

	def get(self, page):
		if not self.user:
			self.redirect('/wiki/login')
		else:
			c = db.GqlQuery('SELECT * FROM WikiData WHERE pageUri=:1 ORDER BY lastModified DESC LIMIT 1000', page)
			c = list(c)

			if not c:
				self.render_edit()
			else:
				self.render_edit(c.get().pageContent)

	def post(self, uri_id):
		if not self.user:
			self.redirect('/wiki/login')
		else:
			content = self.request.get("content")
			if content:
				wp = WikiData(pageUri=uri_id, pageContent=content)
				wp.put()
				self.redirect('/wiki/'+uri_id)

class HistoryPage(Handler):
	def get(self, page_uri):
		content = db.GqlQuery('SELECT * FROM WikiData WHERE pageUri=:1 ORDER BY lastModified DESC', page_uri)
		c = content.fetch(1000)
		if not c:
			self.redirect('/wiki/'+page_uri)
		else:
			self.render('history.html', posts=c)


app = webapp2.WSGIApplication([ ('/wiki/?', MainWiki),
								('/wiki/signup', Signup),
								('/wiki/login', Login),
								('/wiki/logout', Logout),
								('/wiki/_edit/(.+)', EditPage),
								('/wiki/_history/(.+)', HistoryPage),
								(PAGE_RE, Wikipage)
								],
								debug=True)
