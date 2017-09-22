

import webapp2, os, jinja2, time, hashlib, random, re, hmac, json, logging
from google.appengine.ext import db
from string import letters


SECRET = 'mADnaXoaj'

template_dir = os.path.join(os.path.dirname(__file__) ,'html')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def datetimeformat(value, format="%B %d, %Y %I:%M"):
    return value.strftime(format)
def increment(value):
    return value+1
def decrement(value):
    return value-1

jinja_env.filters['datetimeformat'] = datetimeformat
jinja_env.filters['increment'] = increment
jinja_env.filters['decrement'] = decrement

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def make_salt() :
	return "".join(random.choice(letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (h, salt)

def valid_pw(name, password, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, password, salt)


def make_secure_val(val):
	return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def valid_username(username):
	return USER_RE.match(username)

def valid_password(password):
	return PASS_RE.match(password)

def same_password(password, verify):
	return (password == verify)

def valid_email(email):
	if email:
		return EMAIL_RE.match(email)
	else:
		return True


### databases
class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	author = db.StringProperty(required = True)
	permalink = db.StringProperty(required = True)

	def as_dict(self):
		time_fmt = '%c'
		d = {'subject': self.subject,
			 'content': self.content,
			 'created': self.created.strftime(time_fmt)}
		return d

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty(required = False)



### main handler
class Handler(webapp2.RequestHandler) :
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def render_json(self, d):
		json_txt = json.dumps(d)
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		self.write(json_txt)		

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			str('%s=%s; Path=/' % (name, cookie_val)))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		if cookie_val and check_secure_val(cookie_val):
			return cookie_val.split("|")[0]

	def read_cookie_data(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val.split("|")[0]

	def user(self) :
		return self.read_cookie_data("user")

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)

		if self.request.url.endswith('.json'):
			self.format = 'json'
		else:
			self.format = 'html'



### page handlers
class MainPage(Handler):
	def render_front(self, logged_in=False, name=False):
		posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
		if self.format == 'html':
			self.render("front.html", logged_in=logged_in, posts=posts, name=name)
		else:
			return self.render_json([p.as_dict() for p in posts])		

	def get(self):
		if self.read_secure_cookie("user"):
			self.render_front(True, self.user())
		else:
			self.render_front()

		

class NewPost(Handler):
	def render_front(self, subject="", content="", error=""):
		self.render("newpost.html", subject=subject, content=content, error=error, name=self.user())

	def get(self):
		if self.read_secure_cookie("user"):
			self.render_front()
		else:
			self.redirect('/login')

	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")

		if subject and content:
			date = time.localtime()
			entity_name = time.strftime("%y/%m/%d/")
			entity_name += subject[:4].replace(" ", "_")
			entity_name += "_"			
			entity_name += subject[-4:].replace(" ", "_")

			a = Post(subject = subject, content = content, author = self.user(), 
				key_name = entity_name, permalink = entity_name)
			a.put()						
			
			self.redirect("/post/%s" %entity_name)			
		else:
			error = "we need a subject and some content!"
			self.render_front(subject, content, error)



class Permalink(Handler):

	def get(self, post_id):
		if self.format == 'html':					
			post = Post.get_by_key_name(post_id)		
			if self.read_secure_cookie("user"):			
				self.render("success.html", post = post, logged_in = True, name=self.user())
			else:				
				self.render("success.html", post = post, logged_in = False)	
		else:
			post_id = post_id[:-5]
			post = Post.get_by_key_name(post_id)
			self.render_json(post.as_dict())


class SignUp(Handler):

	def render_form(self, username="", email="", error_user="", error_pass="", error_verify="", error_email="") :
		self.render("signup.html", username=username, error_user=error_user, error_pass=error_pass,error_verify=error_verify, email=email, error_email=error_email)

	def get(self):
		self.render_form()

	def post(self):
		username_var = self.request.get("username")
		password_var = self.request.get("password")
		verify_var = self.request.get("verify")
		email_var = self.request.get("email")

		username  = valid_username(username_var)
		password  = valid_password(password_var)
		verify  = same_password(password_var, verify_var)
		email  = valid_email(email_var)

		if not username :
			self.render_form(username= username_var, email= email_var, error_user = "Username is not correct.")
		elif not password :	
			self.render_form(username= username_var, email= email_var, error_pass = "Password is not correct.")
		elif not verify :	
			self.render_form(username= username_var, email= email_var, error_verify = "Password do not match.")
		elif not email :	
			self.render_form(username= username_var, email= email_var, error_email = "Email is not correct.")
		else:

			users = db.GqlQuery("SELECT * FROM User")
			for user in users:
				if username_var == user.username :
					self.render_form(username= username_var, email= email_var, error_user = "Username exists")
					break			
			else:
				secure_pass = make_pw_hash(username_var, password_var)
				a = User(username = username_var, password = secure_pass, email = email_var)
				a.put()

				self.set_secure_cookie("user", username_var)
				self.redirect('/')


class LogIn(Handler):
	def render_form(self, username="", error_user="", error_pass="", error_verify="") :
		self.render("login.html", username=username, error_user=error_user, error_pass=error_pass)

	def get(self):
		self.render_form()

	def post(self):
		username_var = self.request.get("username")
		password_var = self.request.get("password")

		if not username_var :
			self.render_form(username= username_var, error_user = "enter username")
		elif not password_var :	
			self.render_form(username= username_var, error_pass = "enter password")

		else:
			users = db.GqlQuery("SELECT * FROM User")
			for user in users:		
				if username_var == user.username :
					if valid_pw(username_var, password_var, user.password) :
						self.set_secure_cookie("user", username_var)
						self.redirect('/')						
			else:
				self.render_form(username= username_var, error_pass = "wrong username/password")

class LogOut(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'text/plain'
		self.response.headers.add_header('Set-Cookie', 'user=')
		self.response.delete_cookie("user")
		self.redirect("/")



class UserPage(Handler):
	def render_front(self, author, logged_in=False, name=False):
		if self.format == 'html':
			posts = db.GqlQuery("SELECT * FROM Post WHERE author = :1 ORDER BY created DESC LIMIT 10", author)
			self.render("userpage.html", posts=posts, name=name, author=author, logged_in=logged_in)
		else:
			author = author[:-5]
			posts = db.GqlQuery("SELECT * FROM Post WHERE author = :1 ORDER BY created DESC LIMIT 10", author)
			return self.render_json([p.as_dict() for p in posts])		

	def get(self, author):
		if author.endswith('/'):
			author = author[:-1]
		if self.read_secure_cookie("user"):
			self.render_front(author, True, self.user())
		else:
			self.render_front(author) 



app = webapp2.WSGIApplication([('/?(?:.json)?', MainPage),
	('/newpost/?', NewPost),
	('/post/(.+)(?:.json)?', Permalink),
	('/signup/?', SignUp),	
	('/login/?', LogIn),
	('/logout/?', LogOut),
	('/user/(.+)(?:.json)?', UserPage)	
	], debug = True)