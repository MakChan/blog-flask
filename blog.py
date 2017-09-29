from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import random, re, hashlib, os
from string import letters

app = Flask(__name__)
app.debug = True

if os.environ.get('DATABASE_URL') is None:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String, unique=True)
    fullname = db.Column(db.String, nullable=True)   
    password = db.Column(db.String) 
    email = db.Column(db.String,  nullable=True, unique=True)       


class Post(db.Model):
    __tablename__ = 'post'

    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String)
    content = db.Column(db.String)
    time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    author = db.Column(db.String)


    # We added this serialize function to be able to send JSON objects in a
    # serializable format
    @property
    def serialize(self):

        return {
            'subject': self.subject,
            'content': self.content,
            'author': self.author,
            'time': self.time,
        } 
db.create_all()
SECRET = 'mADnaXoaj'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def make_salt() :
	return "".join(random.choice(letters) for x in xrange(5))

def make_pw_hash(password, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(password + salt).hexdigest()
	return "%s|%s" % (h, salt)

def valid_pw(password, hash):
	salt = hash.split('|')[1]
	return hash == make_pw_hash(password, salt)


def make_secure_val(val):
	return '%s|%s' % (val, hashlib.sha256(SECRET + val).hexdigest())

def check_secure_val(val):
	var = val.split('|')[0]
	if val == make_secure_val(var):
		return var


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

def loggedIn():
	logged_in = False
	cookie = request.cookies.get('user_id')
	if cookie:
		if check_secure_val(cookie):
			logged_in = True
	return logged_in

def loggedUser():
	user = None
	cookie = request.cookies.get('user_id')
	if cookie:
		cookie_value = check_secure_val(cookie)
		if cookie_value:
			user = User.query.filter_by(id = cookie_value).one()
	return user

@app.route('/')
@app.route('/page/<int:page>/')
def frontPage(page = 1):
	logged_in = loggedIn()
	user = loggedUser()
	posts = Post.query.order_by(Post.time.desc()).paginate(page, 8, False)
	if logged_in:		
		return render_template(
			'front.html', posts=posts, logged_in=logged_in, user=user)
	else:
		 return render_template(
			'front.html', posts=posts, logged_in=logged_in)       

@app.route('/JSON/')
@app.route('/JSON/<int:page>/')
def frontPageJSON( page = 1):
	posts = Post.query.order_by(Post.time.desc()).paginate(page, 10, False).items
	return jsonify([i.serialize for i in posts])      


@app.route('/newpost/', methods=['GET', 'POST'])
def newPost():
	logged_in = loggedIn()
	user = loggedUser()
	if logged_in:
		if request.method == 'POST':
			newPost = Post(subject=request.form['subject'], content=request.form[
							   'content'], author=user.username)
			db.session.add(newPost)            
			db.session.commit()
			response = redirect(url_for('singlePost', post_id=newPost.id))
			return response
		else:
			return render_template('newpost.html', logged_in=logged_in, user=user)
	else:
		return redirect('/login')


@app.route('/post/<int:post_id>/')
def singlePost(post_id):
	logged_in = loggedIn()
	user = loggedUser()
	post = Post.query.filter_by(id = post_id).one()
	if logged_in:     
		return render_template(
			'success.html', post=post, logged_in=logged_in, user=user)
	else:
		return render_template(
			'success.html', post=post, logged_in=logged_in)


@app.route('/signup/', methods=['GET', 'POST'])
def signUp():
	logged_in = loggedIn()
	user = loggedUser()
	if logged_in:
		return redirect('/')
	else:
		if request.method == 'POST':         
			name_var = request.form['fullname']
			username_var = request.form['username']
			password_var = request.form['password']
			verify_var = request.form['verify']
			email_var = request.form['email']

			username  = valid_username(username_var)
			password  = valid_password(password_var)
			verify  = same_password(password_var, verify_var)
			email  = valid_email(email_var)

			if not name_var :
				return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_name = "Enter Name")
			if not username :
				return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_user = "Username is not correct.")
			elif not password : 
				return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_pass = "Password is not correct.")
			elif not verify :   
				return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_verify = "Password do not match.")
			elif not email :    
				return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_email = "Email is not correct.")
			else:

				if User.query.filter_by(username=username_var).all() != []:
					return render_template('signup.html', fullname = name_var, username= username_var, email= email_var, error_user = "Username exists")
								  
				else:
					secure_pass = make_pw_hash(password_var)                    
					newUser = User(username = username_var, fullname = name_var, password = secure_pass, email = email_var)
					db.session.add(newUser)					
					db.session.commit()
					cookie_val = make_secure_val(str(newUser.id))
					response = redirect("/")
					response.set_cookie('user_id', cookie_val)
					return response


		else:
			return render_template('signup.html', error_name="", error_user="", error_pass="", error_verify="", error_email="")




@app.route('/login/', methods=['GET', 'POST'])
def signIn():
	logged_in = loggedIn()
	user = loggedUser()
	if logged_in:
		return redirect('/')
	else:
		if request.method == 'POST':         

			username_var = request.form['username']
			password_var = request.form['password']

			if not username_var :
				return render_template('login.html', username= username_var, error_user = "enter username")
			elif not password_var : 
				return render_template('login.html', username= username_var, error_pass = "enter password")

			else:
				user = User.query.filter_by(username=username_var).one()
				if  not user:
					return render_template('login.html', error_user = "Username not exists")
								  
				else:
					if valid_pw(password_var, user.password):             
						cookie_val = make_secure_val(str(user.id))

						response = redirect("/")
						response.set_cookie('user_id', cookie_val)
						return response
					else:
						return render_template('login.html', error_pass = "wrong pass")

		else:
			return render_template('login.html', error_user ="", error_pass ="")

@app.route('/logout/')        
def LogOut():
	response = redirect("/")
	response.set_cookie('user_id', "", expires=0)
	logged_in = False
	user_id = None       
	return response



@app.route('/user/<string:username>/')
@app.route('/user/<string:username>/<int:page>/')
def userPage(username, page=1):
	logged_in = loggedIn()
	user = loggedUser()
	posts = Post.query.filter_by(author = username).order_by(Post.time.desc()).paginate(page, 8, False)
	person = User.query.filter_by(username = username).one()	
	if logged_in:     
		return render_template(
			'userpage.html', posts=posts, logged_in=logged_in, user=user, person=person)
	else:
		return render_template(
			'userpage.html', posts=posts, logged_in=logged_in, person=person)

if __name__ == '__main__':
	app.secret_key = 'super_secret_key'
	app.run(debug=True)