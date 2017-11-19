from app import db
from datetime import datetime

class User(db.Model):
	__tablename__ = 'user'

	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String, unique=True)
	fullname = db.Column(db.String, nullable=True)   
	password = db.Column(db.String) 
	email = db.Column(db.String,  nullable=True, unique=True)       

	def __repr__(self):
		return '<User %r>' % (self.username)

class Post(db.Model):
	__tablename__ = 'post'

	id = db.Column(db.Integer, primary_key=True)
	subject = db.Column(db.String)
	content = db.Column(db.String)
	time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	author = db.Column(db.String)

	def __repr__(self):
		return '<Post %r>' % (self.subject)

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

