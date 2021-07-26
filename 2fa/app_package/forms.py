from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email, Length ,ValidationError
from app_package.models import User
import pyotp

class RegisterForm(FlaskForm):
	username = StringField("username",
		validators=[DataRequired(),Length(max=20)])
	email = StringField("Email",
		validators=[DataRequired(),Email()])
	password = PasswordField("Password", 
		validators=[DataRequired(),Length(min=8, max=16)])
	confirm_password = PasswordField("Confirm Password", 
		validators=[DataRequired(), EqualTo('password', message="Passwords must match")])
	submit = SubmitField("Submit")

	def validate_username(self,username):
		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError("Username already taken")

	def validate_email(self,email):
		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError("email already taken")

class LoginForm(FlaskForm):
	email = StringField("Email",
		validators=[DataRequired(),Email()])
	password = PasswordField("Password", 
		validators=[DataRequired(),Length(min=8, max=16)])
	secret_key = StringField("Token",
		validators=[DataRequired()])
	submit = SubmitField("Login")

		
	
