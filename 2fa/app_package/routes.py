from app_package import app, db, bcrypt
from app_package.models import User
from flask import (redirect, render_template, url_for, request, session, abort,flash)
from flask_login import login_user,logout_user,current_user
import base64,os
from app_package.forms import RegisterForm, LoginForm
import secrets
import pyqrcode,pyotp
from io import BytesIO

@app.route("/")
def home():
	return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
	form = RegisterForm()
	if form.validate_on_submit():
		username = form.username.data
		email = form.email.data
		password = form.password.data
		hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
		secret_token = pyotp.random_base32()
		user = User(username=form.username.data, email=form.email.data, password=hashed_password,secret_token=secret_token)
		db.session.add(user)
		db.session.commit()
		user = User.query.filter_by(username=form.username.data).first()
		session['username'] = user.username
		return redirect(url_for("two_factor_setup"))
	return render_template("register.html",form=form)
	
@app.route('/twofactor',methods=['GET',"POST"])
def two_factor_setup():

    if current_user.is_authenticated:
        user = User.query.filter_by(username=current_user.username).first()
        token = user.secret_token
    else:
        if 'username' not in session:
            return redirect(url_for('home'))
        user = User.query.filter_by(username=session['username']).first()
        token = user.secret_token
        if user is None:
            return redirect(url_for('home'))
        if request.method=="POST":
            user = User.query.filter_by(username=session['username']).first()
            token = request.form.get('token')
            if user.verify_totp(token):
                del session['username']
                flash('Account created successfully')
                return redirect(url_for('login'))
            else:
                flash("Invalid token",'danger')
                return redirect(url_for('two_factor_setup'))


    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('2fa.html',token=token), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if current_user.is_authenticated:
        user = User.query.filter_by(username=current_user.username).first()
        url = pyqrcode.create(user.get_totp())
    else:
        if 'username' not in session:
            abort(404)
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            abort(404)

        # for added security, remove username from session

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/login',methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and user.verify_totp(form.secret_key.data):

            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email or password or token','danger')

        return render_template('login.html', title='Login', form=form)
    return render_template("login.html", form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash("Logged out successfully!!","info")
    return redirect(url_for("login"))
