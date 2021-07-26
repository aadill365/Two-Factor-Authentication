from app_package import db,login_manager,admin
from flask_login import UserMixin
import pyotp
from flask_admin.contrib.sqla import ModelView
from flask_admin import BaseView,expose
from flask_login import current_user
from flask import redirect,url_for,abort

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))


class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(20), unique=True, nullable=False)
	email = db.Column(db.String(30), unique=True, nullable=False)
	password = db.Column(db.String(60), nullable=False)
	secret_token = db.Column(db.String(60), nullable=False)
	is_admin = db.Column(db.Boolean,default=False)
	
	def get_totp(self):
		prov = pyotp.totp.TOTP(self.secret_token).provisioning_uri(name=self.username,issuer_name="Koseeke")
		return prov

	def verify_totp(self,token):
			totp = pyotp.TOTP(self.secret_token)
			return totp.verify(token)	

	def __repr__(self):
		return f"User('{self.username}', '{self.email}')"
		
class Controller(ModelView):
	def is_accessible(self):
		if current_user.is_authenticated:
			if current_user.is_admin==True:
				return current_user.is_authenticated
			else:
				abort(404)
		else:
			abort(404)
	def inacessible_callback(self):
		return redirect(url_for('login'))

class Chart(BaseView):
	@expose('/')
	def index(self):
		users = User.query.all()
		admin=[]
		local=[]
		for user in users:
			if user.is_admin==True:
				admin.append(user)
			else:
				local.append(user)
		data=[len(admin),len(local)]
		labels=['admin','local user']
		bg=["red","green"]


		return self.render('admin/chart.html',data=data,labels=labels,bg=bg)


admin.add_view(Controller(User,db.session))
admin.add_view(Chart(name='Charts',endpoint='charts'))


