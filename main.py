#!/usr/bin/env python

####################car rental website############################################################

import string
import hmac
import hashlib
import os
import jinja2
import webapp2
import re
from google.appengine.ext import db
from google.appengine.api import memcache
import datetime
from datetime import date
from datetime import timedelta



#initializing template variables
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader= jinja2.FileSystemLoader(template_dir),
							   autoescape = True)


##################Utils################################################################################
#Handler Class
#Handles HTML Responses using jinja2.  All other classes will inherit this for writing HTML via a template
#Place html templates in the 'templates' directory of the project.
class Handler(webapp2.RequestHandler):
	#this method can be called for basic writing of non template strings
	def write(self, *a, **kw ):
		self.response.write(*a, **kw)

	#this is a method to create the template string for writing
	def render_str(self, template, **params ):
		t = jinja_env.get_template(template)
		return t.render(params)

	#this method is used to create and write a template string
	def render(self, template, **kw ):
		self.write(self.render_str(template, **kw))


#Utilities for hashing cookies and passwords
class CookieHashUtils(webapp2.RequestHandler):
	def hash_str(self,st):
		return hmac.new('ateam',st,digestmod=hashlib.sha256).hexdigest()

	def mk_cookie(self,val):
		hash_val = self.hash_str(val)
		return '%s|%s' %(val, hash_val)

	def valid_cookie(self,hashed_cookie):
		vals = hashed_cookie.split('|')
		if self.hash_str(vals[0]) == vals[1]:
			return vals[0]
		else:
			return None

	def mk_salt(self):
		return os.urandom(32).encode('hex')

	def hash_salt_str(self,st,salt):
		return hmac.new(salt,st,digestmod=hashlib.sha256).hexdigest()

	def mk_hashed_password(self,username,password):
		salt = self.mk_salt()
		userpass = username+password
		hash_val = self.hash_salt_str(userpass,salt)
		return '%s|%s' %(salt,hash_val)

	def valid_hash_password(self,username,password,hashed_pass):
		vals = hashed_pass.split('|')
		userpass = username + password
		test_case = self.hash_salt_str(userpass,vals[0].encode('ascii'))  #need to re-encode incase database stores string as unicode
		if test_case == vals[1]:
			return password
		else:
			return None

	#looks up and returns a user account based on the user cookie
	def lookup_account(self):
		#request cookie from browser
		user_cookie = self.request.cookies.get('user',None)

		#if no cookie is set then return none
		if not user_cookie or user_cookie == 'None':
			return None

		else:
			#validate cookie
			user_id = self.valid_cookie(user_cookie)
			if not user_id or user_id == 'None':
				return None
			
			else:
				#lookup account by ID(high consistency compared to sql query, so this should not fail)
				user_id = int(user_id)
				return Accounts.get_by_id(user_id)
	
	def lookup_dates(self):
		#request cookies from browser
		checkin_cookie = self.request.cookies.get('checkin',None)
		checkout_cookie = self.request.cookies.get('checkout',None)

		#if no cookie is set then set a default date
		if not checkin_cookie or checkin_cookie=='None':
			return None
		
		if not checkout_cookie or checkout_cookie=='None':
			return None			

		else:
			#validate cookies
			checkin = self.valid_cookie(checkin_cookie)
			if checkin:
				checkin = checkin.split('-')
				checkin = datetime.date(int(checkin[0]),int(checkin[1]),int(checkin[2]))
			else:
				return None				
				
			checkout = self.valid_cookie(checkout_cookie)
			if checkout:
				checkout = checkout.split('-')
				checkout = datetime.date(int(checkout[0]),int(checkout[1]),int(checkout[2]))
			else:
				return None
				
			return {'checkin': checkin,'checkout': checkout}
	
	def lookup_type(self):
		type_cookie = self.request.cookies.get('car_type',None)
		if (not type_cookie) or type_cookie=='None':
			return None
		else:
			car_type = self.valid_cookie(type_cookie)
			if not car_type:
				return None
			else:
				return car_type
	
	#sets the date cookies for the customer's checkin and checkout		
	def get_datecookie_from_form(self):
		checkin = self.request.get('checkin')
		checkout = self.request.get('checkout')
		
		if not (checkin and checkout) or (checkin == '' and checkout == ''):
			return None		
		
		checkin = checkin.split('/')
		checkout = checkout.split('/')
		
		#need to include try catch block later to catch invalid date erros
		
		if not len(checkin) == 3:
			return None
		
		else:		
			checkin = datetime.date(int(checkin[2]),int(checkin[0]),int(checkin[1]))
			checkout = datetime.date(int(checkout[2]),int(checkout[0]),int(checkout[1]))
			
			if checkin == checkout:
				checkout = checkout + timedelta(days=1)
			
			checkin_cookie = self.mk_cookie(str(checkin))
			checkout_cookie = self.mk_cookie(str(checkout))		
		
			return {'checkin_cookie':checkin_cookie,'checkout_cookie':checkout_cookie}	



#Utilities for verifying create account input
class VerifyUtils():
	#regular expression used to check validity of usernmae, pass, email
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	NAME_RE = re.compile(r"^[a-zA-Z-]{1,50}$")
	PASSWORD_RE = re.compile(r"^.{3,20}$")
	EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

	#check validity of username and password and emaill using comiled regular expressions
	def valid_name(self, st):
		return self.NAME_RE.match(st)

	def valid_username(self, st):
		st = st.lower()
		if Accounts.all().count(1):  #needed to make sure the query below doesn't crash on an empty database
			exists = db.GqlQuery('SELECT * FROM Accounts WHERE username = :1', st)
			if exists.get():
				return 'exists'
		if self.USER_RE.match(st):
			return 'valid'
		else:
			return 'invalid'

	def valid_password(self, st):
		return self.PASSWORD_RE.match(st)

	def valid_email(self, st):
		st = st.lower()
		if Accounts.all().count(1):
			exists = db.GqlQuery('SELECT * FROM Accounts WHERE email = :1', st)
			if exists.get():
				return 'exists'
		if self.EMAIL_RE.match(st):
			return 'valid'
		else:
			return 'invalid'

	#compare password to verify
	def valid_verify(self,st1,st2):
		if st1 == st2:
			return True
		return False



#Defines and validates hard-coded admins
#NOTE: usernames defined here will automatically be made admin when account is CREATED
#usefull for creating a user or set of users with initial admin priveledges to set up the website
class AdminList():
	def validate_admin(self, user):
		admins = ['jdude801']   #CAUTION: usernames added to this list will have admin when account is created
		if user in admins:      #be sure to immediately create accounts in the above list to ensure access security
			return 'admin'
		else:
			return None
			

#Utility for getting the list of available cars to rent from the database
#Uses memcahce to both check for and store the result	
class AvailableCarsUtils(webapp2.RequestHandler):
	def get_available_cars(self,checkin,checkout):
		#check if reservation is not empty before querying
		if not Reservations.all().count(1):
			reservations = None
		
		else:
			#query for the reservations booked that conflict with the schedule
			res_query1 = db.GqlQuery('SELECT * FROM Reservations WHERE checkout > :1',checkin)
			res_query2 = db.GqlQuery('SELECT * FROM Reservations WHERE checkin < :1',checkout)
			results1 = list(res_query1)
			results2 = list(res_query2)
			#need to find intersection, not union
			reservations = self.intersection(results1, results2)
			
		#get a list of all the cars
		car_query = db.GqlQuery('SELECT * FROM Cars')
		carlist = list(car_query)
		
		#Initialize the in_stock variables
		sporty_instock = False
		economy_instock = False
		luxury_instock = False
		avail_cars = []	
		
		
		
		#get available cars:
		if reservations:			
			for car in carlist:
				if sporty_instock and economy_instock and luxury_instock:
					break
				
				car_booked = False
				for booking in reservations:
					if booking.car_id == car.car_id:
						car_booked=True
						
				if not car_booked:
					avail_cars.append(car)
					if car.car_type == 'Sporty':
						sporty_instock = True
					elif car.car_type == 'Economy':
						economy_instock = True
					elif car.car_type == 'Luxury':
						luxury_instock = True
		else:
			for car in carlist:
				if sporty_instock and economy_instock and luxury_instock:
					break					
			
				avail_cars.append(car)
				if car.car_type == 'Sporty':
					sporty_instock = True
				elif car.car_type == 'Economy':
					economy_instock = True
				elif car.car_type == 'Luxury':
					luxury_instock = True
				
		#return tuple with list of cars and types available
		return {'cars':avail_cars,'sporty':sporty_instock,
					'economy':economy_instock,'luxury':luxury_instock}
	
	def intersection(self,a,b):
		a = sorted(a, key = lambda reservation: reservation.res_id)
		b = sorted(b, key = lambda reservation: reservation.res_id)
		result = []
		while(len(a)>0 and len(b)>0):
			if a[0].res_id == b[0].res_id:
				result.append(a[0])
				a.pop(0)
				b.pop(0)
			elif a[0].res_id < b[0].res_id:
				a.pop(0)
			else:
				b.pop(0)
		if len(result) > 0:					
			return result
		else:
			 return None

class ReservationUtils():
	def delete_reservation(self,reservation_id):
		reservation = Reservations.get_by_id(reservation_id)
		user = Accounts.get_by_id(reservation.acc_id)
		try:
			user.reservations.remove(reservation_id)
		except ValueError:
			pass
		user.put()
		car = Cars.get_by_id(reservation.car_id)
		try:
			car.reservations.remove(reservation_id)
		except ValueError:
			pass
		car.put()
		reservation.delete()

####################################Database Models######################################
#Accounts Database
class Accounts(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	firstname = db.StringProperty(required = True)
	lastname = db.StringProperty(required = True)
	email = db.StringProperty(required = True)
	reservations = db.ListProperty(int)
	admin = db.BooleanProperty(default = False)
	created = db.DateTimeProperty(auto_now_add=True)
	acc_id = db.IntegerProperty()

class Cars(db.Model):
	car_type = db.StringProperty(required = True)
	car_make = db.StringProperty(required = True)
	car_model = db.StringProperty(required = True)
	car_seats = db.IntegerProperty(required = True)
	car_mpg = db.IntegerProperty(required = True)
	reservations = db.ListProperty(int)
	car_id = db.IntegerProperty()
	#available = db.BooleanProperty(required = True)

class Reservations(db.Model):
	res_id = db.IntegerProperty()
	car_id = db.IntegerProperty(required=True)
	acc_id = db.IntegerProperty(required=True)
	checkin= db.DateProperty(required=True)
	checkout = db.DateProperty(required=True)

########################################Page Handlers#####################################

#Home-Page handler
class HomePageHandler(Handler,CookieHashUtils):
	def get(self):
		account = self.lookup_account()
		
		admin = False
		if account and account.admin:
			admin = True
			
		self.render('homepage.html',admin=admin)

	def post(self):
		date_cookies = self.get_datecookie_from_form()
		if not date_cookies:
			self.redirect('browse')
		else:
			checkin_cookie = date_cookies['checkin_cookie']
			checkout_cookie = date_cookies['checkout_cookie']
			
			self.response.headers.add_header('Set-Cookie', 'checkin=%s' % checkin_cookie)
			self.response.headers.add_header('Set-Cookie', 'checkout=%s' % checkout_cookie)
			self.redirect('/browse')
		


#sign-up page handler
class SignupHandler(Handler, VerifyUtils, CookieHashUtils, AdminList):
	def get(self):
		self.render('signup.html')
	def post(self ):
		#get form data
		first = self.request.get('first')
		last = self.request.get('last')
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')

		#validate input
		v_first = self.valid_name(first)
		v_last = self.valid_name(last)
		v_username=self.valid_username(username)
		v_password=self.valid_password(password)
		v_verify=True
		if v_password:
			v_verify=self.valid_verify(password,verify)
		v_email = self.valid_email(email)

		#set errors to blank
		f_err = l_err = u_err = p_err = v_err = e_err = ''

		#Account creation process on success
		if v_first and v_last and v_password and v_verify and v_email=='valid' and v_username=='valid':
			#convert username and email to lowercase(needed for uniqueness testing)
			username = username.lower()
			email = email.lower()

			#hash the password
			hashed_pw = self.mk_hashed_password(username,password)

			#check if this admin was hard-added:
			admin = self.validate_admin(username)
			if admin:
				account = Accounts(username=username,password=hashed_pw,firstname=first,lastname=last,email=email,admin=True)
			else:
				account = Accounts(username=username,password=hashed_pw,firstname=first,lastname=last,email=email)

			#add accounts to database
			key = account.put()
			account.acc_id = key.id()
			account.put()

			#set logged-in cookie
			account_id = account.acc_id
			user_cookie = self.mk_cookie(str(account_id))
			self.response.headers.add_header('Set-Cookie', 'user=%s' %user_cookie)
			self.redirect('/welcome') #redirect to welcome page on success

		else:  #determine which errors to display
			if not v_first:
				f_err = 'Not a valid first name.'
			if not v_last:
				l_err = 'Not a valid last name.'
			if v_username=='invalid':
				u_err = "Invalid username."
			elif v_username=='exists':
				u_err = "This username has been taken"
			if not v_password:
				p_err = "Invalid password choice."
				password = ''
				verify = ''
			if not v_verify:
				v_err = "Passwords do not match."
				password = ''
				verify = ''
			if v_email=='invalid':
				e_err = "Invalid email address."
			elif v_email == 'exists':
				e_err = 'This email has already been registered.'

			#display error msgs
			self.render('signup.html',first=first,last=last,username=username,password=password,
						verify=verify,email=email,f_err=f_err,l_err=l_err,u_err=u_err,
						p_err=p_err,v_err=v_err,e_err=e_err)



#Welcome page handler
class WelcomeHandler(Handler, CookieHashUtils):
	def get(self):
		account = self.lookup_account()
		
		admin = False
		if account and account.admin:
			admin = True	

		#display a message if account was found
		if account:
			self.render('/welcome.html',account=account,admin=admin)

		#if account doesn't exist then redirect to homepage
		else:
			self.redirect('/')


#display the signin form
class SigninHandler(Handler,CookieHashUtils):
	def get(self):
		self.render('signin.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		if username and password:
			#set username to lowercase for database matching
			username = username.lower()

			#query database and get 1st result
			account = db.GqlQuery('SELECT * FROM Accounts WHERE username = :1', username)
			account = account.get()

			#if query fails then display error
			if not account:
				p_err='User not found.'
				self.render('signin.html',username=username,p_err=p_err)

			else:
				#check if password is correct
				pass_hash = account.password
				password = self.valid_hash_password(username,password,pass_hash)

				#display error on invalid password
				if not password:
					p_err = 'Invalid Username or Password.'
					self.render('signin.html',username=username,p_err=p_err)

				#set cookie to user_id and redirect to welcome page
				else:
					user_id = account.acc_id
					user_id = str(user_id)
					user_id = self.mk_cookie(user_id)
					self.response.headers.add_header('Set-Cookie','user=%s' %user_id)
					self.redirect('/welcome')
		else:
			p_err='Invalid Username or Password.'
			self.render('signin.html',username=username,p_err=p_err)


#Logs-out the user when this page is visisted
class LogoutHandler(Handler):
	def get(self):
		self.request.cookies.get('user',None)
		user = None
		self.response.headers.add_header('Set-Cookie', 'user=%s' %user)
		self.redirect('/')



#shows all the users accounts registered on the website
#only users with admin priveledges will be able to see this page
#non-admins will be redirected to homepage
class ShowAllAccountsHandler(Handler,CookieHashUtils,ReservationUtils):
	def get(self):
		account = self.lookup_account()
		
		admin = False
		#list user accounts if exists and admin
		if account and account.admin:
			admin = True
			query = db.GqlQuery('SELECT * FROM Accounts')
			all_accounts = list(query)
			res_dict = {}
			car_dict = {}
			for acct in all_accounts:
				if len(acct.reservations) > 0:
					for res in acct.reservations:
						reservation = Reservations.get_by_id(res)
						res_dict[res] = reservation
						car = Cars.get_by_id(reservation.car_id)
						car_dict[res] = car
			self.render('showallaccounts.html',all_accounts=all_accounts,res_dict=res_dict,car_dict=car_dict,admin=admin)

		#redirect to hompage if account doesn't exist or is not admin
		else:
			self.redirect('/')
			
	def post(self ):
		account = self.lookup_account()
		
		admin=False	
		if account and account.admin:
			admin = True
			
			account_id = self.request.get('account_id')
			admin_button = self.request.get('make_admin')
			delete_button = self.request.get('delete')
			user_account = Accounts.get_by_id(int(account_id))

			if admin_button:
				if not user_account.admin:
					user_account.admin = True
					user_account.put()
					#the below is done to increase consistency (simply redirecting may have inconsistent results)
					#may have to implement strongly consistent approach
					query = db.GqlQuery('SELECT * FROM Accounts')
					all_accounts = list(query)
					for entry in all_accounts:
						if entry.acc_id == int(account_id):
							entry.admin = True
							break
					res_dict = {}
					car_dict = {}
					for acct in all_accounts:
						if len(acct.reservations) > 0:
							for res in acct.reservations:
								reservation = Reservations.get_by_id(res)
								res_dict[res] = reservation
								car = Cars.get_by_id(reservation.car_id)
								car_dict[res] = car
					self.render('showallaccounts.html',all_accounts=all_accounts,res_dict=res_dict,car_dict=car_dict,admin=admin)
				else:
					self.redirect('/user-accounts')


			if delete_button:
				if user_account:
					for res in user_account.reservations:
						self.delete_reservation(res)						
					user_account.delete()
					#the below is done to increase consistency (simply redirecting may have inconsistent results)
					#may have to implement the strongly consistent approach
					query = db.GqlQuery('SELECT * FROM Accounts')
					all_accounts = list(query)
					for entry in all_accounts:
						if entry.acc_id == int(account_id):
							all_accounts.remove(entry)
							break
					res_dict = {}
					car_dict = {}
					for acct in all_accounts:
						if len(acct.reservations) > 0:
							for res in acct.reservations:
								reservation = Reservations.get_by_id(res)
								res_dict[res] = reservation
								car = Cars.get_by_id(reservation.car_id)
								car_dict[res] = car
					self.render('showallaccounts.html',all_accounts=all_accounts,res_dict=res_dict,car_dict=car_dict,admin=admin)
				else:
					self.redirect('/user-accounts')
		else:
			self.redirect('/')


#Shows information about a user's account
#will expand later to link to another page to edit certain account information
class ShowAccountHandler(Handler,CookieHashUtils,ReservationUtils):
	def get(self):
		account = self.lookup_account()		
		
		#show details about the account
		if account:
			admin = False
			if account and account.admin:
				admin = True
				
			res_dict = {}
			car_dict = {}
			for res in account.reservations:
				reservation = Reservations.get_by_id(res)
				res_dict[res] = reservation
				car = Cars.get_by_id(reservation.car_id)
				car_dict[res] = car
			self.render('showaccount.html',account=account,admin=admin,res_dict=res_dict,car_dict=car_dict)

		#redirect to hompage if account doesn't exist
		else:
			self.redirect('/signin')
	
	def post(self):
		account = self.lookup_account()
		if account:
			delete_button = self.request.get('delete')
			res_id = self.request.get('res_id')
			
			if delete_button:
				reservation = Reservations.get_by_id(int(res_id))
				if reservation:
					admin = False
					if account and account.admin:
						admin = True
					self.delete_reservation(reservation.res_id)
					#re-query the database intead of redirect to increase consistency
					account = Accounts.get_by_id(account.acc_id)
					res_dict = {}
					car_dict = {}
					for res in account.reservations:
						reservation = Reservations.get_by_id(res)
						res_dict[res] = reservation
						car = Cars.get_by_id(reservation.car_id)
						car_dict[res] = car
					self.render('showaccount.html',account=account,admin=admin,res_dict=res_dict,car_dict=car_dict)
					
				else:
					self.redirect('/account')
			else:
				self.redirect('/account')
		else:
			self.redirect('/')


#This webpage will allow an admin to automatically populate the cars database for testing or initial start up
#This is mainly for testing but can be modified to perform intitial website startup
class CarInitHandler(Handler,CookieHashUtils):
	def get(self):
		account = self.lookup_account()
		admin = False

		#list user accounts if exists and admin
		if account and account.admin:
			admin=True
			if Cars.all().count(1):
				msg = "There are already cars in the database"
				created = True
			else:
				msg = "The cars DB is empty"
				created = False

			self.render('carinit.html',msg=msg,created=created,admin=admin)

		#redirect to hompage if account doesn't exist or is not admin
		else:
			self.redirect('/')

	def post(self):
		account = self.lookup_account()
			
		if account and account.admin:
			delete_button = self.request.get('delete')
			add_button = self.request.get('addcars')

			#if delete button was clicked
			if delete_button:
				#make sure there are cars to delete				
				if Cars.all().count(1):
					car_query = db.GqlQuery('SELECT * FROM Cars')
					for car in car_query:
						car.delete()
						
					#make sure there are reservation to delete
					if Reservations.all().count(1):
						res_query = db.GqlQuery('SELECT * FROM Reservations')
						for res in res_query:
							res.delete()
					
					#delete user reservations lists
					account_query = db.GqlQuery('SELECT * FROM Accounts')
					for acc in account_query:
						acc.reservations=[]
						acc.put()

					self.redirect('/')
				else:
					 self.redirect('/')		

			#if add button was clicked
			elif add_button:
				#make sure no cars already exist
				if not Cars.all().count(1):

					#add a few cars
					for i in range(3):
						car = Cars(car_type="Economy",car_make="Honda",car_model="Civic",car_seats=5,car_mpg=30)
						key = car.put()
						car.car_id = key.id()
						car.put()

						car = Cars(car_type="Sporty",car_make="Dodge",car_model="Charger",car_seats=5,car_mpg=20)
						key = car.put()
						car.car_id = key.id()
						car.put()

						car = Cars(car_type="Luxury",car_make="BMW",car_model="Mega-Limo",car_seats=12,car_mpg=6)
						key = car.put()
						car.car_id = key.id()
						car.put()	

					self.redirect('/')

				else:
					self.redirect('/')
		else:
			self.redirect('/')


#Page for browsing cars
class BrowseHandler(Handler,AvailableCarsUtils,CookieHashUtils):
	def get(self):
		account = self.lookup_account()
		
		admin = False
		if account and account.admin:
			admin = True
			
		dates = self.lookup_dates()
		if not dates or (dates['checkin'] >= dates['checkout']):
			checkin = date.today()
			checkout = date.today() + datetime.timedelta(days=1)
			checkin_cookie = self.mk_cookie(str(checkin))
			checkout_cookie = self.mk_cookie(str(checkout))
			self.response.headers.add_header('Set-Cookie', 'checkin=%s' % checkin_cookie)
			self.response.headers.add_header('Set-Cookie', 'checkout=%s' % checkout_cookie)
			self.redirect('/browse')
		
		else:			
			checkin = dates['checkin']
			checkout = dates['checkout']
			
			checkin_out=self.format_out_date(checkin)
			checkout_out=self.format_out_date(checkout)

			#make sure there are cars in the DB before querying	
			if not Cars.all().count(1):	
				self.response.out.write("there are no cars in the DB")
			else:
				availability=self.get_available_cars(checkin,checkout)
				sporty_instock = availability['sporty']
				economy_instock = availability['economy']
				luxury_instock = availability['luxury']				
				
				self.render('browse.html',sporty_instock=sporty_instock,
										economy_instock=economy_instock,
										luxury_instock=luxury_instock,
										admin = admin,checkin=checkin_out,
										checkout=checkout_out)		

	def post(self):
		view_car_button = self.request.get('view')
		change_date_button = self.request.get('change')	
		
		if change_date_button:
			date_cookies = self.get_datecookie_from_form()
			if not date_cookies:
				self.redirect('browse')
			else:
				checkin_cookie = date_cookies['checkin_cookie']
				checkout_cookie = date_cookies['checkout_cookie']
				
				self.response.headers.add_header('Set-Cookie', 'checkin=%s' % checkin_cookie)
				self.response.headers.add_header('Set-Cookie', 'checkout=%s' % checkout_cookie)
				self.redirect('/browse')			
		
		elif view_car_button:
			cartype = self.request.get('car_type')			
			cartype = self.mk_cookie(str(cartype))			
			self.response.headers.add_header('Set-Cookie', 'car_type=%s' %cartype)
			self.redirect('/browse/car-info')
			
		else:
			self.redirect('/browse')
			
	def format_out_date(self, date):
		date = str(date)
		date = date.split('-')
		return '%s/%s/%s' %(date[1],date[2],date[0])
		
		
class CarInformationHandler(Handler,AvailableCarsUtils,CookieHashUtils):
	def get(self):		
		car_type = self.lookup_type()
		if not car_type:
			self.redirect('/browse')		
		else:				
			dates = self.lookup_dates()
			if not dates:
				checkin = date.today()
				checkout = date.today() + datetime.timedelta(days=1)
				checkin_cookie = self.mk_cookie(str(checkin))
				checkout_cookie = self.mk_cookie(str(checkout))
				self.response.headers.add_header('Set-Cookie', 'checkin=%s' % checkin_cookie)
				self.response.headers.add_header('Set-Cookie', 'checkout=%s' % checkout_cookie)
				self.redirect('/car-info')
				
			else:			
				checkin = dates['checkin']
				checkout = dates['checkout']

				availability = self.get_available_cars(checkin,checkout)
				sporty_instock = availability['sporty']
				economy_instock = availability['economy']
				luxury_instock = availability['luxury']				
				
				#determine if the selected car is instock
				if car_type == 'sporty' and sporty_instock:
					instock=True
				elif car_type == 'economy' and economy_instock:
					instock=True
				elif car_type == 'luxury' and luxury_instock:
					instock=True
				else:
					instock = False
				
				#if the car is instock then get an example of it from list
				display_car = None
				if instock:
					cars = availability['cars']
					for car in cars:
						if car.car_type.lower() == car_type:
							display_car = car
							break				
				
				#determin if user is logged in
				account = self.lookup_account()
				if account:
					logged_in=True
				else:
					logged_in=False	

				self.render('carinfo.html',car=display_car,instock=instock,logged_in=logged_in)
				
			
	def post(self):
		checkout = self.request.get('checkout')
		if checkout:
			self.redirect('/checkout')
		else:
			self.redirect('/car-info')

class CheckoutHandler(Handler,AvailableCarsUtils,CookieHashUtils):
	def get(self):
		
		car_type = self.lookup_type()
		dates = self.lookup_dates()
		account = self.lookup_account()
		
		if not account and car_type and dates:
			self.redirect('/')
		
		else:
			checkin=dates['checkin']
			checkout=dates['checkout']
			
			#make sure there are cars in the DB before querying	
			if not Cars.all().count(1):	
				self.response.out.write("there are no cars in the DB")
			else:
				availability=self.get_available_cars(checkin,checkout)
				sporty_instock = availability['sporty']
				economy_instock = availability['economy']
				luxury_instock = availability['luxury']
				
				if car_type	is 'sporty' and not sporty_instock:
					sold_out=True
					car = None
				elif car_type is 'economy' and not economy_instock:
					sold_out=True
					car = None
				elif car_type is 'luxury' and not luxury_instock:
					sold_out=True
					car = None
				else:
					sold_out=True
					car=None
					for x in availability['cars']:
						if str(x.car_type).lower() == car_type:
							car = x
							sold_out = False
							break
				
				#get a unique database id that will be used as single-use token and reservation #									
				res_instance = Reservations.all().get()
				if not res_instance:
					handmade_key = db.Key.from_path('Reservations', 1)
					id_tuple = db.allocate_ids(handmade_key, 1)
				else:				
					id_tuple = db.allocate_ids(res_instance.key(), 1)
				id_val = id_tuple[0]
				id_token = self.mk_cookie(str(id_val))
	
				self.render('checkout.html',checkin=checkin,checkout=checkout,car=car,
							sold_out=sold_out,id_token=id_token)	
			
	def post(self):
		reserve_button = self.request.get('reserve_button')
		id_token = self.request.get('id_token')
		
		#check to see if the token has been used
		if not id_token:
			self.redirect('/checkout')
		else:
			id_val = self.validate_token(id_token)
			if not id_val:
				self.redirect('/thanks')						
			elif  not reserve_button:
				self.redirect('/checkout')
			else:
				car_type = self.lookup_type()
				dates = self.lookup_dates()
				account = self.lookup_account()
			
				if not account and car_type and dates:
					self.redirect('/')
				
				else:
					checkin=dates['checkin']
					checkout=dates['checkout']
					
					#make sure there are cars in the DB before querying	
					if not Cars.all().count(1):	
						self.response.out.write("there are no cars in the DB")
					else:
						availability=self.get_available_cars(checkin,checkout)
						sporty_instock = availability['sporty']
						economy_instock = availability['economy']
						luxury_instock = availability['luxury']
						
						if car_type	is 'sporty' and not sporty_instock:
							sold_out=True
							car = None
						elif car_type is 'economy' and not economy_instock:
							sold_out=True
							car = None
						elif car_type is 'luxury' and not luxury_instock:
							sold_out=True
							car = None
						else:
							sold_out=True
							for x in availability['cars']:
								if str(x.car_type).lower() == car_type:
									car = x
									sold_out = False
									break								
						
						if sold_out:
							self.render('checkout.html',checkin=checkin,checkout=checkout,
										sold_out=sold_out)
						else:
							#update reservation database
							new_key = db.Key.from_path('Reservations',id_val)
							date_list = [dates['checkin'],dates['checkout']]
							car_id = car.car_id
							acc_id = account.acc_id
							reservation = Reservations(key=new_key,car_id=car_id,acc_id=acc_id,checkin=dates['checkin'],
														checkout=dates['checkout'])
							res_key = reservation.put()
							reservation.res_id = res_key.id()
							reservation.put()
							
							#update user database
							account.reservations.append(res_key.id())
							account.put()
							
							#update the car database
							car.reservations.append(res_key.id())
							car.put()
							
							self.redirect('/thanks')

	#validate a given token from the form
	def validate_token(self,token):
		id_val = int(self.valid_cookie(token))
		if not id_val:
			self.redirect('/browse')
		else:				
			test_reservation = Reservations.get_by_id(id_val)
			if test_reservation:
				self.redirect('/thanks')
			else:
				 return id_val
				
			 
class ThanksHandler(Handler, CookieHashUtils):
	def get(self):
		account = self.lookup_account()
		
		admin = False
		if account and account.admin:
			admin = True	

		#display a message if account was found
		if account:
			self.render('/thanks.html',admin=admin)

		#if account doesn't exist then redirect to homepage
		else:
			self.redirect('/')

class ViewCarsHandler(Handler, CookieHashUtils):
	def get(self):
		account = self.lookup_account()			
		admin = False
		#list user accounts if exists and admin
		if account and account.admin:			
			admin = True
			
			query = db.GqlQuery('SELECT * FROM Cars')
			carlist = list(query)
			res_dict = {}
			for car in carlist:
				if len(car.reservations) > 0:
					for res in car.reservations:
						reservation = Reservations.get_by_id(res)
						res_dict[res] = reservation
						
			self.render('viewcars.html',admin=admin,carlist=carlist,res_dict=res_dict)
		else:
			self.redirect('/')

	def post(self):
		pass
		#functionality later to add cars, mark cars as available/unavailable, and delete cars which have
		#no outstanding reservations

class ViewReservationsHandler(Handler, CookieHashUtils,ReservationUtils):
	def get(self):
		account = self.lookup_account()
		
		admin=False	
		
		#list user accounts if exists and admin
		if account and account.admin:
			admin=True	
			query = db.GqlQuery('SELECT * FROM Reservations')
			reslist = list(query)
			user_dict = {}
			car_dict = {}
			for reservation in reslist:
				car = Cars.get_by_id(reservation.car_id)
				car_dict[reservation.res_id] = car
				user = Accounts.get_by_id(reservation.acc_id)
				user_dict[reservation.res_id] = user
			self.render('viewreservations.html',admin=admin,reslist=reslist,car_dict=car_dict,user_dict=user_dict)
		else:
			self.redirect('/')

	def post(self):
		account = self.lookup_account()
		admin=False
		if account and account.admin:
			admin=True
			delete_button = self.request.get('delete')
			res_id = self.request.get('res_id')
			if delete_button:
				res = Reservations.get_by_id(int(res_id))
				if res:
					self.delete_reservation(res.res_id)
					query = db.GqlQuery('SELECT * FROM Reservations')
					reslist = list(query)
					for x in reslist:
						if res.res_id == x.res_id:
							reslist.remove(x)
							break				
					user_dict = {}
					car_dict = {}
					for reservation in reslist:
						car = Cars.get_by_id(reservation.car_id)
						car_dict[reservation.res_id] = car
						user = Accounts.get_by_id(reservation.acc_id)
						user_dict[reservation.res_id] = user
					self.render('viewreservations.html',admin=admin,reslist=reslist,car_dict=car_dict,user_dict=user_dict)
					
				else:
					self.redirect('/view-reservations')
			else:
				self.redirect('/view-reservations')		
		else:
			self.redirect('/')
				
		#future functionality to add reservations for phone/walk-in customers under a manager acct

#########################################Page Mapping####################################################
app = webapp2.WSGIApplication([
	('/', HomePageHandler),
	('/signin', SigninHandler),
	('/signup', SignupHandler),
	('/welcome', WelcomeHandler),
	('/logout', LogoutHandler),
	('/account', ShowAccountHandler),
	('/user-accounts', ShowAllAccountsHandler),
	('/car-init', CarInitHandler),
	('/browse', BrowseHandler),
	('/browse/car-info', CarInformationHandler),
	('/checkout', CheckoutHandler),
	('/thanks', ThanksHandler),
	('/view-cars', ViewCarsHandler),
	('/view-reservations',ViewReservationsHandler)
], debug=True)
