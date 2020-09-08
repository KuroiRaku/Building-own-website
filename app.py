import os
import pycountry
from os import path
from flask import Flask, render_template, url_for, request, flash, current_app, redirect, session, send_from_directory
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_bootstrap import Bootstrap
from flask_wtf import Form, FlaskForm
from flask_mail import Message, Mail
from wtforms import TextField, TextAreaField, SubmitField, SelectField, ValidationError, StringField, PasswordField, BooleanField, IntegerField, FileField, DecimalField
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from wtforms.validators import InputRequired, Email, DataRequired, Length, EqualTo
from flask_wtf.file import FileField, FileAllowed, FileRequired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import stripe
import email_validator

stripe_keys = {
  'secret_key': 'pk_test_87AxnNnWKK2upOoR1OynsXVw00ZhJONDsj',
  'publishable_key': 'sk_test_OuQ7AMk9hVz9DdhdwlLPdHrs00gkRO4CCJ'
}

stripe.api_key = stripe_keys['secret_key']

Mail=Mail()
LoginManager = LoginManager()

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)
bootstrap = Bootstrap(app)

upload_folder='database/images'

app.config['SECRET_KEY']='123456789_ABC'
app.config['UPLOAD_FOLDER'] = upload_folder
app.config.from_object(__name__)
db_path = os.path.join(os.path.dirname(__file__), 'database/users.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
db_path_2 = os.path.join(os.path.dirname(__file__), 'database/listing.db')
db_uri_2 = 'sqlite:///{}'.format(db_path_2)
app.config['SQLALCHEMY_BINDS']= {'listing': db_uri_2}
app.config['CSRF_ENABLED']= True

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'mikazuki599@gmail.com'
app.config["MAIL_PASSWORD"] = '123456789_ABC'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024


Mail.init_app(app)
LoginManager.init_app(app)
db.create_all()

LoginManager.session_protection = 'strong'
LoginManager.login_view = 'login'
LoginManager.login_message='You need to login!'

logged_in=False


#Class for User and Hosting
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))
    email = db.Column(db.String(50), unique=True)
    region = db.Column(db.String(50))
    past_hosting = db.Column(db.String(50))
    gender = db.Column(db.String(50))
    #reset password
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')
    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

# class Hosting(db.Model):
#     __bind_key__ = 'listing'
#     id= db.Column(db.Integer, primary_key=True)
#     name=db.Column(db.String(30))
#     location = db.Column(db.String(50))
#     description= db.Column(db.String(60))
#     price=db.Column(db.Integer)
#     category= db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
#     image_url= db.Column(db.String(50))
    #image = db.Column(db.LargeBinary)


# class HostingEditForm(FlaskForm):
#     name= TextField("Product name", validators=[InputRequired()])
#     utility = IntegerField("utility", validators=[DataRequired()])
#     marginal_utility= SelectField("Satisfaction if you get the same product", validators=[DataRequired()], choices=[('3', 'High'), ('2','Average'),
#      ('1', 'Low')])
#     description = StringField('Description', validators=[DataRequired()])
#     price = IntegerField('Price', validators=[DataRequired()])

#class HostingForm(ProductEditForm):
#    category = QuerySelectField("Category of the product", query_factory=lambda: Category.query.all(), get_label='name')
#    image = FileField('Image', validators=[FileRequired("PLEASE")])

class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm = PasswordField('confirm password', validators=[InputRequired(), Length(min=8, max=80), EqualTo('password', message='Passwords must match')])
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('There is account with that email. Please use different account.')

class ContactForm(Form):
    FirstName= TextField("FirstName", validators=[InputRequired("Please")])
    LastName = TextField("LastName", validators=[DataRequired()])
    Email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    Message = TextAreaField("Message")
    Submit = SubmitField("Submit")


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class NewListingForm(FlaskForm):
    budget = DecimalField('Budget', validators=[DataRequired()])
    category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name')

@LoginManager.user_loader
def LoadUser(UserId):
    return User.query.get(int(UserId))

@app.route('/', methods=['GET', 'POST'])
def welcome():
    # global logged_in
    # login= logged_in
    # if form.validate_on_submit():
    #
    #
    #     return render_template('welcome.html', login=login)
    #if i were to change the login function for me :p
    return render_template('welcome.html', form=form)

# @app.route('/image/<path:filename>')
# def access_image(filename):
#     return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
#
# def is_safe_url(target):
#     ref_url = urlparse(request.host_url)
#     test_url = urlparse(urljoin(request.host_url, target))
#     return test_url.scheme in ('http','https')and \
#            ref_url.netloc == test_url.netloc

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     global logged_in
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         if user:
#             if check_password_hash(user.password, form.password.data):
#                 login_user(user, remember=form.remember.data)
#                 session['username'] = user.username
#                 session['email']= user.email
#                 logged_in=True
#                 return redirect(url_for('welcome'))
#
#         return render_template('login.html', form=form, error=True)
#     return render_template('login.html', form=form, error = False)
#
# @app.route('/logout')
# @login_required
# def LogOut():
#     global logged_in
#     logged_in=False
#     logout_user()
#     return redirect ('/login')
#
# @app.route('/signup', methods=['GET', 'POST'])
# def signup():
#     form = RegisterForm()
#
#     if form.validate_on_submit():
#
#         hashed_password = generate_password_hash(form.password.data, method='sha256')
#         new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#
#         return render_template('login.html')
#         #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
#
#     return render_template('signup.html', form=form)



# def send_reset_email(user):
#     token = user.get_reset_token()
#     msg = Message('Password Reset Request',
#                   sender='mikazuki599@gmail.com',
#                   recipients=[user.email])
#     msg.body = user.username+ f''' To reset your password, visit the following link:
# {url_for('reset_token', token=token, _external=True)}
# If you did not make this request then simply ignore this email and no changes will be made.
# '''
#     Mail.send(msg)
#
#
# @app.route("/password", methods=['GET', 'POST'])
# def password():
#     form = RequestResetForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(email=form.email.data).first()
#         send_reset_email(user)
#         flash('An email has been sent with instructions to reset your password.', 'info')
#         return redirect(url_for('login'))
#     return render_template('forget-password.html', title='Reset Password', form=form)
#
#
# @app.route("/password/<token>", methods=['GET', 'POST'])
# def reset_token(token):
#     if current_user.is_authenticated:
#         return redirect(url_for('Home'))
#     user = User.verify_reset_token(token)
#     if user is None:
#         flash('That is an invalid or expired token', 'warning')
#         return redirect(url_for('reset_request'))
#     form = ResetPasswordForm()
#     if form.validate_on_submit():
#         hashed_password = generate_password_hash(form.password.data)
#         user.password = hashed_password
#         db.session.commit()
#         flash('Your password has been updated! You are now able to log in', 'success')
#         return redirect(url_for('login'))
#     return render_template('resetToken.html', title='Reset Password', form=form)



@app.route('/home')
def home():
    return redirect(url_for('welcome'))


@app.route('/all_portfolios')
def all_portfolios():

    return render_template('all_portfolios.html')

@app.route('/about_us')
def about_us():
    return render_template('about.html')


@app.route('/contact_us',methods=['GET','POST'])
def contact():
    form = ContactForm(request.form)
    if request.method =='POST':
        if form.validate==False:
            flash('All fields are required.')
            return render_template('contact.html',form=form)
        else:
             msg = Message(sender=form.Email.data, recipients=['abeansroastery@gmail.com'])
             msg.body = """
             From: %s %s; %s ;
             %s
             """ % (form.FirstName.data, form.LastName.data,form.Email.data, form.Message.data)
             Mail.send(msg)

             return render_template('contact.html', success=True)

    elif request.method == 'GET':
        return render_template('contact.html',form=form)

# @app.route('/Hosting/<path:id>', methods=['GET', 'POST'])
# def product(id):
#
#     form = HostingEditForm(name=product.name, utility=product.utility, description=product.description, marginal_utility=marginal_utility_position, price=product.price)
#
#     if budget_entered:
#         if form.validate_on_submit():
#             Hosting.name = form.name.data
#             product.description = form.description.data
#             product.marginal_utility = form.marginal_utility.data
#             product.price = form.price.data
#             db.session.commit()
#
#         product.image_url = os.path.join("../../image", product.image_url)
#         return render_template('products.html', products=product, form=form)
#
#     return redirect(url_for('welcome'))



# @app.route('/add_item', methods=['GET','POST'])
# def add_item():
#     form= ProductForm()
#     if form.validate_on_submit():
#         f= form.image.data
#         filename= secure_filename(f.filename)
#         file_url= os.path.join(
#             'database/images',
#             filename
#         )
#         image_url='database/images/'+ filename
#         f.save(file_url)
#         new_product = Product(name=form.name.data, utility=form.utility.data, marginal_utility=form.marginal_utility.data, description= form.description.data,
#         price = form.price.data, category=form.category.data.id,image_url=filename)
#         #price = form.price.data, category=form.category.data,image=form.files['image'])
#
#         db.session.add(new_product)
#         db.session.commit()
#         return render_template('add_item.html', form=form)
#         #return redirect(url_for('home'))
#         #return ("Success!"+ {file_url})
#         #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
#
#     return render_template('add_item.html', form=form)

if __name__=="__main__":
    # db.create_all()
    app.run(debug=True)
