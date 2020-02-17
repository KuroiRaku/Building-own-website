import os
from os import path
from flask import Blueprint, Flask, render_template, url_for, request, flash, current_app, redirect, session
from flask_bootstrap import Bootstrap
from flask_wtf import Form, FlaskForm
from flask_mail import Message, Mail
from flask_moment import Moment
from wtforms import TextField, TextAreaField, SubmitField, SelectField, ValidationError, StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, fresh_login_required, logout_user, current_user
from flask_uploads import patch_request_class, UploadSet, configure_uploads, IMAGES
from datetime import datetime



Mail=Mail()
Moment= Moment()
LoginManager = LoginManager()

app = Flask(__name__)
db=SQLAlchemy(app)
bootstrap = Bootstrap(app)


DEBUG=False
Basedir = path.abspath(path.dirname(__file__))
MusicFolder = os.path.join(Basedir, 'static/mp3')
Main = Blueprint('main', __name__)

app.config['MusicFolder'] = MusicFolder
app.config.from_object(__name__)
app.config['SECRET_KEY']='123456789_ABC'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///D:\\All of My folders\\Assignment\\Python Project\\databse.db'
app.config['CSRF_ENABLED']= True
#no money to buy server...
app.config['SERVER_NAME']='localhost:5000'
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = 'mikazuki599@gmail.com'
app.config["MAIL_PASSWORD"] = '123456789_ABC'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.register_blueprint(Main)

Mail.init_app(app)
Moment.init_app(app)
LoginManager.init_app(app)
db.create_all()


LoginManager.session_protection = 'strong'
LoginManager.login_view = 'LogIn'
LoginManager.login_message='You need to login!'

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(Basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite:///' + os.path.join(Basedir, 'data-test.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(Basedir, 'data.sqlite')

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class ContactForm(Form):
    FirstName= TextField("FirstName", validators=[InputRequired("Please")])
    LastName = TextField("LastName", validators=[DataRequired()])
    Email = TextField("Email", validators=[DataRequired(), Email()])
    Continent= SelectField("Continent", validators=[DataRequired()], choices=[('NorthAmerica', 'North America'), ('SouthAmerica','South America'),
     ('Europe', 'Europe'), ('MiddleEast','Middle East'), ('Africa', 'Africa'), ('Asia', 'Asia'),('Australia','Australia')])
    Interest = TextField("Interest",validators=[DataRequired()])
    Message = TextAreaField("Message")
    Submit = SubmitField("Submit")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

@LoginManager.user_loader
def LoadUser(UserId):
    return User.query.get(int(UserId))

@app.route('/')
def Welcome():
    return redirect('/login')

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http','https')and \
           ref_url.netloc == test_url.netloc

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('Home'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return render_template('NewUserCreated.html')
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def LogOut():
    logout_user()
    return redirect ('/login')

@app.route('/Home')
@login_required
def Home():
    return render_template('practice.html')

@app.route('/mp3/Haru.mp3', methods=['GET'])
@login_required
def downloadFile():
        return send_file('./mp3', as_attachment=True, attachment_filename="Haru.mp3" )

@app.route('/mp3/Home.mp3', methods=['GET'])
@login_required
def DownloadFile():
        return send_file('./mp3', as_attachment=True, attachment_filename="Home.mp3")

@app.route('/upload',methods=['GET','POST'])
@fresh_login_required
def UploadFile():
    if request.method =='POST':
        file = request.files["file"]
        file.save(os.path.join("uploads",file.filename))
        return render_template("practice.html", message="success")
    return render_template("practice.html")

@app.route('/Contact_Me',methods=['GET','POST'])
@fresh_login_required
def Contact():
    form = ContactForm(request.form)
    if request.method =='POST':
        if form.validate==False:
            flash('All fields are required.')
            return render_template('ContactMe.html',form=form)
        else:
             msg = Message(form.Interest.data, sender='contact@example.com', recipients=['mikazuki599@gmail.com'])
             msg.body = """
             From: %s %s; %s ;
             %s
             """ % (form.FirstName.data, form.LastName.data,form.Email.data, form.Message.data)
             Mail.send(msg)

             return render_template('ContactMe.html', success=True)

    elif request.method == 'GET':
        return render_template('ContactMe.html',form=form)



if __name__=="__main__":
    db.create_all()
    app.run(debug=True)
