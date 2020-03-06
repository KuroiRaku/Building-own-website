import os
from os import path
from flask import Blueprint, Flask, render_template, url_for, request, flash, current_app, redirect, session
from flask_bootstrap import Bootstrap
from flask_wtf import Form, FlaskForm
from flask_mail import Message, Mail
from flask_moment import Moment
from wtforms import TextField, TextAreaField, SubmitField, SelectField, ValidationError, StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, DataRequired, Length
from config import Config
from flask_uploads import patch_request_class, UploadSet, configure_uploads, IMAGES
from datetime import datetime



Mail=Mail()
Moment= Moment()

app = Flask(__name__)
bootstrap = Bootstrap(app)


DEBUG=False
Basedir = path.abspath(path.dirname(__file__))
MusicFolder = os.path.join(Basedir, 'static/mp3')
Main = Blueprint('main', __name__)

app.config['MusicFolder'] = MusicFolder
app.config.from_object(__name__)
app.config['SECRET_KEY']='123456789_ABC'
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

class ContactForm(Form):
    FirstName= TextField("FirstName", validators=[InputRequired("Please")])
    LastName = TextField("LastName", validators=[DataRequired()])
    Email = TextField("Email", validators=[DataRequired(), Email()])
    Continent= SelectField("Continent", validators=[DataRequired()], choices=[('NorthAmerica', 'North America'), ('SouthAmerica','South America'),
     ('Europe', 'Europe'), ('MiddleEast','Middle East'), ('Africa', 'Africa'), ('Asia', 'Asia'),('Australia','Australia')])
    Interest = TextField("Interest",validators=[DataRequired()])
    Message = TextAreaField("Message")
    Submit = SubmitField("Submit")


@app.route('/')
def Welcome():
    return redirect('/Home')

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http','https')and \
           ref_url.netloc == test_url.netloc

@app.route('/Home')
def Home():
    return render_template('practice.html')

@app.route('/mp3/Haru.mp3', methods=['GET'])
def downloadFile():
        return send_file('./mp3', as_attachment=True, attachment_filename="Haru.mp3" )

@app.route('/mp3/Home.mp3', methods=['GET'])
def DownloadFile():
        return send_file('./mp3', as_attachment=True, attachment_filename="Home.mp3")

@app.route('/upload',methods=['GET','POST'])
def UploadFile():
    if request.method =='POST':
        file = request.files["file"]
        file.save(os.path.join("uploads",file.filename))
        return render_template("practice.html", message="success")
    return render_template("practice.html")

@app.route('/Contact_Me',methods=['GET','POST'])
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
    app.run(debug=True)
