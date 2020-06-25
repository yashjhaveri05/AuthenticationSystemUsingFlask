from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from passlib.hash import sha256_crypt
from functools import wraps
import random
from twilio.rest import Client
import os


app = Flask(__name__)
app.config.from_pyfile('config.py')

mysql = MySQL(app)
mail = Mail(app)

s = URLSafeTimedSerializer('Thisisasecret!')

@app.route('/about')
def about():
    return render_template('about.html')

class SignUpForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    email = EmailField('Email', [
                       validators.DataRequired(), validators.Email()]) 
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')
    mobile_number = StringField('Mobile Number', [validators.Length(min=1, max=15)])


@app.route('/', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    form = SignUpForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))
        mobile_number = form.mobile_number.data

        session['username'] = username
        session['email'] = email
        session['password'] = password
        session['mobile_number'] = mobile_number 
       
       #unique username,mobile number,email for user
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE email=%s or mobile_number=%s or username=%s", ([email], [mobile_number], [username]))
        cur.close()
        if result > 0:
            data = cur.fetchone()
            if data['username'] == username:
                flash('Username already taken', 'info')
                return redirect(url_for('signup'))
            if data['email'] == email:
                flash('Email already taken', 'info')
                return redirect(url_for('signup'))
            if data['mobile_number'] == mobile_number:
                flash('Mobile Number already taken', 'info')
                return redirect(url_for('signup'))
        else:
            #Sending Email Verification Email
            token = s.dumps(email, salt='email-confirm')
            msg = Message('Confirm Email', sender='noreply@demo.com', recipients=[email])
            link = url_for('confirm_email', token=token, _external=True)
            msg.body = 'Your link is {}'.format(link)
            mail.send(msg)

            val = getOTPAPI(mobile_number)
            if val:
                flash('A message with an OTP has been sent to the registered mobile number!!!Please enter the valid OTP here to continue login process!', 'info')
                return render_template('enterOTP.html')
            
                   
    return render_template('signUp.html', form=form)

def getOTPAPI(mobile_number):
    account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
    auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)
    otp = random.randrange(100000,999999)
    session['response'] = str(otp)
    body = 'Your OTP is ' +str(otp)
    message = client.messages.create(
                                from_='+12056971412',
                                body=body,
                                to=mobile_number
                            )
    if message.sid:
        return True
    else:
        False 

@app.route('/confirm_email/<token>')
def confirm_email(token):
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(mobile_number, email, username, password) VALUES( %s, %s, %s, %s)",
                        (session['mobile_number'], session['email'], session['username'], session['password']))
        mysql.connection.commit()
        cur.close()
        session.clear()
        # Account Activated Message
        msg = Message('Account Activated', sender='noreply@demo.com', recipients=[email])
        msg.body = 'Your account is now activated'
        mail.send(msg)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    return redirect(url_for('login'))

@app.route('/validateOTP', methods = ['POST'])
def validateOTP():
    if request.method == 'POST':
        otp = request.form['otp']
        if 'response' in session:
            s = session['response']
            session.pop('response',None)
            if s == otp:
                flash('Mobile verification complete!Please verify your email by clicking on the link sent to the entered email address before logging in!', 'info')
                return redirect(url_for('login'))
            else:
                return 'You arent authorized'
    return render_template('enterOTP.html')

class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=100)])
    password = PasswordField('Password', [
        validators.DataRequired(),
    ])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_input = form.password.data

        cur = mysql.connection.cursor()

        result = cur.execute(
            "SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            data = cur.fetchone()
            password = data['password']

            if sha256_crypt.verify(password_input, password):
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in', 'success')
                return redirect(url_for('index'))
            else:
                error = 'Invalid Password/Email Not Confirmed'
                return render_template('login.html', form=form, error=error)

            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', form=form, error=error)

    return render_template('login.html', form=form)


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Please login', 'info')
            return redirect(url_for('login'))
    return wrap

@app.route('/index')
@is_logged_in
def index():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM users WHERE username = %s", [session['username']])
    credentials = cur.fetchall()
    if result > 0:
        return render_template('index.html', credentials=credentials)
    else:
        msg = 'No credentials have been created'
        return render_template('about.html', msg=msg)
    cur.close()
    return render_template('index.html')

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

class RequestResetForm(Form):
    email = EmailField('Email address', [
                       validators.DataRequired(), validators.Email()])


# The next two routes are for forgot password functionality

@app.route("/reset_request", methods=['GET', 'POST'])
def reset_request():
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    form = RequestResetForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        cur = mysql.connection.cursor()
        result = cur.execute(
            "SELECT id,username,email FROM users WHERE email = %s", [email])
        if result == 0:
            flash(
                'There is no account with that email. You must register first.', 'warning')
            return redirect(url_for('signup'))
        else:
            data = cur.fetchone()
            user_id = data['id']
            user_email = data['email']
            cur.close()
            s = Serializer(app.config['SECRET_KEY'], 1800)
            token = s.dumps({'user_id': user_id}).decode('utf-8')
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com', recipients=[user_email])
            msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make password reset request then simply ignore this email and no changes will be made.
Note:This link is valid only for 30 mins from the time you requested a password change request.
'''
            mail.send(msg)
            flash(
                'An email has been sent with instructions to reset your password.', 'info')
            return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)


class ResetPasswordForm(Form):
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if 'logged_in' in session and session['logged_in'] == True:
        flash('You are already logged in', 'info')
        return redirect(url_for('index'))
    s = Serializer(app.config['SECRET_KEY'])
    try:
        user_id = s.loads(token)['user_id']
    except:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE id = %s", [user_id])
    data = cur.fetchone()
    cur.close()
    user_id = data['id']
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        password = sha256_crypt.encrypt(str(form.password.data))
        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password = %s WHERE id = %s", (password, user_id))
        mysql.connection.commit()
        cur.close()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


if __name__ == '__main__':
    app.run(debug=True)