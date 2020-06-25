## Flask Authentication System

> This is open-source and can be used by anyone.For any suggestions,bugs found,cleaner and better code,more functionality,please contribute to this repository.

><h2>Key Features:</h2>
>Unique Username,Email and Mobile Address<br>
>Email Validator<br>
>Email Verification<br>
>Account Activated email is sent if the account email is verified<br>
>Forgot Password Functionality<br>
>Encrypted Password<br>
>Mobile Verification by sending OTP via message using the Twilio API<br>

><h2>Gmail Mail Config</h2>
> <p>Go to your registered gmail account,in 'myaccount' go to 'app password' and create an app with the name of your website.The Password received can be either stored as an environment variable along with the email and hence this process can help you access the email functionality.<br>
>GMail Account => MyAccount => App Passwords => Create App => Store The Password/Key Provided => Use the stored Key<br><br>
>(Also add to config.py)<br>
>MAIL_SERVER = 'smtp.gmail.com'<br>
>MAIL_PORT = 587<br>
>MAIL_USE_TLS = True<br>
>MAIL_USE_SSL = False<br>
>MAIL_USERNAME = os.environ.get('EMAIL_USER')<br>
>MAIL_PASSWORD = os.environ.get('Authentication_Pwd')<br>

><h2>Twilio Config</h2>
> <p>Go to Twilio API,create account,generate number, store and use SID and Token.<br>

## Requirements
```
A version of python
pip package manager installed
Local instance of MySQL running on localhost as user root
Set MySQL password as an environment variable as 'MYSQL_PWD'
Run queries.sql
```
```bash
pip install flask
pip install mysqlclient
pip install flask-mysqldb
pip install flask-WTF
pip install passlib
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yashjhaveri05/AuthenticationSystemUsingFlask.git
```

> ### Create a file called config.py that looks like
```python
import os

DEBUG = True
TESTING = True
MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASSWORD = os.getenv('MYSQL_PWD')
MYSQL_DB = 'course'
MYSQL_CURSORCLASS = 'DictCursor'
SECRET_KEY = 'your_secret_key'
```

## Go to the directory where you cloned the repository

> Run 
```bash
python app.py
```

Runs the app in the development mode.<br />

### Author [Yash Jhaveri](https://www.linkedin.com/in/yash-jhaveri-3b0882192/)