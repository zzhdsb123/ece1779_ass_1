from flask import Flask
from flask_sqlalchemy import SQLAlchemy

dia='mysql'
dri='pymysql'
username='root'
password='F=mdv/dt123'
host='127.0.0.1'
port='3306'
database='ece1779'

SQLALCHEMY_DATABASE_URI="{}+{}://{}:{}@{}:{}/{}?charset=utf8".format(dia,dri,username,password,host,port,database)

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db = SQLAlchemy(app)
from app import views
