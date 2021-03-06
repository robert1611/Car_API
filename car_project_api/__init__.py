from flask import Flask


from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# Import for Flask Login
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
oauth = OAuth(app)
#login_manager.login_view = 'signin' # Specify what page to load for NON-AUTHED users

from car_project_api import routes, models