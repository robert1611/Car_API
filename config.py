import os

basedir = os.path.abspath(os.path.dirname(__file__))
print("test")
#give access to the project in any OS we find ourselves in
#all outside folders / files to be added to the project
#from the base directory

class Config():

    """
    Set configure variables

    """
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'You will never guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir,'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False #Turn off update messages