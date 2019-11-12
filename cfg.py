class Configuration(object):
    DEBUG = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:////sqlite/account.db'
    APP_TOKEN = 'gnomes'
    SECRET_KEY = 'thisissecretkey'