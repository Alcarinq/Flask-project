import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = 'u3iBX4d4gMmoy9VtFDV4'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASKB_ADMIN = 'admin@flaskb.pl'
    POSTS_PER_PAGE = 10
    FOLLOWERS_PER_PAGE = 5
    COMMENTS_PER_PAGE = 5

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///'

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
