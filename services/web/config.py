import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'postgresql://demoportal:demoportal1in@127.0.0.1/demoportal'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_SECRET_KEY = 'G183823542123618556618846012318562447050'
    # SERVER_NAME="0.0.0.0:5001"
    # SERVER_NAME="0.0.0.0"
    # FLASK_RUN_PORT=5001


class ProductionConfig(Config):
    DB_HOST = 'localhost'
    DB_NAME = 'demoportal'
    DB_USER = 'demoportal'
    DB_PASS = 'demoportal1in'
    JWT_SECRET = 'lSkuzLdjRQyjtwEpbq1H0fOaFbefRvQ90vTka2qQ9bJTKqSj3hHkBytqmP6aAgPz'
    JWT_ALGORITHM = 'HS512'
    REDIS_HOST = 'lb1.uvoo.io'
    REDIS_NAME = 0
    REDIS_PASS = 'redis1in'
    SQLALCHEMY_DATABASE_URI = 'postgresql://demoportal:demoportal1in@127.0.0.1/demoportal'
    JWT_ALGORITHM = "ES512"
    JWT_PRIVATE_KEY = open('jwt_ec_private_key', 'rb').read()
    JWT_PUBLIC_KEY = open('jwt_ec_public_key', 'rb').read()
    # JWT_ALGORITHM = "RS512"
    # JWT_PRIVATE_KEY = open('jwt_rsa_private_key', 'rb').read()
    # JWT_PUBLIC_KEY = open('jwt_rsa_public_key', 'rb').read()
    CLIENT_TOKEN = "Aea84abc487da11e9afa48308d39e8e0aBAZHello"


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/demoportal.db'


class TestingConfig(Config):
    TESTING = True
