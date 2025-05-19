import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '=6CAB607AB08DD5C5'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False