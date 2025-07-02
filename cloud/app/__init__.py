from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import requests

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev' # Une clé secrète est nécessaire pour les sessions
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://clouduser:cloudpass@postgres:5432/cloud'
    db.init_app(app)

    from . import routes
    app.register_blueprint(routes.bp)

    from .models import User  # Import du modèle User
    return app 