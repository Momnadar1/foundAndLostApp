import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify
from flask_cors import CORS

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lostAndFoundApp.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['DB'] = SQLAlchemy(app)
CORS(app)

from views import *

if __name__ == '__main__':

    app.run(debug=True)