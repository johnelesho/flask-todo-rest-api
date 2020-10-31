from enum import unique
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET']= 'elesho'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todoapi.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.Integer, unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50), unique=True, nullable=False)
    complete = db.Column(db.Boolean, nullable=False)
    user_id = db.Column(db.Integer, default=False, nullable=False)




if __name__ == "__main__":
    app.run(debug=True)