from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime


app = Flask(__name__)
app.config['SECRET_KEY']= 'elesho'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todoapi.db'
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



#Setting up the user routes that only admins who have logged in have access to
@app.route('/user/', methods=['GET'])
def get_all_users():
    users = User.query.all()
    output = []
    for user in users:
         user_data = {}
         user_data['public_id'] = user.public_id
         user_data['username'] = user.username
         user_data['password'] = user.password
         user_data['is_admin'] = user.is_admin
         output.append(user_data)

    return jsonify({"users": output})

@app.route('/user/<user_id>', methods=["GET"])
def get_one_user(user_id):
    user = User.query.filter_by(public_id = user_id ).first()
    if user:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.username
        user_data['password'] = user.password
        user_data['is_admin'] = user.is_admin

        return jsonify({"user": user_data})
    else:
        return jsonify({"user": "User not found"})

@app.route('/user/', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user_public_id = str(uuid.uuid4())
    new_user_name = data['username']
   
    new_user = User(public_id = new_user_public_id , username = new_user_name, password=hashed_password, is_admin=False )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message': 'New User Created'})

@app.route('/user/<user_id>', methods=["PUT"])
def promote_user(user_id):
     user = User.query.filter_by(public_id = user_id ).first()
     if user:
        user.is_admin = True
        db.session.commit()
        return jsonify({"user": "User promoted"})
     else:
        return jsonify({"user": "User not found"})
    

@app.route('/user/<user_id>', methods=["DELETE"])
def delete_user(user_id):
    user = User.query.filter_by(public_id = user_id ).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"user": "User Deleted"})
    else:
        return jsonify({"user": "User not found"})


#Login anf get the authorization
@app.route('/login')
def login():
    auth = request.authorization

# if there is no authentication information
    if not auth or not auth.username or not auth.password:
        return make_response('Authentication Information not available, Could not verify', 401, {'WWW-Authentication': 'Basic realm="Login required"'})

# if the authenticated details[username] is in the database 
    user = User.query.filter_by(username=auth.username).first()
    if not user:
         return make_response('User not verified', 401, {'WWW-Authentication': 'Basic realm="Login required"'})

# if the authenticated details[password] matches 
    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {
                "public_id": user.public_id, 
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            },
            app.config['SECRET_KEY']
            )
        return jsonify({'token': token.decode('UTF-8')})

    return make_response('User not finally verified', 401, {'WWW-Authentication': 'Basic realm="Login required"'})

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)