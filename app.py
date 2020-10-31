from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps


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
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, nullable=False)

def check_token(f):
    @wraps(f)
    def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'}), 401

      try:
         data = jwt.decode(token, app.config['SECRET_KEY'])
         current_user = User.query.filter_by(public_id=data['public_id']).first()
      except:
         return jsonify({'message': 'token is invalid'}), 401

      return f(current_user, *args, **kwargs)
    return decorator


#Setting up the user routes that only admins who have logged in have access to
@app.route('/user/', methods=['GET'])
@check_token
def get_all_users(current_user):
    if not current_user.is_admin:
        return jsonify({"message": "Cannot perform that function"})
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
@check_token
def get_one_user(current_user, user_id):
    if not current_user.is_admin:
            return jsonify({"message": "Cannot perform that function"})
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
@check_token
def create_user(current_user):
    if not current_user.is_admin:
            return jsonify({"message": "Cannot perform that function"})
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user_public_id = str(uuid.uuid4())
    new_user_name = data['username']
   
    new_user = User(public_id = new_user_public_id , username = new_user_name, password=hashed_password, is_admin=False )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'Message': 'New User Created'})

@app.route('/user/<user_id>', methods=["PUT"])
@check_token
def promote_user(current_user, user_id):
     if not current_user.is_admin:
            return jsonify({"message": "Cannot perform that function"})
     user = User.query.filter_by(public_id = user_id ).first()
     if user:
        user.is_admin = True
        db.session.commit()
        return jsonify({"user": "User promoted"})
     else:
        return jsonify({"user": "User not found"})
    

@app.route('/user/<user_id>', methods=["DELETE"])
@check_token
def delete_user(current_user, user_id):
    if not current_user.is_admin:
            return jsonify({"message": "Cannot perform that function"})
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


# Todo routes
@app.route('/todo/', methods=['GET'])
@check_token
def get_all_todo(current_user):
    todos=None
    if current_user.is_admin:
        todos = Todo.query.all()
    else: 
        todos = Todo.query.filter_by(user_id=current_user.public_id).all()
        
    if todos:
        todoOutput = []
        for todo in todos:
            todo_data={}
            todo_data['id'] = todo.id
            todo_data['text'] = todo.text
            todo_data['completed'] = todo.completed
            todo_data['user_id'] = todo.user_id

            todoOutput.append(todo_data)        

        return jsonify({"todos": todoOutput})
    else:
        return jsonify({"todos": "No Todo found"})

@app.route('/todo/<todo_id>', methods=['GET'])
@check_token
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id= todo_id, user_id=current_user.public_id).first()
    if todo:
            todo_data={}
            todo_data['text'] = todo.text
            todo_data['completed'] = todo.completed
            todo_data['user_id'] = todo.user_id


            return jsonify({"todos": todo_data})
    else:
            return jsonify({"todos": "No Todo found"})

@app.route('/todo/', methods=['POST'])
@check_token
def create_todo(current_user):
    data = request.get_json()
    new_todo_text = data['text']
    new_todo_user_id = current_user.public_id
    new_todo = Todo(text= new_todo_text, user_id=new_todo_user_id)
    db.session.add(new_todo)
    db.session.commit()
    return jsonify({
        "message":"New Todo Added"
    })

@app.route('/todo/<todo_id>', methods=['PUT'])
@check_token
def complete_all_todo(current_user, todo_id):
    todo = Todo.query.filter_by(id= todo_id, user_id=current_user.public_id).first()
    if todo:
        todo.completed = True
        db.session.commit()
        return jsonify({
            "message":"Todo  now completed"
        })
    else:
            return jsonify({"todos": "No Todo found"})

@app.route('/todo/<todo_id>', methods=['DELETE'])
@check_token
def delete_todo(current_user, todo_id):
     todo = Todo.query.filter_by(id= todo_id, user_id=current_user.public_id).first()
     if todo:
        db.session.delete(todo)
        db.session.commit()
        return jsonify({"todo": "Todo Deleted"})
     else:
        return jsonify({"todo": "Todo not found"})
     

if __name__ == "__main__":
    db.create_all()
    # admin_user = User(public_id = "admin" , username = "admin", password=generate_password_hash("admin", method='sha256'), is_admin=True )
    # db.session.add(admin_user)
    # db.session.commit()
    app.run(debug=True)