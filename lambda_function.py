from flask import Flask, request, jsonify, make_response
from werkzeug.security import generate_password_hash, check_password_hash
# from config import username, password, endpoint, secretKey
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
import jwt
import awsgi
from datetime import datetime, timedelta

# Initialize Flask and SQLAlchemy
app = Flask(__name__)
CORS(app, resources={
    r"/*": {"origins": ["https://purepoker.world"], "supports_credentials": True}
}, allow_headers=["Content-Type", "Authorization", "X-Api-Key", "x-access-tokens"])

username = os.getenv('username')
password = os.getenv('password')
endpoint = os.getenv('endpoint')
secretKey = os.getenv('secretKey')

app.config['SECRET_KEY'] = secretKey
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{username}:{password}@{endpoint}/pure_poker'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Wrap db.create_all in an application context
with app.app_context():
    db.create_all()

# User Model
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

@app.route('/', methods=['GET'])
def health_check():
    return jsonify({'status': 'Authentication is healthy'}), 200

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    hashed_password = generate_password_hash(data['password'])
    
    # Check if email is provided in the request
    if 'email' not in data or not data['email']:
        return jsonify({'message': 'Email is required'}), 400
    
    username = data.get('username')
    # Check if username exists
    if Users.query.filter_by(username=username).first():
        # Username taken, generate suggestions
        return jsonify({'message': 'Username taken already, try another one.'}), 409
    
    email = data.get('email')
    # Check if email exists
    if Users.query.filter_by(email=email).first():
        # TODO: Send an email to the person with that email to tell them that someone tried to login!
        return jsonify({'message': 'Email taken already.'}), 409

    new_user = Users(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'An error occured, please try another email or username', 'error': str(e)}), 500

    expires = datetime.utcnow() + timedelta(hours=24)
    token = jwt.encode({
        'username': new_user.username,
        'email': new_user.email,
        'exp': expires
    }, app.config['SECRET_KEY'], algorithm="HS256")

    response = make_response(jsonify({'message': 'Registration successful'}), 200)
    response.set_cookie('pure-poker-token', token, expires=expires, httponly=True, path='/', secure=True, samesite='None')
    return response

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = Users.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        expires = datetime.utcnow() + timedelta(hours=24) 
        token = jwt.encode({
            'username': user.username,
            'email': user.email,
            'exp': expires 
        }, app.config['SECRET_KEY'], algorithm="HS256")
        response = make_response(jsonify({'message': 'Login successful'}), 200)
        response.set_cookie('pure-poker-token', token, expires=expires, httponly=True, path='/', secure=True, samesite='None')
        return response
    return jsonify({'message': 'Invalid credentials'}), 401

# User Logout
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({'message': 'Logout successful'}), 200)
    response.set_cookie('pure-poker-token', '', expires=0)
    return response

@app.route('/validate_token', methods=['POST'])
def validate_token():
    auth_cookie = request.cookies.get('pure-poker-token')
    if auth_cookie and is_valid_token(auth_cookie):
        return jsonify({'message': 'Token is valid'}), 200
    else:
        return jsonify({'message': 'Token is invalid'}), 401

def is_valid_token(auth_cookie):
    try:
        # Decode the token
        data = jwt.decode(auth_cookie, app.config['SECRET_KEY'], algorithms=["HS256"])
        # Convert current UTC time to a Unix timestamp
        current_time = datetime.utcnow()
        current_timestamp = int(current_time.timestamp())
        # Check if the token has expired
        if data['exp'] < current_timestamp:
            return False
        return True
    except jwt.ExpiredSignatureError:
        # Token has expired
        return False
    except jwt.InvalidTokenError:
        # Token is invalid
        return False

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=8013, use_reloader=False)

def lambda_handler(event, context):
    print("Here we go!")
    response = awsgi.response(app, event, context)

    # Check if the headers exist in the event and set the origin accordingly
    headers = event.get('headers', {})

    origin = headers.get('origin') if headers else 'https://purepoker.world'

    # Prepare the response headers
    response_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Access-Control-Allow-Methods": "GET,PUT,POST,DELETE,OPTIONS"
    }

    # Construct the modified response
    modified_response = {
        "isBase64Encoded": False,
        "statusCode": response['statusCode'],
        "headers": response_headers,
        "multiValueHeaders": response.get('multiValueHeaders', {}),
        "body": response['body']
    }

    # Check if 'Set-Cookie' is in the Flask response headers and add it to the multiValueHeaders
    flask_response_headers = response.get('headers', {})
    if 'Set-Cookie' in flask_response_headers:
        # AWS API Gateway expects the 'Set-Cookie' header to be in multiValueHeaders
        modified_response['multiValueHeaders']['Set-Cookie'] = [flask_response_headers['Set-Cookie']]

    return modified_response
    
