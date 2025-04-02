# server.py
from flask import Flask, request, jsonify
from secure_messaging import SecureMessagingApp
from flask_cors import CORS
import jwt
import datetime

app = Flask(__name__)
CORS(app)
messaging_app = SecureMessagingApp()

# Secret key for JWT tokens
SECRET_KEY = 'your-secret-key-keep-it-safe'

def generate_token(username):
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    return jwt.encode(
        {'user': username, 'exp': expiration},
        SECRET_KEY,
        algorithm='HS256'
    )

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if messaging_app.register_user(username, password):
        token = generate_token(username)
        return jsonify({'status': 'success', 'token': token})
    return jsonify({'status': 'error', 'message': 'Username already exists'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if messaging_app.authenticate_user(username, password):
        token = generate_token(username)
        return jsonify({'status': 'success', 'token': token})
    return jsonify({'status': 'error', 'message': 'Invalid credentials'})

@app.route('/send_message', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        sender = payload['user']
        
        data = request.get_json()
        recipient = data.get('recipient')
        message = data.get('message')
        
        if messaging_app.send_message(sender, recipient, message):
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Failed to send message'})
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token expired'})
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'})

@app.route('/get_messages', methods=['GET'])
def get_messages():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'status': 'error', 'message': 'No token provided'})
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload['user']
        messages = messaging_app.get_messages(username)
        return jsonify({
            'status': 'success',
            'messages': [
                {
                    'sender': sender,
                    'message': message,
                    'timestamp': timestamp
                }
                for sender, message, timestamp in messages
            ]
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'status': 'error', 'message': 'Token expired'})
    except jwt.InvalidTokenError:
        return jsonify({'status': 'error', 'message': 'Invalid token'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)