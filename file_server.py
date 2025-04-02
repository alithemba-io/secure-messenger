from flask import Flask, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def serve_app():
    return send_file('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)