from flask import Flask, request, jsonify
import sqlite3
import os
import subprocess

app = Flask(__name__)

DATABASE = 'test.db'

@app.route('/ping', methods=['GET'])
def ping():
    ip = request.args.get('ip', '')
    output = subprocess.getoutput(f"ping -c 4 {ip}")
    return jsonify({"output": output})

@app.route('/login', methods=['POST'])
def login():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    data = request.json
    username = data.get("username")
    password = data.get("password")

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"message": "Login successful!"})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    file.save(os.path.join("uploads", file.filename))
    return jsonify({"message": "File uploaded successfully!"})

@app.route('/redirect', methods=['GET'])
def open_redirect():
    url = request.args.get('url', '')
    return f'<script>window.location.href="{url}";</script>'

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'password')")
        conn.commit()
        conn.close()
    
    app.run(debug=True)
