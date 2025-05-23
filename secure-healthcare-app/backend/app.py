# File: backend/app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change this in production
jwt = JWTManager(app)

KEY = b'ThisIsASecretKey123'  # 16-byte AES key (use env variable in prod)
DB = "health.db"

# --- Encryption / Decryption ---
def encrypt_data(data):
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_data(enc_data):
    raw = base64.b64decode(enc_data.encode('utf-8'))
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(KEY, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# --- Database Setup ---
def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        email TEXT PRIMARY KEY,
                        password TEXT,
                        role TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_email TEXT,
                        encrypted_data TEXT)''')
        conn.commit()
        # Insert John if not exists
        c.execute("SELECT * FROM users WHERE email=?", ("john@example.com",))
        if not c.fetchone():
                c.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                    ("john@example.com", "john123", "patient"))
                c.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)",
                    ("jay@example.com", "jay456", "doctor"))

# --- Routes ---
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Missing username or password"}), 400

    if username in users_db:
        return jsonify({"message": "User already exists"}), 409

    encrypted_password = encrypt(password)
    users_db[username] = encrypted_password
    return jsonify({"message": "User registered successfully!"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email, password = data['email'], data['password']
    with sqlite3.connect(DB) as conn:
        cur = conn.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = cur.fetchone()
        if user:
            token = create_access_token(identity=email)
            return jsonify({"token": token, "role": user[2]}), 200
        return jsonify({"msg": "Invalid credentials"}), 401

@app.route("/submit", methods=["POST"])
@jwt_required()
def submit():
    data = request.json
    user_email = get_jwt_identity()
    enc_data = encrypt_data(data['data'])
    with sqlite3.connect(DB) as conn:
        conn.execute("INSERT INTO records (user_email, encrypted_data) VALUES (?, ?)", (user_email, enc_data))
        return jsonify({"msg": "Data submitted securely"}), 200

@app.route("/records", methods=["GET"])
@jwt_required()
def get_records():
    user_email = get_jwt_identity()
    with sqlite3.connect(DB) as conn:
        cur = conn.execute("SELECT encrypted_data FROM records WHERE user_email=?", (user_email,))
        rows = cur.fetchall()
        decrypted = [decrypt_data(row[0]) for row in rows]
        return jsonify(decrypted)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
