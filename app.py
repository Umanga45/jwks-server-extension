import sqlite3
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import json
import jwt
import datetime
import time

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS keys')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid TEXT PRIMARY KEY,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
    ''')

    current_time = int(time.time())
    cursor.execute('SELECT COUNT(*) FROM keys WHERE exp > ?', (current_time,))
    key_count = cursor.fetchone()[0]

    if key_count == 0:
        new_key = generate_key()
        serialized_key = serialize_key(new_key)
        exp_time = current_time + 3600

        cursor.execute('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)', ('goodKID', serialized_key, exp_time))

    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    return conn

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def serialize_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

def deserialize_key(serialized_key):
    return serialization.load_pem_private_key(serialized_key, password=None)

def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    cursor.execute('SELECT key, kid FROM keys WHERE exp > ?', (current_time,))
    keys = []

    for row in cursor.fetchall():
        private_key = deserialize_key(row[0])
        numbers = private_key.private_numbers()
        jwk_data = {
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": row[1],
            "n": int_to_base64(numbers.public_numbers.n),
            "e": int_to_base64(numbers.public_numbers.e),
        }
        keys.append(jwk_data)

    conn.close()
    return jsonify({"keys": keys})

@app.route('/auth', methods=['POST'])
def auth():
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = int(time.time())
    expired = request.args.get('expired')

    if expired:
        cursor.execute('SELECT key, kid FROM keys WHERE exp < ?', (current_time,))
    else:
        cursor.execute('SELECT key, kid FROM keys WHERE exp > ?', (current_time,))

    row = cursor.fetchone()
    conn.close()

    if row:
        private_key = deserialize_key(row[0])
        token_payload = {
            "user": "username",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        if expired:
            token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)

        encoded_jwt = jwt.encode(token_payload, private_key, algorithm="RS256", headers={"kid": row[1]})
        
        # Debug log
        print("Generated JWT:", encoded_jwt)
        
        return jsonify({"token": encoded_jwt})

    print("No valid key found")
    return "No valid key found", 404

if __name__ == '__main__':
    init_db()
    app.run(port=8080)
