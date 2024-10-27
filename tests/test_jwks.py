import pytest
import json
import time
from app import app, get_db_connection

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def reset_database():
    with get_db_connection() as conn:
        conn.execute('DELETE FROM keys')
        conn.commit()

def test_auth_with_expired_key(client):
    with get_db_connection() as conn:
        # Create a valid expired key
        expired_key = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ...\n-----END RSA PRIVATE KEY-----\n'
        conn.execute('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)', ('expiredKID', expired_key, int(time.time()) - 3600))
        conn.commit()
    
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    assert 'token' in json.loads(response.data)

def test_auth_no_valid_key(client):
    reset_database()  # Clear the database
    response = client.post('/auth')
    assert response.status_code == 404
    assert b'No valid key found' in response.data

def test_get_jwks_no_keys(client):
    reset_database()  # Ensure there are no keys
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert json.loads(response.data) == {"keys": []}

def test_auth_with_valid_key(client):
    with get_db_connection() as conn:
        # Create a valid key
        valid_key = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n'
        conn.execute('INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)', ('goodKID', valid_key, int(time.time()) + 3600))
        conn.commit()
    
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'token' in json.loads(response.data)

def test_jwks_with_no_keys(client):
    reset_database()  # Ensure there are no keys
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert json.loads(response.data) == {"keys": []}
