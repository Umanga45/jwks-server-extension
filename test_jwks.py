import pytest
import json
import time
from app import app, get_db_connection

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_auth_with_expired_key(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    assert 'token' in json.loads(response.data)

def test_auth_no_valid_key(client):
    response = client.post('/auth')
    assert response.status_code == 404
    assert b'No valid key found' in response.data

def test_get_jwks_no_keys(client):
    with get_db_connection() as conn:
        conn.execute('DELETE FROM keys')
        conn.commit()
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert json.loads(response.data) == {"keys": []}

def test_auth_with_valid_key(client):
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'token' in json.loads(response.data)

def test_get_jwks_with_keys(client):
    with get_db_connection() as conn:
        conn.execute('DELETE FROM keys')
        valid_key = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx5X/qPEluXITMYa1XMgDjTnbAh0fJfXzOZiapJz1epIkpqVv\n8EEarcXcuQQxBExvgiO5rhdNKyhvWKUCNcQQysxrwnmdTxxQpOnf1RdGr7bnE8YD\nYqVwvMRhI3KizAe4+xYraB0YCJedz0dbtkmGNBp7r4m5dpp4aRY/iCFxIJ9D3Z4o\nBO3oMOZ+tqbxHq8CCU9p97Gtu9dwpKQ37dIl+WJPrBAdsoE1ROoI4MwVRe3Pokf+\n9+XgEXUvAwqFrv5XrfO1UCjuWegyWIuP1Q8pIuUxY4J+Q7xiSeh3Oj6IQ1kNeRm9\nb7X2rC3yn2LB03JACXVcs30T0vzqxRz/ygIoYwIDAQABAoIBABaau/pn2XRv4ZGd\n5qOL+a8Aivfp0XHMsc/nozgamMjZjXIcUZm93eYpfy6rNVv9xjFQl4KKnBBTw4yg\nH6h0PMyjK186w+DGXbHX1SR+vuA+0FwSdKazAxo2CaRootyF0WMKpz7i8KpkdZiY\nxd/W4u66wyBl8k3m/9UzEl36H6Rogh564uu78sMp2dQAwQ7emdTCovGryRUisl7m\n0OCWwpbUmWXXeCzJkQ7+GaQF2882Mr0vsjgB5F8wU7/cuCF5vxWMbfpMFaClAt9h\ntfhLplbgwq+nh1tATtfYe5Hk242E641f2XUEMLwDnE9eXmKgOSf/+5H2Fp28Gg/D\nafrUBiUCgYEA6U3zV9gXZl5QZWbVM+KP6f80JdazDXRgUlAjYOW0EH4Pd+gGRMgt\nGceEvw4F2xuCJWP7whzphdsJX9wN0OnG7gXFwcyJjW5aVrrDVTPIHEjvYg/2QE+Z\np1KA+B9bwTqApiaTx0MMSleIyUB1raz/eZjehvljz9SQ8/n9sqIzgQ8CgYEA2wBY\nUTJyb2+LkANjIOfoyGy7It7ENYBuxZFAIKupvnGbtjWVTlOm3ux/s/Go7xis4wR1\n9NEMg9bBy1FBYBvOoYC9ceBuqhl0hkrdr88BvQqNgr6uyHjUR7sfS5B7J6lpxnyR\n1PcqBJ4HA9jBQDGaHkKcDsH09mXmkJZ5e8/Oe20CgYBrZ8p+h2oGY6cJd7TxZP0y\nEZ4VSWk26XuqiWAwLK+f5BkE75lrMuiodJTlS/RgMaLRydzOOXc8e2Euc2Uc53MA\ng0HOfXZZ2RLX2LUyVVtrwhwKfiS06LBpOm9LS0x3gZJWa24fDvvqga/kTrueUAVx\nGnJfmxJbTJXK7Czifw/M+wKBgQC6jPauY/ya9De8O0Zrt2DRqd1W/M/Ci17QqMQp\nkFENyxTLB6XhjNxutKKrk8VFto0+7IPWQWUZwQxftx2rUsSXSmUV5goel4RtCMUC\nh6GBeMXGg8u7NUIOwFUON0rRJDzYOTC4arq+KCbtnewwVJBmCnOJFqsmYPMgYy2k\nzAWlmQKBgFxauePHuWJNxEvAKrFJcT9AgHfPS3iT1o1vVeMp7PZJjwCRk2UO/Qhh\nFEkP0KFuEjjaHx5t7bfDjn5X7IuWV4Ez3md7HA8hqCFtJKWTKFdyeAqRpqHbe31V\nrBi8k7CAgPjhdSw+3Z3zmDFoLtIEPYx9CPSBCcyW9mPwc+Xg0dTY\n-----END RSA PRIVATE KEY-----\n'
        conn.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (valid_key, int(time.time()) + 3600))
        conn.commit()
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    keys_data = json.loads(response.data)
    assert len(keys_data["keys"]) > 0

def test_jwks_with_no_keys(client):
    with get_db_connection() as conn:
        conn.execute('DELETE FROM keys')
        conn.commit()
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert json.loads(response.data) == {"keys": []}
