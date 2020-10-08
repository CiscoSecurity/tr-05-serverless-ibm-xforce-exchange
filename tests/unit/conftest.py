from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import UNAUTHORIZED, UNKNOWN
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'key': 'key', 'password': 'password'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key, check=False).decode('ascii')


@fixture(scope='session')
def valid_jwt_with_wrong_payload(client):
    header = {'alg': 'HS256'}

    payload = {'key': 'key'}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key, check=False).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['key'] = 'wrong'

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def xforce_api_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or {}
    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='session')
def xforce_response_unauthorized_creds(secret_key):
    return xforce_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        {"error": "Not authorized."}
    )


@fixture(scope='session')
def xforce_response_ok(secret_key):
    return xforce_api_response_mock(HTTPStatus.OK)


def authorization_error(message):
    return {
        'data': {},
        'errors': [
            {
                'code': UNAUTHORIZED,
                'message': message,
                'type': 'fatal'
            }
        ]
    }


@fixture(scope='module')
def authorization_header_missing_error_expected_body(route):
    return authorization_error(
        'Authorization failed: Authorization header is missing'
    )


@fixture(scope='module')
def authorization_type_error_expected_body(route):
    return authorization_error(
        'Authorization failed: Wrong authorization type',
    )


@fixture(scope='module')
def jwt_structure_error_expected_body(route):
    return authorization_error(
        'Authorization failed: Wrong JWT structure',
    )


@fixture(scope='module')
def jwt_payload_structure_error_expected_body(route):
    return authorization_error(
        'Authorization failed: Wrong JWT payload structure',
    )


@fixture(scope='module')
def wrong_secret_key_error_expected_body(route):
    return authorization_error(
        'Authorization failed: Failed to decode JWT with provided key'
    )


@fixture(scope='module')
def missed_secret_key_error_expected_body(route):
    return authorization_error(
        'Authorization failed: <SECRET_KEY> is missing'
    )


@fixture(scope='module')
def unauthorized_creds_expected_body(route):
    return authorization_error(
        'Authorization failed on IBM X-Force Exchange side'
    )


@fixture(scope='module')
def ssl_error_expected_body(route):
    return {
        'data': {},
        'errors': [
            {
                'code': UNKNOWN,
                'message': 'Unable to verify SSL certificate:'
                           ' Self signed certificate',
                'type': 'fatal'
            }
        ]
    }
