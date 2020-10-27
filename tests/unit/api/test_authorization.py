from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture

from api.errors import AUTH_ERROR
from .utils import headers


def routes():
    yield '/health'
    yield '/deliberate/observables'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'ibm.com'}]


def authorization_error(message, prefix='Authorization failed: '):
    return {
        'errors': [
            {
                'code': AUTH_ERROR,
                'message': f'{prefix}{message}',
                'type': 'fatal'
            }
        ]
    }


def test_call_with_authorization_header_missing(
        route, client, valid_json
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(
        'Authorization header is missing'
    )


def test_call_with_authorization_type_error(route, client, valid_json):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Basic blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong authorization type')


def test_call_with_jwt_structure_error(route, client, valid_json):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Bearer blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong JWT structure')


def test_call_with_jwt_payload_structure_error(
        route, client, valid_json, valid_jwt_with_wrong_payload
):
    response = client.post(
        route, json=valid_json, headers=headers(valid_jwt_with_wrong_payload)
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('Wrong JWT payload structure')


def test_call_with_wrong_secret_key_error(
        route, client, valid_json, valid_jwt,
):
    valid_secret_key = client.application.secret_key
    client.application.secret_key = 'wrong_key'

    response = client.post(
        route, json=valid_json, headers=headers(valid_jwt)
    )

    client.application.secret_key = valid_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error(
        'Failed to decode JWT with provided key'
    )


def test_call_with_missed_secret_key_error(
        route, client, valid_json, valid_jwt
):
    valid_secret_key = client.application.secret_key
    client.application.secret_key = None

    response = client.post(
        route, json=valid_json, headers=headers(valid_jwt)
    )

    client.application.secret_key = valid_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_error('<SECRET_KEY> is missing')


def test_call_with_unauthorized_creds(
        route, client, valid_jwt, valid_json,
        xforce_response_unauthorized_creds
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_unauthorized_creds
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_error(
            'Authorization failed on IBM X-Force Exchange side', prefix=''
        )
