from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_authorization_header_missing(
        route, client, authorization_header_missing_error_expected_body
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_header_missing_error_expected_body


def test_health_call_with_authorization_type_error(
        route, client, authorization_type_error_expected_body
):
    response = client.post(route, headers={'Authorization': 'Basic blabla'})

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_type_error_expected_body


def test_health_call_with_jwt_structure_error(
        route, client, jwt_structure_error_expected_body
):
    response = client.post(route, headers={'Authorization': 'Bearer blabla'})

    assert response.status_code == HTTPStatus.OK
    assert response.json == jwt_structure_error_expected_body


def test_health_call_with_jwt_payload_structure_error(
        route, client, valid_jwt_with_wrong_payload,
        jwt_payload_structure_error_expected_body
):
    response = client.post(route,
                           headers=headers(valid_jwt_with_wrong_payload))

    assert response.status_code == HTTPStatus.OK
    assert response.json == jwt_payload_structure_error_expected_body


def test_health_call_with_wrong_secret_key_error(
        route, client, valid_jwt,
        wrong_secret_key_error_expected_body
):
    valid_secret_key = client.application.secret_key
    client.application.secret_key = 'wrong_key'

    response = client.post(route, headers=headers(valid_jwt))

    client.application.secret_key = valid_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == wrong_secret_key_error_expected_body


def test_health_call_with_missed_secret_key_error(
        route, client, valid_jwt,
        missed_secret_key_error_expected_body
):
    valid_secret_key = client.application.secret_key
    client.application.secret_key = None

    response = client.post(route, headers=headers(valid_jwt))

    client.application.secret_key = valid_secret_key

    assert response.status_code == HTTPStatus.OK
    assert response.json == missed_secret_key_error_expected_body


def test_health_call_with_unauthorized_creds(
        route, client, valid_jwt,
        xforce_response_unauthorized_creds,
        unauthorized_creds_expected_body,
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_unauthorized_creds
        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == unauthorized_creds_expected_body


def test_health_call_with_ssl_error_failure(
        route, client, valid_jwt,
        ssl_error_expected_body
):
    with patch('requests.request') as get_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt)
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == ssl_error_expected_body


def test_health_call_success(route, client, valid_jwt, xforce_response_ok):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_ok
        response = client.post(route, headers=headers(valid_jwt))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
