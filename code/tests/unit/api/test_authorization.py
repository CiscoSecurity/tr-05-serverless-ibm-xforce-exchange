from .utils import headers
from pytest import fixture
from http import HTTPStatus
from unittest.mock import patch
from requests.exceptions import InvalidURL, ConnectionError
from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWT_STRUCTURE,
    WRONG_PAYLOAD_STRUCTURE,
    WRONG_JWKS_HOST,
    KID_NOT_FOUND,
    WRONG_AUDIENCE,
    WRONG_KEY, JWKS_HOST_MISSING
)


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


def test_call_with_authorization_header_missing(
        route, client, valid_json, authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        NO_AUTH_HEADER
    )


def test_call_with_authorization_type_error(route, client, valid_json,
                                            authorization_errors_expected_payload):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Basic blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE
    )


def test_call_with_jwt_structure_error(route, client, valid_json,
                                       authorization_errors_expected_payload):
    response = client.post(
        route, json=valid_json, headers={'Authorization': 'Bearer blabla'}
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


@patch('requests.get')
def test_call_with_missing_jwks_host(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        xforce_response_public_key
):
    mock_request.return_value = xforce_response_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(jwks_host=''))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING
    )


@patch('requests.get')
def test_call_with_wrong_key(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        xforce_response_wrong_public_key
):
    mock_request.return_value = xforce_response_wrong_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt())
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )


@patch('requests.get')
def test_call_with_jwt_payload_structure_error(
        mock_request, route, client, valid_json, valid_jwt,
        xforce_response_public_key,
        xforce_response_unauthorized_creds,
        authorization_errors_expected_payload
):
    mock_request.side_effect = (xforce_response_unauthorized_creds, xforce_response_public_key)
    response = client.post(
        route, json=valid_json, headers=headers(valid_jwt(wrong_structure=True))
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE
    )


def test_call_with_unauthorized_creds(
        route, client, valid_jwt, valid_json,
        xforce_response_unauthorized_creds,
        xforce_response_public_key,
        authorization_errors_expected_payload
):
    with patch('requests.request') as get_mock, \
            patch('requests.get') as get_public_key_mock:
        get_public_key_mock.return_value = xforce_response_public_key

        get_mock.return_value = xforce_response_unauthorized_creds

        response = client.post(
            route, headers=headers(valid_jwt()), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            'Authorization failed on IBM X-Force Exchange side'
        )


@patch('requests.get')
def test_call_with_wrong_audience(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        xforce_response_public_key
):
    mock_request.return_value = xforce_response_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(aud='wrong_aud'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


@patch('requests.get')
def test_call_with_wrong_kid(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload,
        xforce_response_public_key
):
    mock_request.return_value = xforce_response_public_key

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(kid='wrong_kid'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        KID_NOT_FOUND
    )


@patch('requests.get')
def test_call_with_wrong_jwks_host(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        mock_request.side_effect = error()

        response = client.post(
            route, json=valid_json, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )
