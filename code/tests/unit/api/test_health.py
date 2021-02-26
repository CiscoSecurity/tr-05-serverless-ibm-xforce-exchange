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


def test_health_call_with_ssl_error_failure(
        route, client, valid_jwt,
        ssl_error_expected_body,
        xforce_response_public_key
):
    with patch('requests.request') as get_mock, \
            patch('requests.get') as get_public_key_mock:
        get_public_key_mock.return_value = xforce_response_public_key

        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == ssl_error_expected_body


def test_health_call_success(route, client, valid_jwt, xforce_response_ok,
                             xforce_response_public_key):
    with patch('requests.request') as get_mock, \
            patch('requests.get') as get_public_key_mock:
        get_public_key_mock.return_value = xforce_response_public_key
        get_mock.return_value = xforce_response_ok
        response = client.post(route, headers=headers(valid_jwt()))

        assert response.status_code == HTTPStatus.OK
        assert response.json == {'data': {'status': 'ok'}}
