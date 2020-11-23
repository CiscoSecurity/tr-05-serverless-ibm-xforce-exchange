from http import HTTPStatus
from unittest.mock import patch, MagicMock

from pytest import fixture
from requests.exceptions import SSLError

from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'ibm.com'}]


def test_enrich_call_success(
        route, client, valid_jwt, valid_json,
        xforce_response_success_enrich, success_enrich_expected_body
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_success_enrich

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()
        assert response.get('errors') is None

        if response.get('data') and isinstance(response['data'], dict):
            for s in response['data'].get('verdicts', {}).get('docs', []):
                assert s.pop('valid_time')

        assert response == success_enrich_expected_body


def test_enrich_call_with_critical_error(
        route, client, valid_jwt, valid_json,
        xforce_response_service_unavailable,
        service_unavailable_expected_body,
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_service_unavailable
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == service_unavailable_expected_body


def test_enrich_call_with_not_critical_error(
        route, client, valid_jwt, valid_json,
        xforce_response_not_found, not_found_expected_body,
):
    with patch('requests.request') as get_mock:
        get_mock.return_value = xforce_response_not_found
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == not_found_expected_body


def test_enrich_call_with_ssl_error(
        route, client, valid_jwt, valid_json,
        ssl_error_expected_body
):
    with patch('requests.request') as get_mock:
        mock_exception = MagicMock()
        mock_exception.reason.args.__getitem__().verify_message \
            = 'self signed certificate'
        get_mock.side_effect = SSLError(mock_exception)

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == ssl_error_expected_body


def test_enrich_call_with_key_error(
        route, client, valid_jwt, valid_json,
        xforce_response_ok, key_error_expected_body
):
    with patch('requests.request') as get_mock,\
            patch('api.mappings.Domain.extract_verdict') as extract_mock:
        get_mock.return_value = xforce_response_ok
        extract_mock.side_effect = [KeyError('foo')]

        response = client.post(
            route, headers=headers(valid_jwt),
            json=valid_json
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == key_error_expected_body
