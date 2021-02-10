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
        xforce_response_success_enrich_report,
        xforce_response_success_enrich_resolve,
        xforce_response_success_enrich_api_linkage,
        success_enrich_expected_body
):
    with patch('requests.request') as get_mock:
        get_mock.side_effect = [xforce_response_success_enrich_report,
                                xforce_response_success_enrich_resolve,
                                xforce_response_success_enrich_api_linkage]

        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json
        )

        assert response.status_code == HTTPStatus.OK

        response = response.get_json()
        assert response.get('errors') is None

        if response.get('data') and isinstance(response['data'], dict):
            for _, entity_list in response['data'].items():
                for doc in entity_list['docs']:
                    doc.pop('valid_time', None)
                    doc.pop('observed_time', None)
                    doc.pop('id', None)
                    doc.pop('source_ref', None)
                    doc.pop('target_ref', None)

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


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_invalid_json(
        route, client, valid_jwt, invalid_json, invalid_json_expected_body,
):
    response = client.post(
        route, headers=headers(valid_jwt), json=invalid_json
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_body
