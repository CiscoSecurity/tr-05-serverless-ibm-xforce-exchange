import jwt
import json

from app import app
from pytest import fixture
from http import HTTPStatus
from unittest.mock import MagicMock
from api.errors import (
    UNKNOWN,
    INVALID_ARGUMENT,
    AUTH_ERROR
)
from tests.unit.mock_for_tests import (
    PRIVATE_KEY,
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            password='some_pass',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            ctr_entities_limit=0,
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'password': password,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': ctr_entities_limit
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


def xforce_api_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or {}
    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='session')
def xforce_response_public_key():
    return xforce_api_response_mock(
        HTTPStatus.OK,
        EXPECTED_RESPONSE_OF_JWKS_ENDPOINT
    )


@fixture(scope='session')
def xforce_response_wrong_public_key():
    return xforce_api_response_mock(
        HTTPStatus.OK,
        RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
    )


@fixture(scope='session')
def xforce_response_unauthorized_creds():
    return xforce_api_response_mock(
        HTTPStatus.UNAUTHORIZED,
        {'error': 'Not authorized.'}
    )


@fixture(scope='session')
def xforce_response_service_unavailable():
    return xforce_api_response_mock(
        HTTPStatus.SERVICE_UNAVAILABLE,
        {'error': 'SERVICE UNAVAILABLE.'}
    )


@fixture(scope='session')
def xforce_response_not_found():
    return xforce_api_response_mock(
        HTTPStatus.NOT_FOUND,
        {'error': 'NOT FOUND.'}
    )


@fixture(scope='session')
def xforce_response_ok():
    return xforce_api_response_mock(HTTPStatus.OK, payload='OK')


@fixture(scope='session')
def xforce_response_success_enrich_report():
    return xforce_api_response_mock(
        HTTPStatus.OK,
        payload={
            'result': {
                'url': 'ibm.com',
                'cats': {},
                'score': 1,
                'application': {},
                'categoryDescriptions': {
                    'Software / Hardware': 'ABC',
                    'General Business': 'ABC'
                }
            },
            'tags': []
        }
    )


@fixture(scope='session')
def xforce_response_success_enrich_resolve():
    return xforce_api_response_mock(
        HTTPStatus.OK,
        payload={
            "A": [
                "129.42.38.10"
            ],
            "AAAA": [
                "2606:4700:0000:0000:0000:0000:6810:2548"
            ],
            "TXT": [],
            "MX": [],
            "Passive": {
                "query": "ibm.com",
                "records": [
                    {
                        "value": "23.194.131.195",
                        "type": "ip",
                        "recordType": "A",
                        "first": "2020-11-11T15:50:00Z",
                        "last": "2020-11-11T15:50:00Z"
                    },
                    {
                        "value": "23.194.131.195",
                        "type": "ip",
                        "recordType": "A",
                        "first": "2019-11-11T15:50:00Z",
                        "last": "2019-11-11T15:50:00Z"
                    },
                    {
                        "value": "2606:4700:0000:0000:0000:0000:6810:2548",
                        "type": "ip",
                        "recordType": "AAAA",
                        "first": "2020-11-11T15:50:00Z",
                        "last": "2020-11-11T15:50:00Z"
                    },
                    {
                        "value": "2606:4700:0000:0000:0000:0000:6810:2648",
                        "type": "ip",
                        "recordType": "AAAA",
                        "first": "2020-11-11T15:50:00Z",
                        "last": "2020-11-11T15:50:00Z"
                    }
                ]
            },
            "total_rows": 1892
        }
    )


@fixture(scope='session')
def xforce_response_success_enrich_api_linkage():
    return xforce_api_response_mock(
        HTTPStatus.OK,
        payload={
            "linkedEntities": [
                {
                    "title": "WannaCry",
                    "created": "2020-01-31T19:42:53.350Z",
                    "shared": "public",
                    "category": "3public",
                    "owner": {
                        "name": "Jane Ginn",
                        "userid": "http://www.ibm.com/310000EQ3H",
                        "isDisabled": False
                    },
                    "id": "62eece6bd7e7399a7366cd5d8e910182",
                    "iocs": {
                        "MAL": 275,
                        "BOT": 4,
                        "IP": 7,
                        "VUL": 2,
                        "URL": 1
                    },
                    "type": "casefile"
                },
                {
                    "title": "WCry2 Ransomware Outbreak",
                    "created": "2017-05-30T15:29:21.215Z",
                    "shared": "public",
                    "category": "3public",
                    "owner": {
                        "name": "Nick Bradley",
                        "userid": "http://www.ibm.com/2700039SGG",
                        "verified": "iris",
                        "isDisabled": False
                    },
                    "id": "8b186bc4459380a5606c322ee20c7729",
                    "iocs": {
                        "MAL": 509,
                        "URL": 65,
                        "IP": 37,
                        "file": 7
                    },
                    "type": "casefile"
                }
            ]
        }
    )


def expected_body(r, body, refer_body=None):
    if r.endswith('/refer/observables') and refer_body is not None:
        return refer_body

    return body


@fixture(scope='module')
def service_unavailable_expected_body(route, success_enrich_refer_body):
    return expected_body(
        route,
        {
            'errors': [
                {
                    'code': UNKNOWN,
                    'message': 'Unexpected response from IBM X-Force Exchange:'
                               ' SERVICE UNAVAILABLE.',
                    'type': 'fatal'
                }
            ]
        },
        refer_body=success_enrich_refer_body)


@fixture(scope='module')
def not_found_expected_body(route, success_enrich_refer_body):
    return expected_body(
        route, {'data': {}},
        refer_body=success_enrich_refer_body
    )


@fixture(scope='module')
def ssl_error_expected_body(route, success_enrich_refer_body):
    return expected_body(
        route,
        {
            'errors': [
                {
                    'code': UNKNOWN,
                    'message': 'Unable to verify SSL certificate:'
                               ' Self signed certificate',
                    'type': 'fatal'
                }
            ]
        },
        refer_body=success_enrich_refer_body)


@fixture(scope='module')
def success_enrich_expected_body(route, success_enrich_refer_body):
    def make_body(limit=0):
        with open('tests/unit/data/' + 'enrich_observe_success.json') as file:
            data = json.load(file)[str(limit)]

            if route.endswith('/deliberate/observables'):
                data = {'data': {'verdicts': data['data']['verdicts']}}

        return expected_body(
            route, data, refer_body=success_enrich_refer_body
        )
    return make_body


@fixture(scope='module')
def success_enrich_refer_body():
    return {
        'data': [
            {
                "categories": ["Search", "IBM X-Force Exchange"],
                "description": "Lookup this domain on IBM X-Force Exchange",
                "id": "ref-ibm-xforce-exchange-search-domain-ibm.com",
                "title": "Search for this domain",
                "url": "https://exchange.xforce.ibmcloud.com/url/ibm.com"
            }
        ]
    }


@fixture(scope='module')
def key_error_expected_body(route, success_enrich_refer_body):
    return expected_body(
        route,
        {
            'errors': [
                {
                    'type': 'fatal',
                    'code': 'key error',
                    'message': 'The data structure of IBM X-Force Exchange '
                               'has changed. The module is broken.'
                }
            ]
        },
        refer_body=success_enrich_refer_body
    )


@fixture(scope='module')
def invalid_json_expected_body(route):
    return expected_body(
        route,
        {
            'errors': [
                {
                    'code': INVALID_ARGUMENT,
                    'message':
                        'Invalid JSON payload received. {"0": {"value": '
                        '["Missing data for required field."]}}',
                    'type': 'fatal'
                }
            ]
        }
    )


@fixture(scope='module')
def authorization_errors_expected_payload(route):
    def _make_payload_message(message):
        payload = {
            'errors':
                [
                    {
                        'code': AUTH_ERROR,
                        'message': f'Authorization failed: {message}',
                        'type': 'fatal'
                    }
                ]

        }
        return payload

    return _make_payload_message
