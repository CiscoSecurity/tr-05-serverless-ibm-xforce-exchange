import json
from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import UNKNOWN, INVALID_ARGUMENT
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
        {'error': 'Not authorized.'}
    )


@fixture(scope='session')
def xforce_response_service_unavailable(secret_key):
    return xforce_api_response_mock(
        HTTPStatus.SERVICE_UNAVAILABLE,
        {'error': 'SERVICE UNAVAILABLE.'}
    )


@fixture(scope='session')
def xforce_response_not_found(secret_key):
    return xforce_api_response_mock(
        HTTPStatus.NOT_FOUND,
        {'error': 'NOT FOUND.'}
    )


@fixture(scope='session')
def xforce_response_ok(secret_key):
    return xforce_api_response_mock(HTTPStatus.OK, payload='OK')


@fixture(scope='session')
def xforce_response_success_enrich_report(secret_key):
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
def xforce_response_success_enrich_resolve(secret_key):
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
def xforce_response_success_enrich_api_linkage(secret_key):
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
    with open('tests/unit/data/' + 'enrich_observe_success.json') as file:
        data = json.load(file)

        if route.endswith('/deliberate/observables'):
            data = {'data': {'verdicts': data['data']['verdicts']}}

    return expected_body(
        route, data, refer_body=success_enrich_refer_body
    )


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
