import json
from uuid import uuid5, uuid4

from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, DecodeError
from flask import request, current_app, jsonify, g

from api.errors import InvalidArgumentError, AuthorizationError


def get_credentials():
    """
    Decode Authorization token. Extract and validate credentials.
    """

    expected_errors = {
        AssertionError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }

    token = get_auth_token()
    try:
        credentials = jwt.decode(token, current_app.config['SECRET_KEY'])

        assert credentials.get('key')
        assert credentials.get('password')

        return credentials
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.
    """

    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }

    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(
            f'Invalid JSON payload received. {json.dumps(message)}'
        )

    return data


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_result():
    result = {'data': {}}

    if g.get('verdicts'):
        result['data']['verdicts'] = format_docs(g.verdicts)
    if g.get('judgements'):
        result['data']['judgements'] = format_docs(g.judgements)
    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)
    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)

    if g.get('errors'):
        result['errors'] = g.errors

        if not result.get('data'):
            result.pop('data', None)

    return jsonify(result)


def add_error(error):
    g.errors = [*g.get('errors', []), error.json]


def all_subclasses(cls):
    """
    Retrieve set of class subclasses recursively.

    """
    subclasses = set(cls.__subclasses__())
    return subclasses.union(s for c in subclasses for s in all_subclasses(c))


def time_format(time):
    return f'{time.isoformat(timespec="seconds")}Z'


def transient_id(entity_type: str, base_value=None) -> str:
    uuid = (uuid5(current_app.config['NAMESPACE_BASE'],
                  f'{entity_type}-{base_value}')
            if base_value else uuid4())
    return f'transient:{entity_type}-{uuid}'
