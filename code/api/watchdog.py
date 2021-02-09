from flask import request, Blueprint, current_app
from api.errors import InvalidArgumentError, AuthorizationError
from api.utils import jsonify_data

watchdog_api = Blueprint('watchdog', __name__)


@watchdog_api.route('/watchdog', methods=['GET'])
def watchdog():
    expected_errors = {
        KeyError: 'Invalid Health Check',
    }

    try:
        watchdog_key = request.headers['Health-Check']
        return jsonify_data(watchdog_key)
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors)



