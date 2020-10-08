from flask import Blueprint, current_app

from api.client import XForceClient
from api.utils import get_credentials, jsonify_data

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    client = XForceClient(current_app.config['API_URL'],
                          credentials,
                          current_app.config['USER_AGENT'])

    _ = client.usage()

    return jsonify_data({'status': 'ok'})
