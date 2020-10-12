from functools import partial

from flask import Blueprint, current_app, g

from api.client import XForceClient
from api.mappings import Mapping
from api.schemas import ObservableSchema
from api.utils import get_json, jsonify_data, get_credentials, jsonify_result

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    credentials = get_credentials()
    observables = get_observables()

    client = XForceClient(current_app.config['API_URL'],
                          credentials,
                          current_app.config['USER_AGENT'])

    g.verdicts = []

    try:
        for observable in observables:
            mapping = Mapping.for_(observable)

            if mapping:
                client_data = client.get_data(observable)
                verdict = mapping.extract_verdict(client_data)
                if verdict:
                    g.verdicts.append(verdict)

    except KeyError:
        g.errors = [{
            'type': 'fatal',
            'code': 'key error',
            'message': 'The data structure of IBM X-Force Exchange'
                       ' has changed. The module is broken.'
        }]

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
