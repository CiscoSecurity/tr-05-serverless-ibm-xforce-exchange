from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial
from os import cpu_count

from flask import Blueprint, current_app, g

from api.client import XForceClient
from api.errors import XForceKeyError
from api.mappings import Mapping
from api.schemas import ObservableSchema
from api.utils import (
    get_json, jsonify_data, get_credentials, jsonify_result, add_error
)

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    def deliberate(observable):
        mapping = Mapping.for_(observable)
        client_data = client.get_data(observable)
        if client_data:
            return mapping.extract_verdict(
                client_data, number_of_days_verdict_valid
            )

    credentials = get_credentials()

    observables = get_observables()
    observables = [ob for ob in observables
                   if ob['type'] in current_app.config['X_FORCE_OBSERVABLES']]

    client = XForceClient(current_app.config['API_URL'],
                          credentials,
                          current_app.config['USER_AGENT'])

    number_of_days_verdict_valid = int(
        current_app.config['NUMBER_OF_DAYS_VERDICT_IS_VALID']
    )

    g.verdicts = []

    try:
        with ThreadPoolExecutor(
                max_workers=min(len(observables), (cpu_count() or 1) * 5)
        ) as executor:
            iterator = executor.map(deliberate, observables)

        g.verdicts = [verdict for verdict in iterator if verdict is not None]

    except KeyError:
        add_error(XForceKeyError())

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    client = XForceClient(current_app.config['API_URL'],
                          credentials,
                          current_app.config['USER_AGENT'])

    number_of_days_verdict_valid = int(
        current_app.config['NUMBER_OF_DAYS_VERDICT_IS_VALID']
    )

    g.verdicts = []
    try:
        for observable in observables:
            mapping = Mapping.for_(observable)

            if mapping:
                client_data = client.get_data(observable)

                if client_data:
                    verdict = mapping.extract_verdict(
                        client_data, number_of_days_verdict_valid
                    )

                    if verdict:
                        g.verdicts.append(verdict)

    except KeyError:
        add_error(XForceKeyError())

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    return jsonify_data([])
