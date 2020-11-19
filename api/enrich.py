from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial
from os import cpu_count

from flask import Blueprint, current_app, g

from api.client import XForceClient, XFORCE_OBSERVABLE_TYPES
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
        client_data = client.report(observable)
        if client_data:
            return mapping.extract_verdict(
                client_data, number_of_days_verdict_valid
            )

    credentials = get_credentials()

    observables = get_observables()
    observables = [
        ob for ob in observables if ob['type'] in XFORCE_OBSERVABLE_TYPES
    ]

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
    number_of_days_judgement_valid = int(
        current_app.config['NUMBER_OF_DAYS_JUDGEMENT_IS_VALID']
    )
    number_of_days_indicator_valid = int(
        current_app.config['NUMBER_OF_DAYS_INDICATOR_IS_VALID']
    )

    g.verdicts = []
    g.sightings = []
    g.judgements = []
    g.indicators = []

    try:
        for observable in observables:
            mapping = Mapping.for_(observable)

            if mapping:
                report = client.report(observable)

                if report:
                    verdict = mapping.extract_verdict(
                        report, number_of_days_verdict_valid
                    )
                    if verdict:
                        g.verdicts.append(verdict)

                    g.judgements.extend(
                        mapping.extract_judgements(
                            report, number_of_days_judgement_valid
                        )
                    )

                api_linkage = client.api_linkage(observable)
                if api_linkage:
                    sightings, indicators = (
                        mapping.extract_sightings_and_indicators(
                            api_linkage, report, current_app.config['UI_URL'],
                            number_of_days_indicator_valid
                        )
                    )
                    g.sightings.extend(sightings)
                    g.indicators.extend(indicators)

    except KeyError:
        add_error(XForceKeyError())

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables = get_observables()

    ui_url = current_app.config['UI_URL']

    data = []
    for observable in observables:
        type_ = XFORCE_OBSERVABLE_TYPES.get(observable['type'])
        if type_:
            data.append(
                {
                    'id': (
                        'ref-ibm-xforce-exchange-search-{type}-{value}'.format(
                            **observable
                        )
                    ),
                    'title': f'Search for this {type_}',
                    'description': (
                        f'Lookup this {type_} on IBM X-Force Exchange'
                    ),
                    'url': XForceClient.refer_link(ui_url, observable),
                    'categories': ['Search', 'IBM X-Force Exchange'],
                }
            )

    return jsonify_data(data)
