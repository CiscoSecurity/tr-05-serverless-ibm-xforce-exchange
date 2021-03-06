from concurrent.futures.thread import ThreadPoolExecutor
from functools import partial
from os import cpu_count

from flask import Blueprint, current_app, g

from api.bundle import Bundle
from api.client import XForceClient, XFORCE_OBSERVABLE_TYPES
from api.errors import XForceKeyError
from api.mappings import Mapping, SIGHTING, DNSInformationMapping
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

    g.bundle = Bundle()

    try:
        with ThreadPoolExecutor(
                max_workers=min(len(observables) or 1, (cpu_count() or 1) * 5)
        ) as executor:
            iterator = executor.map(deliberate, observables)

        g.bundle = Bundle(
            *[verdict for verdict in iterator if verdict is not None]
        )

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

    ui_url = current_app.config['UI_URL']
    number_of_days_verdict_valid = int(
        current_app.config['NUMBER_OF_DAYS_VERDICT_IS_VALID']
    )
    number_of_days_judgement_valid = int(
        current_app.config['NUMBER_OF_DAYS_JUDGEMENT_IS_VALID']
    )
    number_of_days_indicator_valid = int(
        current_app.config['NUMBER_OF_DAYS_INDICATOR_IS_VALID']
    )
    limit = current_app.config['CTR_ENTITIES_LIMIT']

    g.bundle = Bundle()

    try:
        for observable in observables:
            refer_link = client.refer_link(ui_url, observable)
            mapping = Mapping.for_(observable, source_uri=refer_link)

            if mapping:
                if limit > 0:
                    report = client.report(observable)
                    if report:
                        report_bundle = mapping.process_report_data(
                            report, number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid, limit
                        )
                        limit -= len(report_bundle.get(SIGHTING))
                        g.bundle.merge(report_bundle)

                if limit > 0 and isinstance(mapping, DNSInformationMapping):
                    resolutions_bundle = mapping.process_resolutions(
                        client.resolve(observable)
                    )
                    limit -= len(resolutions_bundle.get(SIGHTING))
                    g.bundle.merge(resolutions_bundle)

                if limit > 0:
                    api_linkage = client.api_linkage(observable)
                    if api_linkage:
                        api_linkage_bundle = mapping.process_api_linkage(
                            api_linkage, ui_url,
                            number_of_days_indicator_valid, limit
                        )
                        g.bundle.merge(api_linkage_bundle)

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
