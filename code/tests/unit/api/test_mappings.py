import json
from collections import namedtuple
from datetime import datetime, timedelta

from pytest import fixture

from api.mappings import (
    Domain, Mapping,
    IP, IPV6, MD5, SHA1, SHA256, URL
)

TestData = namedtuple('TestData', 'file mapping')
domain_test_data = TestData(
    'domain.json', Domain({'type': 'domain', 'value': 'ibm.com'})
)
url_test_data = TestData(
    'url.json', URL({'type': 'url', 'value': 'www.ibm.com/smarterplanet'})
)
ip_test_data = TestData('ip.json', IP({'type': 'ip', 'value': '1.2.3.4'}))
ipv6_test_data = TestData(
    'ipv6.json',
    IPV6({'type': 'ipv6', 'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'})
)
md5_test_data = TestData(
    'md5.json',
    MD5({'type': 'md5', 'value': '34d5ea586a61b0aba512c0cb1d3d8b15'})
)
sha1_test_data = TestData(
    'sha1.json',
    SHA1({'type': 'sha1',
          'value': '0x5C11EE95649AAC7A4DE06BC83CE45C15448F44E0'})
)
sha256_test_data = TestData(
    'sha256.json',
    SHA256({'type': 'sha256',
            'value': '091835b16192e526ee1b8a04d0fcef5'
                     '34544cad306672066f2ad6973a4b18b19'})
)


@fixture(
    scope='module', ids=lambda d: d.file,
    params=(domain_test_data, url_test_data,
            ip_test_data, ipv6_test_data,
            md5_test_data, sha1_test_data, sha256_test_data)
)
def input_data(request):
    return request.param


def test_process_report_data(input_data):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)
        number_of_days_valid = 3

        result = input_data.mapping.process_report_data(
            data['process_report_data']['input'],
            number_of_days_valid, number_of_days_valid, number_of_days_valid,
            100
        )

        check_bundle(result, data['process_report_data']['output'])


def test_process_api_linkage(input_data):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)
        number_of_days_valid = 3

        result = input_data.mapping.process_api_linkage(
            data['process_api_linkage']['input'],
            'https://exchange', number_of_days_valid, 100
        )

        check_bundle(result, data['process_api_linkage']['output'])


def test_limit(input_data):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)
        number_of_days_valid = 3

        for limit in (1, 2, 5):
            results = input_data.mapping.process_api_linkage(
                data['process_api_linkage']['input'],
                'https://exchange', number_of_days_valid, limit
            )
            check_bundle_len(results, limit)

            results = input_data.mapping.process_report_data(
                data['process_report_data']['input'],
                number_of_days_valid, number_of_days_valid,
                number_of_days_valid,
                limit
            )
            check_bundle_len(results, limit)


@fixture(
    scope='module', ids=lambda d: d.file,
    params=(domain_test_data, ip_test_data, ipv6_test_data)
)
def resolve_input_data(request):
    return request.param


def test_process_resolutions(resolve_input_data):
    with open('tests/unit/data/' + resolve_input_data.file) as file:
        data = json.load(file)

        result = resolve_input_data.mapping.process_resolutions(
            data['process_resolutions']['input']
        )

        check_bundle(result, data['process_resolutions']['output'])


def test_mapping_for_():
    assert isinstance(Mapping.for_({'type': 'domain'}), Domain)
    assert isinstance(Mapping.for_({'type': 'url'}), URL)
    assert isinstance(Mapping.for_({'type': 'ip'}), IP)
    assert isinstance(Mapping.for_({'type': 'ipv6'}), IPV6)
    assert isinstance(Mapping.for_({'type': 'md5'}), MD5)
    assert isinstance(Mapping.for_({'type': 'sha1'}), SHA1)
    assert isinstance(Mapping.for_({'type': 'sha256'}), SHA256)
    assert Mapping.for_({'type': 'whatever'}) is None


def check_bundle(
        bundle, expected_result, number_of_days_valid=3
):
    def check_and_pop_time(entity, time_field_name, end_time=None):
        assert entity[time_field_name]['start_time'].startswith(
            start_time.isoformat(timespec="minutes")
        )
        if end_time is None:
            end_time = start_time + timedelta(number_of_days_valid)

        assert entity.pop(time_field_name)['end_time'].startswith(
            end_time.isoformat(timespec="minutes")
        )

    def check_and_pop_id(entity):
        assert entity.pop('id').startswith(f'transient:{entity["type"]}-')

    start_time = datetime.now()
    result = dict(bundle._entities_by_type)

    for verdict in result.get('verdicts', []):
        end_time = None
        if verdict['observable']['type'] in ('md5', 'sha1', 'sha256'):
            end_time = datetime(2525, 1, 1)

        check_and_pop_time(verdict, 'valid_time', end_time=end_time)

    for judgement in result.get('judgements', []):
        check_and_pop_id(judgement)
        check_and_pop_time(judgement, 'valid_time')

    for sighting in result.get('sightings', []):
        check_and_pop_id(sighting)
        if not expected_result['sightings'][0].get('observed_time'):
            check_and_pop_time(sighting, 'observed_time', end_time=start_time)

    for indicator in result.get('indicators', []):
        check_and_pop_id(indicator)
        check_and_pop_time(indicator, 'valid_time')

    for relation in result.get('relationships', []):
        check_and_pop_id(relation)
        source_ref = relation.pop('source_ref')
        target_ref = relation.pop('target_ref')

        assert (source_ref.startswith('transient:sighting-')
                or source_ref.startswith('transient:judgement-'))
        assert (target_ref.startswith('transient:indicator-')
                or target_ref.startswith('transient:judgement-'))
        assert source_ref != target_ref

    assert result == expected_result


def check_bundle_len(bundle, limit):
    result = dict(bundle._entities_by_type)
    result.pop('verdicts', None)
    result.pop('relationships', None)

    for entity_type, entities in result.items():
        assert len(entities) <= limit
