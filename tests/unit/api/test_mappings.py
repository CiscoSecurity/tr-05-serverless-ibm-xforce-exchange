import json
from collections import namedtuple
from datetime import datetime, timedelta

from pytest import fixture

from api.mappings import (
    Domain, Mapping,
    IP, IPV6, MD5, SHA1, SHA256, URL
)


def input_sets():
    TestData = namedtuple('TestData', 'file mapping')
    yield TestData(
        'domain.json', Domain({'type': 'domain', 'value': 'ibm.com'})
    )
    yield TestData(
        'url.json',
        Domain({'type': 'url', 'value': 'www.ibm.com/smarterplanet'})
    )
    yield TestData('ip.json', IP({'type': 'ip', 'value': '1.2.3.4'}))
    yield TestData(
        'ipv6.json',
        IPV6({'type': 'ipv6',
              'value': '2001:0db8:85a3:0000:0000:8a2e:0370:7334'})
    )
    yield TestData(
        'md5.json',
        MD5({'type': 'md5', 'value': '34d5ea586a61b0aba512c0cb1d3d8b15'})
    )
    yield TestData(
        'sha1.json',
        SHA1({'type': 'sha1',
              'value': '0x5C11EE95649AAC7A4DE06BC83CE45C15448F44E0'}))
    yield TestData(
        'sha256.json',
        SHA256({'type': 'sha256',
                'value': '091835b16192e526ee1b8a04d0fcef5'
                         '34544cad306672066f2ad6973a4b18b19'}))


@fixture(scope='module', params=input_sets(), ids=lambda d: d.file)
def input_data(request):
    return request.param


def test_extract_verdict(input_data):
    with open('tests/unit/data/' + input_data.file) as file:
        data = json.load(file)
        number_of_days_verdict_valid = 3

        result = input_data.mapping.extract_verdict(
            data['input'], number_of_days_verdict_valid)

        start_time = datetime.now()
        assert result['valid_time']['start_time'].startswith(
            start_time.isoformat(timespec="minutes")
        )

        if input_data.file in ('md5.json',  'sha1.json',  'sha256.json'):
            end_time = datetime(2525, 1, 1)
        else:
            end_time = start_time + timedelta(number_of_days_verdict_valid)

        assert result.pop('valid_time')['end_time'].startswith(
                end_time.isoformat(timespec="minutes")
            )

        assert result == data['output']


def test_mapping_for_():
    assert isinstance(Mapping.for_({'type': 'domain'}), Domain)
    assert isinstance(Mapping.for_({'type': 'url'}), URL)
    assert isinstance(Mapping.for_({'type': 'ip'}), IP)
    assert isinstance(Mapping.for_({'type': 'ipv6'}), IPV6)
    assert isinstance(Mapping.for_({'type': 'md5'}), MD5)
    assert isinstance(Mapping.for_({'type': 'sha1'}), SHA1)
    assert isinstance(Mapping.for_({'type': 'sha256'}), SHA256)
    assert Mapping.for_({'type': 'whatever'}) is None
