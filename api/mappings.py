from abc import ABCMeta, abstractmethod, ABC
from datetime import datetime, timedelta
from urllib.parse import urljoin

from api.bundle import Bundle
from api.utils import all_subclasses, time_format, transient_id

CTIM_DEFAULTS = {
    'schema_version': '1.0.22',
}
SOURCE = 'IBM X-Force Exchange'

UNKNOWN_DISPOSITION = 5
SUSPICIOUS_DISPOSITION = 3
MALICIOUS_DISPOSITION = 2

DISPOSITION_NAME_MAP = {
    UNKNOWN_DISPOSITION: 'Unknown',
    SUSPICIOUS_DISPOSITION: 'Suspicious',
    MALICIOUS_DISPOSITION: 'Malicious',
}

NONE_SEVERITY = 'None'
UNKNOWN_SEVERITY = 'Unknown'
LOW_SEVERITY = 'Low'
MEDIUM_SEVERITY = 'Medium'
HIGH_SEVERITY = 'High'


class Mapping(metaclass=ABCMeta):

    def __init__(self, observable, source_uri=None):
        self.observable = observable
        self.source_uri = source_uri

    @classmethod
    def for_(cls, observable, source_uri=None):
        """Return an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
            if subcls.type() == observable['type']:
                return subcls(observable, source_uri=source_uri)

        return None

    @classmethod
    @abstractmethod
    def type(cls):
        """Return the observable type that the mapping is able to process."""

    def process_api_linkage(self, api_linkage_data, ui_url,
                            number_of_days_indicator_valid):

        linked_entities = api_linkage_data.get('linkedEntities', [])

        external_references_map = {
            entity['id']: {
                'source_name': SOURCE,
                'external_id': entity['id'],
                'url': urljoin(ui_url,
                               f'/collection/{entity["title"]}-{entity["id"]}')
            } for entity in linked_entities
        }
        external_ids = list(external_references_map.keys())
        external_references = list(external_references_map.values())

        def common(entity):
            external_reference = external_references_map[entity['id']]
            return {
                **CTIM_DEFAULTS,
                'confidence': 'High',
                'external_ids': external_ids,
                'external_references': external_references,
                'source': SOURCE,
                'source_uri': external_reference['url'],
            }

        def sighting(entity):
            return {
                'id': transient_id('sighting', entity['id']),
                'count': 1,
                'observed_time': {
                    'start_time': entity['created'],
                    'end_time': entity['created'],
                },
                'type': 'sighting',
                # Original values: "1owned", "2shared", "3public", "4premier"
                'internal':
                    entity['category'] == '1owned',
                'observables': [self.observable],
                'title':
                    f'Contained in Collection: {entity["title"]}',
            }

        def indicator(entity):
            return {
                'id': transient_id('indicator', entity['id']),
                'producer': entity['owner']['name'],
                'type': 'indicator',
                'valid_time': self._valid_time(number_of_days_indicator_valid),
                'title': entity["title"],
            }

        sightings = []
        indicators = []
        relationships = []

        for entity in linked_entities:
            common_value = common(entity)
            s = {**sighting(entity), **common_value}
            i = {**indicator(entity), **common_value}
            sightings.append(s)
            indicators.append(i)
            relationships.append(self._relationship(s, i, 'member-of'))

        return Bundle(*sightings, *indicators, *relationships)

    @abstractmethod
    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        pass

    def _verdict(self, score, number_of_days_verdict_valid):
        disposition = self._disposition(score)

        return {
            'disposition': disposition,
            'observable': self.observable,
            'type': 'verdict',
            'valid_time':
                self._valid_time(number_of_days_verdict_valid),
            'disposition_name': DISPOSITION_NAME_MAP[disposition],
        }

    def _judgement(self, score, number_of_days_judgements_valid):
        disposition = self._disposition(score)

        return {
            **CTIM_DEFAULTS,
            'id': transient_id('judgement'),
            'confidence': 'High',
            'disposition': disposition,
            'disposition_name': DISPOSITION_NAME_MAP[disposition],
            'observable': self.observable,
            'priority': 85,
            'severity': self._severity(score),
            'source': SOURCE,
            'type': 'judgement',
            'valid_time': self._valid_time(number_of_days_judgements_valid)
        }

    def _sighting(self, category):
        now = time_format(datetime.now())
        return {
            **CTIM_DEFAULTS,
            'id': transient_id('sighting', category),
            'confidence': 'High',
            'count': 1,
            'observed_time': {'start_time': now, 'end_time': now},
            'type': 'sighting',
            'internal': False,
            'observables': [self.observable],
            'source': SOURCE,
            'source_uri': self.source_uri,
            'title': category,
        }

    def _indicator(self, category, number_of_days_indicator_valid, flag=None):
        result = {
            **CTIM_DEFAULTS,
            'id': transient_id('indicator', category),
            'producer': SOURCE,
            'type': 'indicator',
            'valid_time': self._valid_time(number_of_days_indicator_valid),
            'confidence': 'High',
            'source': SOURCE,
            'source_uri': self.source_uri,
            'title': category
        }

        if flag is not None:
            result['tags'] = [str(flag)]

        return result

    @staticmethod
    def _relationship(source, target, relationship_type):
        return {
            **CTIM_DEFAULTS,
            'id': transient_id('relationship'),
            'type': 'relationship',
            'relationship_type': relationship_type,
            'source_ref': source['id'],
            'target_ref': target['id']
        }

    @staticmethod
    def _disposition(score):
        if not score:
            return UNKNOWN_DISPOSITION

        segments = [
            (3.9, UNKNOWN_DISPOSITION),
            (6.9, SUSPICIOUS_DISPOSITION),
            (10, MALICIOUS_DISPOSITION)
        ]

        for bound, result in segments:
            if score <= bound:
                return result

    @staticmethod
    @abstractmethod
    def _severity(score):
        """Map score value to CTIM severity."""

    @staticmethod
    def _valid_time(number_of_days_valid=None):
        start_time = datetime.now()
        if number_of_days_valid is None:
            end_time = datetime(2525, 1, 1)
        else:
            end_time = start_time + timedelta(number_of_days_valid)

        return {
            'start_time': time_format(start_time),
            'end_time': time_format(end_time)
        }


class URL(Mapping):
    @classmethod
    def type(cls):
        return 'url'

    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid):

        verdict = self.extract_verdict(report_data,
                                       number_of_days_verdict_valid)

        judgements = [
            self._judgement(
                report_data['result']['score'], number_of_days_judgement_valid
            )
        ]

        sightings = []
        indicators = []
        relationships = []

        for category, flag in report_data.get('result',
                                              {}).get('cats', {}).items():
            s = self._sighting(category)
            i = self._indicator(
                category, number_of_days_indicator_valid, flag=flag
            )
            sightings.append(s)
            indicators.append(i)
            relationships.append(self._relationship(s, i, 'sighting-of'))

        return Bundle(verdict, *judgements, *sightings, *indicators, *relationships)

    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        return self._verdict(report_data.get('result', {}).get('score'),
                             number_of_days_verdict_valid)



    @staticmethod
    def _severity(score):
        pass


class Domain(URL):
    @classmethod
    def type(cls):
        return 'domain'


class IP(Mapping):
    @classmethod
    def type(cls):
        return 'ip'

    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid):
        verdict = self.extract_verdict(report_data,
                                       number_of_days_verdict_valid)

        sightings = []
        indicators = []
        judgements = []
        relationships = []

        for category, score in report_data.get('cats', {}).items():
            s = self._sighting(category)
            i = self._indicator(category, number_of_days_indicator_valid)
            j = self._judgement(score / 10, number_of_days_judgement_valid)
            sightings.append(s)
            indicators.append(i)
            judgements.append(j)
            relationships.append(self._relationship(s, j, 'based-on'))
            relationships.append(self._relationship(j, i, 'based-on'))

        return Bundle(
            verdict, *judgements, *sightings, *indicators, *relationships
        )

    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        return self._verdict(report_data.get('score'),
                             number_of_days_verdict_valid)

    @staticmethod
    def _severity(score):
        if not score:
            return UNKNOWN_SEVERITY

        segments = [
            (3.9, LOW_SEVERITY),
            (6.9, MEDIUM_SEVERITY),
            (10, HIGH_SEVERITY)
        ]

        for bound, result in segments:
            if score <= bound:
                return result


class IPV6(IP):
    @classmethod
    def type(cls):
        return 'ipv6'


class FileHash(Mapping, ABC):
    def extract_verdict(self, report_data, *args):
        return self._verdict(
            report_data.get('malware', {}).get('risk'),
            number_of_days_verdict_valid=None,
        )

    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid):

        verdict = self.extract_verdict(report_data,
                                       number_of_days_verdict_valid)

        j = self._judgement(report_data.get('malware', {}).get('risk'),
                      number_of_days_judgement_valid)

        return Bundle(verdict, j)

    @staticmethod
    def _disposition(score):
        if not score:
            return UNKNOWN_DISPOSITION

        return {
            'low': UNKNOWN_DISPOSITION,
            'medium': SUSPICIOUS_DISPOSITION,
            'high': MALICIOUS_DISPOSITION
        }.get(str(score).lower())

    @staticmethod
    def _severity(score):
        if score is None:
            return NONE_SEVERITY

        score = str(score).capitalize()
        if score in (LOW_SEVERITY, MEDIUM_SEVERITY, HIGH_SEVERITY):
            return score

        return UNKNOWN_SEVERITY


class MD5(FileHash):
    @classmethod
    def type(cls):
        return 'md5'


class SHA1(FileHash):
    @classmethod
    def type(cls):
        return 'sha1'


class SHA256(FileHash):
    @classmethod
    def type(cls):
        return 'sha256'
