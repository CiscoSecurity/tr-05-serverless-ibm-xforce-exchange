from abc import abstractmethod, ABC
from datetime import datetime, timedelta
from operator import itemgetter
from urllib.parse import urljoin

from api.bundle import Bundle
from api.utils import all_subclasses, time_format, transient_id

CTIM_DEFAULTS = {
    'schema_version': '1.1.1',
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

VERDICT = 'verdict'
JUDGEMENT = 'judgement'
SIGHTING = 'sighting'
INDICATOR = 'indicator'

SIGHTING_DEFAULTS = {
    **CTIM_DEFAULTS,
    'confidence': 'High',
    'count': 1,
    'type': SIGHTING,
    'source': SOURCE,
}

INDICATOR_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': INDICATOR,
    'confidence': 'High',
    'source': SOURCE,
}

RESOLVED_TO = 'Resolved_To'

DNS_INFORMATION_CATEGORY = 'DNS Information'
IP_DNS_RECORD_TYPE = 'A'
IPV6_DNS_RECORD_TYPE = 'AAAA'
IP_DNS_RECORD_TYPES = (IP_DNS_RECORD_TYPE, IPV6_DNS_RECORD_TYPE)


class Mapping(ABC):

    def __init__(self, observable, source_uri=''):
        self.observable = observable
        self.source_uri = source_uri
        self.resolutions = None

    @classmethod
    def for_(cls, observable, source_uri=''):
        """Return an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
            if subcls.type() == observable['type']:
                return subcls(observable, source_uri=source_uri)

        return None

    @classmethod
    @abstractmethod
    def type(cls):
        """Return the observable type that the mapping is able to process."""

    @abstractmethod
    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        """Extract CTIM verdict from X-Force report."""

    @abstractmethod
    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid, limit):
        """Extract CTIM entities from X-Force report."""

    def process_api_linkage(self, api_linkage_data, ui_url,
                            number_of_days_indicator_valid, limit):

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

        def sighting(entity):
            return {
                **SIGHTING_DEFAULTS,
                'id': transient_id(SIGHTING, entity['id']),
                'observed_time': {
                    'start_time': entity['created'],
                    'end_time': entity['created'],
                },
                # Original values: "1owned", "2shared", "3public", "4premier"
                'internal':
                    entity['category'] == '1owned',
                'observables': [self.observable],
                'title':
                    f'Contained in Collection: {entity["title"]}',
            }

        def indicator(entity):
            return {
                **INDICATOR_DEFAULTS,
                'id': transient_id(INDICATOR, entity['id']),
                'producer': entity['owner']['name'],
                'valid_time': self._valid_time(number_of_days_indicator_valid),
                'title': entity["title"],
            }

        linked_entities = sorted(
            linked_entities, key=itemgetter('created'), reverse=True
        )[:limit]

        bundle = Bundle()
        for entity in linked_entities:
            external_reference = external_references_map[entity['id']]
            common_value = {
                'external_ids': external_ids,
                'external_references': external_references,
                'source_uri': external_reference['url'],
            }

            s = {**sighting(entity), **common_value}
            i = {**indicator(entity), **common_value}
            bundle.add(s)
            bundle.add(i)
            bundle.add(self._relationship(s, i, 'member-of'))

        return bundle

    def _verdict(self, score, number_of_days_verdict_valid):
        disposition = self._disposition(score)

        return {
            'disposition': disposition,
            'observable': self.observable,
            'type': VERDICT,
            'valid_time':
                self._valid_time(number_of_days_verdict_valid),
            'disposition_name': DISPOSITION_NAME_MAP[disposition],
        }

    def _judgement(self, score, number_of_days_judgements_valid):
        disposition = self._disposition(score)

        return {
            **CTIM_DEFAULTS,
            'id': transient_id(JUDGEMENT),
            'confidence': 'High',
            'disposition': disposition,
            'disposition_name': DISPOSITION_NAME_MAP[disposition],
            'observable': self.observable,
            'priority': 85,
            'severity': self._severity(score),
            'source': SOURCE,
            'type': JUDGEMENT,
            'valid_time': self._valid_time(number_of_days_judgements_valid)
        }

    def _sighting(self, category, description=None):
        now = time_format(datetime.now())
        result = {
            **SIGHTING_DEFAULTS,
            'id': transient_id(SIGHTING, category),
            'observed_time': {'start_time': now, 'end_time': now},
            'internal': False,
            'observables': [self.observable],
            'source_uri': self.source_uri,
            'title': category,
        }
        if description:
            result['description'] = description
        return result

    def _indicator(self, category, number_of_days_indicator_valid, flag=None):
        result = {
            **INDICATOR_DEFAULTS,
            'id': transient_id(INDICATOR, category),
            'producer': SOURCE,
            'valid_time': self._valid_time(number_of_days_indicator_valid),
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


class DNSInformationMapping(Mapping, ABC):
    def process_resolutions(self, resolutions):
        bundle = Bundle()

        related = self._extract_related(resolutions)
        if related:
            related = sorted(related)
            description = self._resolution_description()
            sighting = self._sighting(
                DNS_INFORMATION_CATEGORY, description=description
            )
            sighting['relations'] = [self._resolved_to(r) for r in related]
            bundle.add(sighting)

        return bundle

    @staticmethod
    def _observable_relation(relation_type, source, related):
        return {
            "origin": f"{SOURCE} Enrichment Module",
            "relation": relation_type,
            "source": source,
            "related": related
        }

    @abstractmethod
    def _resolved_to(self, related):
        """
        Return TR resolved_to relation
        depending on an observable and related types.

        """

    @abstractmethod
    def _resolution_description(self, *args):
        """
        Return description for a sighting based on DNS resolutions
        depending on observable type.

        """

    def _extract_related(self, data):
        passive = data.get('Passive', {}).get('records', [])
        return set(
            r['value'] for r in passive
            if r['recordType'] in IP_DNS_RECORD_TYPES
        )


class URL(Mapping):
    @classmethod
    def type(cls):
        return 'url'

    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        return self._verdict(report_data.get('result', {}).get('score'),
                             number_of_days_verdict_valid)

    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid, limit):
        bundle = Bundle()

        bundle.add(self.extract_verdict(report_data,
                                        number_of_days_verdict_valid))

        bundle.add(self._judgement(report_data['result']['score'],
                                   number_of_days_judgement_valid))

        categories = report_data.get('result', {}).get('cats', {})
        categories = sorted(categories.items())[:limit]

        for category, flag in categories:
            s = self._sighting(category)
            i = self._indicator(
                category, number_of_days_indicator_valid, flag=flag
            )
            bundle.add(s)
            bundle.add(i)
            bundle.add(self._relationship(s, i, 'sighting-of'))

        return bundle


class Domain(URL, DNSInformationMapping):
    @classmethod
    def type(cls):
        return 'domain'

    def _extract_related(self, data):
        related = super()._extract_related(data)
        related |= set(data.get(IP_DNS_RECORD_TYPE, {}))
        related |= set(data.get(IPV6_DNS_RECORD_TYPE, {}))
        return related

    def _resolution_description(self):
        return f'IP addresses that {self.observable["value"]} resolves to'

    def _resolved_to(self, ip):
        return self._observable_relation(
            RESOLVED_TO,
            source=self.observable,
            related={
                'value': ip,
                'type': 'ipv6' if ':' in ip else 'ip'
            }
        )


class IP(DNSInformationMapping):
    @classmethod
    def type(cls):
        return 'ip'

    def extract_verdict(self, report_data, number_of_days_verdict_valid):
        return self._verdict(report_data.get('score'),
                             number_of_days_verdict_valid)

    def process_report_data(self, report_data,
                            number_of_days_verdict_valid,
                            number_of_days_judgement_valid,
                            number_of_days_indicator_valid, limit):
        bundle = Bundle()

        bundle.add(self.extract_verdict(report_data,
                                        number_of_days_verdict_valid))

        categories = sorted(report_data.get('cats', {}).items())[:limit]
        for category, score in categories:
            sighting = self._sighting(category)
            indicator = self._indicator(category,
                                        number_of_days_indicator_valid)
            judgement = self._judgement(score / 10,
                                        number_of_days_judgement_valid)
            bundle.add(sighting)
            bundle.add(indicator)
            bundle.add(judgement)
            bundle.add(self._relationship(sighting, judgement, 'based-on'))
            bundle.add(self._relationship(judgement, indicator, 'based-on'))

        return bundle

    def _extract_related(self, data):
        related = super()._extract_related(data)
        related |= set(data.get('RDNS', {}))
        return related

    def _resolution_description(self):
        return f'Domains that have resolved to {self.observable["value"]}'

    def _resolved_to(self, domain):
        return self._observable_relation(
            RESOLVED_TO,
            source={'value': domain, 'type': 'domain'},
            related=self.observable
        )


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

    def process_report_data(
            self, report_data, number_of_days_verdict_valid,
            number_of_days_judgement_valid, *args
    ):

        bundle = Bundle()
        bundle.add(self.extract_verdict(report_data,
                                        number_of_days_verdict_valid))

        bundle.add(self._judgement(report_data.get('malware', {}).get('risk'),
                                   number_of_days_judgement_valid))

        return bundle

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
