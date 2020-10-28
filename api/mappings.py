from abc import ABCMeta, abstractmethod, ABC
from datetime import datetime, timedelta

from api.utils import all_subclasses, time_format

UNKNOWN_DISPOSITION = 5
SUSPICIOUS_DISPOSITION = 3
MALICIOUS_DISPOSITION = 2

DISPOSITION_NAME_MAP = {
    UNKNOWN_DISPOSITION: 'Unknown',
    SUSPICIOUS_DISPOSITION: 'Suspicious',
    MALICIOUS_DISPOSITION: 'Malicious',
}


class Mapping(metaclass=ABCMeta):

    def __init__(self, observable):
        self.observable = observable

    @classmethod
    def for_(cls, observable):
        """Return an instance of `Mapping` for the specified type."""

        for subcls in all_subclasses(Mapping):
            if subcls.type() == observable['type']:
                return subcls(observable)

        return None

    @classmethod
    @abstractmethod
    def type(cls):
        """Return the observable type that the mapping is able to process."""

    @staticmethod
    @abstractmethod
    def _extract_disposition_score(data):
        """
        Extract the value disposition is based on
        from an X-Force API record.

        """

    @staticmethod
    def verdict_valid_time(number_of_days_verdict_valid):
        start_time = datetime.now()
        return {
            'start_time': time_format(start_time),
            'end_time': time_format(
                start_time + timedelta(number_of_days_verdict_valid)
            )
        }

    def extract_verdict(self, report_data, number_of_days_verdict_valid=30):
        disposition = self._disposition(
            self._extract_disposition_score(report_data)
        )
        if not disposition:
            return

        return {
            'type': 'verdict',
            'observable': self.observable,
            'valid_time':
                self.verdict_valid_time(number_of_days_verdict_valid),
            'disposition': disposition,
            'disposition_name': DISPOSITION_NAME_MAP[disposition],
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


class URL(Mapping):
    @classmethod
    def type(cls):
        return 'url'

    @staticmethod
    def _extract_disposition_score(data):
        return data.get('result', {}).get('score')


class Domain(URL):
    @classmethod
    def type(cls):
        return 'domain'


class IP(Mapping):
    @classmethod
    def type(cls):
        return 'ip'

    @staticmethod
    def _extract_disposition_score(data):
        return data.get('score')


class IPV6(IP):
    @classmethod
    def type(cls):
        return 'ipv6'


class FileHash(Mapping, ABC):
    @staticmethod
    def _extract_disposition_score(data):
        return data.get('malware', {}).get('risk')

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
    def verdict_valid_time(self, *args, **kwargs):
        return {
            'start_time': time_format(datetime.now()),
            'end_time': time_format(datetime(2525, 1, 1))
        }


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
