import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY')

    API_URL = 'https://api.xforce.ibmcloud.com/'
    UI_URL = 'https://exchange.xforce.ibmcloud.com/'

    X_FORCE_OBSERVABLES = {
        'domain': 'domain',
        'url': 'URL',
        'ip': 'IP',
        'ipv6': 'IPv6',
        'md5': 'MD5',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
    }

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NUMBER_OF_DAYS_VERDICT_IS_VALID = 30
