import os
from uuid import NAMESPACE_X500

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY')

    API_URL = 'https://api.xforce.ibmcloud.com/'
    UI_URL = 'https://exchange.xforce.ibmcloud.com/'

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NUMBER_OF_DAYS_VERDICT_IS_VALID = 30
    NUMBER_OF_DAYS_JUDGEMENT_IS_VALID = 7
    NUMBER_OF_DAYS_INDICATOR_IS_VALID = 30

    NAMESPACE_BASE = NAMESPACE_X500

    CTR_ENTITIES_LIMIT_DEFAULT = 100
    CTR_ENTITIES_LIMIT_MAX = 1000

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_DEFAULT
    if CTR_ENTITIES_LIMIT > CTR_ENTITIES_LIMIT_MAX:
        CTR_ENTITIES_LIMIT = CTR_ENTITIES_LIMIT_MAX
