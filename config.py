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
