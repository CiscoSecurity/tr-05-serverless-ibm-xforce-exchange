import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY')

    API_URL = 'https://api.xforce.ibmcloud.com/'
    UI_URL = 'https://exchange.xforce.ibmcloud.com/'

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    NUMBER_OF_DAYS_VERDICT_IS_VALID = 30
