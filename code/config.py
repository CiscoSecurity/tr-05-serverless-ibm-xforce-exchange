import json
from uuid import NAMESPACE_X500


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    API_URL = 'https://api.xforce.ibmcloud.com/'
    UI_URL = 'https://exchange.xforce.ibmcloud.com/'

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    CTR_ENTITIES_LIMIT_MAX = 1000
    CTR_ENTITIES_LIMIT_DEFAULT = 100

    NUMBER_OF_DAYS_VERDICT_IS_VALID = 30
    NUMBER_OF_DAYS_JUDGEMENT_IS_VALID = 7
    NUMBER_OF_DAYS_INDICATOR_IS_VALID = 30

    NAMESPACE_BASE = NAMESPACE_X500

