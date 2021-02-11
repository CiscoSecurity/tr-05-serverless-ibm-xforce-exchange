from http import HTTPStatus
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import SSLError

from api.errors import (
    CriticalXForceResponseError,
    XForceSSLError
)

NOT_CRITICAL_ERRORS = (
    HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.NOT_ACCEPTABLE
)

IP = 'ip'
IPV6 = 'ipv6'
DOMAIN = 'domain'
URL = 'url'
MD5 = 'md5'
SHA1 = 'sha1'
SHA256 = 'sha256'

XFORCE_OBSERVABLE_TYPES = {
    DOMAIN: 'domain',
    URL: 'URL',
    IP: 'IP',
    IPV6: 'IPv6',
    MD5: 'MD5',
    SHA1: 'SHA1',
    SHA256: 'SHA256',
}


class XForceClient:
    URL_PATH = 'url'
    IP_PATH = 'ip'
    HASH_PATH = 'malware'

    PATH_MAP = {
        URL: URL_PATH, DOMAIN: URL_PATH,
        IP: IP_PATH, IPV6: IP_PATH,
        MD5: HASH_PATH, SHA1: HASH_PATH, SHA256: HASH_PATH
    }

    def __init__(self, base_url, credentials, user_agent):
        self.base_url = base_url
        self.headers = {
            'Accept': 'application/json',
            'User-Agent': user_agent
        }
        self.auth = HTTPBasicAuth(
            credentials['key'], credentials['password']
        )

    @staticmethod
    def refer_link(ui_url, observable):
        path = XForceClient.PATH_MAP.get(observable['type'])
        return urljoin(ui_url, f'/{path}/{observable["value"]}')

    def usage(self):
        """
        https://api.xforce.ibmcloud.com/doc/#Usage_get_all_subscriptions_usage
        """
        return self._request('/all-subscriptions/usage')

    def report(self, observable):
        """
        https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_ip
        https://api.xforce.ibmcloud.com/doc/#URL_get_url_url
        https://api.xforce.ibmcloud.com/doc/#Malware_get_malware_filehash
        """
        path = self.PATH_MAP.get(observable['type'])
        if path == self.IP_PATH:
            path = 'ipr'
        if path:
            return self._request(f'/{path}/{observable["value"]}')

    def api_linkage(self, observable):
        path = self.PATH_MAP.get(observable['type'])
        if path:
            return self._request(
                f'/api/linkage/{path}/{observable["value"]}?maxpertype=20'
            )

    def resolve(self, observable):
        if observable['type'] in (URL, DOMAIN, IP, IPV6):
            return self._request(
                f'/api/resolve/{observable["value"]}?basicResolve=true'
            )

    def _request(self, path, method='GET'):
        url = urljoin(self.base_url, path)

        try:
            response = requests.request(
                method, url, auth=self.auth, headers=self.headers
            )
        except SSLError as error:
            raise XForceSSLError(error)

        if response.ok:
            return response.json()

        if response.status_code in NOT_CRITICAL_ERRORS:
            return {}

        raise CriticalXForceResponseError(response)
