from http import HTTPStatus
from urllib.parse import urljoin

import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import SSLError

from api.errors import (
    CriticalXForceResponseError,
    AuthorizationError,
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
        observable_type = observable['type']

        if observable_type in (DOMAIN, URL):
            return urljoin(ui_url, f'/url/{observable["value"]}')

        if observable_type in (IP, IPV6):
            return urljoin(ui_url, f'/ip/{observable["value"]}')

        if observable_type in (MD5, SHA1, SHA256):
            return urljoin(ui_url, f'/malware/{observable["value"]}')

    def usage(self):
        """
        https://api.xforce.ibmcloud.com/doc/#Usage_get_all_subscriptions_usage
        """
        return self._request('/all-subscriptions/usage')

    def get_data(self, observable):
        observable_type = observable['type']
        observable_value = observable['value']

        if observable_type in (DOMAIN, URL):
            return self._url_report(observable_value)

        if observable_type in (IP, IPV6):
            return self._ip_report(observable_value)

        if observable_type in (MD5, SHA1, SHA256):
            return self._malware(observable_value)

    def _ip_report(self, ip):
        """
        https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_ip
        """
        return self._request(f'/ipr/{ip}')

    def _url_report(self, url):
        """
        https://api.xforce.ibmcloud.com/doc/#URL_get_url_url
        """
        return self._request(f'/url/{url}')

    def _malware(self, filehash):
        """
        https://api.xforce.ibmcloud.com/doc/#Malware_get_malware_filehash
        """
        return self._request(f'/malware/{filehash}')

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

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            raise AuthorizationError(
                'Authorization failed on IBM X-Force Exchange side', prefix=''
            )

        if response.status_code in NOT_CRITICAL_ERRORS:
            return {}

        raise CriticalXForceResponseError(response)
