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

    def usage(self):
        """
        https://api.xforce.ibmcloud.com/doc/#Usage_get_all_subscriptions_usage
        """
        return self._request('/all-subscriptions/usage')

    def ip_report(self, ip):
        """
        https://api.xforce.ibmcloud.com/doc/#IP_Reputation_get_ipr_ip
        """
        return self._request(f'/ipr/{ip}')

    def url_report(self, url):
        """
        https://api.xforce.ibmcloud.com/doc/#URL_get_url_url
        """
        return self._request(f'/url/{url}')

    def malware(self, filehash):
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
