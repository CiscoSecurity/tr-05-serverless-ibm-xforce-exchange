from http import HTTPStatus

INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
TOO_MANY_REQUESTS = 'too many requests'
AUTH_ERROR = 'authorization error'
NOT_FOUND = 'not found'
UNAVAILABLE = 'unavailable'
KEY_ERROR = 'key error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, error):
        super().__init__(
            INVALID_ARGUMENT,
            str(error)
        )


class XForceKeyError(TRFormattedError):
    def __init__(self):
        super().__init__(
            KEY_ERROR,
            'The data structure of IBM X-Force Exchange has changed.'
            ' The module is broken.'
        )


class XForceSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class CriticalXForceResponseError(TRFormattedError):
    def __init__(self, response):
        """
        https://api.xforce.ibmcloud.com/doc/#error_handling
        """

        status_code_map = {
            HTTPStatus.BAD_REQUEST: INVALID_ARGUMENT,
            HTTPStatus.UNAUTHORIZED: AUTH_ERROR,
            HTTPStatus.FORBIDDEN: PERMISSION_DENIED,
            HTTPStatus.NOT_FOUND: NOT_FOUND,
            HTTPStatus.TOO_MANY_REQUESTS: TOO_MANY_REQUESTS,
            HTTPStatus.INTERNAL_SERVER_ERROR: UNKNOWN,
            HTTPStatus.SERVICE_UNAVAILABLE: UNKNOWN,
        }

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            message = 'Authorization failed: Authorization failed on IBM X-Force Exchange side'
        else:
            message = (f'Unexpected response from'
                       f' IBM X-Force Exchange: {response.json()["error"]}')

        super().__init__(
            status_code_map.get(response.status_code),
            message
        )


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )
