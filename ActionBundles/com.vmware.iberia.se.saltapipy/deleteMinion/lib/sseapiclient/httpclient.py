# coding: utf-8

import base64
import datetime
import errno
import json
import logging
import os
import socket
import ssl
import sys
import tempfile
import time
import timeit
import uuid

# isort:skip_file

# Import SSEApiClient libs
import sseapiclient.serialize
from sseapiclient.exc import AuthenticationFailure, NotConnectable, RequestFailure, TimeoutFailure

try:
    import salt.ext.six as six
    import salt.ext.six.moves.http_cookiejar as cookielib
    import salt.ext.six.moves.urllib.error as urllib_error
    import salt.ext.six.moves.urllib.parse as urllib_parse
    import salt.ext.six.moves.urllib.request as urllib_request
except ImportError:
    import six
    import six.moves.http_cookiejar as cookielib
    import six.moves.urllib.error as urllib_error
    import six.moves.urllib.parse as urllib_parse
    import six.moves.urllib.request as urllib_request

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP

if sys.version_info[0] < 3:
    ModuleNotFoundError = ImportError
    SocketError = socket.error
else:
    SocketError = OSError

try:
    JSON_DECODE_ERROR = json.decoder.JSONDecodeError
except AttributeError:
    JSON_DECODE_ERROR = ValueError

log = logging.getLogger(__name__)


class ResponseSaverErrorProcessor(urllib_request.HTTPErrorProcessor, object):
    '''
    The default HTTPErrorProcessor hides the response but we kinda sorta need it
    '''
    def __init__(self, http_client):
        self.http_client = http_client

    def http_response(self, request, response):
        self.http_client._error_response = response
        return super(ResponseSaverErrorProcessor, self).http_response(request, response)

    https_response = http_response


class HTTPClient(object):
    '''
    A synchronous http client for use with the SaltStack Enterprise API.
    Intended for use by the APIClient class rather than instantiated directly.
    '''
    def __init__(self,
                 server,
                 username,
                 password=None,
                 config_name='internal',
                 timeout=60,
                 use_jwt=True,
                 shared_jwt=None,
                 pubkey_path=None,
                 cookies_path=None,
                 json_encoder=None,
                 rpc_api_version=None,
                 ssl_key=None,
                 ssl_cert=None,
                 ssl_validate_cert=True,
                 ssl_context=None):

        self.server = server.rstrip('/')
        self.username = username
        self.password = password
        self.config_name = config_name
        self.timeout = timeout
        self.shared_jwt = shared_jwt
        self.pubkey_path = pubkey_path
        if cookies_path is None:
            ofh, cookies_path = tempfile.mkstemp()
            os.close(ofh)
            os.unlink(cookies_path)
        self.cookies = cookielib.LWPCookieJar(filename=cookies_path)
        self.json_encoder = json_encoder
        self.rpc_api_version = rpc_api_version

        if ssl_context:
            if not isinstance(ssl_context, ssl.SSLContext):
                raise RuntimeError('ssl_context must be an instance of ssl.SSLContext')
            if ssl_key or ssl_cert:
                raise RuntimeError('When passing ssl_context, none of the other ssl options should be passed')
        self.ssl_key = ssl_key
        self.ssl_cert = ssl_cert
        self.ssl_validate_cert = ssl_validate_cert
        self.ssl_context = ssl_context

        self._xsrf_token = None
        self._use_key_auth = not self.username and not self.password and self.pubkey_path
        self._use_jwt = use_jwt or self._use_key_auth
        self._jwt = None
        self._authenticated = False
        self._known_raisins = set()
        self._last_auth_request_time = 0
        self._error_response = None

        try:
            Crypto.Random.atfork()
        except NameError:
            pass

    def __repr__(self):
        return '<{cls} {desc}>'.format(cls=self.__class__.__name__, desc=self.describe())

    def _make_url(self, url, params=None):
        '''
        Format a raas url. Optional query args can be passed in params.
        '''
        url = urllib_parse.urljoin(self.server, url)
        if params:
            url = '{}?{}'.format(url, urllib_parse.urlencode(params))
        return url

    def _make_opener(self, url):
        '''
        Make a urllib request opener that can handle cookies and optional ssl.
        '''
        if url.startswith('https:'):
            if self.ssl_context:
                context = self.ssl_context
            else:
                if self.ssl_validate_cert:
                    context = ssl.create_default_context()
                else:
                    context = ssl._create_unverified_context()
                if self.ssl_cert and self.ssl_key:
                    context.load_cert_chain(self.ssl_cert, self.ssl_key)
            prot_handler = urllib_request.HTTPSHandler(context=context)
        else:
            prot_handler = urllib_request.HTTPHandler()
        cookie_handler = urllib_request.HTTPCookieProcessor(self.cookies)
        error_handler = ResponseSaverErrorProcessor(self)
        return urllib_request.build_opener(prot_handler, cookie_handler, error_handler)

    def _build_request(self, url, method, body=None):
        '''
        Build the request object
        '''
        if body is not None and not isinstance(body, six.binary_type):
            body = self.json_dumps(body).encode()
        if six.PY2:
            request = urllib_request.Request(url, data=body)
            request.get_method = lambda: method
        else:
            request = urllib_request.Request(url, method=method, data=body)
        if self._xsrf_token:
            request.add_header('X-XSRFToken', self._xsrf_token)
        if self._use_jwt and self._jwt:
            request.add_header('Authorization', 'JWT {}'.format(self._jwt))
        if self.rpc_api_version:
            request.add_header('X-RaaS-RPC-Version', self.rpc_api_version)
        self.cookies.add_cookie_header(request)
        return request

    def describe(self):
        '''
        Return a string showing some important parameters
        '''
        if self._use_key_auth:
            fmt = ('server={server!r} master_id={username!r} pubkey={pubkey!r} '
                   'rpc_api_version={apiver!r} authenticated={auth!r}')
        else:
            fmt = ('server={server!r} username={username!r} config_name={config_name!r} '
                   'rpc_api_version={apiver!r} authenticated={auth!r}')
        return fmt.format(server=self.server,
                          username=self.username,
                          pubkey=self.pubkey_path,
                          config_name=self.config_name,
                          apiver=self.rpc_api_version,
                          auth=self._authenticated)

    def json_dumps(self, data):
        return sseapiclient.serialize.json_dumps(data, cls=self.json_encoder)

    def encrypt_message(self, data, pubkey_path):
        data = self.json_dumps(data).encode()
        if hasattr(RSA, 'load_pub_key'):
            pubkey = RSA.load_pub_key(pubkey_path)
            emsg = pubkey.public_encrypt(data, RSA.pkcs1_oaep_padding)
        else:
            with open(pubkey_path, 'r') as fh:
                if hasattr(RSA, 'import_key'):
                    pubkey = RSA.import_key(fh.read())
                else:
                    pubkey = RSA.importKey(fh.read())

                cipher = PKCS1_OAEP.new(pubkey)
                emsg = cipher.encrypt(data)

        emsg = base64.b64encode(emsg)
        if six.PY3:
            return emsg.decode()
        return emsg

    def init_xsrf(self):
        if self._xsrf_token is None:
            # Try to get the XSRF token header
            self.fetch('/account/login')
            if self._xsrf_token is None:
                # This means that the XSRF token is disabled
                self._xsrf_token = False

    def get_lock(self, lock_name):
        self.init_xsrf()
        body = {
            'resource': 'master',
            'method': 'get_lock',
            'kwarg': {
                'name': lock_name,
            }
        }
        response = self.fetch('/rpc', method='POST', body=body, retry_on_auth_failure=False)
        return response

    def request_master_key(self, master_id):
        if os.path.exists(self.pubkey_path):
            return None

        self.init_xsrf()
        body = {
            'resource': 'master',
            'method': 'request_master_key',
            'kwarg': {
                'master_id': master_id,
            }
        }
        response = self.fetch('/rpc', method='POST', body=body, retry_on_auth_failure=False)
        pubkey = response['ret']['pubkey']
        orig_mask = os.umask(0o177)
        with open(self.pubkey_path, 'w') as fh:
            fh.write(pubkey)
        os.umask(orig_mask)

        log.critical('Public key retrieved, waiting to be accepted.')
        log.critical('Public key: %s', self.pubkey_path)
        log.critical('Public key: %s', response['ret']['fingerprint'])

        wait_time = 2
        while True:
            time.sleep(wait_time)
            log.critical('Checking public key acceptance.')
            response = self.get_master_jwt()
            if response['ret']:
                log.critical('Public key accepted.')
                return response
            wait_time = min(60, 2 * wait_time)

    def get_master_jwt(self, test=False, init_xsrf=False):
        if init_xsrf:
            self.init_xsrf()

        try:
            data = {
                'created': datetime.datetime.utcnow().isoformat() + 'Z',
                'master_id': self.username,
            }
            emsg = self.encrypt_message(data, self.pubkey_path)
        except IOError:
            log.error('Public key auth has not been initialized.')
            return None

        body = {
            'resource': 'master',
            'method': 'get_master_jwt',
            'kwarg': {
                'master_id': self.username,
                'encrypted_message': emsg,
                'test': test,
            }
        }
        response = self.fetch('/rpc', method='POST', body=body, retry_on_auth_failure=False)
        return response

    def authenticate(self):
        self._authenticated = False
        self.init_xsrf()

        if self._use_jwt and self.shared_jwt is not None:
            shared = self.shared_jwt.get()
            if shared:
                self._authenticated = True
                self._jwt = shared
                return self._authenticated

        self._last_auth_request_time = time.time()

        if self.password:
            body = {
                'username': self.username,
                'password': self.password,
                'config_name': self.config_name,
            }

            if self._use_jwt:
                body['token_type'] = 'jwt'

            response = self.fetch('/account/login', method='POST', body=body, retry_on_auth_failure=False)
            if isinstance(response, dict):
                if 'attributes' in response and 'username' in response['attributes']:
                    self._authenticated = self.username == response['attributes']['username']
                if self._use_jwt and 'jwt' in response:
                    self._jwt = response['jwt']
                    if self.shared_jwt is not None:
                        self.shared_jwt.set(response['jwt'])
        else:
            response = self.request_master_key(self.username)
            if not response:
                response = self.get_master_jwt()
            if isinstance(response, dict):
                if 'ret' in response and response['ret'] and 'jwt' in response['ret']:
                    self._authenticated = True
                    self._jwt = response['ret']['jwt']
                    if self.shared_jwt is not None:
                        self.shared_jwt.set(response['ret']['jwt'])

        return self._authenticated

    def _handle_auth_error(self, retry_on_auth_failure):
        '''
        If the response is a 401 or 403 error, either prepare for retrying the
        request or raise AuthenticationFailure. A retry is appropriate for a
        401 error caused by missing or bad credentials or a 403 error caused by
        a missing or invalid XSRF token.

        Return value:
        - False if the response is not a 401 or 403 error
        - True if the response is a 401 or 403 error that should be retried
        - Raise AuthenticationFailure (401) or RequestFailure (403) if the
          request should not be retried
        '''
        response = self._error_response
        if response is None or response.code not in (401, 403):
            return False

        self._authenticated = False

        if response.code == 401:
            # Try to get error detail from the response body
            try:
                body = response.read()
                if six.PY3:
                    body = json.loads(body.decode('utf-8'))
                else:
                    body = json.loads(body)
                error = body.get('errors')[0]
            except (TypeError, ValueError, KeyError, IndexError, JSON_DECODE_ERROR):
                error = None

            if error:
                if 'jwt not authorized' in error.get('message', '').lower():
                    if self.shared_jwt:
                        self.shared_jwt.remove()
                    if not retry_on_auth_failure:
                        log.error('Failed to authenticate with JWT: %s', error['message'])
                        raise AuthenticationFailure(message=error['message'])
                elif 'invalid credentials' in error.get('title', '').lower():
                    if not retry_on_auth_failure:
                        log.error('Failed to authenticate %s/%s: %s', self.config_name, self.username, error['detail'])
                        raise AuthenticationFailure(message=error['detail'])
                else:
                    message = '{}: {}'.format(error['message'], error['detail'])
                    log.error(message)
                    raise AuthenticationFailure(message=message)
            return retry_on_auth_failure

        if response.code == 403:
            # RaaS Versions >= 8.3 set the header, lower versions use the response message.
            if 'missing xsrf' in response.msg.lower() or\
                    'missing xsrf' in response.headers.get('X-XSRFToken-Missing', '').lower():
                self._xsrf_token = None
                self.cookies.clear()
                if retry_on_auth_failure:
                    return True
            raise RequestFailure(code=response.code, message=response.msg)

    def _decode_body(self, response):
        '''
        JSON decode a response body
        '''
        if response.code == 204:
            return response.body

        try:
            body = response.read()
        except ssl.SSLError as exc:
            try:
                exc_text = exc.reason
            except AttributeError:
                exc_text = str(exc)
            raise NotConnectable(exc_text)

        try:
            if six.PY3:
                return json.loads(body.decode('utf-8'))
            else:
                return json.loads(body)
        except ValueError:
            log.debug('Failed to decode JSON from: %r', body)
            return body

    @property
    def last_auth_request_time(self):
        return self._last_auth_request_time

    def fetch(self, url, method='GET', body=None, timeout=None, retry_on_auth_failure=True, params=None):
        '''
        Issue the request to the server
        '''
        url = self._make_url(url, params)
        opener = self._make_opener(url)
        request = self._build_request(url, method, body)

        log.debug('Sending %s request (id %x) to %s', request.get_method(), id(request), request.get_full_url())

        if timeout is None:
            timeout = self.timeout
        if self._use_key_auth and not os.path.exists(self.pubkey_path):
            log.info('Temporarily overriding timeout to wait for key acceptance')
            timeout = max(self.timeout, 60*60*2)

        start = timeit.default_timer()
        try:
            response = opener.open(request, timeout=timeout)
            elapsed = timeit.default_timer() - start
            log.debug('The %s request (id: %x) to %s finished in %.2fms. HTTP Code: %s',
                    request.get_method(),
                    id(request),
                    request.get_full_url(),
                    1000 * elapsed,
                    response.code)
        except urllib_error.HTTPError as exc:
            elapsed = timeit.default_timer() - start
            log.debug('The %s request (id: %x) to %s finished in %.2fms and returned an error: %s %s',
                    request.get_method(),
                    id(request),
                    request.get_full_url(),
                    1000 * elapsed,
                    exc.code,
                    exc.reason)
            if self._handle_auth_error(retry_on_auth_failure):
                log.debug('Will authenticate and retry %s request (id: %x) to %s',
                        request.get_method(),
                        id(request),
                        request.get_full_url())
                self.authenticate()
                return self.fetch(url, method=method, body=body, timeout=timeout,
                                    retry_on_auth_failure=False, params=params)
            raise RequestFailure(code=exc.code, message=exc.reason)
        except urllib_error.URLError as exc:
            if isinstance(exc.reason, socket.timeout):
                raise TimeoutFailure('Request timed out')
            raise NotConnectable(exc.reason)
        except ssl.SSLError as exc:
            try:
                exc_text = exc.reason
            except AttributeError:
                exc_text = str(exc)
            raise NotConnectable(exc_text)
        except socket.timeout as exc:
            raise TimeoutFailure('Request timed out')
        except SocketError as exc:
            if exc.errno == errno.ECONNRESET:
                if isinstance(exc, OSError):
                    raise NotConnectable(exc.strerror)
                else:
                    raise NotConnectable(exc)
            raise

        self.cookies.extract_cookies(response, request)
        for cookie in self.cookies:
            if cookie.name == '_xsrf':
                self._xsrf_token = cookie.value
                break

        # Check the raas instance id against known raisins. If this is a
        # formerly unknown instance, update the last authentication request
        # time.
        try:
            raas_instance_id = response.headers['RaaS-Instance-ID']
            raas_instance_id = str(uuid.UUID(raas_instance_id))
            if raas_instance_id not in self._known_raisins:
                log.debug('New raas instance detected: %s', raas_instance_id)
                self._last_auth_request_time = time.time()
                self._known_raisins.add(raas_instance_id)
        except (KeyError, TypeError, ValueError):
            pass
        return self._decode_body(response)
